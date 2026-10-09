# xhttp_siz10.py
# ══════════════════════════════════════════════════════════════════════════════
# Siz10a · XHTTP Ultra Transport — مود auto (packet-up / stream-up)
#  مسیر سرور دیگه به مود بستگی نداره (سازگار با mode=packet-up به‌عنوان حالت پیش‌فرض لینک‌های X4G):
#  کلاینت خودش بر اساس نوع اتصال (H2/REALITY یا نه) بین packet-up و
#  stream-up انتخاب می‌کنه، و مود واقعی فقط از روی شکل درخواست POST
#  (وجود یا عدم وجود seq در انتهای مسیر) روی سرور تشخیص داده می‌شه.
#  (stream-one حذف شد. منطق relay_vless دست‌نخورده.
#   stream-up بازنویسی شده با موتور تطبیقی: _AdaptiveFlow (AIMD روی high-water)
#   + _QuotaGate تطبیقی (batch بر اساس نرخ واقعی هر سشن) + سوکت تیون‌شده)
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
from network import open_destination
import os
import secrets
import socket
import time
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

import main as _main
from relay_vless import parse_vless_header, VLESSNeedMoreData, check_and_use
from speed_limit import throttle

router = APIRouter()

XHTTP_BUF = 512 * 1024
DOWNLINK_QUEUE_MAX = 16
SESSION_IDLE_TIMEOUT = float(os.environ.get("XHTTP_SESSION_IDLE_TIMEOUT", "120"))
REAPER_INTERVAL = float(os.environ.get("XHTTP_REAPER_INTERVAL", "15"))
TCP_CONNECT_TIMEOUT = float(os.environ.get("TCP_CONNECT_TIMEOUT", "15"))
HEADER_BUFFER_LIMIT = 64 * 1024

# ── تنظیمات موتور تطبیقی ──────────────────────────────────────────────────────
SOCK_BUF_SIZE = 2 * 1024 * 1024     # SO_SNDBUF / SO_RCVBUF

# _AdaptiveFlow: بازه‌ی مجاز برای high-water تطبیقی (AIMD)
FLOW_MIN_HW = 256 * 1024
FLOW_MAX_HW = 16 * 1024 * 1024
FLOW_START_HW = 2 * 1024 * 1024
FLOW_FAST_DRAIN_MS = 2.0    # زیر این یعنی downstream خیلی سریعه → بافر مجاز رو زیاد کن
FLOW_SLOW_DRAIN_MS = 25.0   # بالای این یعنی backpressure واقعی → فوری نصفش کن

PACKET_UP_HIGH_WATER = 2 * 1024 * 1024  # packet-up همون منطق ساده‌ی قبلی رو داره (تمرکز این راند فقط stream-up بود)

xhttp_sessions: dict = {}
XHTTP_LOCK = asyncio.Lock()

FINGERPRINTS = {
    "chrome": {
        "content-type": "application/grpc",
        "cache-control": "no-cache, no-store",
        "x-accel-buffering": "no",
        "server": "cloudflare",
    },
    "plain": {
        "content-type": "application/octet-stream",
        "cache-control": "no-store",
        "x-accel-buffering": "no",
    },
}
DEFAULT_FINGERPRINT = "chrome"


def _resp_headers(fp: str) -> dict:
    return dict(FINGERPRINTS.get(fp, FINGERPRINTS[DEFAULT_FINGERPRINT]))


def _tune_socket(writer: asyncio.StreamWriter):
    """TCP_NODELAY + بافرهای بزرگ‌تر سوکت برای کاهش سربار سیستم‌عامل روی ترافیک بالا."""
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except (AttributeError, OSError):
            pass
    except OSError:
        pass


class _QuotaGate:
    """Check authorization and charge bytes before forwarding each chunk."""
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.ok = True

    async def add(self, nbytes: int) -> bool:
        self.ok = self.ok and await check_and_use(self.uuid, nbytes)
        return self.ok

    async def flush(self) -> bool:
        return self.ok


class _AdaptiveFlow:
    """
    high-water تطبیقی برای drain(), رفتار شبیه AIMD در TCP congestion control:
      - هر بار drain() صدا زده می‌شه، مدت زمانش اندازه‌گیری می‌شه.
      - اگه سریع تموم بشه (لینک پایین‌دستی داره جواب می‌ده) → سقف بافر مجاز رو
        additive increase می‌کنیم؛ یعنی دفعه‌ی بعد دیرتر drain صدا زده می‌شه،
        پس syscall/context-switch کمتر می‌شه و throughput واقعی بالا می‌ره.
      - اگه drain کند بشه (backpressure واقعیه، صف داره جمع می‌شه) → سقف رو فوری
        نصف می‌کنیم (multiplicative decrease) تا بافربلوت/لتنسی رشد نکنه.
    هر سشن یک نمونه‌ی جدا از این داره، پس مسیرهای کند و سریع تداخلی با هم ندارن.
    """
    __slots__ = ("high_water", "last_drain_ms")

    def __init__(self):
        self.high_water = FLOW_START_HW
        self.last_drain_ms = 0.0

    def should_drain(self, buf_size: int) -> bool:
        return buf_size > self.high_water

    async def drain(self, writer: asyncio.StreamWriter):
        t0 = time.monotonic()
        await writer.drain()
        elapsed_ms = (time.monotonic() - t0) * 1000
        self.last_drain_ms = elapsed_ms
        if elapsed_ms < FLOW_FAST_DRAIN_MS:
            self.high_water = min(FLOW_MAX_HW, int(self.high_water * 1.5) + 65536)
        elif elapsed_ms > FLOW_SLOW_DRAIN_MS:
            self.high_water = max(FLOW_MIN_HW, self.high_water // 2)


def _req_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


async def _open_tcp_from_header(first_chunk: bytes, uuid: str):
    command, address, port, payload = parse_vless_header(first_chunk, uuid)
    reader, writer = await asyncio.wait_for(
        open_destination(address, port), timeout=TCP_CONNECT_TIMEOUT
    )
    _tune_socket(writer)
    if payload:
        writer.write(payload)
        await writer.drain()
    return reader, writer, address, port


async def _check_link(uuid: str):
    async with _main.LINKS_LOCK:
        link = _main.LINKS.get(uuid)
    if not _main.is_link_allowed(link):
        raise HTTPException(status_code=403, detail="not authorized")


async def _get_or_create_session(uuid: str, mode: str, session_id: str, ip: str = "نامشخص") -> dict:
    """Session بر اساس session_id که خودِ کلاینت در URL فرستاده، lazily ساخته می‌شه."""
    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)
        if sess is not None:
            if sess["uuid"] != uuid:
                raise HTTPException(status_code=403, detail="session belongs to another link")
            if mode != "auto" and sess["mode"] not in ("auto", mode):
                raise HTTPException(status_code=409, detail="session transport mismatch")
            sess["last_seen"] = time.time()
            return sess

        async with _main.LINKS_LOCK:
            link = _main.LINKS.get(uuid)
        if not _main.is_link_allowed(link):
            raise HTTPException(status_code=403, detail="not authorized")
        if not _main.is_ip_allowed(link, uuid, ip):
            _main.logger.warning(f"🚫 XHTTP[{mode}] rejected uuid={uuid[:8]} ip={ip} (ip limit reached)")
            raise HTTPException(status_code=403, detail="ip limit reached")

        conn_id = secrets.token_urlsafe(6)
        _main.connections[conn_id] = {
            "uuid": uuid,
            "ip": ip,
            "connected_at": datetime.now().isoformat(),
            "bytes": 0,
            "transport": f"xhttp-{mode}",
        }
        sess = {
            "uuid": uuid, "mode": mode, "writer": None,
            "downlink_task": None, "uplink_task": None,
            "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
            "last_seen": time.time(),
            "conn_id": conn_id, "tcp_open": False, "closed": False,
            "seq_buf": {}, "next_seq": 0,
            "header_buf": bytearray(),
            "upload_lock": asyncio.Lock(), "download_started": False,
            "session_id": session_id,
            "gate": None,  # لازی ساخته می‌شه: _QuotaGate تطبیقی مخصوص stream-up
            "flow": None,  # لازی ساخته می‌شه: _AdaptiveFlow مخصوص stream-up
        }
        xhttp_sessions[session_id] = sess
        _main.logger.info(f"new XHTTP[{mode}] session [{session_id[:8]}] uuid={uuid[:8]} ip={ip}")
        return sess


async def _mark_real_mode(session_id: str, sess: dict, real_mode: str):
    """وقتی سشن با مود 'auto' ساخته شده، اولین درخواست POST واقعی مشخص می‌کنه
    که کلاینت در عمل packet-up انتخاب کرده یا stream-up؛ همون‌جا برچسب سشن و
    اتصال نمایشی رو به‌روز می‌کنیم تا در بخش «اتصالات» درست دیده بشه."""
    if sess.get("mode") == real_mode:
        return
    sess["mode"] = real_mode
    conn = _main.connections.get(sess.get("conn_id"))
    if conn:
        conn["transport"] = f"xhttp-{real_mode}"


async def _teardown(session_id: str, notify: bool = True):
    async with XHTTP_LOCK:
        sess = xhttp_sessions.pop(session_id, None)
    if not sess:
        return
    sess["closed"] = True
    for t in ("uplink_task", "downlink_task"):
        task = sess.get(t)
        if task and task is not asyncio.current_task():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    writer = sess.get("writer")
    if writer:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    _main.connections.pop(sess.get("conn_id"), None)
    dq = sess.get("down_q")
    if dq is not None and notify:
        try:
            if dq.full():
                dq.get_nowait()
            dq.put_nowait(None)
        except Exception:
            pass
    _main.logger.info(f"closed XHTTP[{sess.get('mode')}] [{session_id[:8]}] total={len(xhttp_sessions)}")


async def _reaper():
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.time()
        async with XHTTP_LOCK:
            stale = [sid for sid, s in xhttp_sessions.items()
                     if now - s["last_seen"] > SESSION_IDLE_TIMEOUT]
        for sid in stale:
            await _teardown(sid)


_reaper_task = None


def ensure_reaper():
    global _reaper_task
    if _reaper_task is None or _reaper_task.done():
        _reaper_task = asyncio.create_task(_reaper())


async def shutdown_sessions():
    global _reaper_task
    if _reaper_task is not None:
        _reaper_task.cancel()
        await asyncio.gather(_reaper_task, return_exceptions=True)
        _reaper_task = None
    for sid in list(xhttp_sessions):
        await _teardown(sid)


async def _pump_tcp_to_queue(session_id: str, uuid: str, reader: asyncio.StreamReader, down_q: asyncio.Queue):
    gate = _QuotaGate(uuid)
    try:
        await down_q.put(b"\x00\x00")
        while True:
            data = await reader.read(XHTTP_BUF)
            if not data:
                break
            if not await gate.add(len(data)):
                break
            await throttle(uuid, len(data))
            async with XHTTP_LOCK:
                sess = xhttp_sessions.get(session_id)
            if sess:
                sess["last_seen"] = time.time()
                c = _main.connections.get(sess["conn_id"])
                if c:
                    c["bytes"] += len(data)
            await down_q.put(data)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        _main.logger.warning("XHTTP downlink failed: %s", exc)
    finally:
        await gate.flush()
        sess = xhttp_sessions.get(session_id)
        if sess is not None and not sess["closed"]:
            await down_q.put(None)
            await _teardown(session_id, notify=False)


async def _open_tcp_for_session(session_id: str, uuid: str, sess: dict, first_chunk: bytes):
    """تونل TCP رو از روی هدر VLESS باز می‌کنه و پمپ دانلینک رو راه می‌اندازه."""
    reader, writer, address, port = await _open_tcp_from_header(first_chunk, uuid)
    _main.logger.info(f"connect XHTTP[{sess['mode']}] [{session_id[:8]}] -> {address}:{port}")
    sess["writer"] = writer
    sess["tcp_open"] = True
    sess["downlink_task"] = asyncio.create_task(
        _pump_tcp_to_queue(session_id, uuid, reader, sess["down_q"])
    )
    asyncio.create_task(_main.save_state())


def _downstream_gen(sess: dict):
    async def gen():
        try:
            while True:
                chunk = await sess["down_q"].get()
                if chunk is None:
                    break
                sess["last_seen"] = time.time()
                yield chunk
        finally:
            await _teardown(sess["session_id"])
    return gen()


# ══════════════════════════════ GET دانلینک (مشترک بین دو مد، بدون وابستگی به مود) ══════════════════════════════
@router.get("/xhttp-siz10/{uuid}/{session_id}")
async def xhttp_downlink(uuid: str, session_id: str, request: Request):
    ensure_reaper()
    await _check_link(uuid)
    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    sess = await _get_or_create_session(uuid, "auto", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    if sess["download_started"]:
        raise HTTPException(status_code=409, detail="downlink already attached")
    sess["download_started"] = True
    headers = _resp_headers(fp)
    return StreamingResponse(_downstream_gen(sess), headers=headers, media_type=headers["content-type"])


# ══════════════════════════════ PACKET-UP (آپلینک با seq) ══════════════════════════════
async def _packet_up_upload(uuid: str, session_id: str, seq: int, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "packet-up", session_id, _req_client_ip(request))
    await _mark_real_mode(session_id, sess, "packet-up")
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    sess["last_seen"] = time.time()
    if seq < sess["next_seq"] or seq in sess["seq_buf"] or seq > sess["next_seq"] + 64:
        raise HTTPException(status_code=409, detail="invalid or duplicate sequence")
    body_buf = bytearray()
    async for chunk in request.stream():
        body_buf.extend(chunk)
        if len(body_buf) > 1024 * 1024:
            await _teardown(session_id)
            raise HTTPException(status_code=413, detail="packet exceeds 1 MiB")
    body = bytes(body_buf)
    if sum(map(len, sess["seq_buf"].values())) + len(body) > 4 * 1024 * 1024:
        await _teardown(session_id)
        raise HTTPException(status_code=413, detail="sequence buffer limit")
    if not body:
        return {"ok": True}

    if not await check_and_use(uuid, len(body)):
        await _teardown(session_id)
        raise HTTPException(status_code=403, detail="quota/disabled/unknown")
    await throttle(uuid, len(body))

    _main.stats["total_requests"] += 1
    _main.connections[sess["conn_id"]]["bytes"] += len(body)

    try:
        if sess["writer"] is None:
            # The VLESS header may span several packet-up requests. Consume
            # contiguous sequence numbers into header_buf until it parses.
            if seq != sess["next_seq"]:
                sess["seq_buf"][seq] = body
                return {"ok": True, "buffered": True}

            sess["header_buf"].extend(body)
            sess["next_seq"] += 1
            while True:
                try:
                    parse_vless_header(bytes(sess["header_buf"]), uuid)
                    break
                except VLESSNeedMoreData:
                    if len(sess["header_buf"]) > HEADER_BUFFER_LIMIT:
                        raise ValueError("VLESS header exceeded safety limit")
                    if sess["next_seq"] not in sess["seq_buf"]:
                        return {"ok": True, "header_buffered": True}
                    pending = sess["seq_buf"].pop(sess["next_seq"])
                    sess["header_buf"].extend(pending)
                    sess["next_seq"] += 1

            first_chunk = bytes(sess["header_buf"])
            sess["header_buf"].clear()
            await _open_tcp_for_session(session_id, uuid, sess, first_chunk)

            # Send any already-arrived packets after the parsed header in order.
            while sess["next_seq"] in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(sess["next_seq"])
                sess["writer"].write(pending)
                sess["next_seq"] += 1
            await sess["writer"].drain()
            return {"ok": True, "connected": True}

        if seq == sess["next_seq"]:
            sess["writer"].write(body)
            sess["next_seq"] += 1
            while sess["next_seq"] in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(sess["next_seq"])
                sess["writer"].write(pending)
                sess["next_seq"] += 1
        else:
            sess["seq_buf"][seq] = body

        if sess["writer"].transport.get_write_buffer_size() > PACKET_UP_HIGH_WATER:
            await sess["writer"].drain()
    except Exception as exc:
        _main.error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="write failed")

    return {"ok": True}


# ══════════════════════════════ STREAM-UP (یک POST پیوسته) ══════════════════════════════
# موتور تطبیقی: _QuotaGate (batch کوتا بر اساس نرخ واقعی) + _AdaptiveFlow (AIMD روی
# high-water درین) + کش رفرنس‌ها داخل لوپ. هیچ داده‌ای بافر/coalesce نمی‌شه —
# هر بایت فوری write() می‌شه، فقط «کِی صبر کنیم برای drain» تطبیقیه.
async def _stream_up_upload(uuid: str, session_id: str, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "stream-up", session_id, _req_client_ip(request))
    await _mark_real_mode(session_id, sess, "stream-up")
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.get("gate")
    if gate is None:
        gate = _QuotaGate(uuid)
        sess["gate"] = gate

    flow = sess.get("flow")
    if flow is None:
        flow = _AdaptiveFlow()
        sess["flow"] = flow

    conn = _main.connections[sess["conn_id"]]   # یک بار لوک‌آپ، نه هر چانک
    writer = sess["writer"]               # ممکنه هنوز None باشه

    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            sess["last_seen"] = time.time()

            if not await gate.add(len(chunk)):
                raise HTTPException(status_code=403, detail="quota/disabled/unknown")
            await throttle(uuid, len(chunk))

            _main.stats["total_requests"] += 1
            conn["bytes"] += len(chunk)

            if writer is None:
                sess["header_buf"].extend(chunk)
                try:
                    parse_vless_header(bytes(sess["header_buf"]), uuid)
                except VLESSNeedMoreData:
                    if len(sess["header_buf"]) > HEADER_BUFFER_LIMIT:
                        raise ValueError("VLESS header exceeded safety limit")
                    continue

                first_chunk = bytes(sess["header_buf"])
                sess["header_buf"].clear()
                await _open_tcp_for_session(session_id, uuid, sess, first_chunk)
                writer = sess["writer"]
                continue

            writer.write(chunk)
            if flow.should_drain(writer.transport.get_write_buffer_size()):
                await flow.drain(writer)
    except HTTPException:
        await gate.flush()
        await _teardown(session_id)
        raise
    except Exception as exc:
        _main.error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await gate.flush()
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="stream error")

    await gate.flush()
    if writer is not None:
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    return {"ok": True}


@router.post("/xhttp-siz10/{uuid}/{session_id}/{seq}")
async def packet_up_upload(uuid: str, session_id: str, seq: int, request: Request):
    await _check_link(uuid)
    sess = await _get_or_create_session(uuid, "packet-up", session_id, _req_client_ip(request))
    async with sess["upload_lock"]:
        if sess["closed"]:
            raise HTTPException(status_code=404, detail="session closed")
        return await _packet_up_upload(uuid, session_id, seq, request)


@router.post("/xhttp-siz10/{uuid}/{session_id}")
async def stream_up_upload(uuid: str, session_id: str, request: Request):
    await _check_link(uuid)
    sess = await _get_or_create_session(uuid, "stream-up", session_id, _req_client_ip(request))
    if sess["upload_lock"].locked():
        raise HTTPException(status_code=409, detail="uplink already attached")
    async with sess["upload_lock"]:
        return await _stream_up_upload(uuid, session_id, request)
