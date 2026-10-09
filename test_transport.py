"""Local protocol/transport regression tests; these do not test an Iranian ISP."""
import asyncio
import os
import struct
import tempfile
import unittest
import uuid
from unittest.mock import patch

for key in ('ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY', 'all_proxy', 'https_proxy', 'http_proxy'):
    os.environ.pop(key, None)
os.environ.setdefault('DATA_DIR', tempfile.mkdtemp(prefix='x4g-tests-'))
os.environ.setdefault('ADMIN_PASSWORD', 'local-test-password')
os.environ['ALLOW_PRIVATE_DESTINATIONS'] = '1'

import httpx
import uvicorn
import websockets
import main
import xhttp_siz10 as xhttp
from relay_vless import parse_vless_header, check_and_use
from speed_limit import _Bucket


def header(uid, port, payload=b''):
    return b'\0' + uuid.UUID(uid).bytes + b'\0\1' + struct.pack('>H', port) + b'\1\x7f\0\0\1' + payload


class ParserSecurityTests(unittest.TestCase):
    def test_real_vless_version_and_identity(self):
        uid = str(uuid.uuid4())
        self.assertEqual(parse_vless_header(header(uid, 80), uid)[:3], (1, '127.0.0.1', 80))
        with self.assertRaises(ValueError):
            parse_vless_header(b'\1' + header(uid, 80)[1:])
        with self.assertRaises(ValueError):
            parse_vless_header(header(uid, 80), str(uuid.uuid4()))

    def test_udp_mux_and_zero_port_are_not_treated_as_tcp(self):
        uid = str(uuid.uuid4())
        for command in (2, 3):
            data = bytearray(header(uid, 80)); data[18] = command
            with self.assertRaises(ValueError):
                parse_vless_header(bytes(data), uid)
        with self.assertRaises(ValueError):
            parse_vless_header(header(uid, 0))


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        main.AUTH["password_hash"] = main.hash_password("local-test-password")
        main.LINKS.clear()
        main.connections.clear()
        main.SESSIONS.clear()
        # Test state remains isolated from any real persisted deployment.
        main.DATA_FILE.unlink(missing_ok=True)
        self.server_socket = __import__('socket').socket()
        self.server_socket.bind(('127.0.0.1', 0))
        self.server_socket.listen(128)
        self.port = self.server_socket.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(main.app, log_level='error', lifespan='on'))
        self.server_task = asyncio.create_task(self.server.serve(sockets=[self.server_socket]))
        for _ in range(200):
            if self.server.started:
                break
            await asyncio.sleep(.01)
        self.assertTrue(self.server.started)
        self.client = httpx.AsyncClient(base_url=f'http://127.0.0.1:{self.port}', timeout=5)
        self.target_tasks = set()
        async def echo(reader, writer):
            self.target_tasks.add(asyncio.current_task())
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                self.target_tasks.discard(asyncio.current_task())
        self.echo = await asyncio.start_server(echo, '127.0.0.1', 0)
        self.echo_port = self.echo.sockets[0].getsockname()[1]
        self.uid, _ = await main.make_link(label='test')

    async def asyncTearDown(self):
        await self.client.aclose()
        await xhttp.shutdown_sessions()
        self.server.should_exit = True
        await asyncio.wait_for(self.server_task, 5)
        self.echo.close()
        await self.echo.wait_closed()
        for task in list(self.target_tasks):
            task.cancel()
        await asyncio.gather(*self.target_tasks, return_exceptions=True)

    async def test_websocket_fragmented_header_and_large_transfer(self):
        payload = os.urandom(2 * 1024 * 1024)
        async with websockets.connect(f'ws://127.0.0.1:{self.port}/ws/{self.uid}', max_size=None) as ws:
            h = header(self.uid, self.echo_port)
            for byte in h:
                await ws.send(bytes([byte]))
            self.assertEqual(await asyncio.wait_for(ws.recv(), 3), b'\0\0')
            async def send():
                for offset in range(0, len(payload), 32768):
                    await ws.send(payload[offset:offset + 32768])
            task = asyncio.create_task(send())
            received = bytearray()
            while len(received) < len(payload):
                received.extend(await asyncio.wait_for(ws.recv(), 5))
            await task
            self.assertEqual(received, payload)
        for _ in range(100):
            if not main.connections:
                break
            await asyncio.sleep(.01)
        self.assertFalse(main.connections)

    async def test_websocket_wrong_uuid_rejected(self):
        async with websockets.connect(f'ws://127.0.0.1:{self.port}/ws/{self.uid}') as ws:
            await ws.send(header(str(uuid.uuid4()), self.echo_port))
            with self.assertRaises(websockets.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), 3)

    async def test_xhttp_out_of_order_split_header(self):
        base = f'/xhttp-siz10/{self.uid}/ordered'
        payload = b'fragmented-xhttp-payload' * 4096
        h = header(self.uid, self.echo_port)
        for seq, body in ((1, h[8:] + payload), (0, h[:8])):
            response = await self.client.post(f'{base}/{seq}', content=body)
            self.assertEqual(response.status_code, 200, response.text)
        async with self.client.stream('GET', base) as response:
            self.assertEqual(response.status_code, 200)
            received = bytearray()
            async for chunk in response.aiter_bytes():
                received.extend(chunk)
                if len(received) >= len(payload) + 2:
                    break
            self.assertEqual(received, b'\0\0' + payload)
        await asyncio.sleep(.05)
        self.assertFalse(xhttp.xhttp_sessions)

    async def test_xhttp_stream_and_eof_cleanup(self):
        base = f'/xhttp-siz10/{self.uid}/stream'
        payload = b'stream-payload' * 8192
        async def upload():
            h = header(self.uid, self.echo_port)
            yield h[:7]
            await asyncio.sleep(.01)
            yield h[7:] + payload
        response = await self.client.post(base, content=upload())
        self.assertEqual(response.status_code, 200, response.text)
        # GET must attach before the upstream EOF cleanup removes the session.
        # A real XHTTP client opens GET before POST, so use a concurrent GET below.

    async def test_xhttp_stream_download_before_upload(self):
        base = f'/xhttp-siz10/{self.uid}/stream-live'
        payload = b'full-duplex' * 16384
        async def download():
            async with self.client.stream('GET', base) as response:
                self.assertEqual(response.status_code, 200)
                return await response.aread()
        task = asyncio.create_task(download())
        await asyncio.sleep(.05)
        async def upload():
            h = header(self.uid, self.echo_port)
            yield h[:8]
            await asyncio.sleep(.01)
            yield h[8:] + payload
        response = await self.client.post(base, content=upload())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(await asyncio.wait_for(task, 5), b'\0\0' + payload)
        self.assertNotIn('stream-live', xhttp.xhttp_sessions)

    async def test_session_is_bound_to_uuid_and_auth(self):
        await xhttp._get_or_create_session(self.uid, 'packet-up', 'owned', 'test')
        other, _ = await main.make_link(label='other')
        response = await self.client.post(f'/xhttp-siz10/{other}/owned/0', content=b'x')
        self.assertEqual(response.status_code, 403)
        response = await self.client.post('/xhttp-siz10/not-a-link/new/0', content=b'x')
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('new', xhttp.xhttp_sessions)

    async def test_large_first_packet_is_allowed(self):
        data = header(self.uid, self.echo_port, b'x' * 100000)
        response = await self.client.post(f'/xhttp-siz10/{self.uid}/large/0', content=data)
        self.assertEqual(response.status_code, 200, response.text)

    async def test_duplicate_negative_and_oversized_packets(self):
        base = f'/xhttp-siz10/{self.uid}/bounded'
        response = await self.client.post(base + '/-1', content=b'x')
        self.assertEqual(response.status_code, 409)
        response = await self.client.post(base + '/1', content=b'x')
        self.assertEqual(response.status_code, 200)
        response = await self.client.post(base + '/1', content=b'x')
        self.assertEqual(response.status_code, 409)
        response = await self.client.post(base + '/0', content=b'x' * (1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)

    async def test_auth_proxy_cookie_and_persistence(self):
        self.assertEqual((await self.client.get('/proxy/example.com')).status_code, 401)
        self.assertEqual((await self.client.get('/api/links')).status_code, 401)
        response = await self.client.post('/api/login', json={'password': 'local-test-password'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Secure', response.headers['set-cookie'])
        token = response.cookies.get(main.SESSION_COOKIE)
        self.assertEqual((await self.client.get('/api/links', headers={'Cookie': f'{main.SESSION_COOKIE}={token}'})).status_code, 200)
        main.LINKS[self.uid]['used_bytes'] = 12345
        await main.save_state()
        main.LINKS.clear()
        await main.load_state()
        self.assertEqual(main.LINKS[self.uid]['used_bytes'], 12345)
        count = sum(getattr(r, 'path', '') == '/xhttp-siz10/{uuid}/{session_id}/{seq}' for r in main.app.routes)
        main.register_xhttp_router()
        self.assertEqual(count, sum(getattr(r, 'path', '') == '/xhttp-siz10/{uuid}/{session_id}/{seq}' for r in main.app.routes))

    async def test_quota_does_not_overshoot(self):
        main.LINKS[self.uid]['limit_bytes'] = 10
        self.assertFalse(await check_and_use(self.uid, 11))
        self.assertEqual(main.LINKS[self.uid]['used_bytes'], 0)
        self.assertTrue(await check_and_use(self.uid, 10))
        self.assertFalse(await check_and_use(self.uid, 1))


class ThrottleTests(unittest.IsolatedAsyncioTestCase):
    async def test_chunk_larger_than_bucket_finishes(self):
        b = _Bucket(1024 * 1024)
        await asyncio.wait_for(b.consume(2 * 1024 * 1024), 3)

class AdditionalSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_private_destinations_blocked_by_default(self):
        from network import open_destination
        with patch.dict(os.environ, {'ALLOW_PRIVATE_DESTINATIONS': '0'}):
            for host in ('127.0.0.1', '169.254.169.254', '::1'):
                with self.assertRaisesRegex(ValueError, 'private/local'):
                    await open_destination(host, 80)

    async def test_disabled_xhttp_link_cannot_forward_small_unbatched_chunks(self):
        uid = str(uuid.uuid4())
        main.LINKS[uid] = {'active': False, 'used_bytes': 0}
        try:
            self.assertFalse(await xhttp._QuotaGate(uid).add(1))
            self.assertEqual(main.LINKS[uid]['used_bytes'], 0)
        finally:
            main.LINKS.pop(uid, None)

    async def test_password_hashing_and_legacy_migration_compatibility(self):
        import hashlib
        stored = main.hash_password('a-long-test-password')
        self.assertTrue(main.verify_password('a-long-test-password', stored))
        self.assertFalse(main.verify_password('wrong', stored))
        self.assertNotEqual(stored, main.hash_password('a-long-test-password'))
        legacy = hashlib.sha256(f"old-password{main.CONFIG['secret']}".encode()).hexdigest()
        self.assertTrue(main.verify_password('old-password', legacy))

    async def test_idle_connected_session_is_reaped(self):
        uid = str(uuid.uuid4())
        main.LINKS[uid] = {'active': True, 'used_bytes': 0}
        try:
            sess = await xhttp._get_or_create_session(uid, 'packet-up', 'idle-test', 'local-test')
            sess['tcp_open'] = True
            sess['last_seen'] = 0
            with patch.object(xhttp, 'REAPER_INTERVAL', .01):
                task = asyncio.create_task(xhttp._reaper())
                try:
                    await asyncio.sleep(.03)
                    self.assertNotIn('idle-test', xhttp.xhttp_sessions)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        finally:
            main.LINKS.pop(uid, None)
            await xhttp._teardown('idle-test')
