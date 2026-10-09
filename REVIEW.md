# Review and validation — 2026-10-09

## Scope and results

Read the Python server, transport modules, dashboard/public-page templates, Telegram bot, existing tests, container recipe and deployment instructions. Tested in Linux/Python 3.12. No Iranian ISP, deployed VPS, public TLS certificate or paid hosting account was available. No claim of uninterrupted access from Iran is made.

## Corrections

- Accept VLESS version 0, matching Xray's protocol implementation; previous code and parser tests used version 1 and could pass tests while rejecting real clients.
- Validate the header UUID against the authorized link. Explicitly reject unsupported UDP/Mux/addons and zero ports instead of treating them as TCP.
- Send the VLESS response header immediately after connecting, including server-first protocols.
- Fix token-bucket deadlock when a chunk exceeds its maximum capacity.
- Bind XHTTP sessions to one UUID/transport, authorize before creation, serialize uploads, reject invalid/duplicate sequence numbers and bound packet/sequence/queue memory.
- Accept a valid header with a large initial payload rather than rejecting all first packets above 64 KiB.
- Avoid XHTTP pump self-cancellation during teardown; clean up on downstream disconnect, idle expiry and application shutdown; preserve queued data on normal EOF.
- Check authorization/quota for every chunk before forwarding, and reject chunks that would overshoot a configured allowance. Wire header bytes continue to count toward usage.
- Periodically save usage, make state snapshots independent of concurrent mutation, and prevent duplicate router registration.
- Require an initial admin password; retain existing password hashes and migrate legacy hashes to salted PBKDF2 on successful login. Add login rate limiting, Secure cookies, a 12-character minimum on password changes, and remove unused permissive CORS.
- Require admin authentication for HTTP proxy and remove admin cookies/authorization from forwarded requests.
- Resolve and pin TCP destination addresses; block non-public destinations by default, including local services and link-local metadata endpoints.
- Prefer configured PUBLIC_HOST to untrusted request host values.
- Generate QR codes locally instead of sending connection credentials to a third-party QR API.
- Update/audit dependencies, add Compose/Caddy HTTPS setup, ignore local secrets, add test CI and replace inaccurate deployment/feature claims.

## Validation

- Original baseline: 5 tests passed but did not test the real VLESS version or transport interoperability.
- Final local suite: **22 tests passed**. Expanded regression tests cover protocol/UUID/command validation, oversized chunks, quota boundaries, fragmented headers, WebSocket binary transfers, XHTTP ordered/out-of-order and streaming transfers, session ownership, bounded packets, authentication, cookies, persistence and router idempotence.
- Actual Xray **26.3.27** client on loopback: **5 × 1 MiB HTTP downloads per transport**, WebSocket and XHTTP packet-up. All response bytes matched. Retested after dependency upgrades and security fixes.
- Requirements audited with pip-audit: **27 resolved dependencies, zero reported known vulnerabilities** at review time. This is a database check, not a guarantee that all code is secure.

## Remaining limits / deployment checks

- TCP only. UDP, QUIC, XUDP, Mux, REALITY and VLESS flow/addons are not implemented. This is not a replacement for every capability of a full Xray server.
- No test from Iran, no long-duration Internet soak, no public TLS/CDN test, no live Telegram test. Telegram remained disabled during testing.
- Docker was unavailable locally; Compose and Caddy need an actual server deployment check. CI configuration is supplied; its remote outcome should be checked separately.
- A single application worker is required. Multiple replicas do not share active transport sessions, login sessions or quota accounting.
- Idle XHTTP sessions expire intentionally; restart/deploy and mobile network changes can terminate active TCP streams. A healthcheck cannot guarantee censorship resistance or uninterrupted connectivity.
- The API protects quota at chunk boundaries, so a final chunk larger than the remaining quota is rejected in full. A failed outgoing write may still have charged accepted bytes.
- Global in-memory stats reset on restart. Persistent per-link usage is saved periodically; a crash may lose the last interval. Login sessions reset on restart.
- Forwarded IP headers assume a trusted reverse proxy. Compose keeps the app port internal; if using another host, do not expose the backend directly to untrusted clients.
- Dashboard decorative fonts/icons still use external assets, which may fail to load on a restricted network. Connection QR generation is served locally.

## Sources

- VLESS wire header: https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go
- Android client: https://github.com/2dust/v2rayNG
- Caddy HTTPS: https://caddyserver.com/docs/automatic-https
- Caddy reverse proxy: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy

