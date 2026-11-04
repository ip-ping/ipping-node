# Changelog

Progress log for `ipping-node`, newest first. Each entry is one small, tested step.

## Unreleased

### 2026-11-04: backend connection, enrollment and CLI
- `ipping-node enroll` / `run`: state directory with private permissions, credential sent only in
  an `Authorization` header, plain-`http://` backends refused unless local.
- Connection loop: hello/welcome handshake with protocol negotiation, heartbeat, reconnect with
  jittered exponential backoff, local concurrency cap (`node_busy`), bounded outbound buffer,
  cancellation of running tasks when the connection ends, clean shutdown on SIGINT/SIGTERM.
- Capabilities re-detected on every connect.
- Verified end to end against the real backend: enroll with a single-use token, approval, live
  pings of a public IP and of a pasted URL, loopback refused, node goes offline when stopped.

### 2026-11-04: ICMP probe and task runner
- `Prober` trait with an ICMP implementation (`surge-ping`): unprivileged ping sockets first, raw
  sockets as fallback; fixed 56-byte payload; monotonic round-trip timing.
- Capabilities are detected, not assumed: a socket must open *and* a route must exist per IP version.
- Task runner: range-checks options, re-applies the destination policy to every resolved address,
  paces echoes by the interval, honours cancellation and expiry (with a server-clock offset), and
  reports "could not send" (permission, no route) as a failure rather than 100% loss.
- 22 tests with scripted probe results and DNS answers, plus a live loopback echo test.

### 2026-11-04: destination policy
- Allowlist of globally routable unicast addresses; IANA special-purpose IPv4 and IPv6 ranges,
  multicast, and ranges that embed an IPv4 address (NAT64, 6to4, Teredo, IPv4-mapped) are refused.
- Strict literal parsing (no `127.1`, hex, scoped or `host:port` forms) and hostname validation.
- The node re-checks every target even though the backend already did.

### 2026-11-04: crate skeleton and protocol types
- Cargo project (edition 2024), CI (fmt, clippy `-D warnings`, tests), MIT license, plan in README.
- Protocol v1 frame types, with tests that parse every example frame from the backend's
  `contracts/fixtures/` and require node frames to round-trip byte-for-byte.
