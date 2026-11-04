# Changelog

Progress log for `ipping-node`, newest first. Each entry is one small, tested step.

## Unreleased

### 2026-11-04: release workflow cleanup
- Prerelease flag in `release.yml` no longer relies on shell word splitting; actionlint clean.

### 2026-11-04: installer (`ipping-node.sh`)
- Direct mode: unprivileged service account, 0700 state directory, hardened systemd unit
  (`ProtectSystem=strict`, no new privileges, `CAP_NET_RAW` only when unprivileged ping is not
  permitted), release binary verified against `SHA256SUMS` (a mismatch installs nothing), enrollment
  token passed through the environment so it never appears in `ps` or on disk.
- Docker mode: Docker installed from its apt repository only if missing; hardened compose project,
  `.env` mode 0600, used token cleared once the node has connected.
- `install`, `update` (previous release kept, automatic rollback), `start`/`stop`/`restart`,
  `status`, `logs`, `doctor`, `uninstall` (`--purge` to also delete the identity), interactive menu,
  `--allow-insecure` opt-in for plain-HTTP backends.
- The CLI treats empty `IPPING_NODE_*` values as unset (an empty country in an `.env` file used to
  be sent to the backend and refused).
- Tested in clean containers against the real backend: bad checksum refused, install, idempotent
  re-run, update, uninstall, purge, in both modes. `systemctl` was shimmed in the direct-mode test
  because containers have no systemd, so the unit file's contents were checked but not run by systemd.
- ShellCheck runs in CI.

### 2026-11-04: Docker image and publishing
- `Dockerfile`: cross-compiles on the build machine (no emulated compiling), builds on Debian 11 for
  a low glibc requirement, ships in `distroless/cc` as uid 65532; a `binary` target extracts the
  plain executable for releases. 11 MB.
- `compose.yaml` + `.env.example` for a node-only host: all capabilities dropped, read-only
  filesystem, state in a named volume.
- Workflows: `ci.yml` (fmt, clippy, tests, two-architecture image build), `docker.yml` (publish
  `latest` + commit SHA on pushes to `main`, like `file-node`), `release.yml` (tag -> versioned image,
  linux binaries, `SHA256SUMS`, GitHub release). Actions pinned to commit SHAs.
- Verified with the real backend: a container with `--cap-drop ALL --read-only` enrolls itself from
  environment variables, pings through an unprivileged socket, and keeps its identity across restarts.
- Logs are plain text unless stderr is a terminal.

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
