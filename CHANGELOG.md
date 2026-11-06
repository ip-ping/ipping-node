# Changelog

Progress log for `ipping-node`, newest first. Each entry is one small, tested step.

## Unreleased

### 2026-11-06: TCP connect checks
- New task kind `tcp`: open a connection to a port, time the handshake, close it without sending a
  byte. A refusal is reported as an `error` sample that keeps its time (the host answered); a timeout
  is a timeout; an unreachable route is its own code. The node advertises `tcp` in its hello.
- Ports are an allowlist (22, 25, 53, 80, 110, 143, 443, 465, 587, 853, 993, 995, 3306, 3389, 5432,
  8080, 8443 by default; `--ports` / `IPPING_NODE_PORTS` takes a list or `any`), enforced on the node
  whatever the backend asks for: a node that connects anywhere is a port scanner. Port 0 never passes.
- The runner now checks a task against what the node advertised: a kind it did not offer, or a kind
  from a newer backend, is answered with `unsupported_kind` instead of being dropped or run.
- Protocol types follow the backend's additive changes (`port`/`server_name` in the target, `scheme`,
  `path`, `max_redirects`, `max_hops` in the options, `detail` in samples); the new contract fixtures
  are copied in and checked, including exact round trips.
- 11 new tests (20 runner tests with scripted probes, port rules, real loopback connect and refusal).

### 2026-11-06: a nicer installer
- Guided install: Docker or direct, where your ipping site is (checked to be reachable before anything
  changes, with a warning and a safe default for plain HTTP), the enrollment token typed without echo,
  the node's name and location, then a summary to confirm.
- Progress for every step with the command output kept in `/var/log/ipping-node-install.log` and
  shown only on failure; a summary box; `status` shows the service, the site and whether the site has
  approved the node yet; `doctor` explains what to try for each failing check; a menu that shows the
  current state.
- A failed install can be run again: a mistyped token no longer leaves the node marked "installed".
- Country codes are validated and upper-cased; the site address and `--version` are validated before
  sudo is requested.
- Verified through a real terminal emulator on fresh Debian 13 machines: direct and Docker installs,
  a bad token then a retry, an unreachable address, plain HTTP without `--allow-insecure`.

### 2026-11-06: fix: installing Docker on Debian 13 broke the release lookup
- The installer *sourced* `/etc/os-release` into its own shell, and that file defines `VERSION`
  (Debian 13: `13 (trixie)`) and `NAME` (the node's own display name, so a Docker install on Debian also renamed the node to "Debian GNU/Linux"). Whenever Docker had to be installed, `VERSION` became the release to
  download, giving `Could not download .../releases/download/v13 (trixie)/release-manifest.json`.
  The file is now read in a subshell (`os_release KEY`), so it can never touch the script's variables.
- `--version` is validated up front (`v1.2.3`, `latest`), so any other value is refused with a
  clear message instead of ending up inside a URL.
- Arguments are validated *before* asking for sudo, not after.
- Reproduced on a real Debian 13 machine (systemd, no Docker): v0.2.0 fails with the exact error above;
  with the fix the same machine installs Docker, fetches the right release and the whole stack comes
  up healthy and a node enrolls with the name it was given.
- Why it was missed: every earlier test ran with Docker already installed, so the install-Docker branch
  never executed. `tests/installer.sh` now covers the helper (Debian 13 and Ubuntu 24.04 fixtures), the
  version rules and the command line, and runs in CI.

## v0.2.0 (2026-11-05)

### 2026-11-04: verification and hardening
- Run for real under systemd 255 (a container with systemd as PID 1): the published v0.1.0 installers
  bring up PostgreSQL, backend, frontend, Caddy and a node, a measurement completes through the
  sandboxed node, systemd restarts a killed node, all services are enabled for boot, and uninstall
  removes the units.
- Units tightened (clock, hostname, /proc, SUID, IPC, native syscalls only, private umask, no
  capabilities unless needed, a syscall filter on the node). `systemd-analyze security` exposure:
  node 5.8 -> 1.5, backend 3.5, frontend 3.5, Caddy 5.0 (it must bind low ports).
- The `CAP_NET_RAW` fallback was exercised: with unprivileged ping disabled on the host the node's unit
  keeps exactly that one capability and still measures (raw sockets).
- Release files get signed build-provenance attestations (`gh attestation verify`); takes effect with the next release.

### 2026-11-04: IPv6 and systemd verification
- Live ICMPv6 loopback test (macOS and Linux): the probe gets real replies over IPv6; capability
  detection reports `ipv6: false` on hosts with no public IPv6 route. A public IPv6 destination could
  not be exercised from the test machine (no IPv6 internet).
- The published installer and hardened unit were run by real systemd 255: the node probes under
  `ProtectSystem=strict`, `MemoryDenyWriteExecute` and the address-family filter, and systemd restarts
  it after a SIGKILL.

## v0.1.0 (2026-11-04)

First release. Everything below shipped in it.

### 2026-11-04: release tags and published installers
- Same release flow as the application (tag or manual run, dry run, `Cargo.toml` version check,
  `main`-only publishing, re-runnable); a release now attaches the binaries, `ipping-node.sh` and
  `SHA256SUMS`.
- `edge.yml` keeps a rolling `edge` prerelease with the current `ipping-node.sh` from `main`.
- `ipping-node.sh` starts itself again through sudo when run as a normal user.

### 2026-11-04: installer lint fixes
- Fixed what the newest ShellCheck (the one on CI runners) reports: `A && B || C` chains, and a
  `grep -q` inside a pipeline under `pipefail`, which could end the "wait until the node has
  connected" loop early.

### 2026-11-04: installer ships with releases
- Releases now attach `ipping-node.sh`, so it can be fetched from `releases/latest/download/`.

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
