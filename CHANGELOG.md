# Changelog

Progress log for `ipping-node`, newest first. Each entry is one small, tested step.

## Unreleased

### 2026-11-07: DNS checks
- A new kind, `dns`: ask one resolver one question (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT` or `SOA`)
  and report the answer in full: the response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL` ...), every
  record with its TTL, whether the answer was authoritative, and how long it took. "No such name" is
  an answer, not a failure; silence is a timeout.
- The DNS client is written for this node (no resolver library): one query with EDNS0, UDP first, TCP
  if the answer was cut short. A reply must carry the id and the question that were sent or it is
  ignored; names are followed only backwards, lengths are checked, records are capped. 12 unit tests
  and 8 tests against a fake server on loopback (UDP answer, forged and stray replies, truncation
  and the TCP fallback, silence, a closed port, garbage) run on macOS and Linux.
- Who may be asked: a public resolver the backend names (port 53, a public address) or the node's own
  resolvers. What is shown: from the node's own resolver, answers that are private addresses are counted
  and left out, because that resolver may know names that exist only inside the operator's network.
  Internal names (`.lan`, `.home.arpa`, `.corp`, single labels ...) are refused. 9 runner tests.
- The node advertises `dns` in its hello. The protocol change is additive: new `kind`, new task options
  `record_type` and `resolver_ip`, and a new sample `detail` shape, with example frames in the fixtures.

### 2026-11-07: README brought up to date
- The README now says what the node is today (four kinds, Linux amd64 and arm64, glibc 2.31), lists
  every option with its environment variable, the default allowed ports and how the HTTP client works,
  what has and has not been tested for IPv6, a troubleshooting section (permission denied on the state
  directory, plain-http refusal, waiting for approval, coming back after a site update, ICMP
  permissions), the development commands including the Linux-only checks and the namespace traceroute
  test, the design rules about redirects, unauthenticated servers and private hops, and a roadmap
  that includes v0.3.1 to v0.3.3.

## v0.3.3 (2026-11-06)

### fix: v0.3.2 refused to start on any install that allows plain http://
- v0.3.2 made `--insecure` a command-line flag *bound to* `IPPING_NODE_ALLOW_INSECURE`. A boolean
  flag only accepts `true`/`false`, and every install made with `--allow-insecure` sets that variable
  to `1` in its systemd unit or `.env`, so the service died at start with `invalid value '1' for
  '--insecure'`. It was caught the same day by installing the released v0.3.2 on a fresh Debian 13
  machine and reproducing the report that led to it; v0.3.2 was marked a prerelease (so the stable
  link served v0.3.1 again) before this release.
- The flag no longer reads the variable; the node itself reads `IPPING_NODE_ALLOW_INSECURE`, and now
  accepts `1`, `true` and `yes`. The test that should have caught it only checked that the node
  did not print the refusal (a parse error does not); there is now one that runs every command with
  the values installs actually set (`1`, `true`, `yes`, `0`, `false`) and requires the node to reach
  its own logic. Everything else in v0.3.2 (state ownership, `--insecure`, narrow terminals) stands.

## v0.3.2 (2026-11-06)

### `--insecure`
- `ipping-node enroll --server http://... --token ... --insecure` (also `--allow-insecure`, and
  before or after the subcommand) is the same as `IPPING_NODE_ALLOW_INSECURE=1`, which still works.
  It applies to `run` too. The refusal message names the flag. Tested against the real binary.

### fix: a node whose state files belonged to another account would not start
- Reported on a real machine: after an install that found the node "already enrolled", the service
  died with `cannot read /var/lib/ipping-node: Permission denied`. The state directory was owned
  by the service account but the files inside (`credential`, `node.json`) were not, typically
  because `enroll` had once been run as root. Now the installer (install and update) hands the whole
  state directory to the service account and sets the modes again, `doctor` checks it and says what
  to run, and the node's own error names the file and the fix (`sudo chown -R ipping-node: ...`)
  instead of the directory.
- Reproduced on Debian 13 (root-owned state, service failing), then fixed by install and by update.

### fix: the installer on a narrow terminal
- The layout forced a minimum width of 60 columns, so on a narrower terminal rules and boxes wrapped.
  It now follows the terminal; a box whose lines do not fit is printed without a frame; a spinner line
  is cut to one row (a wrapped one left a row behind when cleared); a banner subtitle that does not fit
  beside the title goes on its own line.
- When the node is already approved the summary no longer tells you to go and approve it.

## v0.3.1 (2026-11-06)

Two things found by installing the real v0.3.0 releases on a fresh Debian 13 machine and updating
them.

### fix: a node stayed away for a minute after every backend update
- While the backend restarts, the proxy in front of it answers HTTP 502. The node read *any* HTTP
  answer to its connection as "the backend refused this node's credential" and waited the full minute
  before trying again, so every update of the site left its nodes offline for about 63 seconds with a
  misleading message in the log. Now only 401 and 403 mean a refused credential; anything else
  (502, 503, 504, 429, 500) is "the site answered HTTP N; it is probably restarting" and the node
  retries at the normal pace (about a second, then longer). Tested against a fake backend: a 502, 503
  or 504 is retried within 2.6 s, a 401 or 403 is not retried.
- Seen for real: after `ipping.sh update` the node was back after 63 s; it should be about 1 s.

### fix: `status` kept saying "waiting for an administrator" after approval
- A node approved while it is already connected logs nothing new, so the installer's status, doctor
  and summary (which read the node's log) went on saying it was waiting. They now ask the site: its
  public node list only holds approved nodes, so being in it means approved, and its `online` flag
  says whether the node is connected. If the site cannot be asked the log is used as before.

## v0.3.0 (2026-11-06)

TCP, HTTP and traceroute checks, a port allowlist, and an installer fixed for Debian 13 with a guided
interface. Needs backend v0.3.0 for the new kinds; works with older backends for ping.

### 2026-11-06: the traceroute test was flaky for a real reason
- One CI run of the namespace test saw 2 answers to 3 probes at a hop. Reproduced locally (1 run in 12)
  and traced: a stress run showed that only router replies were lost, only when probes were sent
  together, and the router's `OutRateLimitGlobal` counter was 8 (the kernel allows 1000 ICMP errors a
  second with a burst of 50). The node was right, the lab was rate-limiting: real routers do the same,
  which is what three probes per hop are for. The lab now raises that limit and the test asks for at
  least one answer per hop.

### 2026-11-06: IPv6 checked as far as this machine allows
- TCP and HTTP are exercised over the IPv6 loopback (connect, refusal, a request with a bracketed
  `Host`), and traceroute over IPv6 through real routers in namespaces. What has *not* been tested is
  a route to the public IPv6 internet: the machine used for development has none. IPv6 targets are
  otherwise handled like IPv4 (same policy, same code paths), but treat public IPv6 as untested.

### 2026-11-06: fix: a lint that only Linux can see
- The traceroute code is Linux-only, so clippy on macOS never compiled it; CI on Linux flagged one
  cast that is needed on musl but redundant on glibc. Allowed with the reason. Lesson kept in the
  workflow: check clippy on Linux too (`docker run rust:1 cargo clippy --all-targets -- -D warnings`).
  The traceroute-in-namespaces job itself passed on GitHub's runners: real routers, IPv4 and IPv6.

### 2026-11-06: fix: CI had been failing on a lint note in the installer
- The latest ShellCheck (stricter than the version used while developing) flagged the menu's
  `( MODE=...; cmd_install )` as a variable modified in a subshell. The mode is now set before the
  subshell and cleared after it. This had kept the Docker image and the `edge` installer from being
  published since the guided-installer commit; both are published again now. The local check now
  uses the same ShellCheck image as CI (`koalaman/shellcheck:stable -S style`).

### 2026-11-06: traceroute
- New task kind `traceroute` (Linux): one sample per hop, three probes per hop sent together, the
  fastest reply is the hop's time. It uses the same unprivileged ICMP ping sockets as ping, with
  `IP_RECVERR`: a router whose TTL ran out sends "time exceeded", which the kernel delivers to the
  socket's error queue together with the router's address. No raw socket, no extra capability, both
  IPv4 and IPv6. Advertised only if the node can open such a socket.
- The trace stops at the destination, when a router says it is unreachable, at `max_hops` (30), or
  after eight silent hops in a row. Silent routers cost only their timeout.
- A hop that is not a public address (the node operator's router, carrier-grade NAT) is reported as
  "a private hop" with no address, so a result never discloses someone's network.
- Tested for real, not mocked: `tests/netns/traceroute.sh` builds `src - r1 - r2 - dst` out of network
  namespaces and traces through it over IPv4 and IPv6 (hops 10.0.1.2, 10.0.2.2, then the destination,
  all three probes answered with microsecond round trips); it runs in CI. 9 scripted tests cover the
  route logic. Verified on aarch64 Linux in Docker; macOS builds without it.
- `rust-version` is now 1.88 (the code uses let chains).

### 2026-11-06: HTTP checks
- New task kind `http`: connect to the pinned address, optionally TLS, send one `GET` (headers
  only, no body is ever read), and report the status, server, timings of each phase (DNS, connect,
  TLS, first byte, total) and the TLS certificate (version, cipher, subject, issuer, validity).
  A small HTTP/1.1 client written for measuring rather than a general one: each phase has its own
  clock and the address is the one the backend chose, with the Host header and TLS server name set
  from the name it was given.
- Certificates are verified against the Mozilla roots. One that does not verify (expired, wrong name,
  unknown issuer) still completes the handshake so it can be *described*, and the result is
  `tls_certificate_invalid` with the reason, but **nothing is sent to a server that could not be
  authenticated**; a test asserts the server received zero bytes.
- Redirects are reported, and followed only if the task allows (up to 5). Each hop is a new
  destination nobody vetted, so the node resolves it itself and applies the policy again: public
  addresses only, allowed ports only, http/https only, no credentials in the URL, a bounded target.
  Query strings are never reported. The whole chain shares one time budget.
- Anything from the network that is reported (Server header, certificate names) is reduced to
  printable ASCII and length-limited; a response head over 16 KiB, non-HTTP answers and oversized
  redirect targets are `protocol_error`.
- 20 new tests: scripted redirects and policy at every hop, request-smuggling inputs, real sockets with
  a test CA (trusted, expired, wrong name, unknown issuer, IP-address certificate, TLS to a plain
  server), and the runner with the real client following a redirect chain.

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
