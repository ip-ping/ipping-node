# Changelog

Progress log for `ipping-node`, newest first. Each entry is one small, tested step.

## v0.8.0 (2026-11-11)

A node needs no name. It no longer sends its host name when none is given, and the installer's question is optional.

- `ipping-node enroll` sends an empty name when `--name` / `IPPING_NODE_NAME` is not set (it used to send `HOSTNAME`, `/etc/hostname`
  or `ipping-node`). Backend v0.10.0 then calls the node after its place and its network, for example `Sydney, AU - OVH SAS · AS16276`;
  an older backend refuses an empty name, so give `--name` there.
- `ipping-node.sh`: "What should this node be called?" has no default and may be left empty (it used to propose the host name), the
  summary says "named after its place and network" in that case, the enrollment question says the token is single-use unless the
  administrator made it reusable, and `--help` and the README say so. Nodes that already have a name keep it.
- Tests: the installer tests (all pass), ShellCheck stable and 0.10.0, `cargo fmt`, `clippy` and the unit tests are clean.

## v0.7.2 (2026-11-10)

The node runs on Alpine Linux: the release now carries **static musl binaries**, and the installer picks them there.

- v0.7.1's installer ran the glibc binary on Alpine through `gcompat`, which does not work ("The downloaded binary does not
  run on this host"). Every release now also publishes `ipping-node-linux-amd64-musl` and `ipping-node-linux-arm64-musl`
  (built from the same source with `--target binary-musl` in the Dockerfile, on `ghcr.io/rust-cross/rust-musl-cross`, which
  cross-compiles on the build machine without emulation; the release workflow refuses a musl file that is not static).
  They are in `SHA256SUMS` and attested like the others.
- The installer picks the asset by libc (`detect_libc`: a `/lib/ld-musl-*.so.1` means musl), checks `SHA256SUMS` before
  downloading, and for a release without a musl build says that Alpine needs v0.7.2 or newer. `gcompat` and `libgcc` are no
  longer installed.
- **Run on a real Alpine 3.21 (arm64) with OpenRC**: started with plain `sh` (it installed bash and ran itself again), the
  musl binary downloaded and checked, enrolled over HTTP, and run by `supervise-daemon`; once approved it did ping (ICMP),
  TCP, DNS, DNS over HTTPS (HTTP/2) to Quad9, TLS, HTTP and traceroute. `status`, `doctor` (all checks), `stop`, `start`,
  `restart`, `logs`, `update` (to a newer release, staying up) and `uninstall --purge` (service, config, directories, log,
  runlevel entry and account all gone) work on it, the service is in the default runlevel so it starts at boot, and a
  `kill -9` of the node is followed by the supervisor starting it again.
- Not run: the **amd64** musl binary (this machine cannot run amd64 containers; it is built the same way and checked as a
  static ELF only).

## v0.7.1 (2026-11-10)

The installer runs the node with **OpenRC on Alpine Linux** instead of systemd. The node itself is unchanged.

### Alpine / OpenRC
- `ipping-node.sh` detects Alpine (`/etc/os-release` `ID=alpine`, or `/etc/alpine-release`; `IPPING_NODE_INIT=systemd|openrc`
  overrides it) and in direct mode writes `/etc/init.d/ipping-node` (run by `supervise-daemon`, restart after 3 s, enabled in
  the default runlevel, log in `/var/log/ipping-node.log`) and `/etc/conf.d/ipping-node` for the environment, instead of a
  systemd unit. `start`, `stop`, `restart`, `logs`, `status`, `doctor`, `update` (with the same rollback) and `uninstall` use it.
- Everything else Alpine does differently: packages come from `apk` (`curl`, `ca-certificates`, `su-exec`; v0.7.1 also installed
  `gcompat` and `libgcc`); the account is made with `addgroup`/`adduser` and removed with
  `deluser`; enrollment runs as that account through `su-exec` where there is no `runuser`; when the account cannot send
  unprivileged pings the binary gets `CAP_NET_RAW` as a file capability (re-applied on every update); `--mode docker` installs
  Docker from `apk` and starts it with OpenRC.
- A script started with `sh` (Alpine has no bash) installs bash and runs itself again.
- **It did not work**: the glibc binary does not run on Alpine through `gcompat`. Fixed in v0.7.2 with musl builds.

## v0.7.0 (2026-11-10)

DNS over HTTPS over HTTP/2, so Quad9 can be asked. Asking Quad9 needs backend v0.7.0, which only sends it to nodes of this
version; everything else is as before.

### Public IPv6 on the internet: still untested, and now known to be untestable from here
Asked a GitHub-hosted runner with a throwaway workflow: it has only a link-local IPv6 address and no route (`curl -6
https://ipv6.google.com` fails to connect), like the development Mac and Docker. The workflow was removed again. Whether a
host has IPv6 is decided on every connection by a route lookup, not assumed (`has_route`), so a host that gains IPv6 starts
announcing it when its node next connects; the lab in network namespaces remains the test.

### DNS over HTTPS over HTTP/2 (Quad9)
- The DoH client offers `h2` and `http/1.1` in the TLS handshake and speaks what the server picks. Quad9 answers
  `505 HTTP Version Not Supported` to HTTP/1.1, so before this it could not be asked; now it answers (A, TXT and NXDOMAIN
  for a missing name, in the ignored internet test, in about 25 ms). Cloudflare and Google also pick h2, so they are asked
  over HTTP/2 now; a server that picks nothing, or `http/1.1`, is asked as before.
- Uses the `h2` crate (hyper's HTTP/2), driven inside the same task as the request so the deadline ends the connection.
  The certificate is checked before anything is sent, the body is read to 16 KiB and no further, and a reset stream,
  an error status, a wrong content type or too long a body are protocol errors or a reset, never a hang. The Linux arm64
  release binary grows from 4.94 MB (v0.6.0) to 5.46 MB.
- Tests: a loopback HTTP/2-only server with a test CA (the request is a GET whose authority is the certificate name, with
  `accept` and `user-agent`; the answer in one frame and in two; a 505 and a 404, a wrong type, a body that is too long and
  a reset stream; silence is a timeout; an untrusted certificate stops it before any request); the HTTP/1.1 tests now run
  against a server that offers only `http/1.1`, which proves the fallback. 9 tests in `doh_live.rs`.
- The error message for a DoH question that got no DNS message no longer blames missing HTTP/2.

### What the released v0.6.0 does against real QUIC servers
- Checked with the released binary on a fresh Debian 13: `www.cloudflare.com` and `example.com` complete a QUIC handshake
  offering `h3` and agree `h3` (trusted, TLS 1.3). `github.com` and `expired.badssl.com` do not serve HTTP/3 and come back
  as a timeout, which is the right answer: a QUIC check says nothing about a server that does not listen for QUIC.
- **The handshake took 5 to 7 seconds from the machine used for testing**, against 35 to 40 ms for TLS over TCP to the same
  hosts. Not the client: an independent implementation (`aioquic`, run from the same machine) took 5.2 to 6.2 s for the same
  handshakes, so it is something on that network's path for UDP (not found where). The check's default timeout is 8 s, which this path
  came close to; expect a node on an ordinary connection to answer in well under a second, and a node behind a path like
  this one to show up as slow or timing out for QUIC only. `tests/quic_internet.rs::how_often_each_host_answers` (ignored without the internet) now prints each attempt's time.
- Google's own servers (`www.google.com`, `dns.google`) never answered a QUIC handshake from that network.

## v0.6.0 (2026-11-09)

DNS over HTTPS, a QUIC handshake for the certificate check, and a test of every kind over IPv6 with global addresses. Both new
transports need backend v0.6.0 to be asked for; against an older backend the node keeps working as before.

### QUIC handshake (the transport of HTTP/3)
- The certificate check can be a QUIC handshake (`transport: "quic"`): UDP to the port, offering `h3`, using `quinn` with the same
  certificate verifier the other checks use, so an untrusted or wrong-name certificate still completes the handshake and is
  reported with its reason. The sample adds `transport: "quic"` and `alpn` (the protocol agreed, `h3`); the version is
  TLSv1.3 (QUIC requires it) and the cipher suite is not exposed. A server that is not listening on UDP is silence and ends as a
  timeout; one that does not offer `h3` ends with an error that says the QUIC handshake failed.
- Tests: a real QUIC server on loopback with a test CA (trusted: the certificate, its names, the chain and `h3`; untrusted and
  wrong-name: described with the reason; a server offering only `h2`; a UDP port that never answers), runner tests (the flag and
  the detail, and the transports that are refused), run on macOS and Linux. `tests/quic_internet.rs` (ignored) handshakes with the
  real Cloudflare 4 times of 4. **Google's QUIC endpoints never answered from the development network, nor for an independent client
  (aioquic)**, so that is the network, not this client; the internet test asserts only Cloudflare.
- `quinn` 0.11 with the ring backend is a new dependency; it builds with the TLS stack already used. Example frames
  `task_tls_quic.json` and `sample_tls_quic.json`.

### DNS over HTTPS
- The DNS check can ask over HTTPS (`transport: "doh"`, with `resolver_ip`, `doh_host` and `doh_path` from the backend): the
  same question the node already builds (id 0, as RFC 8484 recommends for GET), base64url in `?dns=`, an HTTPS GET to the
  resolver's address on port 443 with the certificate checked against the Mozilla roots for `doh_host`. A certificate that
  does not verify ends it before the question is sent. A new `HttpClient::get_body` reads a bounded response (a length, a
  chunked body, or to the end; at most 16 KiB; anything else is refused), and the answer goes through the parser the
  UDP path uses, so the sample is the same with `transport: "doh"` added.
- The host must be a public name, the path plain path characters (no query), and port 443 must be allowed; a node's own
  resolvers cannot be asked this way. All of it is checked before anything is sent.
- **Quad9 does not work**, found by running it against the real resolvers: it answers `505 ... requires HTTP/2` to
  HTTP/1.1, and an HTTP/2 client would be a large dependency for one resolver. The node reports a protocol error with a
  message that says some resolvers require HTTP/2; the backend does not offer Quad9 over HTTPS. Cloudflare and Google
  work (real answers for A and TXT, and NXDOMAIN for a missing name, in the ignored internet test).
- Tests: parser (a length, chunked, extensions, cut short, too long, not HTTP, a 503), base64url against the RFC vectors,
  runner planning and refusals (11 cases), and a real HTTPS server on loopback with a test CA (the request line, `Host` and
  `Accept`; an error status, a wrong content type, garbage; an untrusted certificate and a certificate for another name,
  both with nothing sent; silence; a closed port). `tests/doh_internet.rs` (ignored; `cargo test --test doh_internet
  -- --ignored`) asks the real resolvers. Example frames `task_dns_doh.json` and `sample_dns_doh.json`.
- Clippy now allows `large_enum_variant` on the backend frame enum, with a reason (a task grew by three options).

### test: every kind over IPv6 with global addresses, in a namespace lab
- `tests/netns/ipv6.sh` builds a source, a router and a destination out of network namespaces with global IPv6
  addresses (an allocated range, so the node's real, production policy calls them public) and real servers: a web
  server, `openssl s_server` with a certificate nobody trusts, and a resolver that answers A and AAAA. The Rust
  test `tests/ipv6_live.rs` runs the node's real prober over it. It needs no IPv6 internet and sends nothing out.
- 6 tests, all passing on the first run, in CI as a new job: ping and TCP (a closed port is a refusal that keeps its
  time), HTTP to an address (the `Host` header is bracketed), a certificate over IPv6 (self-signed: reported
  with its reason and names), DNS A and AAAA from a resolver named by IPv6 address, a traceroute in rounds that
  reports the router's global address as a router (not "private") and reaches the destination, and the policy refusing
  ULA, documentation, link-local, loopback, IPv4-mapped and NAT64-mapped private addresses before anything is sent.
- What this is not: the real IPv6 internet. The roadmap item stays open for that, reworded.

## v0.5.1 (2026-11-09)

The installer now tries a download again when its connection dies halfway. The node itself is unchanged from v0.5.0.

### fix: a download that loses its connection halfway is tried again
Found installing the released v0.5.0 on a Debian 13 container while the machine went to sleep: the TLS connection
died in the middle of a download ("curl: (56) ... unexpected EOF") and the installer stopped with "Could not
download".
- `ipping-node.sh` fetched everything with plain `curl` (the node installer without any retry; the site installer with
  `--retry 3`, which does not retry a connection that dies halfway). Every download now goes through `fetch`, which
  tries up to four times (3, 6 and 9 seconds apart) and has a 20 second connect timeout. It is a few lines of shell
  and not `--retry-all-errors`, because curl older than 7.71 (Ubuntu 20.04, which these installers support) does
  not know that option.
- Tested with a stand-in for curl that drops the connection (exit 56): fetched once when it works, fetched on the
  third try after two drops, given up after four; a test also fails if any download bypasses `fetch`. ShellCheck
  (stable and v0.10.0) is clean.

## v0.5.0 (2026-11-09)

Traceroute in rounds like `mtr`, and certificate checks. Both need backend v0.5.0 to be given such tasks; against an
older backend the node keeps working as before (it traces once and is never asked for a certificate).

### 2026-11-08: certificate checks
- A new kind, `tls`: connect to an address, complete the TLS handshake for a name (or for the address itself)
  and report what the certificate says, then hang up. **No request is sent**, so it works for any TLS service on
  an allowed port (a web server, a mail server) and a test proves that nothing is written after the handshake.
- The certificate is verified like the HTTP check does (Mozilla roots, shared verifier). One that does not
  verify is **not** a failed handshake: the sample is an `error` with `tls_certificate_invalid` and the detail
  still has everything (subject, issuer, validity, the names it is valid for, why it was not trusted), because
  the reason is the whole point. A trusted one is `ok` with the time of connect plus handshake as its round trip.
- The detail adds to what an HTTP check already reports: up to 24 names from the subject alternative name
  extension (DNS names and addresses, 3000 bytes at most so a result fits the backend's sample size) and how many
  certificates the server sent. Days left are not computed here: the node reports `not_after` and whoever reads
  the result knows what day it is.
- Same destination policy as every other kind (public addresses, allowed ports, no internal names), refused
  before anything is sent; 7 runner tests with scripted handshakes and 8 tests against real sockets with a test CA
  (trusted, address certificate, wrong name, expired, unknown issuer, 60 names, a server that is not TLS, a closed
  port, silence). Example frames `task_tls.json` and `sample_tls.json`; `hello_all_kinds.json` brought up to date.
- The node advertises `tls` in its hello. A backend that does not know it never asks for it (tasks
  need backend v0.5.0).

### 2026-11-07: traceroute in rounds, like mtr
- A traceroute task with `count` above one (up to 10 rounds, `interval_ms` apart) repeats the trace.
  The first round is the trace as before (three probes to each hop, stops at the destination or after
  eight silent hops); every later round sends one probe to each hop that was found, all hops at once.
  Probing hops at the same time but rounds a second apart is what `mtr` does: a router answers a
  burst to itself with less and less, which would look like loss that is not there.
- A hop is still one sample, sent once at the end with every round-trip time and `sent`, the number of
  probes it got, so a hop's loss is `1 - len(rtts_us) / sent`. A single round is unchanged on the
  wire: no `sent`, three probes, hops reported live as they are found. A repeated trace reports
  nothing until its last round is done, and a task that is cancelled or expires in between reports
  nothing at all.
- The node refuses `count` outside 1 to 10 and an interval outside 200 ms to 5 s for a traceroute.
- 5 runner tests with scripted hops (replies and loss over rounds, spacing, cancelling, limits) and a
  second test through real routers in network namespaces for IPv4 and IPv6. Example frames in the
  fixtures: `task_traceroute_rounds.json` and `sample_hop_rounds.json`.
- Needs backend v0.5.0 to be given `count` for a traceroute; against v0.4.x it keeps tracing once.

## v0.4.0 (2026-11-07)

### feat: DNS checks
The node can ask a resolver about a name (a new `dns` kind, advertised in its hello). It needs backend v0.4.0 to
be given such tasks; against an older backend it simply never gets one.

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
  Internal names (`.lan`, `.home.arpa`, `.corp`, single labels ...) are refused. An answer too big for a
  sample (backend limit 8 KiB) is cut and marked `truncated`. 10 runner tests.
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
