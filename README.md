# ipping-node

The measurement node for **ipping**, a self-hostable distributed network diagnostics service.
A node is a small Rust program: it connects *out* to the backend, receives typed tasks (never
shell commands), checks them against its own safety policy, runs bounded probes (**ping, TCP
connect, HTTP request, traceroute, DNS lookup, certificate check**) and reports structured results.

Current release: **v0.8.2**. It works with any backend for ping; TCP, HTTP and traceroute need backend
**v0.3.0** or newer, DNS checks need backend **v0.4.0**, traceroute rounds and certificate checks need backend **v0.5.0**, and DNS over HTTPS and QUIC need backend **v0.6.0** (DNS over HTTPS to Quad9, **v0.7.0**). Binaries are published for Linux `amd64` and `arm64` (built against
glibc 2.31, so they run on Debian 11 and newer), plus a distroless Docker image.

| Repository | Role |
|---|---|
| [`ipping`](https://github.com/ip-ping/ipping) | Next.js frontend, and the installer for the whole central application |
| [`ipping-backend`](https://github.com/ip-ping/ipping-backend) | FastAPI service that coordinates nodes |
| **`ipping-node`** (this one) | Rust node, installed on its own on every measurement host |

Nodes dial out over a TLS WebSocket, so a node host needs **no inbound port**. The wire protocol
is defined by the backend (`contracts/node-protocol-v1.schema.json`); `tests/fixtures/` holds
copies of its example frames and the tests fail if this crate drifts from them.

## Install on a host

Download the installer from the newest release and run it (it asks for sudo itself, and shows a
menu when given no arguments):

(The command uses curl's `--retry-all-errors`, which needs curl 7.71 or newer: drop it on the now end-of-life Ubuntu 20.04.)

```bash
curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors https://github.com/ip-ping/ipping-node/releases/latest/download/ipping-node.sh -o ipping-node.sh && chmod +x ipping-node.sh && bash ipping-node.sh
```

Or run it non-interactively:

```bash
# Direct: a systemd service (an OpenRC one on Alpine Linux, picked automatically), no Docker, no Rust.
# Downloads one named release and verifies it against that release's SHA256SUMS before installing.
sudo bash ipping-node.sh install --mode direct --server https://ping.example.com --token ipt_...

# Docker: the same node in a hardened container.
sudo bash ipping-node.sh install --mode docker --server https://ping.example.com --token ipt_...

sudo bash ipping-node.sh status | logs | doctor | restart | update | uninstall
```

That link always serves the installer of the newest tagged release; the unreleased one from `main` is
at `https://github.com/ip-ping/ipping-node/releases/download/edge/ipping-node.sh`. Releases are
cut as described in [RELEASING.md](https://github.com/ip-ping/ipping/blob/main/RELEASING.md).
Run it with no options and it guides you: how to run the node, where your ipping site is (it checks
the site answers before changing anything), the enrollment token (typed without echo), the node's
name and location, then a summary to confirm. Each step shows progress; the output of the commands
behind it goes to `/var/log/ipping-node-install.log` and is shown only if a step fails.
`status` also tells you whether the site has approved the node yet. An install that fails part-way
(a mistyped token, say) can simply be run again.

Run it without arguments for an interactive menu. Installs are repeatable (a second run keeps the
node's identity and repairs the ownership of its state files), updates keep the previous release
for rollback and roll back by themselves if the new one does not start, and `uninstall` keeps the
node's identity unless you add `--purge`. Options: `--name`, `--country`, `--city`, `--provider`
(what the public node list shows), `--version vX.Y.Z`, `--binary FILE`.
`--allow-insecure` (or `--insecure`) is needed to connect to a plain `http://` backend on another host
(the default central install serves HTTP until you give it a domain); the credential then travels
unencrypted. The layout follows the width of the terminal and is plain text in a pipe.

Direct mode runs as an unprivileged `ipping-node` user under a locked-down systemd unit. It
checks `net.ipv4.ping_group_range`; only if the user cannot send unprivileged pings does the unit
get `CAP_NET_RAW`, and nothing else.

**Alpine Linux** is detected and uses OpenRC instead of systemd: an init script in `/etc/init.d/ipping-node` run by
`supervise-daemon` (restarts after a crash, starts at boot, log in `/var/log/ipping-node.log`), the service account made
with `adduser`, and packages from `apk` (`curl`, `su-exec`). Alpine is musl and cannot run the glibc binary, so every
release also carries a **static musl build** (`ipping-node-linux-amd64-musl`, `ipping-node-linux-arm64-musl`, verified in
`SHA256SUMS` like the others) and the installer picks it by looking for the musl loader (v0.7.2 and newer; an older
release has none and the installer says so). If `ipping-node.sh` is started with `sh`, it installs bash and runs itself
again. OpenRC has no capability setting, so if the service account cannot send unprivileged pings the binary gets
`CAP_NET_RAW` as a file capability (`libcap-utils`). `--mode docker` also works on Alpine (Docker from `apk`).

**Alpine in an LXC container** is the usual case for that file capability: the container's `net.ipv4.ping_group_range` is
`1 0` (nobody) and cannot be changed from inside, because LXC mounts `/proc/sys` read-only. Nothing needs to be done on the host:
the node runs as its unprivileged user with `CAP_NET_RAW` on the binary and does **ping and traceroute** through raw sockets
(traceroute needs v0.8.1 or newer; older nodes of this kind ping but do not offer traceroute). The installer does this by itself;
`update` repeats it for every new binary. The node's log says what it offers when it connects
(`kinds=ping,tcp,http,tls,dns,traceroute`) and, when it cannot offer traceroute, why. If you do run the LXC host, allowing the group in
`net.ipv4.ping_group_range` instead is also fine: the node prefers ping sockets whenever it may have them.

## Run it

```bash
cargo build --release

# One-time: trade an enrollment token (admin page) for this node's own credential.
ipping-node --state-dir ~/.ipping-node enroll --server https://ping.example.com --token ipt_... \
    --name "Falkenstein 1" --country DE --city Falkenstein

# A site that is plain http:// on another host needs --insecure here and on `run` (or
# IPPING_NODE_ALLOW_INSECURE=1, which is the same thing); the credential then travels unencrypted:
#   ipping-node enroll --server http://203.0.113.7:8088 --token ... --insecure

# An administrator approves the node in the admin page, then:
ipping-node --state-dir ~/.ipping-node run
```

The state directory (default `/var/lib/ipping-node`) holds `node.json` and `credential`, both
mode `0600`, and everything in it must belong to the account the node runs as. The credential is
shown once at enrollment and is sent only in an `Authorization` header; a plain `http://` backend is
refused unless it is on this machine (or you pass `--insecure`). `run` will enroll by itself when
`IPPING_NODE_SERVER` and `IPPING_NODE_ENROLL_TOKEN` are set and no credential exists yet (convenient
for containers).

| Option | Environment variable | Meaning |
|---|---|---|
| `--state-dir DIR` | `IPPING_NODE_STATE_DIR` | where the identity lives (default `/var/lib/ipping-node`) |
| `--server URL` | `IPPING_NODE_SERVER` | the backend (for `run`, overrides the one saved at enrollment) |
| `--token T` | `IPPING_NODE_ENROLL_TOKEN` | the enrollment token (single-use, unless the administrator made it reusable) |
| `--name`, `--country`, `--city`, `--region`, `--provider`, `--latitude`, `--longitude`, `--asn` | `IPPING_NODE_NAME`, `..._COUNTRY`, ... | what the node tells the site about itself (coordinates feed the location estimate). **No name is fine** (and what the installer's guided install proposes): the site then calls the node after where it is and whose network it is, `City, CC - Provider · ASn`, for example `Sydney, AU - OVH SAS · AS16276`, and an administrator can still give it a name |
| `--insecure` (`--allow-insecure`) | `IPPING_NODE_ALLOW_INSECURE=1` | allow plain `http://` to a backend on another host |
| `--ports LIST` | `IPPING_NODE_PORTS` | destination ports for TCP and HTTP (a comma-separated list, or `any`) |
| `--max-tasks N` | `IPPING_NODE_MAX_TASKS` | most tasks at once (default 8, and never above what the backend allows) |
| | `IPPING_NODE_LOG` | log filter (default `info`) |

ICMP uses unprivileged ping sockets where the kernel allows them. On Linux that means
`net.ipv4.ping_group_range` must include the node's group; otherwise grant `CAP_NET_RAW`, and ping and traceroute use raw
sockets instead (traceroute from v0.8.1; before that it needed the ping sockets and was not offered with `CAP_NET_RAW` alone).

### What it measures

| Kind | One sample | Node-side limits |
| --- | --- | --- |
| `ping` | an ICMP echo | 1 to 10 per task, 56-byte payload, public addresses only |
| `tcp` | opening a connection, then closing it with no data | ports from an allowlist (`--ports` / `IPPING_NODE_PORTS`, a list or `any`), public addresses only |
| `traceroute` | one hop (three probes, or more with `count` above one) | Linux only (ping sockets, or raw sockets with `CAP_NET_RAW`); up to 30 hops; hop addresses that are not public are reported as "private" without the address. With `count` rounds the trace is repeated like `mtr`: one probe per hop and round, `interval_ms` apart, and each hop is reported once with every reply and how many probes it got |
| `dns` | one question to one resolver, answered in full | `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`; the resolver is a public one the backend names (port 53) or this node's own (`/etc/resolv.conf`); `transport` `doh` asks over HTTPS instead (RFC 8484 GET on port 443, the certificate checked for the resolver's name; Cloudflare, Google and Quad9 work; the node offers `h2` and speaks HTTP/2 when the server picks it, which Quad9 needs); names that are internal (`.lan`, `.corp`, single labels ...) are refused; from the node's own resolver, private addresses in an answer are counted but never reported |
| `tls` | one TLS handshake with no request after it (`transport` `quic`: a QUIC handshake over UDP offering `h3`, the transport of HTTP/3) | same ports as TCP; the certificate is checked against the Mozilla roots for the name presented (or the address, for a bare address) and a certificate that does not verify is still described, with the reason; it reports the version, cipher, subject, issuer, validity, up to 24 names the certificate is valid for and how many certificates the server sent |
| `http` | one `GET`, headers only | same ports; redirects (at most 5, only if asked) are re-checked at every hop; a certificate that does not verify is described but never sent a request |

The node refuses any task for a kind it did not advertise, whatever the backend sends. Allowed
ports by default: 22, 25, 53, 80, 110, 143, 443, 465, 587, 853, 993, 995, 3306, 3389, 5432, 8080 and
8443; a node connects only to ports on its own list, so a port an administrator adds on the site also
has to be added here. HTTP is a small HTTP/1.1 client written for measuring: it times DNS, connect,
TLS and first byte separately, verifies certificates against the Mozilla roots, and reports the
certificate's issuer, subject and validity.

IPv6 works like IPv4 (same policy, same code paths) when the node has a route for it. It is tested in two
ways: over the IPv6 loopback, and in a lab of network namespaces (`tests/netns/ipv6.sh`, run in CI) where
a source, a router and a destination use *global* IPv6 addresses from an allocated range, so the node's real
policy treats them as public. In that lab every kind runs against real servers (ping, TCP including a
refusal, HTTP with a bracketed `Host`, a TLS handshake that reports an untrusted certificate with its
reason, DNS A and AAAA from a resolver named by IPv6 address, a traceroute that reports the router's global
address) and the policy refuses ULA, documentation, link-local, loopback, IPv4-mapped and NAT64-mapped
private addresses. What it does not prove: the namespaces are isolated, so there are no real routers, real
resolvers or real certificates, and a route to the public IPv6 internet has not been tested (neither the
development machine nor CI runners have one).

## Docker

```bash
cp .env.example .env     # set IPPING_NODE_SERVER and IPPING_NODE_ENROLL_TOKEN
docker compose up -d
```

The image (`tonyliuzj/ipping-node`) is built by GitHub Actions on every push to `main`
(`latest` and the commit SHA, `linux/amd64` + `linux/arm64`). It is distroless, runs as an
unprivileged user and needs **no** `--privileged`, no `CAP_NET_RAW` and no Docker socket:
`compose.yaml` drops every capability, makes the filesystem read-only and only sets the
`net.ipv4.ping_group_range` sysctl that unprivileged ICMP needs. The default Docker bridge has no
IPv6, so such a node reports IPv4 only; use host or an IPv6-enabled network to measure IPv6.

## Troubleshooting

`sudo bash ipping-node.sh doctor` checks the service, the state directory, the credential, ICMP
permission (and what it gives the node: with `CAP_NET_RAW` alone a node of 0.8.1 or newer offers every kind, an older one does not offer traceroute) and that
the site answers, and says what to try for each failing check. `status` tells
you whether the site has approved the node. Common cases:

* **`cannot read ...: Permission denied`**: the state files belong to another account (for example
  `enroll` was run as root). Run the installer again (`install` or `update` repairs it), or
  `sudo chown -R ipping-node: /var/lib/ipping-node`.
* **"refused to send credentials over plain http://"**: the site is plain HTTP on another host. Use
  HTTPS, or `--insecure` if you trust the network.
* **"waiting for an administrator to approve"**: approve the node in the site's *Admin > Nodes*.
* **Offline after the site was updated**: the node retries about every second at first and then
  backs off (up to a minute). Only a refused credential (HTTP 401 or 403, a revoked or rotated key)
  makes it wait the full minute; a 502 from the proxy while the backend restarts does not.
* **Ping or traceroute fails with a permission error**: the node's group must be in
  `net.ipv4.ping_group_range` (the installer checks this and adds `CAP_NET_RAW` only if it must).
  Traceroute is Linux only and is not advertised where it cannot work: the node's log line `connected ... kinds=...` lists what it
  offers, and a `traceroute is not offered: ...` line before it says why. Before v0.8.1 a node that had only `CAP_NET_RAW`
  (an Alpine or other LXC container, a host that keeps `ping_group_range` closed) pinged but never offered traceroute: update it.

## Develop

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
bash tests/installer.sh                              # the installer's own logic, no root needed
shellcheck -S style ipping-node.sh tests/installer.sh
sudo tests/netns/traceroute.sh                       # Linux: traceroute through real routers (network namespaces)
```

Linux-only code (traceroute) is not compiled on macOS, so also run clippy on Linux, for example
`docker run --rm -v "$PWD":/src -w /src rust:1 cargo clippy --all-targets -- -D warnings`. CI runs
the namespace test on every push. The live tests use real sockets on the loopback interface, a local
TLS server with a throwaway CA (trusted, expired, wrong name, unknown issuer) and a fake backend
that answers the WebSocket upgrade with HTTP errors.

## Design rules

* **No arbitrary commands.** The node understands one task kind per probe type, with fixed
  packet sizes, bounded counts and timeouts. No flood mode, no sweeps.
* **The node re-checks everything.** Destination policy is enforced locally even though the
  backend already did; a compromised or buggy backend cannot aim a node at private networks.
* **Bounded.** Concurrency, buffering and task lifetime all have limits on the node itself.
* **Honest timing.** Round-trip times come from a monotonic clock.
* **Redirects are new destinations.** An HTTP redirect is only followed if asked for, and every hop
  is resolved on the node and checked again: public addresses, allowed ports, http/https, no
  credentials in the URL.
* **Nothing is sent to a server that cannot be authenticated.** A certificate that does not verify
  is described, and the connection is dropped before any request.
* **No private network in a result.** A traceroute hop that is not a public address is reported as
  "private", never as an address, and a DNS answer from the node's own resolver that is not a public
  address is only counted.
* **DNS replies are checked, not trusted.** The reply must carry the id and the question that were
  sent (anything else is ignored while the node keeps waiting), compression pointers may only point
  backwards, lengths are checked, at most 32 records are kept and a long TXT is shortened. A cut-short
  UDP answer is fetched again over TCP.
* **No `--privileged`, no Docker socket.** ICMP uses unprivileged ping sockets where the kernel
  allows them; `CAP_NET_RAW` is the fallback.

## Roadmap

Small steps, each one committed and logged in [CHANGELOG.md](CHANGELOG.md).

- [x] Protocol types, checked against the backend's example frames
- [x] Destination policy (public addresses only)
- [x] ICMP ping probe and task runner
- [x] Backend connection with reconnect/backoff, enrollment, CLI
- [x] End-to-end run against the real backend (local: enroll, approve, ping 1.1.1.1)
- [x] Docker image and Docker Hub publishing (distroless, non-root, amd64 + arm64)
- [x] Release workflow: binaries (linux amd64 / arm64), checksums, installer; rolling `edge` installer
- [x] First tagged release: v0.1.0
- [x] `ipping-node.sh` installer (direct and Docker modes; tested in clean containers, see CHANGELOG)
- [x] TCP connect checks
- [x] HTTP checks (timings, TLS certificate, redirects)
- [x] Traceroute (Linux; tested through real routers in network namespaces, IPv4 and IPv6)
- [x] Traceroute through a raw socket where only `CAP_NET_RAW` is allowed (an LXC container), tested in the same lab with ping sockets refused, and on Alpine as an unprivileged user with the file capability (v0.8.1)
- [x] The installer's `doctor` says what a `CAP_NET_RAW`-only host gives the node (every kind from v0.8.1; an older node pings but does not offer traceroute) and how to update
- [x] Tagged releases: v0.1.0, v0.2.0, v0.3.0, v0.4.0, v0.5.0, v0.5.1, v0.6.0 (with v0.3.1 to v0.3.3 between: faster reconnect after a site update, approval status read from the site, `--insecure`, state ownership repair, narrow terminals)
- [x] Every kind over IPv6 with global addresses and the real policy, in a network-namespace lab (node CI); see the node README for what that does and does not prove
- [ ] Over the real public IPv6 internet (needs a host with IPv6 connectivity; neither the development machine nor CI runners have it)
- [x] DNS checks (A, AAAA, CNAME, MX, NS, TXT, SOA from a public resolver or the node's own; the comparison across nodes is in the web interface)
- [x] QUIC as a transport of the certificate check (tested against a real QUIC server on loopback and a real HTTP/3 server)
- [x] DNS over HTTPS as a transport of the DNS check (tested against real Cloudflare, Google and Quad9)
- [x] HTTP/2 for DNS over HTTPS (the `h2` crate; Quad9 answers no other way), tested against a loopback HTTP/2 server and the real Quad9
- [x] Certificate checks (a handshake with no request: what the certificate says and whether this node trusts it)
- [x] Repeated traceroute rounds, like `mtr` (loss and spread per hop; tested through real routers in network namespaces)

## License

MIT, see [LICENSE](LICENSE).
