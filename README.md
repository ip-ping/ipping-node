# ipping-node

The measurement node for **ipping**, a self-hostable distributed network diagnostics service.
A node is a small Rust program: it connects *out* to the backend, receives typed tasks (never
shell commands), checks them against its own safety policy, runs bounded probes and reports
structured results.

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

```bash
curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors https://github.com/ip-ping/ipping-node/releases/latest/download/ipping-node.sh -o ipping-node.sh && chmod +x ipping-node.sh && bash ipping-node.sh
```

Or run it non-interactively:

```bash
# Direct: a systemd service, no Docker, no Rust. Downloads one named release and verifies it
# against that release's SHA256SUMS before installing.
sudo bash ipping-node.sh install --mode direct --server https://ping.example.com --token ipt_...

# Docker: the same node in a hardened container.
sudo bash ipping-node.sh install --mode docker --server https://ping.example.com --token ipt_...

sudo bash ipping-node.sh status | logs | doctor | restart | update | uninstall
```

That link always serves the installer of the newest tagged release; the unreleased one from `main` is
at `https://github.com/ip-ping/ipping-node/releases/download/edge/ipping-node.sh`. Releases are
cut as described in [RELEASING.md](https://github.com/ip-ping/ipping/blob/main/RELEASING.md).
Run it without arguments for an interactive menu. Installs are repeatable (a second run keeps the
node's identity), updates keep the previous release for rollback and roll back by themselves if the
new one does not start, and `uninstall` keeps the node's identity unless you add `--purge`.
`--allow-insecure` is needed to connect to a plain `http://` backend on another host (the default
central install serves HTTP until you give it a domain); the credential then travels unencrypted.

Direct mode runs as an unprivileged `ipping-node` user under a locked-down systemd unit. It
checks `net.ipv4.ping_group_range`; only if the user cannot send unprivileged pings does the unit
get `CAP_NET_RAW`, and nothing else.

## Run it

```bash
cargo build --release

# One-time: trade an enrollment token (admin page) for this node's own credential.
ipping-node --state-dir ~/.ipping-node enroll --server https://ping.example.com --token ipt_... \
    --name "Falkenstein 1" --country DE --city Falkenstein

# An administrator approves the node in the admin page, then:
ipping-node --state-dir ~/.ipping-node run
```

The state directory (default `/var/lib/ipping-node`) holds `node.json` and `credential`, both
mode `0600`. The credential is shown once at enrollment and is sent only in an `Authorization`
header; a plain `http://` backend is refused unless it is on this machine. `IPPING_NODE_LOG`
sets the log filter (default `info`). Every option can also be given as an `IPPING_NODE_*`
environment variable, and `run` will enroll by itself when `IPPING_NODE_SERVER` and
`IPPING_NODE_ENROLL_TOKEN` are set and no credential exists yet (convenient for containers).

ICMP uses unprivileged ping sockets where the kernel allows them. On Linux that means
`net.ipv4.ping_group_range` must include the node's group; otherwise grant `CAP_NET_RAW`.

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

## Develop

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

## Design rules

* **No arbitrary commands.** The node understands one task kind per probe type, with fixed
  packet sizes, bounded counts and timeouts. No flood mode, no sweeps.
* **The node re-checks everything.** Destination policy is enforced locally even though the
  backend already did; a compromised or buggy backend cannot aim a node at private networks.
* **Bounded.** Concurrency, buffering and task lifetime all have limits on the node itself.
* **Honest timing.** Round-trip times come from a monotonic clock.
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
- [ ] TCP, HTTP and traceroute probes

## License

MIT, see [LICENSE](LICENSE).
