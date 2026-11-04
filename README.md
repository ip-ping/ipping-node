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
- [ ] Backend connection with reconnect/backoff, enrollment, CLI
- [ ] End-to-end run against the real backend
- [ ] Docker image and Docker Hub publishing
- [ ] Release binaries (linux amd64 / arm64) and checksums
- [ ] `ipping-node.sh` installer (direct and Docker modes)
- [ ] TCP, HTTP and traceroute probes

## License

MIT, see [LICENSE](LICENSE).
