#!/usr/bin/env bash
# Build a small network out of Linux network namespaces and run the traceroute test inside it:
#
#   src --- r1 --- r2 --- dst          (IPv4: 10.0.N.0/24, IPv6: fd00:N::/64)
#
# Needs root (or CAP_SYS_ADMIN) and iproute2. Used by CI and by hand:
#
#   sudo tests/netns/traceroute.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
PREFIX="ippingtest$$"
NS_SRC="${PREFIX}s" NS_R1="${PREFIX}1" NS_R2="${PREFIX}2" NS_DST="${PREFIX}d"

cleanup() {
  for ns in "$NS_SRC" "$NS_R1" "$NS_R2" "$NS_DST"; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT

# Compile first, outside the namespaces. CI builds as the normal user and passes the binary in
# TRACEROUTE_TEST_BIN, so root never needs the Rust toolchain.
BIN="${TRACEROUTE_TEST_BIN:-}"
if [ -z "$BIN" ]; then
  BIN="$(cargo test --test traceroute_live --no-run --locked --message-format=json \
    | grep -o '"executable":"[^"]*traceroute_live[^"]*"' | head -1 | cut -d'"' -f4)"
fi
[ -x "$BIN" ] || { echo "could not find the test binary" >&2; exit 1; }

for ns in "$NS_SRC" "$NS_R1" "$NS_R2" "$NS_DST"; do ip netns add "$ns"; done

link() { # link <nsA> <nsB> <net number>
  local a="$1" b="$2" n="$3"
  ip link add "v${n}a" netns "$a" type veth peer name "v${n}b" netns "$b"
  ip -n "$a" addr add "10.0.$n.1/24" dev "v${n}a"
  ip -n "$b" addr add "10.0.$n.2/24" dev "v${n}b"
  ip -n "$a" -6 addr add "fd00:$n::1/64" dev "v${n}a" nodad
  ip -n "$b" -6 addr add "fd00:$n::2/64" dev "v${n}b" nodad
  ip -n "$a" link set "v${n}a" up
  ip -n "$b" link set "v${n}b" up
}
link "$NS_SRC" "$NS_R1" 1
link "$NS_R1" "$NS_R2" 2
link "$NS_R2" "$NS_DST" 3
for ns in "$NS_SRC" "$NS_R1" "$NS_R2" "$NS_DST"; do ip -n "$ns" link set lo up; done

# Routes: everything towards the destination goes right, everything back goes left.
ip -n "$NS_SRC" route add default via 10.0.1.2
ip -n "$NS_R1" route add 10.0.3.0/24 via 10.0.2.2
ip -n "$NS_R2" route add 10.0.1.0/24 via 10.0.2.1
ip -n "$NS_DST" route add default via 10.0.3.1
ip -n "$NS_SRC" -6 route add default via fd00:1::2
ip -n "$NS_R1" -6 route add fd00:3::/64 via fd00:2::2
ip -n "$NS_R2" -6 route add fd00:1::/64 via fd00:2::1
ip -n "$NS_DST" -6 route add default via fd00:3::1

for ns in "$NS_R1" "$NS_R2"; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  # Routers rate-limit the ICMP errors they send (per peer, and globally: 1000 a second with a burst
  # of 50), and the test sends three probes per hop at once. Real routers do this too, which is why
  # a hop gets three probes; the lab just should not be the one to drop them.
  ip netns exec "$ns" sysctl -qw net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0 \
    net.ipv4.icmp_msgs_per_sec=100000 net.ipv4.icmp_msgs_burst=100000
done
# The test user must be allowed to open ping sockets (what `ping` itself relies on).
ip netns exec "$NS_SRC" sysctl -qw net.ipv4.ping_group_range="0 2147483647"

# Resolve every neighbour once, so the first probes are not delayed by neighbour discovery (which
# says nothing about traceroute). `ping` here is only a way to make that happen.
if command -v ping >/dev/null; then
  for target in 10.0.1.2 10.0.3.2 fd00:1::2 fd00:3::2; do
    ip netns exec "$NS_SRC" ping -c 2 -W 2 "$target" >/dev/null 2>&1 || true
  done
  ip netns exec "$NS_R1" ping -c 1 -W 2 10.0.2.2 >/dev/null 2>&1 || true
  ip netns exec "$NS_R1" ping -c 1 -W 2 fd00:2::2 >/dev/null 2>&1 || true
  ip netns exec "$NS_R1" ping -c 1 -W 2 fd00:1::1 >/dev/null 2>&1 || true
  ip netns exec "$NS_R2" ping -c 1 -W 2 fd00:2::1 >/dev/null 2>&1 || true
  ip netns exec "$NS_R2" ping -c 1 -W 2 fd00:3::2 >/dev/null 2>&1 || true
fi

run() { # run <destination> <routers>
  echo "== tracing $1"
  ip netns exec "$NS_SRC" env IPPING_TRACE_DEST="$1" IPPING_TRACE_HOPS="$2" \
    "$BIN" through_real_routers --nocapture --test-threads=1
}
run 10.0.3.2 10.0.1.2,10.0.2.2
run fd00:3::2 fd00:1::2,fd00:2::2
echo "traceroute works through real routers (IPv4 and IPv6)"
