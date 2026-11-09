#!/usr/bin/env bash
# The node over IPv6, through a router, to a destination with real servers, using GLOBAL IPv6 addresses.
#
#   src --- router --- dst        (2a00:1450:4001:N::/64, an allocated range: the node's real policy calls it public)
#
# The namespaces are isolated, so nothing leaves the machine. That is what makes it possible to test the public-address
# code paths (the policy, the hop addresses a traceroute reports, resolvers named by address) on a host with no IPv6
# internet. It is the next best thing to the real internet, and it is not the same thing: no real routers, no real
# resolvers, no real certificates.
#
# Needs root, iproute2, python3 and openssl. Used by CI and by hand:
#
#   sudo tests/netns/ipv6.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
PREFIX="ippingv6$$"
NS_SRC="${PREFIX}s" NS_R="${PREFIX}r" NS_DST="${PREFIX}d"
SRC=2a00:1450:4001:1::1 ROUTER_A=2a00:1450:4001:1::2 ROUTER_B=2a00:1450:4001:2::1 DEST=2a00:1450:4001:2::2
WORK="$(mktemp -d)"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for ns in "$NS_SRC" "$NS_R" "$NS_DST"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

# Compile first, outside the namespaces. CI builds as the normal user and passes the binary in IPV6_TEST_BIN.
BIN="${IPV6_TEST_BIN:-}"
if [ -z "$BIN" ]; then
  BIN="$(cargo test --test ipv6_live --no-run --locked --message-format=json \
    | grep -o '"executable":"[^"]*ipv6_live[^"]*"' | head -1 | cut -d'"' -f4)"
fi
[ -x "$BIN" ] || { echo "could not find the test binary" >&2; exit 1; }

for ns in "$NS_SRC" "$NS_R" "$NS_DST"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
link() { # link <nsA> <nsB> <net number> <address A> <address B>
  ip link add "v6$3a" netns "$1" type veth peer name "v6$3b" netns "$2"
  ip -n "$1" -6 addr add "$4/64" dev "v6$3a" nodad
  ip -n "$2" -6 addr add "$5/64" dev "v6$3b" nodad
  ip -n "$1" link set "v6$3a" up
  ip -n "$2" link set "v6$3b" up
}
link "$NS_SRC" "$NS_R" 1 "$SRC" "$ROUTER_A"
link "$NS_R" "$NS_DST" 2 "$ROUTER_B" "$DEST"
ip -n "$NS_SRC" -6 route add default via "$ROUTER_A"
ip -n "$NS_DST" -6 route add default via "$ROUTER_B"
ip netns exec "$NS_R" sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv6.icmp.ratelimit=0
ip netns exec "$NS_SRC" sysctl -qw net.ipv4.ping_group_range="0 2147483647"

# The servers: a web server (the HTTP check, and the TCP one), a TLS server with a certificate nobody trusts,
# and a resolver that answers every A and AAAA question.
mkdir "$WORK/www" && echo "ipv6 lab" > "$WORK/www/index.html"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=ipv6-lab" \
  -addext "subjectAltName=DNS:ipv6-lab.example.org" -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
cat > "$WORK/dns.py" <<'PYEOF'
import socket, struct, sys
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], 53))
ANSWERS = {1: socket.inet_pton(socket.AF_INET, "192.0.2.7"), 28: socket.inet_pton(socket.AF_INET6, "2001:4860:4860::7")}
while True:
    query, peer = sock.recvfrom(1500)
    end = 12
    while query[end] != 0:
        end += query[end] + 1
    question = query[12 : end + 5]
    qtype = struct.unpack(">H", question[-4:-2])[0]
    data = ANSWERS.get(qtype)
    header = query[:2] + struct.pack(">HHHHH", 0x8580, 1, 1 if data else 0, 0, 0)
    reply = header + question
    if data:
        reply += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(data)) + data
    sock.sendto(reply, peer)
PYEOF
ip netns exec "$NS_DST" python3 -m http.server 80 --bind "$DEST" --directory "$WORK/www" >/dev/null 2>&1 &
PIDS+=($!)
ip netns exec "$NS_DST" openssl s_server -accept "[$DEST]:8443" -cert "$WORK/cert.pem" -key "$WORK/key.pem" -quiet >/dev/null 2>&1 &
PIDS+=($!)
ip netns exec "$NS_DST" python3 "$WORK/dns.py" "$DEST" &
PIDS+=($!)

# Wait until the servers answer from the source side.
for _ in $(seq 1 50); do
  if ip netns exec "$NS_SRC" python3 -c "import socket,sys; socket.create_connection((sys.argv[1], 80), 1).close()" "$DEST" 2>/dev/null; then break; fi
  sleep 0.2
done
ip netns exec "$NS_SRC" ping -6 -c 1 -W 2 "$DEST" >/dev/null 2>&1 || true

ip netns exec "$NS_SRC" env IPPING_V6_DEST="$DEST" IPPING_V6_ROUTER="$ROUTER_A" "$BIN" --nocapture --test-threads=1
echo "the node works over IPv6 through a router: ping, TCP, HTTP, certificate, DNS, traceroute"
