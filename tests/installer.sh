#!/usr/bin/env bash
# shellcheck disable=SC2329,SC2317  # test doubles that the sourced script calls; shellcheck cannot see that
# Tests for the installer's own logic (no root, no network, nothing installed).
#   bash tests/installer.sh
set -u
cd "$(dirname "$0")/.." || exit 1
SCRIPT=./ipping-node.sh
HERE="$PWD/tests/fixtures"

failures=0
check() { # check "what" expected actual
  if [ "$2" = "$3" ]; then printf '  ok    %s\n' "$1"; else printf '  FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; failures=$((failures + 1)); fi
}

echo "sourcing the script must not run it"
out="$(bash -c ". $SCRIPT; echo sourced" 2>&1)"
check "no output other than ours, no exit" "sourced" "$out"

# Everything below runs in this shell, with the script's functions loaded and its variables set.
# shellcheck source=/dev/null
. "$SCRIPT"
set +e +u +o pipefail

echo "versions are compared by number, not by letters"
check "0.8.0 is older than 0.8.1" yes "$(version_older 0.8.0 0.8.1 && echo yes || echo no)"
check "0.8.1 is not older than 0.8.1" no "$(version_older 0.8.1 0.8.1 && echo yes || echo no)"
check "0.10.0 is not older than 0.8.1 (10 is more than 8)" no "$(version_older 0.10.0 0.8.1 && echo yes || echo no)"
check "0.7.2 is older than 0.8.1" yes "$(version_older 0.7.2 0.8.1 && echo yes || echo no)"
check "a leading v is ignored" yes "$(version_older v0.8.0 v0.8.1 && echo yes || echo no)"
check "1.0 is not older than 0.8.1 (missing parts are 0)" no "$(version_older 1.0 0.8.1 && echo yes || echo no)"

echo "doctor says what a host that allows only CAP_NET_RAW gives the node"
note() { printf '%s\n' "$*"; }
installed_mode() { echo direct; }
node_version() { echo "0.8.0"; }
out="$(raw_only_note)"
case "$out" in *"offers ping but not traceroute"*"update"*) r=warns ;; *) r="$out" ;; esac
check "a node older than 0.8.1 is told traceroute is missing, and to update" warns "$r"
node_version() { echo "0.8.1"; }
out="$(raw_only_note)"
case "$out" in *"every kind"*) r=ok ;; *) r="$out" ;; esac
check "a node of 0.8.1 or newer is told it offers every kind" ok "$r"
node_version() { echo ""; }
out="$(raw_only_note)"
case "$out" in *"every kind"*) r=ok ;; *) r="$out" ;; esac
check "a version that cannot be read is not accused of anything" ok "$r"

echo "approval is read from the site, not only from the node's log"
node_id() { echo "abc123"; }
node_server() { echo "https://ping.example.com/"; }
installed_mode() { echo direct; }
node_recent_log() { printf '%s\n' "INFO connected" "WARN waiting for an administrator to approve this node"; }
FAKE_BODY=""; FAKE_FAIL=0
curl() { [ "$FAKE_FAIL" = 0 ] || return 22; printf '%s' "$FAKE_BODY"; }
FAKE_BODY='[{"id":"zzz","name":"other","online":true},{"id":"abc123","name":"mine","country":"NL","online":true,"ipv4":true}]'
check "listed and online" online "$(site_node_state)"
check "...says so even though its log still says it is waiting" "approved and connected" "$(node_approval)"
FAKE_BODY='[{"id":"abc123","name":"mine","online": false,"ipv4":true}]'
check "listed but offline (spaces in the JSON)" offline "$(site_node_state)"
check "...is approved, not connected" "approved, not connected right now" "$(node_approval)"
FAKE_BODY='[{"id":"zzz","name":"other","online":true}]'
check "not listed" absent "$(site_node_state)"
check "...falls back to the log: still waiting" "waiting for an administrator to approve it" "$(node_approval)"
FAKE_BODY='[]'
check "an empty list is not listed either" absent "$(site_node_state)"
FAKE_BODY='<html>502 Bad Gateway</html>'
check "an answer that is not the node list is unknown" unknown "$(site_node_state)"
FAKE_FAIL=1
check "an unreachable site is unknown" unknown "$(site_node_state)"
check "...and the log is all there is" "waiting for an administrator to approve it" "$(node_approval)"
unset -f curl node_id node_server installed_mode node_recent_log

echo "os-release is read without touching the script's own variables"
VERSION="v0.2.0"; NAME="my node"; MODE="docker"
for fixture in debian13 ubuntu2404; do
  export OS_RELEASE_FILE="$HERE/os-release.$fixture"
  distro="$(os_release ID)"
  codename="$(os_release UBUNTU_CODENAME)"; codename="${codename:-$(os_release VERSION_CODENAME)}"
  case "$fixture" in
    debian13) check "debian 13: distro" debian "$distro"; check "debian 13: codename" trixie "$codename" ;;
    ubuntu2404) check "ubuntu 24.04: distro" ubuntu "$distro"; check "ubuntu 24.04: codename" noble "$codename" ;;
  esac
  check "$fixture: VERSION survives" "v0.2.0" "$VERSION"
  check "$fixture: NAME survives" "my node" "$NAME"
  check "$fixture: MODE survives" "docker" "$MODE"
done
export OS_RELEASE_FILE=/nonexistent
check "a missing file reads as empty" "" "$(os_release ID)"
unset OS_RELEASE_FILE

echo "no code path sources os-release into the main shell"
bad="$(grep -nE '^[[:space:]]*(\.|source)[[:space:]]+/etc/os-release' "$SCRIPT" || true)"
check "nothing sources /etc/os-release directly" "" "$bad"

echo "versions"
for v in "" latest v0.2.0 0.2.0 v1.10.3 v0.3.0-rc.1 1.0.0-beta.2; do
  valid_version "$v"; check "accepted: '$v'" 0 "$?"
done
for v in "13 (trixie)" "v1.2" "1.2.3.4" "vv1.2.3" "../../etc" "1.2.3;rm" "v1.2.3 " "latest2" main; do
  valid_version "$v"; check "refused: '$v'" 1 "$?"
done
check "tag gets its v" "v0.2.0" "$(normalize_tag 0.2.0)"
check "tag keeps its v" "v0.2.0" "$(normalize_tag v0.2.0)"

echo "interface helpers"
UI_LOG="$(mktemp)"
out="$(run "Say hello" echo hello 2>&1)"; rc=$?
check "run: a command that works returns 0" 0 "$rc"
case "$out" in *"Say hello"*) check "run: reports what it did" ok ok ;; *) check "run: reports what it did" ok "$out" ;; esac
check "run: keeps the command's output in the log, not on screen" "hello" "$(grep -x hello "$UI_LOG")"
case "$out" in *hello*"Say hello"* | *"Say hello"*hello*) check "run: does not print the command's output" "no" "yes" ;; *) check "run: does not print the command's output" ok ok ;; esac
out="$( ( run "Break things" sh -c 'echo boom-text >&2; exit 3' ) 2>&1 )"; rc=$?
check "run: a failing command ends the installer" 1 "$rc"
case "$out" in *"Break things failed"*) check "run: says which step failed" ok ok ;; *) check "run: says which step failed" ok "$out" ;; esac
case "$out" in *boom-text*) check "run: shows the command's own error" ok ok ;; *) check "run: shows the command's own error" ok "$out" ;; esac
run_soft "Soft failure" false >/dev/null 2>&1; check "run_soft: returns the exit status" 1 "$?"
out="$(box "Title" "one" "a much longer line of text")"
check "box: every line has the same width" 1 "$(printf '%s\n' "$out" | grep -v '^$' | awk '{ print length }' | sort -u | wc -l | tr -d ' ')"
UI_COLS=80
out="$(box "Title" "one" "a much longer line of text")"
check "box: a frame on a terminal that is wide enough" 4 "$(printf '%s\n' "$out" | grep -c "^[+|]")"
UI_COLS=24
out="$(box "Title" "a line that cannot fit inside a narrow terminal")"
check "box: no frame on a narrow terminal" 0 "$(printf '%s\n' "$out" | grep -c '^[+|]')"
check "box: ...but every line is still there" 1 "$(printf '%s\n' "$out" | grep -c 'cannot fit')"
UI_COLS=80
ui_init_cols() { COLUMNS="$1" ui_init; echo "$UI_COLS/$UI_WIDTH"; }
check "a 50-column terminal is not stretched to 60" "50/50" "$(ui_init_cols 50)"
check "a very wide terminal is capped at 100" "200/100" "$(ui_init_cols 200)"
check "an absurdly narrow one gets a floor" "24/24" "$(ui_init_cols 5)"
check "a junk COLUMNS falls back" "ok" "$(COLUMNS=abc ui_init; [ "$UI_COLS" -ge 24 ] && echo ok)"
# shellcheck disable=SC2034  # ASSUME_YES is read by is_interactive in the script under test
X=already; ASSUME_YES=1; prompt X "Question?" "" ""; check "prompt: leaves a value given on the command line alone" already "$X"
Y=""; prompt Y "Question?" "default" ""; check "prompt: asks nothing without a terminal" "" "$Y"
# shellcheck disable=SC2034
ASSUME_YES=0

echo "site addresses and country codes"
for v in https://ping.example.com http://localhost:8000 http://127.0.0.1:8000 "http://[::1]:8000" https://a.b.co:8443/ http://10.0.0.5; do valid_server "$v"; check "accepted site: '$v'" 0 "$?"; done
for v in ping.example.com ftp://x.com https:// https://x.com/path "https://user:pw@x.com" "https://x.com?q=1" "https://exa mple.com" "http://:80"; do valid_server "$v"; check "refused site: '$v'" 1 "$?"; done
for v in "" DE de Us; do valid_country "$v"; check "accepted country: '$v'" 0 "$?"; done
for v in D DEU 1a "d e" "?!"; do valid_country "$v"; check "refused country: '$v'" 1 "$?"; done
is_local_address "http://localhost:8000"; check "localhost counts as local" 0 "$?"
is_local_address "http://192.168.1.5:8000"; check "a LAN address is not local" 1 "$?"

echo "the command line"
out="$(bash "$SCRIPT" --help 2>&1)"; rc=$?
check "--help exits 0" 0 "$rc"
case "$out" in *Usage:*) check "--help prints usage" ok ok ;; *) check "--help prints usage" ok "$out" ;; esac
out="$(bash "$SCRIPT" --version "13 (trixie)" install 2>&1)"; rc=$?
check "a bad --version is refused" 1 "$rc"
case "$out" in *"is not a version"*) check "...with a message that says so" ok ok ;; *) check "...with a message that says so" ok "$out" ;; esac
out="$(bash "$SCRIPT" --no-such-flag 2>&1)"; rc=$?
check "an unknown flag is refused" 1 "$rc"

echo
echo "downloads are tried again when the connection dies halfway"
sleep() { :; }
attempts=0
curl() { attempts=$((attempts + 1)); [ "$attempts" -le "$FAIL_FIRST" ] && return 56; return 0; }
FAIL_FIRST=0; attempts=0; fetch http://x /dev/null; check "a download that works is fetched once" "0 1" "$? $attempts"
FAIL_FIRST=2; attempts=0; fetch http://x /dev/null; check "two dropped connections, then it works (curl exit 56 is retried)" "0 3" "$? $attempts"
FAIL_FIRST=99; attempts=0; fetch http://x /dev/null; check "it gives up after four tries" "1 4" "$? $attempts"
unset -f curl sleep
# shellcheck disable=SC2016 # the pattern is literal text, not something to expand
bad="$(grep -nE 'curl -fsSL' "$SCRIPT" | grep -v 'curl -fsSL --connect-timeout 20 "\$1" -o "\$2" && return 0' || true)"
check "no download bypasses fetch" "" "$bad"

if [ "$failures" -eq 0 ]; then echo "all passed"; else echo "$failures failed"; exit 1; fi
