#!/usr/bin/env bash
#
# ipping-node installer: runs a measurement node on this host, directly (systemd, no Docker) or in
# Docker. The menu and command layout follow tonyliuzj/file-node (MIT).
#
#   sudo bash ipping-node.sh install --mode direct --server https://ping.example.com --token ipt_...
#   sudo bash ipping-node.sh install --mode docker --server https://ping.example.com --token ipt_...
#   sudo bash ipping-node.sh {update|start|stop|restart|status|logs|doctor|uninstall}
#
# Unlike a "pull the latest and upgrade the system" script, an install is reproducible: the binary
# comes from one named release and is verified against that release's SHA256SUMS, apt is only used
# to install what is missing, and nothing is upgraded behind your back.

set -euo pipefail

REPO="${IPPING_NODE_REPO:-ip-ping/ipping-node}"
IMAGE="${IPPING_NODE_IMAGE:-tonyliuzj/ipping-node}"
# Where release assets are fetched from. Override to install from a mirror or an offline directory.
RELEASE_BASE="${IPPING_NODE_RELEASE_BASE:-https://github.com/${REPO}/releases/download}"
API_BASE="${IPPING_NODE_API_BASE:-https://api.github.com/repos/${REPO}}"

APP_DIR="${IPPING_NODE_DIR:-/opt/ipping-node}"
STATE_DIR="${IPPING_NODE_STATE_DIR:-/var/lib/ipping-node}"
RUN_USER="${IPPING_NODE_USER:-ipping-node}"
SERVICE="ipping-node"
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
BIN_LINK="/usr/local/bin/ipping-node"
MODE_FILE="${APP_DIR}/mode"
COMPOSE_PROJECT="ipping-node"

ASSUME_YES=0
MODE=""
SERVER=""
TOKEN=""
NAME=""
COUNTRY=""
CITY=""
PROVIDER=""
VERSION=""
PURGE=0
ALLOW_INSECURE=0
BINARY_OVERRIDE=""

# ------------------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------------------
# Terminal interface
#
# These helpers are shared with the other ipping installer and kept identical in both. Colour,
# symbols and the spinner appear only on a terminal that can show them (NO_COLOR is honoured); in a
# pipe or a log file the same information is printed as plain lines. Slow commands go through `run`:
# their output is written to a log file and shown only if the command fails.
# ------------------------------------------------------------------------------------------------

UI_LOG="/dev/null"
UI_SPINNER_PID=""

ui_init() {
  UI_TTY=0; UI_COLOR=0; UI_UNICODE=0
  if [ -t 1 ]; then UI_TTY=1; fi
  if [ "$UI_TTY" -eq 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then UI_COLOR=1; fi
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UI_UNICODE=1 ;; esac
  if [ "$UI_TTY" -eq 0 ]; then UI_UNICODE=0; fi
  # UI_COLS is how wide the terminal really is; UI_WIDTH what the layout uses (never wider than 100).
  UI_COLS="${COLUMNS:-}"
  case "$UI_COLS" in '' | *[!0-9]*) UI_COLS="$(tput cols 2>/dev/null || echo 80)" ;; esac
  case "$UI_COLS" in '' | *[!0-9]*) UI_COLS=80 ;; esac
  if [ "$UI_COLS" -lt 24 ]; then UI_COLS=24; fi
  UI_WIDTH=$UI_COLS
  if [ "$UI_WIDTH" -gt 100 ]; then UI_WIDTH=100; fi
  if [ "$UI_COLOR" -eq 1 ]; then
    C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_RESET=$'\033[0m'
  else
    C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_RESET=""
  fi
  if [ "$UI_UNICODE" -eq 1 ]; then
    S_OK="✔"; S_FAIL="✖"; S_WARN="!"; S_STEP="▸"; S_UP="●"; S_DOWN="○"; S_SEP="·"
    S_H="─"; S_V="│"; S_TL="┌"; S_TR="┐"; S_BL="└"; S_BR="┘"
    UI_SPIN=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
  else
    S_OK="ok"; S_FAIL="!!"; S_WARN="!"; S_STEP="==>"; S_UP="*"; S_DOWN="-"; S_SEP="-"
    S_H="-"; S_V="|"; S_TL="+"; S_TR="+"; S_BL="+"; S_BR="+"
    UI_SPIN=("-" "\\" "|" "/")
  fi
}
ui_init

ui_rule() {
  local width=$UI_WIDTH line="" i
  if [ "$width" -gt 64 ]; then width=64; fi
  for ((i = 0; i < width; i++)); do line+="$S_H"; done
  printf '%s%s%s\n' "$C_DIM" "$line" "$C_RESET"
}

banner() { # banner TITLE [SUBTITLE]
  printf '\n%s%s%s' "$C_BOLD" "$1" "$C_RESET"
  if [ -n "${2:-}" ]; then
    # Beside the title if it fits, on its own line if not (a wrapped line would split a word).
    if [ $((${#1} + ${#2} + 2)) -lt "$UI_COLS" ]; then printf '  '; else printf '\n'; fi
    printf '%s%s%s' "$C_DIM" "$2" "$C_RESET"
  fi
  printf '\n'
  ui_rule
}

step() { printf '\n%s%s%s %s%s%s\n' "$C_CYAN" "$S_STEP" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
info() { printf '  %s\n' "$*"; }
note() { printf '  %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
# para INDENT TEXT   dim text, wrapped at word boundaries to the width of the terminal.
para() {
  local pad="" i
  for ((i = 0; i < $1; i++)); do pad+=" "; done
  printf '%s\n' "$2" | fold -s -w $((UI_WIDTH - $1 - 1)) | sed "s/ *$//; s/^/${pad}/; s/^\(.*\)\$/${C_DIM}\1${C_RESET}/"
}
tick() { printf '  %s%s%s %s\n' "$C_GREEN" "$S_OK" "$C_RESET" "$*"; }
warn() { printf '  %s%s%s %s\n' "$C_YELLOW" "$S_WARN" "$C_RESET" "$*" >&2; }
ok() { printf '\n%s%s%s %s%s%s\n' "$C_GREEN" "$S_OK" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
die() { printf '\n%s%s%s %s\n' "$C_RED" "$S_FAIL" "$C_RESET" "$*" >&2; exit 1; }

# The file that collects the output of commands run through `run`.
ui_log_init() { # ui_log_init DEFAULT_PATH
  UI_LOG="${IPPING_LOG:-$1}"
  if ! { mkdir -p "$(dirname "$UI_LOG")" && : >>"$UI_LOG"; } 2>/dev/null; then UI_LOG="$(mktemp)"; fi
  chmod 600 "$UI_LOG" 2>/dev/null || true
  printf '\n===== %s  %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$(basename "$0")" >>"$UI_LOG"
}

ui_log_tail() {
  if [ "$UI_LOG" = "/dev/null" ] || [ ! -f "$UI_LOG" ]; then return 0; fi
  printf '\n  %slast lines of the output (everything is in %s):%s\n' "$C_DIM" "$UI_LOG" "$C_RESET" >&2
  tail -n 15 "$UI_LOG" | sed 's/^/    /' >&2
}

ui_spin_start() {
  UI_SPINNER_PID=""
  if [ "$UI_TTY" -ne 1 ]; then return 0; fi
  printf '\033[?25l'
  (
    i=0
    n=${#UI_SPIN[@]}
    while :; do
      # Cut to one line: a wrapped spinner line leaves its first row behind when it is cleared.
      printf '\r\033[K  %s%s%s %s' "$C_CYAN" "${UI_SPIN[i % n]}" "$C_RESET" "${1:0:$((UI_COLS - 6))}"
      i=$((i + 1))
      sleep 0.1
    done
  ) &
  UI_SPINNER_PID=$!
}

ui_spin_stop() {
  if [ -n "$UI_SPINNER_PID" ]; then
    kill "$UI_SPINNER_PID" 2>/dev/null || true
    wait "$UI_SPINNER_PID" 2>/dev/null || true
    UI_SPINNER_PID=""
    printf '\r\033[K\033[?25h'
  fi
}

# run_soft "what this does" command args...   shows progress, returns the command's exit status.
# The command must be a program (or a function that is a single command): a function with several
# commands loses `set -e` inside it here, because it is called as part of a `||` list.
run_soft() {
  local what="$1" start=$SECONDS rc=0 took suffix=""
  shift
  printf '\n-- %s\n' "$what" >>"$UI_LOG"
  ui_spin_start "$what"
  "$@" >>"$UI_LOG" 2>&1 </dev/null || rc=$?
  ui_spin_stop
  took=$((SECONDS - start))
  if [ "$took" -ge 3 ]; then suffix=" ${C_DIM}(${took}s)${C_RESET}"; fi
  if [ "$rc" -eq 0 ]; then
    printf '  %s%s%s %s%s\n' "$C_GREEN" "$S_OK" "$C_RESET" "$what" "$suffix"
  else
    printf '  %s%s%s %s%s\n' "$C_RED" "$S_FAIL" "$C_RESET" "$what" "$suffix"
  fi
  return "$rc"
}

# fetch URL DEST: curl, tried up to four times. `curl --retry` alone does not retry a connection that dies
# halfway ("unexpected EOF", exit 56) or a file that stops short (exit 18), which is what a flaky link, or a
# machine that goes to sleep, does to a download; `--retry-all-errors` would, but curl older than 7.71 (Ubuntu
# 20.04) does not know it. A single command on purpose, so `run` can show progress for it.
fetch() {
  local tries=0
  while :; do
    curl -fsSL --connect-timeout 20 "$1" -o "$2" && return 0
    tries=$((tries + 1))
    [ "$tries" -ge 4 ] && return 1
    sleep $((tries * 3))
  done
}

# run "what this does" command args...   as run_soft, but a failure ends the installer.
run() {
  local what="$1"
  if run_soft "$@"; then return 0; fi
  ui_log_tail
  die "${what} failed."
}

# box "Title" "line" ...   a framed block. Lines are plain text: their width is measured.
box() {
  local title="$1" line w i bar="" tbar="" color="${UI_BOX_COLOR:-$C_GREEN}"
  shift
  w=$((${#title} + 2))
  for line in "$@"; do if [ "${#line}" -gt "$w" ]; then w=${#line}; fi; done
  if [ $((w + 4)) -gt "$UI_COLS" ]; then
    # Too wide for this terminal: a frame would wrap into a mess, so print the same lines plainly.
    printf '\n%s%s%s\n' "${C_BOLD}${color}" "$title" "$C_RESET"
    for line in "$@"; do printf '  %s\n' "$line"; done
    return 0
  fi
  for ((i = 0; i < w + 2; i++)); do bar+="$S_H"; done
  for ((i = 0; i < w - ${#title} - 1; i++)); do tbar+="$S_H"; done
  printf '\n%s%s%s %s%s%s%s %s%s%s\n' "$color" "$S_TL" "$S_H" "$C_BOLD" "$title" "$C_RESET" "$color" "$tbar" "$S_TR" "$C_RESET"
  for line in "$@"; do
    printf '%s%s%s %-*s %s%s%s\n' "$color" "$S_V" "$C_RESET" "$w" "$line" "$color" "$S_V" "$C_RESET"
  done
  printf '%s%s%s%s%s\n' "$color" "$S_BL" "$bar" "$S_BR" "$C_RESET"
}

# prompt VAR "Question" [DEFAULT] [VALIDATOR] [HINT]
# Skipped when VAR already has a value (it came from the command line) or there is no terminal.
prompt() {
  local var="$1" question="$2" default="${3:-}" validator="${4:-}" hint="${5:-}" answer
  if [ -n "${!var}" ] || ! is_interactive; then return 0; fi
  while :; do
    printf '\n%s%s%s\n' "$C_BOLD" "$question" "$C_RESET"
    if [ -n "$hint" ]; then para 2 "$hint"; fi
    if [ -n "$default" ]; then printf '  %s>%s %s[%s]%s ' "$C_CYAN" "$C_RESET" "$C_DIM" "$default" "$C_RESET"; else printf '  %s>%s ' "$C_CYAN" "$C_RESET"; fi
    read -r answer || answer=""
    answer="${answer:-$default}"
    if [ -z "$validator" ] || "$validator" "$answer"; then
      printf -v "$var" '%s' "$answer"
      return 0
    fi
    warn "That does not look right. Try again."
  done
}

# prompt_secret VAR "Question" [HINT]   like prompt, but what is typed is not shown.
prompt_secret() {
  local var="$1" question="$2" hint="${3:-}" answer
  if [ -n "${!var}" ] || ! is_interactive; then return 0; fi
  while :; do
    printf '\n%s%s%s\n' "$C_BOLD" "$question" "$C_RESET"
    if [ -n "$hint" ]; then para 2 "$hint"; fi
    printf '  %s>%s ' "$C_CYAN" "$C_RESET"
    read -r -s answer || answer=""
    printf '\n'
    if [ -n "$answer" ]; then printf -v "$var" '%s' "$answer"; return 0; fi
    warn "Nothing was entered."
  done
}

# choose VAR "Question" DEFAULT_NUMBER "Label|Description" ...   VAR becomes the chosen number.
choose() {
  local var="$1" question="$2" default="$3" item answer n=0
  shift 3
  if ! is_interactive; then return 0; fi
  printf '\n%s%s%s\n' "$C_BOLD" "$question" "$C_RESET"
  for item in "$@"; do
    n=$((n + 1))
    printf '  %s%d%s  %s\n' "$C_CYAN" "$n" "$C_RESET" "${item%%|*}"
    if [ "$item" != "${item#*|}" ]; then para 5 "${item#*|}"; fi
  done
  while :; do
    printf '  %s>%s %s[%s]%s ' "$C_CYAN" "$C_RESET" "$C_DIM" "$default" "$C_RESET"
    read -r answer || answer=""
    answer="${answer:-$default}"
    if [[ $answer =~ ^[0-9]+$ ]] && [ "$answer" -ge 1 ] && [ "$answer" -le "$n" ]; then
      printf -v "$var" '%s' "$answer"
      return 0
    fi
    warn "Enter a number from 1 to ${n}."
  done
}

# confirm "Question" [y|n]   the default answer is the second argument (y when omitted).
confirm() {
  if ! is_interactive; then return 0; fi
  local default="${2:-y}" hint="Y/n" reply
  if [ "$default" = n ]; then hint="y/N"; fi
  printf '\n%s%s%s %s[%s]%s ' "$C_BOLD" "$1" "$C_RESET" "$C_DIM" "$hint" "$C_RESET"
  read -r reply || reply=""
  reply="${reply:-$default}"
  case "$reply" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

# A host name such as ping.example.com (empty is allowed: it means "no domain").
valid_domain() {
  if [ -z "$1" ]; then return 0; fi
  local pattern='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
  [[ ${#1} -le 253 && $1 =~ $pattern ]]
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  [ "$(id -u)" -eq 0 ] || die "Run this as root (for example: sudo bash $0 $*)."
}

is_interactive() { [ -t 0 ] && [ "$ASSUME_YES" -eq 0 ]; }

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) die "Unsupported CPU architecture: $(uname -m) (supported: x86_64, aarch64)." ;;
  esac
}

installed_mode() {
  if [ -f "$MODE_FILE" ]; then cat "$MODE_FILE"; fi
}

require_mode() {
  local mode
  mode="$(installed_mode)"
  [ -n "$mode" ] || die "No installation found. Run: bash $0 install --mode direct|docker"
  echo "$mode"
}

TMP_DIRS=()
cleanup() {
  ui_spin_stop
  if [ "${#TMP_DIRS[@]}" -gt 0 ]; then rm -rf "${TMP_DIRS[@]}"; fi
}
trap cleanup EXIT

make_temp_dir() {
  local dir
  dir="$(mktemp -d)"
  TMP_DIRS+=("$dir")
  echo "$dir"
}

# ------------------------------------------------------------------------------------------------
# Releases
# ------------------------------------------------------------------------------------------------

resolve_version() {
  # A tag such as v0.1.0, or the newest published release.
  if [ -n "$VERSION" ] && [ "$VERSION" != "latest" ]; then
    normalize_tag "$VERSION"
    return
  fi
  local tag
  tag="$(fetch "${API_BASE}/releases/latest" /dev/stdout | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)" || true
  [ -n "$tag" ] || die "Could not find a published release of ${REPO}. Pass --version vX.Y.Z (or --binary FILE)."
  echo "$tag"
}

download_verified_binary() {
  # download_verified_binary TAG DEST -> fetches the binary for this CPU and checks it against the
  # release's SHA256SUMS. Refuses to continue on any mismatch.
  local tag="$1" dest="$2" arch asset tmp expected actual
  arch="$(detect_arch)"
  asset="ipping-node-linux-${arch}"
  tmp="$(make_temp_dir)"
  run "Downloading ipping-node ${tag} (${arch})" fetch "${RELEASE_BASE}/${tag}/${asset}" "${tmp}/${asset}"
  fetch "${RELEASE_BASE}/${tag}/SHA256SUMS" "${tmp}/SHA256SUMS" || die "Could not download SHA256SUMS for ${tag}."
  expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "${tmp}/SHA256SUMS" | head -n 1)"
  [ -n "$expected" ] || die "SHA256SUMS has no entry for ${asset}."
  actual="$(sha256sum "${tmp}/${asset}" | awk '{ print $1 }')"
  [ "$expected" = "$actual" ] || die "Checksum mismatch for ${asset} (expected ${expected}, got ${actual}). Nothing was installed."
  tick "Checked it against the release's published checksum"
  install -m 0755 "${tmp}/${asset}" "$dest"
}

# ------------------------------------------------------------------------------------------------
# Docker
# ------------------------------------------------------------------------------------------------

# A release is vX.Y.Z (the v is optional), optionally with a -rc.N style suffix. Anything else is
# refused up front, so a typo can never end up inside a download URL.
valid_version() {
  case "$1" in
    "" | latest) return 0 ;;
  esac
  local pattern='^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
  [[ $1 =~ $pattern ]]
}

normalize_tag() {
  case "$1" in v*) printf '%s' "$1" ;; *) printf 'v%s' "$1" ;; esac
}

# One value from /etc/os-release, read in a subshell. Never `source` that file into this script:
# it defines VERSION, NAME, ID and more, which silently replaced this script's own variables
# (Debian 13 has VERSION="13 (trixie)", which became the release to download).
os_release() {
  ( # shellcheck source=/dev/null
    . "${OS_RELEASE_FILE:-/etc/os-release}" 2>/dev/null
    printf '%s' "${!1:-}" )
}

APT_UPDATED=0

apt_install() {
  # apt_install PACKAGE... : the package lists are refreshed once, unless something changed them.
  command_exists apt-get || die "Missing: $*. Automatic installation of system packages supports Debian and Ubuntu only."
  if [ "$APT_UPDATED" -eq 0 ]; then
    run "Updating the package lists" env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    APT_UPDATED=1
  fi
  run "Installing ${APT_LABEL:-$*}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@"
}

install_docker_if_missing() {
  if command_exists docker && docker compose version >/dev/null 2>&1; then return; fi
  command_exists apt-get || die "Docker with the compose plugin is required. Install it (https://docs.docker.com/engine/install/) and run this again."
  local distro codename
  distro="$(os_release ID)"
  codename="$(os_release UBUNTU_CODENAME)"
  codename="${codename:-$(os_release VERSION_CODENAME)}"
  case "$distro" in ubuntu | debian) ;; *) die "Automatic Docker installation supports Debian and Ubuntu; install Docker manually." ;; esac
  [ -n "$codename" ] || die "Could not tell which release of ${distro} this is (no codename in /etc/os-release)."
  confirm "Docker is not installed. Install it from Docker's apt repository?" \
    || die "Docker is required for --mode docker."
  step "Installing Docker"
  apt_install ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  run "Adding Docker's package signing key" fetch "https://download.docker.com/linux/${distro}/gpg" /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${distro}
Suites: ${codename}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  APT_UPDATED=0   # a new package source: the lists have to be refreshed again
  APT_LABEL="Docker Engine and the compose plugin" apt_install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker >/dev/null 2>&1 || true
}

compose() {
  docker compose -p "$COMPOSE_PROJECT" -f "${APP_DIR}/compose.yaml" --env-file "${APP_DIR}/.env" "$@"
}

write_compose_file() {
  # The same file as compose.yaml in the repository, embedded so an install needs no extra download.
  cat >"${APP_DIR}/compose.yaml" <<'EOF'
services:
  ipping-node:
    image: ${IPPING_NODE_IMAGE:-tonyliuzj/ipping-node:latest}
    restart: unless-stopped
    env_file: .env
    volumes:
      - ipping-node-state:/var/lib/ipping-node
    sysctls:
      net.ipv4.ping_group_range: "0 2147483647"
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    read_only: true

volumes:
  ipping-node-state:
EOF
}

node_recent_log() {
  case "$(installed_mode)" in
    direct) journalctl -u "$SERVICE" -n 60 --no-pager -o cat 2>/dev/null || true ;;
    docker) compose logs --tail 60 --no-color 2>/dev/null || true ;;
  esac
}

wait_for_node_log() { # wait_for_node_log TEXT SECONDS
  local waited=0 logs
  while [ "$waited" -lt "$2" ]; do
    logs="$(node_recent_log)"
    case "$logs" in *"$1"*) return 0 ;; esac
    sleep 1; waited=$((waited + 1))
  done
  return 1
}

# Does the site know this node as approved? Its public node list only holds approved nodes, so
# being in it means approved, and "online" says whether the node is connected right now. This
# matters because a node approved while it is already connected says nothing in its own log.
# Prints online, offline, absent (not listed: pending or revoked) or unknown (could not ask).
site_node_state() {
  local id server body rest
  id="$(node_id)"; server="$(node_server)"
  if [ -z "$id" ] || [ -z "$server" ]; then echo unknown; return; fi
  body="$(curl -fsS --max-time 5 "${server%/}/api/v1/nodes" 2>/dev/null)" || { echo unknown; return; }
  body="${body//[[:space:]]/}"
  case "$body" in
    *"\"id\":\"$id\""*)
      rest="${body#*\"id\":\""$id"\"}"
      case "${rest%%\}*}" in *'"online":true'*) echo online ;; *) echo offline ;; esac
      ;;
    *'"id":'*|"[]") echo absent ;;
    *) echo unknown ;;
  esac
}

# What the node says about itself, in words: what the site says if it can be asked, else the log.
node_approval() {
  local last
  case "$(site_node_state)" in
    online) echo "approved and connected"; return ;;
    offline) echo "approved, not connected right now"; return ;;
  esac
  last="$(node_recent_log | grep -E 'approved; ready for tasks|waiting for an administrator|refused this node|session ended' | tail -n 1 || true)"
  case "$last" in
    *"approved; ready"*) echo "approved, ready for work" ;;
    *"waiting for an administrator"*) echo "waiting for an administrator to approve it" ;;
    *"refused this node"*) echo "refused by the site (revoked, or its key was rotated)" ;;
    *"session ended"*) echo "reconnecting" ;;
    *) echo "connecting" ;;
  esac
}

env_value() { grep -E "^$1=" "${APP_DIR}/.env" 2>/dev/null | head -n 1 | cut -d= -f2- || true; }

# ------------------------------------------------------------------------------------------------
# install
# ------------------------------------------------------------------------------------------------

# A backend address: http(s)://host[:port], nothing else (no path, no credentials).
valid_server() {
  local pattern='^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:[0-9]{1,5})?/?$'
  [[ ${#1} -le 253 && $1 =~ $pattern ]]
}

valid_country() { [ -z "$1" ] || [[ $1 =~ ^[A-Za-z]{2}$ ]]; }

valid_node_name() { [ -n "$1" ] && [ "${#1}" -le 100 ]; }

is_local_address() {
  case "${1#*://}" in localhost | localhost:* | 127.* | "[::1]"*) return 0 ;; *) return 1 ;; esac
}

describe_server() { printf '%s' "${SERVER%/}"; }

enrollment_questions() {
  # Everything the node needs to join, asked up front. Values given on the command line are not asked again.
  if [ -z "$SERVER" ]; then
    prompt SERVER "Where is your ipping site?" "" valid_server \
      "The address you open in the browser, for example https://ping.example.com (the node connects to it; it never listens for connections)."
  fi
  [ -n "$SERVER" ] || die "Say where the ipping site is with --server https://your-site."
  valid_server "$SERVER" || die "'${SERVER}' is not a site address. Use the form https://ping.example.com (no path)."
  SERVER="${SERVER%/}"
  if [ "${SERVER#http://}" != "$SERVER" ] && ! is_local_address "$SERVER" && [ "$ALLOW_INSECURE" -eq 0 ]; then
    if is_interactive; then
      warn "${SERVER} uses plain HTTP, so this node's credential would travel unencrypted."
      confirm "Continue anyway? (only do this on a network you trust)" n || die "Use an https:// address, or add --allow-insecure."
      ALLOW_INSECURE=1
    else
      die "${SERVER} uses plain HTTP, which would send this node's credential unencrypted. Use https://, or add --allow-insecure."
    fi
  fi
  prompt_secret TOKEN "Enrollment token" "Create one in the admin page: Admin > Enrollment > Create enrollment token. It works once and then expires."
  prompt NAME "What should this node be called?" "$(hostname)" valid_node_name "Shown on the public node list and in results."
  NAME="${NAME:-$(hostname)}"
  prompt COUNTRY "Which country is this node in? (two letters, for example DE)" "" valid_country \
    "Optional. An administrator can correct it later; results are placed on a map from it."
  prompt CITY "Which city?" "" "" "Optional."
  COUNTRY="$(printf '%s' "$COUNTRY" | tr '[:lower:]' '[:upper:]')"
}

collect_enrollment_details() {
  # Enrollment is only needed the first time; a node that already has its credential keeps it.
  [ -n "$TOKEN" ] || die "An enrollment token is needed the first time: pass --token (create one in the admin page)."
}

install_docker_mode() {
  install_docker_if_missing
  local existing="no"
  if [ -f "${APP_DIR}/.env" ]; then existing="yes"; fi
  if [ "$existing" = "yes" ]; then note "Keeping the configuration already in ${APP_DIR}/.env."; fi

  step "Setting up ${APP_DIR}"
  install -d -m 0750 "$APP_DIR"
  write_compose_file
  local image_ref="${IMAGE}:latest"
  if [ -n "$VERSION" ] && [ "$VERSION" != "latest" ]; then image_ref="${IMAGE}:${VERSION#v}"; fi

  if [ "$existing" = "no" ]; then
    (
      umask 077
      {
        echo "IPPING_NODE_SERVER=${SERVER}"
        echo "IPPING_NODE_ENROLL_TOKEN=${TOKEN}"
        echo "IPPING_NODE_NAME=${NAME}"
        if [ -n "$COUNTRY" ]; then echo "IPPING_NODE_COUNTRY=${COUNTRY}"; fi
        if [ -n "$CITY" ]; then echo "IPPING_NODE_CITY=${CITY}"; fi
        if [ -n "$PROVIDER" ]; then echo "IPPING_NODE_PROVIDER=${PROVIDER}"; fi
        if [ "$ALLOW_INSECURE" -ne 0 ]; then echo "IPPING_NODE_ALLOW_INSECURE=1"; fi
        echo "IPPING_NODE_IMAGE=${image_ref}"
      } >"${APP_DIR}/.env"
    )
  elif ! grep -q '^IPPING_NODE_IMAGE=' "${APP_DIR}/.env"; then
    echo "IPPING_NODE_IMAGE=${image_ref}" >>"${APP_DIR}/.env"
  fi
  chmod 600 "${APP_DIR}/.env"
  tick "Wrote ${APP_DIR}/.env (readable by root only)"

  step "Starting the node"
  run_soft "Downloading the image" compose pull --quiet \
    || warn "Could not download ${image_ref}; continuing with a local copy if there is one."
  run "Starting the container" compose up -d
  echo docker >"$MODE_FILE"   # only now is it "installed": a failure before this can simply be retried

  if [ "$existing" = "no" ]; then
    # The token is single-use and the node now holds its own credential in the state volume, so
    # it does not need to stay on disk.
    run_soft "Waiting for the node to connect" wait_for_node_log connected 30 \
      || warn "The node has not connected yet. Look at: sudo bash $0 logs"
    sed -i 's/^IPPING_NODE_ENROLL_TOKEN=.*/IPPING_NODE_ENROLL_TOKEN=/' "${APP_DIR}/.env"
  fi
  finish_message
}

service_group_can_ping() {
  # Is the node's group inside net.ipv4.ping_group_range (unprivileged ICMP)?
  local gid range min max
  gid="$(id -g "$RUN_USER")"
  range="$(cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo "1 0")"
  min="${range%%[[:space:]]*}"; max="${range##*[[:space:]]}"
  [ "$gid" -ge "$min" ] && [ "$gid" -le "$max" ]
}

write_unit_file() {
  local caps=$'CapabilityBoundingSet=' insecure_env=""
  [ "$ALLOW_INSECURE" -eq 0 ] || insecure_env="Environment=IPPING_NODE_ALLOW_INSECURE=1"
  if service_group_can_ping; then
    info "unprivileged ping sockets are allowed for this user; no extra capability needed"
  else
    warn "net.ipv4.ping_group_range does not include ${RUN_USER}; granting the service CAP_NET_RAW only"
    caps=$'AmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW'
  fi
  cat >"$UNIT_FILE" <<EOF
[Unit]
Description=ipping measurement node
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
Environment=IPPING_NODE_STATE_DIR=${STATE_DIR}
${insecure_env}
ExecStart=${APP_DIR}/current/ipping-node run
Restart=always
RestartSec=3
${caps}
# The node needs the network and its own state directory, and nothing else.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=true
RemoveIPC=true
SystemCallArchitectures=native
UMask=0077
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
ReadWritePaths=${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$UNIT_FILE"
}

install_direct_mode() {
  command_exists systemctl || die "--mode direct needs systemd. Use --mode docker on this host."
  command_exists curl || die "curl is required."
  command_exists sha256sum || die "sha256sum is required (coreutils)."

  local tag releases_dir binary enrolled="no"
  if [ -f "${STATE_DIR}/credential" ]; then enrolled="yes"; fi
  if [ "$enrolled" = "yes" ]; then note "This node is already enrolled; keeping its credential."; fi

  step "Preparing this machine"
  if ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$RUN_USER"
  fi
  install -d -m 0755 "$APP_DIR"
  install -d -m 0700 -o "$RUN_USER" -g "$RUN_USER" "$STATE_DIR"
  fix_state_ownership
  tick "An unprivileged account (${RUN_USER}) and a private state directory"

  step "Getting ipping-node"
  if [ -n "$BINARY_OVERRIDE" ]; then
    tag="local"
    [ -x "$BINARY_OVERRIDE" ] || die "--binary ${BINARY_OVERRIDE} is not an executable file."
    releases_dir="${APP_DIR}/releases/${tag}"
    install -d -m 0755 "$releases_dir"
    install -m 0755 "$BINARY_OVERRIDE" "${releases_dir}/ipping-node"
    tick "Using ${BINARY_OVERRIDE}"
  else
    tag="$(resolve_version)"
    releases_dir="${APP_DIR}/releases/${tag}"
    install -d -m 0755 "$releases_dir"
    download_verified_binary "$tag" "${releases_dir}/ipping-node"
  fi
  binary="${releases_dir}/ipping-node"
  "$binary" --version >/dev/null || die "The downloaded binary does not run on this host."

  ln -sfn "$releases_dir" "${APP_DIR}/current"
  ln -sfn "${APP_DIR}/current/ipping-node" "$BIN_LINK"

  if [ "$enrolled" = "no" ]; then
    step "Joining ${SERVER}"
    # The token goes through the environment, not the command line, so it never shows up in `ps`.
    local enroll_env=("IPPING_NODE_ENROLL_TOKEN=${TOKEN}" "IPPING_NODE_SERVER=${SERVER}" "IPPING_NODE_NAME=${NAME}")
    if [ -n "$COUNTRY" ]; then enroll_env+=("IPPING_NODE_COUNTRY=${COUNTRY}"); fi
    if [ -n "$CITY" ]; then enroll_env+=("IPPING_NODE_CITY=${CITY}"); fi
    if [ -n "$PROVIDER" ]; then enroll_env+=("IPPING_NODE_PROVIDER=${PROVIDER}"); fi
    if [ "$ALLOW_INSECURE" -ne 0 ]; then enroll_env+=("IPPING_NODE_ALLOW_INSECURE=1"); fi
    run "Enrolling this node" runuser -u "$RUN_USER" -- env "${enroll_env[@]}" "$binary" --state-dir "$STATE_DIR" enroll
  fi

  step "Starting the service"
  write_unit_file
  systemctl daemon-reload
  run "Enabling the service at boot" systemctl enable "$SERVICE"
  run "Starting the service" systemctl restart "$SERVICE"
  echo direct >"$MODE_FILE"   # only now is it "installed": a failure before this can simply be retried
  run_soft "Checking that it stays up" wait_for_active 5 \
    || { journalctl -u "$SERVICE" --no-pager -n 20 2>/dev/null || true; die "The service did not start. See the log above (journalctl -u ${SERVICE})."; }
  finish_message
}

# Whatever is already in the state directory (an `enroll` once run as root, an account recreated
# with another id) must belong to the service account, or the node cannot read its own credential.
fix_state_ownership() {
  chown -R "${RUN_USER}:${RUN_USER}" "$STATE_DIR"
  chmod 0700 "$STATE_DIR"
  find "$STATE_DIR" -type f -exec chmod 600 {} +
}

wait_for_active() { # wait_for_active SECONDS: the service must be active for this long without restarting
  local i
  for ((i = 0; i < $1; i++)); do
    sleep 1
    systemctl is-active --quiet "$SERVICE" || return 1
  done
}

node_id() { sed -n 's/.*"node_id": *"\([^"]*\)".*/\1/p' "${STATE_DIR}/node.json" 2>/dev/null | head -n 1; }

node_server() {
  if [ "$(installed_mode)" = direct ]; then
    sed -n 's/.*"server": *"\([^"]*\)".*/\1/p' "${STATE_DIR}/node.json" 2>/dev/null | head -n 1
  else
    env_value IPPING_NODE_SERVER
  fi
}

finish_message() {
  local server
  server="$(node_server)"
  box "ipping-node is running" \
    "" \
    "Site     ${server:-${SERVER}}" \
    "Node     ${NAME:-$(hostname)}" \
    "Status   $(node_approval)" \
    ""
  case "$(node_approval)" in
    approved*) printf '\n%sThis node is approved and already receives measurements.%s\n' "$C_BOLD" "$C_RESET" ;;
    *)
      printf '\n%sNext%s\n' "$C_BOLD" "$C_RESET"
      info "Open the admin page of your ipping site, go to Nodes, and approve this node."
      info "It starts receiving measurements as soon as you do."
      ;;
  esac
  printf '\n%sLater%s   sudo bash %s status | doctor | logs | update\n' "$C_BOLD" "$C_RESET" "$(basename "$0")"
}

# ------------------------------------------------------------------------------------------------
# lifecycle
# ------------------------------------------------------------------------------------------------

cmd_start() {
  case "$(require_mode)" in
    direct) run "Starting the node" systemctl start "$SERVICE" ;;
    docker) run "Starting the node" compose up -d ;;
  esac
  ok "The node is started."
}

cmd_stop() {
  case "$(require_mode)" in
    direct) run "Stopping the node" systemctl stop "$SERVICE" ;;
    docker) run "Stopping the node" compose stop ;;
  esac
  ok "The node is stopped. Its identity is kept; 'start' brings it back."
}

cmd_restart() {
  case "$(require_mode)" in
    direct) run "Restarting the node" systemctl restart "$SERVICE" ;;
    docker) run "Restarting the node" compose restart ;;
  esac
  ok "The node is restarted."
}

node_running() {
  case "$(installed_mode)" in
    direct) systemctl is-active --quiet "$SERVICE" ;;
    docker) [ -n "$(compose ps --status running --quiet 2>/dev/null)" ] ;;
    *) return 1 ;;
  esac
}

node_version() {
  case "$(installed_mode)" in
    direct) "${APP_DIR}/current/ipping-node" --version 2>/dev/null | awk '{ print $2 }' ;;
    docker)
      # Ask the running container; fall back to the image tag.
      compose exec -T ipping-node /usr/local/bin/ipping-node --version 2>/dev/null | awk '{ print $2 }' | grep . \
        || env_value IPPING_NODE_IMAGE | sed 's/.*://'
      ;;
  esac
}

cmd_status() {
  local mode
  mode="$(require_mode)"
  banner "ipping-node" "$(node_version)  ${S_SEP}  ${mode}"
  step "Service"
  if node_running; then
    printf '  %s%s%s %-14s running
' "$C_GREEN" "$S_UP" "$C_RESET" "ipping-node"
  else
    printf '  %s%s%s %-14s %sstopped%s
' "$C_RED" "$S_DOWN" "$C_RESET" "ipping-node" "$C_RED" "$C_RESET"
  fi
  step "Connection"
  info "Site      $(node_server)"
  if [ -n "$(node_id)" ]; then info "Node id   $(node_id)"; fi
  info "Status    $(node_approval)"
  note "Run 'doctor' for a full check."
}

cmd_logs() {
  case "$(require_mode)" in
    direct) journalctl -u "$SERVICE" -f --no-pager -n 100 ;;
    docker) compose logs -f --tail 100 ;;
  esac
}

cmd_update() {
  local mode
  mode="$(require_mode)"
  banner "ipping-node" "update"
  if [ "$mode" = "docker" ]; then
    step "Updating the image"
    if [ -n "$VERSION" ] && [ "$VERSION" != "latest" ]; then
      sed -i "s|^IPPING_NODE_IMAGE=.*|IPPING_NODE_IMAGE=${IMAGE}:${VERSION#v}|" "${APP_DIR}/.env"
    fi
    run_soft "Downloading the image" compose pull --quiet || warn "Could not download the image; continuing with the local copy."
    run "Recreating the container" compose up -d
    ok "Updated."
    return
  fi

  local tag previous releases_dir
  step "Looking for a release"
  tag="$(resolve_version)"
  previous="$(readlink "${APP_DIR}/current" || true)"
  releases_dir="${APP_DIR}/releases/${tag}"
  if [ "$previous" = "$releases_dir" ]; then
    ok "Already running ${tag}; nothing to do."
    return
  fi
  install -d -m 0755 "$releases_dir"
  download_verified_binary "$tag" "${releases_dir}/ipping-node"
  "${releases_dir}/ipping-node" --version >/dev/null || die "The new binary does not run on this host; keeping the current version."

  step "Switching to ${tag}"
  ln -sfn "$releases_dir" "${APP_DIR}/current"
  fix_state_ownership
  run "Restarting the service" systemctl restart "$SERVICE"
  if ! run_soft "Checking that the new version stays up" wait_for_active 5; then
    warn "The new version did not start; rolling back."
    if [ -n "$previous" ]; then ln -sfn "$previous" "${APP_DIR}/current"; fi
    systemctl restart "$SERVICE" || true
    die "Update to ${tag} failed and was rolled back."
  fi
  ok "Updated to ${tag}. Previous releases stay in ${APP_DIR}/releases for rollback."
}

cmd_doctor() {
  local mode problems=0 total=0 server
  mode="$(installed_mode)"
  [ -n "$mode" ] || die "Not installed."
  banner "ipping-node doctor" "$(node_version)  ${S_SEP}  ${mode}"
  # check "what" "what to try if it fails" command...
  check() {
    local what="$1" hint="$2"
    shift 2
    total=$((total + 1))
    if "$@" >/dev/null 2>&1; then
      tick "$what"
    else
      printf '  %s%s%s %s\n' "$C_RED" "$S_FAIL" "$C_RESET" "$what"
      note "   try: ${hint}"
      problems=$((problems + 1))
    fi
  }
  step "The node"
  check "the node is running" "sudo bash $0 logs" node_running
  if [ "$mode" = "direct" ]; then
    check "the state directory belongs to ${RUN_USER}" "sudo chown -R ${RUN_USER}: ${STATE_DIR}" bash -c "[ -z \"\$(find '${STATE_DIR}' ! -user '${RUN_USER}' 2>/dev/null | head -n 1)\" ]"
    check "the credential file is private (mode 600)" "sudo chmod 600 ${STATE_DIR}/credential" bash -c "[ \"\$(stat -c %a '${STATE_DIR}/credential')\" = 600 ]"
    if service_group_can_ping; then
      check "unprivileged ICMP is allowed (ping_group_range)" "" true
    else
      check "the service has CAP_NET_RAW for ICMP" "reinstall the node" grep -q CAP_NET_RAW "$UNIT_FILE"
    fi
  fi
  step "The site"
  server="$(node_server)"
  if [ -n "$server" ]; then
    check "the site answers at ${server}" "check the address and the firewall" curl -fsS --max-time 8 "${server%/}/api/v1/health/live"
  fi
  note "Approval: $(node_approval)"
  if [ "$problems" -eq 0 ]; then
    ok "All ${total} checks passed."
  else
    die "${problems} of ${total} checks failed."
  fi
}

cmd_uninstall() {
  local mode
  mode="$(require_mode)"
  step "Uninstalling ipping-node"
  if [ "$PURGE" -eq 1 ]; then warn "--purge deletes this node's identity: it would have to enroll again."; fi
  confirm "Remove ipping-node from this host?" n || exit 0
  if [ "$mode" = "docker" ]; then
    if [ "$PURGE" -eq 1 ]; then run "Removing the container and its state" compose down -v; else run "Removing the container" compose down; fi
  else
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    rm -f "$UNIT_FILE" "$BIN_LINK"
    systemctl daemon-reload
    rm -rf "${APP_DIR}/releases" "${APP_DIR}/current"
  fi
  rm -f "$MODE_FILE"
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$STATE_DIR" "$APP_DIR"
    if id "$RUN_USER" >/dev/null 2>&1; then userdel "$RUN_USER" 2>/dev/null || true; fi
    ok "Removed, including the node's credential."
  else
    ok "Removed. The node's identity (${STATE_DIR} / the state volume) was kept so reinstalling reuses it; add --purge to delete it."
  fi
}

# ------------------------------------------------------------------------------------------------
# menu and argument parsing
# ------------------------------------------------------------------------------------------------

usage() {
  cat <<EOF
Usage: sudo bash $0 <command> [options]

Commands:
  install      Install the node (--mode direct | docker)
  update       Move to a newer release (--version vX.Y.Z, default: latest)
  start | stop | restart | status | logs
  doctor       Check the installation
  uninstall    Remove it (state is kept unless --purge)

Options:
  --mode direct|docker     direct: systemd service, no Docker. docker: container, no Rust or Python needed.
  --server URL             Where your ipping site is, e.g. https://ping.example.com
                           Run without options for a guided install.
  --token TOKEN            Single-use enrollment token from the admin page (or IPPING_NODE_ENROLL_TOKEN)
  --name NAME  --country CC  --city CITY  --provider NAME     What the public node list shows
  --version vX.Y.Z         Release to install (default: latest)
  --binary FILE            Install this binary instead of downloading a release (direct mode)
  --allow-insecure         (or --insecure) Permit a plain http:// backend on another host. The node's credential is then
                           sent unencrypted, so use it only on a network you trust (the default is to refuse).
  --purge                  With uninstall: also delete the node's identity
  -y, --yes                Do not ask questions
EOF
}

menu_status_line() {
  if [ -n "$(installed_mode)" ]; then
    local state=stopped
    if node_running; then state=running; fi
    printf '%s  %s  %s  %s  %s' "$(node_version)" "$S_SEP" "$(installed_mode)" "$S_SEP" "$state"
  else
    printf 'not installed'
  fi
}

menu() {
  local choice mode keys=() labels=() i
  trap ':' INT   # Ctrl-C stops a running action (such as logs), not the menu
  while :; do
    mode="$(installed_mode)"
    keys=(); labels=()
    if [ -z "$mode" ]; then
      keys=(install_direct install_docker)
      labels=("Install directly on this machine (recommended)" "Install with Docker")
    else
      keys=(status doctor logs update restart stop start uninstall)
      labels=("Show what is running" "Check that everything works" "Follow the logs" "Update to the latest release" "Restart" "Stop" "Start" "Uninstall")
    fi
    banner "ipping-node" "$(menu_status_line)"
    printf '\n'
    for ((i = 0; i < ${#keys[@]}; i++)); do printf '  %s%2d%s  %s\n' "$C_CYAN" $((i + 1)) "$C_RESET" "${labels[i]}"; done
    printf '  %s q%s  Quit\n\n' "$C_CYAN" "$C_RESET"
    printf '  %s>%s ' "$C_CYAN" "$C_RESET"
    read -r choice || exit 0
    case "$choice" in q | Q | quit | exit | "") exit 0 ;; esac
    if [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#keys[@]}" ]; then
      case "${keys[choice - 1]}" in
        install_direct) MODE=direct; ( cmd_install ) || true; MODE="" ;;
        install_docker) MODE=docker; ( cmd_install ) || true; MODE="" ;;
        status) ( cmd_status ) || true ;;
        doctor) ( cmd_doctor ) || true ;;
        logs) ( cmd_logs ) || true ;;
        update) ( cmd_update ) || true ;;
        restart) ( cmd_restart ) || true ;;
        stop) ( cmd_stop ) || true ;;
        start) ( cmd_start ) || true ;;
        uninstall) ( cmd_uninstall ) || true ;;
      esac
      printf '\n%sPress Enter to return to the menu.%s ' "$C_DIM" "$C_RESET"
      read -r _ || exit 0
    else
      warn "Choose a number from the list, or q to quit."
      sleep 1
    fi
  done
}

cmd_install() {
  need_root install
  ui_log_init /var/log/ipping-node-install.log
  banner "ipping-node" "installer"
  if [ -n "$(installed_mode)" ]; then
    die "ipping-node is already installed. Use 'update' to change versions, or 'uninstall' first."
  fi
  local pick=1 enrolled=no
  if [ -f "${STATE_DIR}/credential" ]; then enrolled=yes; fi
  if is_interactive && [ -z "$MODE" ]; then
    choose pick "How should the node run on this machine?" 1 \
      "Directly on this machine (recommended)|A small program run by systemd. Nothing else to install." \
      "Docker|A hardened container. Docker is installed for you if it is missing."
    case "$pick" in 1) MODE=direct ;; *) MODE=docker ;; esac
  fi
  case "$MODE" in direct | docker) ;; *) die "Choose how to run it with --mode direct or --mode docker." ;; esac
  if [ "$enrolled" = yes ] && [ "$MODE" = direct ]; then
    note "This node is already enrolled; it keeps its identity."
    SERVER="$(node_server_from_state)"
  elif [ -f "${APP_DIR}/.env" ]; then
    note "Found the settings of an earlier install; they will be reused."
  else
    enrollment_questions
    collect_enrollment_details
    run_soft "Checking that ${SERVER} answers" curl -fsS --max-time 10 "${SERVER}/api/v1/health/live" \
      || die "Could not reach ${SERVER}. Check the address, that the site is up, and this machine's firewall."
  fi
  if is_interactive; then
    box "Ready to install" \
      "" \
      "Mode      $( [ "$MODE" = docker ] && echo "Docker" || echo "Directly on this machine (systemd)" )" \
      "Site      ${SERVER:-kept from the earlier install}" \
      "Node      ${NAME:-$(hostname)}" \
      "Location  ${CITY:+${CITY}, }${COUNTRY:-not set}" \
      "Release   ${VERSION:-latest}" \
      ""
    confirm "Install now?" || { note "Nothing was changed."; exit 0; }
  fi
  case "$MODE" in
    direct) install_direct_mode ;;
    docker) install_docker_mode ;;
  esac
}

node_server_from_state() {
  sed -n 's/.*"server": *"\([^"]*\)".*/\1/p' "${STATE_DIR}/node.json" 2>/dev/null | head -n 1
}

elevate_if_needed() {
  # Started as a normal user (the usual "download and run" one-liner)? Run again through sudo,
  # keeping the same arguments. Help text needs no privileges.
  [ "$(id -u)" -eq 0 ] && return 0
  local arg
  for arg in "$@"; do case "$arg" in -h | --help) return 0 ;; esac; done
  if ! command_exists sudo; then die "This needs root and sudo is not installed. Run it as root."; fi
  if [ ! -f "$0" ]; then die "Save the script to a file and run it from there (it has to start itself again with sudo)."; fi
  note "This needs root: running again with sudo."
  exec sudo --preserve-env bash "$0" "$@"
}

main() {
  local command="" original_args=("$@")
  TOKEN="${IPPING_NODE_ENROLL_TOKEN:-}"
  SERVER="${IPPING_NODE_SERVER:-}"
  NAME="${IPPING_NODE_NAME:-}"
  COUNTRY="${IPPING_NODE_COUNTRY:-}"
  CITY="${IPPING_NODE_CITY:-}"
  PROVIDER="${IPPING_NODE_PROVIDER:-}"
  while [ $# -gt 0 ]; do
    case "$1" in
      install | update | start | stop | restart | status | logs | doctor | uninstall) command="$1" ;;
      --mode) MODE="${2:?--mode needs a value}"; shift ;;
      --server)
        SERVER="${2:?--server needs a value}"; shift
        valid_server "$SERVER" || die "'${SERVER}' is not a site address. Use the form https://ping.example.com (no path)."
        ;;
      --token) TOKEN="${2:?--token needs a value}"; shift ;;
      --name) NAME="${2:?--name needs a value}"; shift ;;
      --country)
        COUNTRY="${2:?--country needs a value}"; shift
        valid_country "$COUNTRY" || die "'${COUNTRY}' is not a two-letter country code (for example DE)."
        COUNTRY="$(printf '%s' "$COUNTRY" | tr '[:lower:]' '[:upper:]')"
        ;;
      --city) CITY="${2:?--city needs a value}"; shift ;;
      --provider) PROVIDER="${2:?--provider needs a value}"; shift ;;
      --version)
        VERSION="${2:?--version needs a value}"; shift
        valid_version "$VERSION" || die "'${VERSION}' is not a version. Use something like v0.2.0 or latest."
        ;;
      --binary) BINARY_OVERRIDE="${2:?--binary needs a value}"; shift ;;
      --allow-insecure | --insecure) ALLOW_INSECURE=1 ;;
      --purge) PURGE=1 ;;
      -y | --yes) ASSUME_YES=1 ;;
      -h | --help) usage; exit 0 ;;
      *) usage >&2; die "Unknown argument: $1" ;;
    esac
    shift
  done

  # Only now, with the arguments known to be good: asking for a password for a typo is rude.
  elevate_if_needed "${original_args[@]}"
  case "$command" in
    "") if [ -t 0 ]; then need_root; ui_log_init /var/log/ipping-node-install.log; menu; else usage; exit 1; fi ;;
    install) cmd_install ;;
    update) need_root; ui_log_init /var/log/ipping-node-install.log; cmd_update ;;
    start) need_root; ui_log_init /var/log/ipping-node-install.log; cmd_start ;;
    stop) need_root; ui_log_init /var/log/ipping-node-install.log; cmd_stop ;;
    restart) need_root; ui_log_init /var/log/ipping-node-install.log; cmd_restart ;;
    status) cmd_status ;;
    logs) cmd_logs ;;
    doctor) cmd_doctor ;;
    uninstall) need_root; ui_log_init /var/log/ipping-node-install.log; cmd_uninstall ;;
  esac
}

# Run when executed (also when piped from curl), but not when a test sources this file.
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
