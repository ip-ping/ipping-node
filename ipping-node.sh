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

if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
else
  BOLD=""; RED=""; YELLOW=""; GREEN=""; RESET=""
fi

step() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%sWarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
ok()   { printf '%s%s%s\n' "$GREEN" "$*" "$RESET"; }
die()  { printf '%sError:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  [ "$(id -u)" -eq 0 ] || die "Run this as root (for example: sudo bash $0 $*)."
}

is_interactive() { [ -t 0 ] && [ "$ASSUME_YES" -eq 0 ]; }

confirm() {
  # confirm "question" -> true when yes. Non-interactive runs (or --yes) accept the default of yes.
  if ! is_interactive; then return 0; fi
  local reply
  read -r -p "$1 [Y/n] " reply
  case "${reply:-y}" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

ask() {
  # ask VAR "prompt" [secret]; leaves VAR alone when it is already set or there is no terminal.
  local var="$1" prompt="$2" secret="${3:-}" current
  current="${!var}"
  if [ -n "$current" ] || ! is_interactive; then return 0; fi
  if [ -n "$secret" ]; then
    read -r -s -p "$prompt: " current; echo
  else
    read -r -p "$prompt: " current
  fi
  printf -v "$var" '%s' "$current"
}

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
cleanup() { [ "${#TMP_DIRS[@]}" -eq 0 ] || rm -rf "${TMP_DIRS[@]}"; }
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
    case "$VERSION" in v*) echo "$VERSION" ;; *) echo "v$VERSION" ;; esac
    return
  fi
  local tag
  tag="$(curl -fsSL "${API_BASE}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)" || true
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
  step "Downloading ${asset} ${tag}"
  curl -fsSL "${RELEASE_BASE}/${tag}/${asset}" -o "${tmp}/${asset}" || die "Could not download ${asset} for ${tag}."
  curl -fsSL "${RELEASE_BASE}/${tag}/SHA256SUMS" -o "${tmp}/SHA256SUMS" || die "Could not download SHA256SUMS for ${tag}."
  expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "${tmp}/SHA256SUMS" | head -n 1)"
  [ -n "$expected" ] || die "SHA256SUMS has no entry for ${asset}."
  actual="$(sha256sum "${tmp}/${asset}" | awk '{ print $1 }')"
  [ "$expected" = "$actual" ] || die "Checksum mismatch for ${asset} (expected ${expected}, got ${actual}). Nothing was installed."
  info "checksum verified (${actual})"
  install -m 0755 "${tmp}/${asset}" "$dest"
}

# ------------------------------------------------------------------------------------------------
# Docker
# ------------------------------------------------------------------------------------------------

install_docker_if_missing() {
  if command_exists docker && docker compose version >/dev/null 2>&1; then return; fi
  command_exists apt-get || die "Docker with the compose plugin is required. Install it (https://docs.docker.com/engine/install/) and run this again."
  confirm "Docker (with the compose plugin) is not installed. Install it from Docker's apt repository?" \
    || die "Docker is required for --mode docker."
  step "Installing Docker from Docker's apt repository"
  # shellcheck source=/dev/null
  . /etc/os-release
  local distro="$ID"
  case "$distro" in ubuntu | debian) ;; *) die "Automatic Docker installation supports Debian and Ubuntu; install Docker manually." ;; esac
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${distro}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${distro}
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
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

env_value() { grep -E "^$1=" "${APP_DIR}/.env" 2>/dev/null | head -n 1 | cut -d= -f2- || true; }

# ------------------------------------------------------------------------------------------------
# install
# ------------------------------------------------------------------------------------------------

collect_enrollment_details() {
  ask SERVER "Backend address (for example https://ping.example.com)"
  [ -n "$SERVER" ] || die "--server is required."
  ask TOKEN "Enrollment token (from the admin page)" secret
  ask NAME "Name for this node [$(hostname)]"
  NAME="${NAME:-$(hostname)}"
  ask COUNTRY "Two-letter country code (optional)"
  ask CITY "City (optional)"
}

install_docker_mode() {
  install_docker_if_missing
  local existing="no"
  [ -f "${APP_DIR}/.env" ] && existing="yes"
  if [ "$existing" = "no" ]; then
    collect_enrollment_details
    [ -n "$TOKEN" ] || die "--token is required for the first install."
  else
    info "Existing configuration found in ${APP_DIR}/.env; keeping it."
  fi

  step "Writing ${APP_DIR}"
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
        [ -z "$COUNTRY" ] || echo "IPPING_NODE_COUNTRY=${COUNTRY}"
        [ -z "$CITY" ] || echo "IPPING_NODE_CITY=${CITY}"
        [ -z "$PROVIDER" ] || echo "IPPING_NODE_PROVIDER=${PROVIDER}"
        [ "$ALLOW_INSECURE" -eq 0 ] || echo "IPPING_NODE_ALLOW_INSECURE=1"
        echo "IPPING_NODE_IMAGE=${image_ref}"
      } >"${APP_DIR}/.env"
    )
  elif ! grep -q '^IPPING_NODE_IMAGE=' "${APP_DIR}/.env"; then
    echo "IPPING_NODE_IMAGE=${image_ref}" >>"${APP_DIR}/.env"
  fi
  chmod 600 "${APP_DIR}/.env"
  echo docker >"$MODE_FILE"

  step "Starting the node container"
  compose pull --quiet || warn "Could not pull ${image_ref}; continuing with a local copy if there is one."
  compose up -d

  if [ "$existing" = "no" ]; then
    # The token is single-use and the node now holds its own credential in the state volume, so
    # it does not need to stay on disk.
    local waited=0 logs
    while [ "$waited" -lt 30 ]; do
      logs="$(compose logs --no-color 2>/dev/null || true)"
      case "$logs" in *connected*) break ;; esac
      sleep 1; waited=$((waited + 1))
    done
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
  local caps="" insecure_env=""
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
  [ -f "${STATE_DIR}/credential" ] && enrolled="yes"
  if [ "$enrolled" = "no" ]; then
    collect_enrollment_details
    [ -n "$TOKEN" ] || die "--token is required for the first install."
  else
    info "This node is already enrolled; keeping its credential."
  fi

  step "Creating the service account and directories"
  if ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$RUN_USER"
  fi
  install -d -m 0755 "$APP_DIR"
  install -d -m 0700 -o "$RUN_USER" -g "$RUN_USER" "$STATE_DIR"

  if [ -n "$BINARY_OVERRIDE" ]; then
    tag="local"
    [ -x "$BINARY_OVERRIDE" ] || die "--binary ${BINARY_OVERRIDE} is not an executable file."
    releases_dir="${APP_DIR}/releases/${tag}"
    install -d -m 0755 "$releases_dir"
    install -m 0755 "$BINARY_OVERRIDE" "${releases_dir}/ipping-node"
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
  echo direct >"$MODE_FILE"

  if [ "$enrolled" = "no" ]; then
    step "Enrolling this node with ${SERVER}"
    # The token goes through the environment, not the command line, so it never shows up in `ps`.
    local enroll_env=("IPPING_NODE_ENROLL_TOKEN=${TOKEN}" "IPPING_NODE_SERVER=${SERVER}" "IPPING_NODE_NAME=${NAME}")
    [ -z "$COUNTRY" ] || enroll_env+=("IPPING_NODE_COUNTRY=${COUNTRY}")
    [ -z "$CITY" ] || enroll_env+=("IPPING_NODE_CITY=${CITY}")
    [ -z "$PROVIDER" ] || enroll_env+=("IPPING_NODE_PROVIDER=${PROVIDER}")
    [ "$ALLOW_INSECURE" -eq 0 ] || enroll_env+=("IPPING_NODE_ALLOW_INSECURE=1")
    runuser -u "$RUN_USER" -- env "${enroll_env[@]}" "$binary" --state-dir "$STATE_DIR" enroll \
      || die "Enrollment failed. Nothing was started."
  fi

  step "Installing the systemd service"
  write_unit_file
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1
  systemctl restart "$SERVICE"
  sleep 2
  systemctl is-active --quiet "$SERVICE" || {
    journalctl -u "$SERVICE" --no-pager -n 20 2>/dev/null || true
    die "The service did not start. See the log above (journalctl -u ${SERVICE})."
  }
  finish_message
}

finish_message() {
  echo
  ok "ipping-node is running."
  info "A new node waits for approval: open the admin page of your ipping site, Nodes tab, and approve it."
  info "Check on it with: bash $0 status    |    bash $0 logs    |    bash $0 doctor"
}

# ------------------------------------------------------------------------------------------------
# lifecycle
# ------------------------------------------------------------------------------------------------

cmd_start() {
  case "$(require_mode)" in
    direct) systemctl start "$SERVICE" ;;
    docker) compose up -d ;;
  esac
}

cmd_stop() {
  case "$(require_mode)" in
    direct) systemctl stop "$SERVICE" ;;
    docker) compose stop ;;
  esac
}

cmd_restart() {
  case "$(require_mode)" in
    direct) systemctl restart "$SERVICE" ;;
    docker) compose restart ;;
  esac
}

cmd_status() {
  case "$(require_mode)" in
    direct) systemctl status "$SERVICE" --no-pager || true ;;
    docker) compose ps ;;
  esac
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
  if [ "$mode" = "docker" ]; then
    step "Pulling the image and recreating the container"
    if [ -n "$VERSION" ] && [ "$VERSION" != "latest" ]; then
      sed -i "s|^IPPING_NODE_IMAGE=.*|IPPING_NODE_IMAGE=${IMAGE}:${VERSION#v}|" "${APP_DIR}/.env"
    fi
    compose pull --quiet || warn "Could not pull the image; continuing with the local copy."
    compose up -d
    return
  fi

  local tag previous releases_dir
  tag="$(resolve_version)"
  previous="$(readlink "${APP_DIR}/current" || true)"
  releases_dir="${APP_DIR}/releases/${tag}"
  if [ "$previous" = "$releases_dir" ]; then
    info "Already running ${tag}."
    return
  fi
  install -d -m 0755 "$releases_dir"
  download_verified_binary "$tag" "${releases_dir}/ipping-node"
  "${releases_dir}/ipping-node" --version >/dev/null || die "The new binary does not run on this host; keeping the current version."

  step "Switching to ${tag}"
  ln -sfn "$releases_dir" "${APP_DIR}/current"
  systemctl restart "$SERVICE"
  sleep 2
  if ! systemctl is-active --quiet "$SERVICE"; then
    warn "The new version did not start; rolling back."
    [ -n "$previous" ] && ln -sfn "$previous" "${APP_DIR}/current"
    systemctl restart "$SERVICE" || true
    die "Update to ${tag} failed and was rolled back."
  fi
  ok "Updated to ${tag}. Previous releases stay in ${APP_DIR}/releases for rollback."
}

cmd_doctor() {
  local mode problems=0
  mode="$(installed_mode)"
  check() { # check "what" command...
    local what="$1"; shift
    if "$@" >/dev/null 2>&1; then printf '  %sok%s   %s\n' "$GREEN" "$RESET" "$what"; else printf '  %sFAIL%s %s\n' "$RED" "$RESET" "$what"; problems=$((problems + 1)); fi
  }
  echo "ipping-node doctor (mode: ${mode:-not installed})"
  [ -n "$mode" ] || die "Not installed."
  local server
  if [ "$mode" = "direct" ]; then
    server="$(sed -n 's/.*"server": *"\([^"]*\)".*/\1/p' "${STATE_DIR}/node.json" 2>/dev/null | head -n 1)"
    check "service is running" systemctl is-active --quiet "$SERVICE"
    check "credential file exists with mode 600" bash -c "[ \"\$(stat -c %a '${STATE_DIR}/credential')\" = 600 ]"
    if service_group_can_ping; then
      check "unprivileged ICMP allowed (ping_group_range)" true
    else
      check "service has CAP_NET_RAW for ICMP" grep -q CAP_NET_RAW "$UNIT_FILE"
    fi
  else
    server="$(env_value IPPING_NODE_SERVER)"
    check "container is running" bash -c "docker compose -p '$COMPOSE_PROJECT' -f '${APP_DIR}/compose.yaml' --env-file '${APP_DIR}/.env' ps --status running --quiet | grep -q ."
  fi
  if [ -n "$server" ]; then
    check "backend reachable at ${server}" curl -fsS --max-time 8 "${server%/}/api/v1/health/live"
  fi
  if [ "$problems" -eq 0 ]; then ok "No problems found."; else die "${problems} problem(s) found."; fi
}

cmd_uninstall() {
  local mode
  mode="$(require_mode)"
  confirm "Remove ipping-node from this host?" || exit 0
  if [ "$mode" = "docker" ]; then
    if [ "$PURGE" -eq 1 ]; then compose down -v; else compose down; fi
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
  --server URL             Backend address, e.g. https://ping.example.com
  --token TOKEN            Single-use enrollment token from the admin page (or IPPING_NODE_ENROLL_TOKEN)
  --name NAME  --country CC  --city CITY  --provider NAME     What the public node list shows
  --version vX.Y.Z         Release to install (default: latest)
  --binary FILE            Install this binary instead of downloading a release (direct mode)
  --allow-insecure         Permit a plain http:// backend on another host. The node's credential is then
                           sent unencrypted, so use it only on a network you trust (the default is to refuse).
  --purge                  With uninstall: also delete the node's identity
  -y, --yes                Do not ask questions
EOF
}

menu() {
  echo "ipping-node"
  # shellcheck disable=SC2034  # the menu acts on $REPLY, not the selected text
  select choice in "Install (direct, systemd)" "Install (Docker)" "Update" "Status" "Logs" "Doctor" "Restart" "Uninstall" "Quit"; do
    case "$REPLY" in
      1) MODE=direct; cmd_install; break ;;
      2) MODE=docker; cmd_install; break ;;
      3) cmd_update; break ;;
      4) cmd_status; break ;;
      5) cmd_logs; break ;;
      6) cmd_doctor; break ;;
      7) cmd_restart; break ;;
      8) cmd_uninstall; break ;;
      9) break ;;
    esac
  done
}

cmd_install() {
  need_root install
  [ -n "$MODE" ] || { ask MODE "Mode (direct or docker)"; }
  case "$MODE" in
    direct) install_direct_mode ;;
    docker) install_docker_mode ;;
    *) die "--mode must be direct or docker." ;;
  esac
}

elevate_if_needed() {
  # Started as a normal user (the usual "download and run" one-liner)? Run again through sudo,
  # keeping the same arguments. Help text needs no privileges.
  [ "$(id -u)" -eq 0 ] && return 0
  local arg
  for arg in "$@"; do case "$arg" in -h | --help) return 0 ;; esac; done
  if ! command_exists sudo; then die "This needs root and sudo is not installed. Run it as root."; fi
  if [ ! -f "$0" ]; then die "Save the script to a file and run it from there (it has to start itself again with sudo)."; fi
  info "Root is needed; running again with sudo."
  exec sudo --preserve-env bash "$0" "$@"
}

main() {
  elevate_if_needed "$@"
  local command=""
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
      --server) SERVER="${2:?--server needs a value}"; shift ;;
      --token) TOKEN="${2:?--token needs a value}"; shift ;;
      --name) NAME="${2:?--name needs a value}"; shift ;;
      --country) COUNTRY="${2:?--country needs a value}"; shift ;;
      --city) CITY="${2:?--city needs a value}"; shift ;;
      --provider) PROVIDER="${2:?--provider needs a value}"; shift ;;
      --version) VERSION="${2:?--version needs a value}"; shift ;;
      --binary) BINARY_OVERRIDE="${2:?--binary needs a value}"; shift ;;
      --allow-insecure) ALLOW_INSECURE=1 ;;
      --purge) PURGE=1 ;;
      -y | --yes) ASSUME_YES=1 ;;
      -h | --help) usage; exit 0 ;;
      *) usage >&2; die "Unknown argument: $1" ;;
    esac
    shift
  done

  case "$command" in
    "") if [ -t 0 ]; then need_root; menu; else usage; exit 1; fi ;;
    install) cmd_install ;;
    update) need_root; cmd_update ;;
    start) need_root; cmd_start ;;
    stop) need_root; cmd_stop ;;
    restart) need_root; cmd_restart ;;
    status) cmd_status ;;
    logs) cmd_logs ;;
    doctor) cmd_doctor ;;
    uninstall) need_root; cmd_uninstall ;;
  esac
}

main "$@"
