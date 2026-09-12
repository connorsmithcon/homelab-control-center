#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

REPOSITORY=connorsmithcon/homelab-control-center
BRANCH=main
API_BASE=https://api.github.com/repos/$REPOSITORY
RAW_BASE=https://raw.githubusercontent.com/$REPOSITORY
INSTALL_ROOT=/opt/homelab-control-center
RELEASES=$INSTALL_ROOT/releases
CURRENT=$INSTALL_ROOT/current
PREVIOUS=$INSTALL_ROOT/previous
CONFIG_DIR=/etc/homelab-control-center
CONFIG=$CONFIG_DIR/config.json
STATE=/var/lib/homelab-control-center
MODE=install
AUDIT=false
DRY_RUN=false
STAGING=

usage() {
  cat <<'USAGE'
Usage: install.sh [--audit | --dry-run | --update]

  --audit    Download and verify the exact release, print its contents, and exit
  --dry-run  Download and verify the release, print planned changes, and exit
  --update   Install as an update while preserving configuration and state
USAGE
}

die() {
  echo "install.sh: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n $STAGING && -d $STAGING ]]; then
    rm -rf -- "$STAGING"
  fi
}
trap cleanup EXIT

for argument in "$@"; do
  case $argument in
    --audit) AUDIT=true ;;
    --dry-run) DRY_RUN=true ;;
    --update) MODE=update ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $argument" ;;
  esac
done

if [[ $AUDIT == true && $DRY_RUN == true ]]; then
  die "--audit and --dry-run cannot be combined"
fi

for required in curl python3 sha256sum awk install; do
  command -v "$required" >/dev/null 2>&1 || die "$required is required"
done

python3 - <<'PY' || die "Python 3.10 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

resolve_ref() {
  if [[ -n ${HCC_REF:-} ]]; then
    [[ $HCC_REF =~ ^[0-9a-f]{40}$ ]] || die "HCC_REF must be a full 40-character commit SHA"
    printf '%s\n' "$HCC_REF"
    return
  fi
  curl -fsSL --proto '=https' --tlsv1.2 "$API_BASE/commits/$BRANCH" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])'
}

REF=$(resolve_ref)
[[ $REF =~ ^[0-9a-f]{40}$ ]] || die "could not resolve the source commit"
STAGING=$(mktemp -d)
mkdir -p "$STAGING/source"

curl -fsSL --proto '=https' --tlsv1.2 "$RAW_BASE/$REF/manifest.sha256" -o "$STAGING/source/manifest.sha256"

allowed_payload() {
  case $1 in
    VERSION|install.sh|bin/homelabctl|bin/hcc-node-helper|src/server.py|src/actiond.py|src/static/index.html|src/static/app.js|src/static/styles.css|config/config.example.json|packaging/homelab-control-center.service|packaging/homelab-control-center-actions.service|packaging/homelab-control-center-actions.socket)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

while IFS=' ' read -r checksum relative; do
  relative=${relative# }
  [[ -n $checksum && -n $relative ]] || continue
  [[ $checksum =~ ^[0-9a-f]{64}$ ]] || die "manifest contains an invalid checksum"
  [[ $relative != /* && $relative != *..* ]] || die "manifest contains an unsafe path"
  allowed_payload "$relative" || die "manifest requested an unexpected payload: $relative"
  mkdir -p "$STAGING/source/$(dirname "$relative")"
  curl -fsSL --proto '=https' --tlsv1.2 "$RAW_BASE/$REF/$relative" -o "$STAGING/source/$relative"
done < "$STAGING/source/manifest.sha256"

(
  cd "$STAGING/source"
  sha256sum -c manifest.sha256
) || die "payload checksum verification failed"

VERSION=$(tr -d '[:space:]' < "$STAGING/source/VERSION")
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || die "VERSION is invalid"
RELEASE_ID=$VERSION-${REF:0:12}
RELEASE_DIR=$RELEASES/$RELEASE_ID

echo
echo "Homelab Control Center $VERSION"
echo "Source commit: $REF"
echo "Verified payload:"
sed 's/^[0-9a-f]\{64\}  /  - /' "$STAGING/source/manifest.sha256"
echo

if [[ $AUDIT == true ]]; then
  echo "Audit completed. No system changes were made."
  exit 0
fi

if [[ $DRY_RUN == true ]]; then
  cat <<PLAN
Planned changes:
  - create the hcc system user and group when missing
  - install immutable release $RELEASE_DIR
  - preserve existing $CONFIG
  - preserve existing $STATE
  - install and start three systemd units
  - point $CURRENT at the new release
  - keep the prior release at $PREVIOUS
  - expose the dashboard on the configured port
No system changes were made.
PLAN
  exit 0
fi

[[ $EUID -eq 0 ]] || die "installation must be run with sudo"
for required in systemctl useradd groupadd getent runuser ssh-keygen; do
  command -v "$required" >/dev/null 2>&1 || die "$required is required"
done
[[ -d /run/systemd/system ]] || die "systemd is required"

if ! getent group hcc >/dev/null; then
  groupadd --system hcc
fi
if ! id hcc >/dev/null 2>&1; then
  useradd --system --gid hcc --home-dir "$STATE" --create-home --shell /usr/sbin/nologin hcc
fi

install -d -o root -g root -m 0755 "$INSTALL_ROOT" "$RELEASES"
install -d -o root -g hcc -m 0750 "$CONFIG_DIR"
install -d -o hcc -g hcc -m 0750 "$STATE"
install -d -o hcc -g hcc -m 0700 "$STATE/.ssh"

if [[ ! -d $RELEASE_DIR ]]; then
  release_temporary=$RELEASES/.$RELEASE_ID.new.$$
  install -d -o root -g root -m 0755 "$release_temporary"
  cp -a "$STAGING/source/." "$release_temporary/"
  find "$release_temporary" -type d -exec chmod 0755 {} +
  find "$release_temporary" -type f -exec chmod 0644 {} +
  chmod 0755     "$release_temporary/install.sh"     "$release_temporary/bin/homelabctl"     "$release_temporary/src/server.py"     "$release_temporary/src/actiond.py"
  chown -R root:root "$release_temporary"
  mv "$release_temporary" "$RELEASE_DIR"
else
  (
    cd "$RELEASE_DIR"
    sha256sum -c manifest.sha256 >/dev/null
  ) || die "existing release directory failed verification: $RELEASE_DIR"
fi

if [[ ! -f $CONFIG ]]; then
  install -o root -g hcc -m 0640 "$RELEASE_DIR/config/config.example.json" "$CONFIG"
fi

if [[ ! -f $STATE/.ssh/id_ed25519 ]]; then
  runuser -u hcc -- ssh-keygen -q -t ed25519 -N '' -C homelab-control-center -f "$STATE/.ssh/id_ed25519"
fi
touch "$STATE/.ssh/known_hosts"
chown hcc:hcc "$STATE/.ssh/known_hosts"
chmod 0600 "$STATE/.ssh/id_ed25519" "$STATE/.ssh/known_hosts"
chmod 0644 "$STATE/.ssh/id_ed25519.pub"

admin_exists=false
if [[ -f $STATE/control-center.db ]]; then
  if python3 - "$STATE/control-center.db" <<'PY'
import sqlite3
import sys
try:
    connection = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
    row = connection.execute("SELECT 1 FROM users LIMIT 1").fetchone()
except sqlite3.Error:
    raise SystemExit(1)
raise SystemExit(0 if row else 1)
PY
  then
    admin_exists=true
  fi
fi

if [[ $admin_exists == false && ! -s $STATE/bootstrap-token ]]; then
  umask 0027
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$STATE/bootstrap-token"
  chown root:hcc "$STATE/bootstrap-token"
  chmod 0640 "$STATE/bootstrap-token"
fi

atomic_link() {
  local target=$1
  local link=$2
  local temporary=$link.new.$$
  ln -s "$target" "$temporary"
  mv -Tf "$temporary" "$link"
}

old_release=
if [[ -L $CURRENT ]]; then
  old_release=$(readlink -f "$CURRENT")
fi
if [[ -n $old_release && $old_release != "$RELEASE_DIR" ]]; then
  [[ $old_release == "$RELEASES/"* ]] || die "existing current symlink points outside the release directory"
  atomic_link "$old_release" "$PREVIOUS"
fi
atomic_link "$RELEASE_DIR" "$CURRENT"

ln -sfn "$CURRENT/bin/homelabctl" /usr/local/bin/homelabctl
install -o root -g root -m 0644 "$CURRENT/packaging/homelab-control-center.service" /etc/systemd/system/homelab-control-center.service
install -o root -g root -m 0644 "$CURRENT/packaging/homelab-control-center-actions.service" /etc/systemd/system/homelab-control-center-actions.service
install -o root -g root -m 0644 "$CURRENT/packaging/homelab-control-center-actions.socket" /etc/systemd/system/homelab-control-center-actions.socket

systemctl daemon-reload
systemctl enable --now homelab-control-center-actions.socket
systemctl try-restart homelab-control-center-actions.service >/dev/null 2>&1 || true
systemctl enable homelab-control-center.service
systemctl restart homelab-control-center.service

sleep 1
if ! /usr/local/bin/homelabctl doctor; then
  echo
  echo "Installation finished, but one or more health checks failed."
  echo "Inspect logs with: homelabctl logs"
  exit 1
fi

host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
if [[ -z $host_ip ]]; then
  host_ip=127.0.0.1
fi
port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "$CONFIG")

echo
echo "Installation complete."
echo "Dashboard: http://$host_ip:$port/"
echo "Source: https://github.com/$REPOSITORY/commit/$REF"
if [[ -s $STATE/bootstrap-token ]]; then
  echo
  echo "One-time setup token:"
  cat "$STATE/bootstrap-token"
  echo
  echo "The token file is deleted automatically after the first administrator is created."
fi
if [[ $MODE == update ]]; then
  echo "The prior release remains available through: sudo homelabctl rollback"
fi
