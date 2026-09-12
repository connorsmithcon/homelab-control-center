#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

REPOSITORY=connorsmithcon/homelab-control-center
BRANCH=main
RAW_BASE=https://raw.githubusercontent.com/$REPOSITORY

die() {
  echo "install-node-helper: $*" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || die "run this installer with sudo"
[[ $# -eq 1 ]] || die "usage: sudo bash install-node-helper.sh REMOTE_USERNAME"

remote_user=$1
[[ $remote_user =~ ^[A-Za-z_][A-Za-z0-9_-]{0,31}$ ]] || die "remote username is invalid"
id "$remote_user" >/dev/null 2>&1 || die "remote user does not exist"
for required in curl python3 sha256sum visudo; do
  command -v "$required" >/dev/null 2>&1 || die "$required is required"
done

commit_sha=$(curl -fsSL --proto '=https' --tlsv1.2 "https://api.github.com/repos/$REPOSITORY/commits/$BRANCH" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
[[ $commit_sha =~ ^[0-9a-f]{40}$ ]] || die "could not resolve source commit"

temporary_directory=$(mktemp -d)
trap 'rm -rf -- "$temporary_directory"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 "$RAW_BASE/$commit_sha/manifest.sha256" -o "$temporary_directory/manifest.sha256"
curl -fsSL --proto '=https' --tlsv1.2 "$RAW_BASE/$commit_sha/bin/hcc-node-helper" -o "$temporary_directory/hcc-node-helper"

expected=$(awk '$2 == "bin/hcc-node-helper" {print $1}' "$temporary_directory/manifest.sha256")
[[ $expected =~ ^[0-9a-f]{64}$ ]] || die "node-helper checksum is missing from the release manifest"
actual=$(sha256sum "$temporary_directory/hcc-node-helper" | awk '{print $1}')
[[ $actual == "$expected" ]] || die "node-helper checksum verification failed"

install -o root -g root -m 0755 "$temporary_directory/hcc-node-helper" /usr/local/sbin/hcc-node-helper

sudoers_path=/etc/sudoers.d/homelab-control-center-node
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/hcc-node-helper *\n' "$remote_user" > "$sudoers_path"
chown root:root "$sudoers_path"
chmod 0440 "$sudoers_path"
visudo -cf "$sudoers_path" >/dev/null || {
  rm -f "$sudoers_path"
  die "generated sudoers rule failed validation"
}

echo "Remote helper installed for $remote_user from commit $commit_sha"
echo "Review or remove it at $sudoers_path"
