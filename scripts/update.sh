#!/usr/bin/env bash
# Update this Mail Warden install from git and restart the systemd unit when it exists.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${MAIL_WARDEN_UPDATE_LOG:-/var/log/mail-warden-update.log}"
log() { echo "[$(date -Is)] $*" | tee -a "$LOG_FILE"; }

cd "$ROOT"
if [[ -d .git ]]; then
  remote="${UPDATE_GIT_REMOTE:-origin}"
  branch="${UPDATE_GIT_BRANCH:-main}"
  git fetch "$remote"
  git pull --ff-only "$remote" "$branch"
fi
mkdir -p "$ROOT/bin"
go build -o "$ROOT/bin/mailwarden" ./cmd/mailwarden
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^mailwarden.service'; then
  systemctl restart mailwarden
  log "restarted mailwarden"
else
  log "binary rebuilt at $ROOT/bin/mailwarden; restart the process to pick it up"
fi
