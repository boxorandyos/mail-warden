#!/usr/bin/env bash
# Copy Mail Warden's Redis data into a new major. The running container and its volume stay as they are.
# Usage: sudo UPGRADE_REDIS_CONFIRM=1 bash scripts/upgrade-redis.sh 8
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-}"
case "${TARGET}" in
  8) ;;
  *)
    echo "Usage: sudo UPGRADE_REDIS_CONFIRM=1 bash scripts/upgrade-redis.sh 8" >&2
    echo "The shipped cache is Redis 7. The copy listens on 127.0.0.1:16380 unless --port is set." >&2
    exit 2
    ;;
esac

PORT=16380
if [[ "${2:-}" == "--port" ]]; then
  PORT="${3:-}"
fi
if [[ ! "${PORT}" =~ ^[0-9]+$ ]]; then
  echo "Port must be a number." >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
if [[ "${UPGRADE_REDIS_CONFIRM:-}" != 1 ]]; then
  echo "This starts a second Redis and leaves the live one running." >&2
  echo "Re-run with UPGRADE_REDIS_CONFIRM=1" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi

if [[ -n "${MAIL_REDIS_CONTAINER:-}" ]]; then
  OLD="${MAIL_REDIS_CONTAINER}"
else
  mapfile -t found < <(docker ps --filter label=com.docker.compose.service=redis --format '{{.Names}}')
  if [[ "${#found[@]}" -ne 1 ]]; then
    echo "Found ${#found[@]} Compose Redis containers. Set MAIL_REDIS_CONTAINER to the live one." >&2
    printf '  %s\n' "${found[@]}" >&2
    exit 1
  fi
  OLD="${found[0]}"
fi
if ! docker inspect "${OLD}" >/dev/null 2>&1; then
  echo "Container ${OLD} was not found." >&2
  exit 1
fi

image="$(docker inspect -f '{{.Config.Image}}' "${OLD}")"
current="$(printf '%s' "${image}" | sed -n 's/.*redis:\([0-9][0-9]*\).*/\1/p')"
if [[ -z "${current}" ]]; then
  echo "Could not read a Redis major from image ${image}." >&2
  exit 1
fi
if [[ "${TARGET}" -le "${current}" ]]; then
  echo "Container ${OLD} is already Redis ${current}. Refusing to move to ${TARGET}." >&2
  exit 1
fi

NEW="mailwarden-redis-${TARGET}"
VOLUME="mailwarden-redis-${TARGET}-data"
if docker inspect "${NEW}" >/dev/null 2>&1; then
  echo "Container ${NEW} already exists. Remove that container yourself to retry. The live container was not touched." >&2
  exit 1
fi
if command -v ss >/dev/null 2>&1 && ss -tln | grep -E ":${PORT}([^0-9]|$)" >/dev/null; then
  echo "127.0.0.1:${PORT} is already in use. Re-run with --port <free-port>." >&2
  exit 1
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="${ROOT}/.upgrade"
mkdir -p "${backup_dir}"
chmod 700 "${backup_dir}"
rdb="${backup_dir}/redis-${current}-to-${TARGET}-${stamp}.rdb"

echo "Saving ${OLD} (${image}) to ${rdb}"
docker exec "${OLD}" redis-cli SAVE >/dev/null
docker cp "${OLD}:/data/dump.rdb" "${rdb}"
chmod 600 "${rdb}"

echo "Starting ${NEW} from redis:8.2 on 127.0.0.1:${PORT}"
docker volume create "${VOLUME}" >/dev/null
docker run --rm --user 0 --entrypoint sh \
  -v "${VOLUME}:/data" \
  -v "${backup_dir}:/backup:ro" \
  "redis:8.2" \
  -c "cp \"/backup/$(basename "${rdb}")\" /data/dump.rdb && chown redis:redis /data/dump.rdb"
docker run -d \
  --name "${NEW}" \
  -p "127.0.0.1:${PORT}:6379" \
  -v "${VOLUME}:/data" \
  --restart unless-stopped \
  "redis:8.2" \
  redis-server --appendonly yes >/dev/null

ready=0
for _ in $(seq 1 30); do
  if docker exec "${NEW}" redis-cli PING 2>/dev/null | grep -q PONG; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  echo "Redis ${TARGET} did not answer PING. ${OLD} was not stopped." >&2
  docker stop "${NEW}" >/dev/null 2>&1 || true
  exit 1
fi

echo "Redis ${TARGET} answered PING. Mail Warden is still using ${OLD}."
echo "Outbound counters live in Redis. Losing them is safe for delivery; reputation counters start again."
echo "Switch by pointing stores.redis_addr at 127.0.0.1:${PORT}, or by replacing the Compose service during a window."
echo "Roll back by pointing the API back at ${OLD}."
echo "Snapshot kept at ${rdb}"
