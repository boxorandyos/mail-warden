#!/usr/bin/env bash
# Build the API with a Go image and run the tests. Does not retag mailwarden:latest or restart the service.
# Usage: bash scripts/try-go.sh 1.27
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "Usage: bash scripts/try-go.sh <1.x or 1.x.y>" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi

image="golang:${VERSION}"
tag="mailwarden-builder:go${VERSION}"
echo "Building ${tag} from ${image}"
docker build \
  --target builder \
  --build-arg GO_IMAGE="${image}" \
  -f "${ROOT}/deployments/docker/Dockerfile.mailwarden" \
  -t "${tag}" \
  "${ROOT}"
docker run --rm "${tag}" go test ./...
echo "Tests passed on ${image}. The running mailwarden image was not changed."
echo "To build a release image with this toolchain:"
echo "  docker build --build-arg GO_IMAGE=${image} -f deployments/docker/Dockerfile.mailwarden -t mailwarden:go${VERSION} ."
echo "  docker build --build-arg GO_IMAGE=${image} -f deployments/docker/Dockerfile.policy-worker -t mailwarden-worker:go${VERSION} ."
