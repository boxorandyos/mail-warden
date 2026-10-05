#!/usr/bin/env bash
# Install a newer Go toolchain under /usr/local/go. The previous tree is kept at /usr/local/go.previous.
# Usage: sudo UPGRADE_GO_CONFIRM=1 bash scripts/upgrade-go.sh 1.27.0
set -euo pipefail

VERSION="${1:-}"
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Usage: sudo UPGRADE_GO_CONFIRM=1 bash scripts/upgrade-go.sh <1.x.y>" >&2
  echo "Run scripts/try-go.sh with the same version first. This does not rebuild mailwarden." >&2
  exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
if [[ "${UPGRADE_GO_CONFIRM:-}" != 1 ]]; then
  echo "This replaces /usr/local/go. Re-run with UPGRADE_GO_CONFIRM=1" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

tarball="go${VERSION}.linux-${arch}.tar.gz"
url="https://go.dev/dl/${tarball}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
echo "Downloading ${url}"
curl -fsSL "${url}" -o "${tmp}/${tarball}"
rm -rf /usr/local/go.previous
if [[ -d /usr/local/go ]]; then
  mv /usr/local/go /usr/local/go.previous
fi
tar -C /usr/local -xzf "${tmp}/${tarball}"
cat > /etc/profile.d/mailwarden-go.sh <<'EOF'
export PATH=/usr/local/go/bin:${PATH}
EOF
chmod 644 /etc/profile.d/mailwarden-go.sh

echo "Go is now $(PATH="/usr/local/go/bin:${PATH}" go version)."
echo "The previous toolchain is /usr/local/go.previous. Move it back over /usr/local/go to roll back."
echo "Next: PATH=/usr/local/go/bin:\$PATH go test ./... && PATH=/usr/local/go/bin:\$PATH bash scripts/update.sh"
echo "systemd does not need Go at runtime. New shells pick up /etc/profile.d/mailwarden-go.sh."
