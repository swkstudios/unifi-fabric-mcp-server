#!/usr/bin/env bash
# Install the pinned gitleaks CLI, checksum-verified.
#
#   bash scripts/install_gitleaks.sh             # /usr/local/bin/gitleaks (sudo install)
#   bash scripts/install_gitleaks.sh --dest DIR  # DIR/gitleaks, no root needed
#
# The version and the sha256 of the linux_x64 release archive come from
# .github/gitleaks.pin, the single source for every workflow that installs gitleaks.
# The archive is verified before it is unpacked; a checksum mismatch installs nothing.
set -euo pipefail

usage() {
  echo "usage: scripts/install_gitleaks.sh [--dest DIR]" >&2
  exit 2
}

dest=""
case "$#" in
  0) ;;
  2)
    if [ "$1" != "--dest" ] || [ -z "$2" ]; then usage; fi
    dest="$2"
    ;;
  *) usage ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin="$root/.github/gitleaks.pin"
version=""
sha256=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    "" | "#"*) ;;
    version=*) version="${line#version=}" ;;
    sha256=*) sha256="${line#sha256=}" ;;
    *)
      echo "install_gitleaks: unexpected line in $pin: $line" >&2
      exit 1
      ;;
  esac
done < "$pin"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "install_gitleaks: $pin has no valid version=X.Y.Z line" >&2
  exit 1
fi
if ! [[ "$sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "install_gitleaks: $pin has no valid sha256=<64 hex> line" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf -- "${tmp:?}"' EXIT
curl -fsSL -o "$tmp/gitleaks.tar.gz" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
echo "${sha256}  $tmp/gitleaks.tar.gz" | sha256sum -c -
tar -xzf "$tmp/gitleaks.tar.gz" -C "$tmp" gitleaks
if [ -n "$dest" ]; then
  mkdir -p "$dest"
  install -m 0755 "$tmp/gitleaks" "$dest/gitleaks"
  "$dest/gitleaks" version
else
  sudo -n install -m 0755 "$tmp/gitleaks" /usr/local/bin/gitleaks
  gitleaks version
fi
