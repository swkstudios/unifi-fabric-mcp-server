#!/usr/bin/env bash
# Check that an image reference is a multi-platform image index listing exactly the
# expected platforms (attestation manifests, platform unknown/unknown, are ignored).
#
#   scripts/check_image_platforms.sh REFERENCE PLATFORM...
#
# REFERENCE is anything `docker buildx imagetools inspect` reads: a registry reference
# (ghcr.io/owner/image@sha256:...) or a local OCI layout (oci-layout:///path/to/dir).
# Example: scripts/check_image_platforms.sh "$IMAGE@$DIGEST" linux/amd64 linux/arm64
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 REFERENCE PLATFORM..." >&2
  exit 2
fi
REFERENCE="$1"
shift

docker buildx imagetools inspect "$REFERENCE"
MEDIA_TYPE="$(docker buildx imagetools inspect --format '{{.Manifest.MediaType}}' "$REFERENCE")"
case "$MEDIA_TYPE" in
  application/vnd.oci.image.index.v1+json|application/vnd.docker.distribution.manifest.list.v2+json) ;;
  *)
    echo "::error::${REFERENCE} is ${MEDIA_TYPE}, not a multi-platform image index" >&2
    exit 1
    ;;
esac
FOUND="$(docker buildx imagetools inspect \
  --format '{{range .Manifest.Manifests}}{{if .Platform}}{{.Platform.OS}}/{{.Platform.Architecture}}{{"\n"}}{{end}}{{end}}' \
  "$REFERENCE" | grep -v '^unknown/unknown$' | grep -v '^$' | sort -u)"
EXPECTED="$(printf '%s\n' "$@" | sort -u)"
echo "platforms in the index: $(echo "$FOUND" | tr '\n' ' ')"
if [ "$FOUND" != "$EXPECTED" ]; then
  echo "::error::${REFERENCE} lists [$(echo "$FOUND" | tr '\n' ' ')], expected [$(echo "$EXPECTED" | tr '\n' ' ')]" >&2
  exit 1
fi
echo "image index platforms verified: $(echo "$EXPECTED" | tr '\n' ' ')"
