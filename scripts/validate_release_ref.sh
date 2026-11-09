#!/usr/bin/env bash
# Shared release-ref validator for the publish workflow's build-amd64 and build-arm64 jobs.
#
# publish.yml runs this copy from the workflow's own commit (github.workflow_sha), checked
# out into a separate directory before the release ref, never from the checked-out tag tree:
# a check loaded from the ref it is meant to reject could be replaced by that ref.
#
#   EVENT_NAME=create INPUT_TAG=v1.2.3 WORKFLOW_REF=refs/tags/v1.2.3 bash scripts/validate_release_ref.sh
#
# The tag reaches the shell only through environment variables, never as an inline
# workflow expression, so a crafted tag cannot inject commands before validation.
#   1. Tag format. A dispatched release is a clean vX.Y.Z; a pushed or created tag may also
#      carry a pre-release suffix (for example -rc.1 or -dev.3), which builds linux/amd64 only.
#   2. Workflow ref. A dispatch must run on the release tag itself: keyless signatures
#      embed the workflow ref, and refusing any other ref keeps the signing identity
#      (publish.yml@refs/tags/v*) true.
set -euo pipefail

EVENT_NAME="${EVENT_NAME:?EVENT_NAME is required}"
INPUT_TAG="${INPUT_TAG-}"
INPUT_CORRELATION_NONCE="${INPUT_CORRELATION_NONCE-}"
WORKFLOW_REF="${WORKFLOW_REF-}"

if [[ "$EVENT_NAME" == "workflow_dispatch" ]]; then
  pattern='^v[0-9]+\.[0-9]+\.[0-9]+$'
else
  pattern='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'
fi
if [[ ! "$INPUT_TAG" =~ $pattern ]]; then
  echo "::error::Invalid tag format. Must match vX.Y.Z (a pushed or created tag may add a pre-release suffix such as -rc.1)"
  exit 1
fi

if [[ "$EVENT_NAME" == "workflow_dispatch" && "$WORKFLOW_REF" != "refs/tags/${INPUT_TAG}" ]]; then
  echo "::error::Dispatch this workflow on the release tag (--ref ${INPUT_TAG}) so the image signature identity is the tag."
  exit 1
fi
if [[ "$EVENT_NAME" == "workflow_dispatch" && ! "$INPUT_CORRELATION_NONCE" =~ ^[0-9a-f]{32}$ ]]; then
  echo "::error::A release dispatch correlation must be exactly 32 lowercase hexadecimal characters."
  exit 1
fi
echo "release ref ok: ${INPUT_TAG} (${EVENT_NAME})"
