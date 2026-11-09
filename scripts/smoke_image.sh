#!/usr/bin/env bash
# Boot a built server image and send the README's initialize smoke request.
#
#   scripts/smoke_image.sh IMAGE [PLATFORM]
#
# IMAGE is a local tag or a registry reference (a digest is fine). PLATFORM (for example
# linux/arm64) selects one image of a multi-platform index and is checked against the
# architecture the container reports. The container gets a placeholder UniFi key
# (initialize makes no UniFi request) and a random bearer token. The README's POST /mcp
# initialize request is sent from inside the container to 127.0.0.1:3000, so the check
# needs no published port and works against a remote Docker daemon. It passes only on
# HTTP 200 with the version in pyproject.toml. Run it from the repository root; it needs
# bash, Docker and coreutils only (the probe runs on the image's own Python).
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 IMAGE [PLATFORM]" >&2
  exit 2
fi
IMAGE="$1"
PLATFORM="${2:-}"
EXPECTED_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml | head -n 1)"
if [ -z "$EXPECTED_VERSION" ]; then
  echo "::error::no version in pyproject.toml" >&2
  exit 2
fi
case "$PLATFORM" in
  "") MACHINE="" ;;
  linux/amd64) MACHINE=x86_64 ;;
  linux/arm64) MACHINE=aarch64 ;;
  *) echo "::error::no architecture check defined for ${PLATFORM}" >&2; exit 2 ;;
esac
MCP_BEARER_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export MCP_BEARER_TOKEN
NAME="unifi-fabric-smoke-$$"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

run_args=(--detach --name "$NAME"
  --env UNIFI_API_KEY=image-smoke-placeholder-key
  --env MCP_AUTH_MODE=bearer --env MCP_BEARER_TOKEN)
if [ -n "$PLATFORM" ]; then
  run_args+=(--platform "$PLATFORM")
fi
docker run "${run_args[@]}" "$IMAGE" >/dev/null

# The README smoke request (initialize over POST /mcp with the bearer token). Exit 3 means
# the server is not listening yet; any other failure is final.
PROBE='
import json, os, platform, sys, urllib.error, urllib.request
expected, machine = sys.argv[1], sys.argv[2]
request = urllib.request.Request(
    "http://127.0.0.1:3000/mcp",
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "image-smoke", "version": "0.1.0"}}}).encode(),
    method="POST",
    headers={"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream",
             "Authorization": "Bearer " + os.environ["MCP_BEARER_TOKEN"]},
)
try:
    response = urllib.request.urlopen(request)
except urllib.error.HTTPError as error:
    print(f"::error::initialize returned HTTP {error.code}: {error.read()[:500]!r}")
    sys.exit(1)
except OSError:
    sys.exit(3)
status, body = response.status, response.read().decode()
data = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
try:
    result = json.loads(data[0] if data else body)["result"]
    version, negotiated = result["serverInfo"]["version"], result["protocolVersion"]
except (ValueError, KeyError, IndexError, TypeError):
    print(f"::error::no initialize result in the response: {body[:500]!r}")
    sys.exit(1)
print(f"initialize: HTTP {status}, serverInfo.version {version}, protocolVersion {negotiated}")
failed = status != 200 or version != expected
if failed:
    print(f"::error::expected HTTP 200 and serverInfo.version {expected}")
if machine:
    print(f"platform: container runs on {platform.machine()} (expected {machine})")
    failed = failed or platform.machine() != machine
sys.exit(1 if failed else 0)
'
# The loop ends when the probe gets an answer or when the container stops (start-up
# failure), so it needs no deadline of its own.
while :; do
  if [ "$(docker inspect --format '{{.State.Running}}' "$NAME")" != "true" ]; then
    docker logs "$NAME" >&2 || true
    echo "::error::the container for ${IMAGE} exited before answering initialize" >&2
    exit 1
  fi
  status=0
  docker exec "$NAME" python3 -c "$PROBE" "$EXPECTED_VERSION" "$MACHINE" || status=$?
  case "$status" in
    0) break ;;
    3) sleep 2 ;;
    *)
      docker logs "$NAME" >&2 || true
      echo "::error::image smoke check failed for ${IMAGE} ${PLATFORM}" >&2
      exit 1
      ;;
  esac
done
echo "image smoke check passed: ${IMAGE} ${PLATFORM}"
