#!/usr/bin/env bash
# IMAGE is an already-built image. For TLS, provide a public,
# synthetic localhost server certificate, private key, and trusted CA certificate.
# Usage: scripts/proxy_container_smoke.sh IMAGE https CERT KEY CA [expect-421]
#        scripts/proxy_container_smoke.sh IMAGE http [expect-421]
set -euo pipefail
if [[ $# -lt 1 ]]; then echo "usage: $0 IMAGE https CERT KEY CA [expect-421] | IMAGE http [expect-421]" >&2; exit 2; fi
root=$(cd "$(dirname "$0")/.." && pwd)
image=$1
shift
scheme=${1:-https}
if [[ $# -gt 0 ]]; then shift; fi
fixture_dir=""
network=""
server=""
cleanup() {
  [[ -z $server ]] || docker rm -f "$server" >/dev/null 2>&1 || true
  [[ -z $network ]] || docker network rm "$network" >/dev/null 2>&1 || true
  [[ -z $fixture_dir ]] || rm -rf -- "${fixture_dir:?}"
}
trap cleanup EXIT
fixtures=()
if [[ $scheme == https ]]; then
  if [[ $# -eq 0 || ( $# -eq 1 && $1 == expect-421 ) ]]; then
    fixture_dir=$(mktemp -d)
    python3 - "$root/tests/proxy_container/cpython-keycert.pem.gz" "$fixture_dir/keycert.pem" <<'FIXTURE'
import gzip
import sys
from pathlib import Path
Path(sys.argv[2]).write_bytes(gzip.decompress(Path(sys.argv[1]).read_bytes()))
FIXTURE
    printf "%s  %s\n" cfd723672e8205a30f93aa14e24ef5b0264c41db367b50cfa0b6fcb83d881947 "$fixture_dir/keycert.pem" | sha256sum -c --status
    chmod 644 "$fixture_dir/keycert.pem"
    set -- "$fixture_dir/keycert.pem" "$fixture_dir/keycert.pem" "$fixture_dir/keycert.pem" "$@"
  fi
  [[ $# -ge 3 ]] || { echo "TLS requires CERT KEY CA fixture files" >&2; exit 2; }
  fixtures=("$(realpath "$1")" "$(realpath "$2")" "$(realpath "$3")")
  shift 3
elif [[ $scheme != http ]]; then echo "scheme must be http or https" >&2; exit 2
fi
expect=${1:-success}
[[ $# -le 1 && ( $expect == success || $expect == expect-421 ) ]] || exit 2
image_id=$(docker image inspect --format '{{.Id}}' "$image")
revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ && $revision =~ ^[0-9a-f]{40}$ ]] || { echo "image must carry immutable ID and full revision label" >&2; exit 1; }
network="unifi-proxy-smoke-$$"
server="${network}-server"
docker network create --internal "$network" >/dev/null
export MCP_BEARER_TOKEN=synthetic-proxy-smoke-token
failed=0
for mode in stateful stateless; do
  state=true
  [[ $mode == stateful ]] && state=false
  docker run -d --name "$server" --network "$network" --network-alias server \
    -e UNIFI_API_KEY=synthetic-placeholder -e UNIFI_API_BASE_URL=http://127.0.0.1:8080 \
    -e FASTMCP_HOST=127.0.0.1 \
    -e MCP_AUTH_MODE=bearer -e MCP_BEARER_TOKEN -e UNIFI_READ_ONLY=1 -e FASTMCP_STATELESS_HTTP="$state" "$image" >/dev/null
  actual_image=$(docker inspect --format '{{.Image}}' "$server")
  [[ $actual_image == "$image_id" ]] || { echo "running image mismatch" >&2; exit 1; }
  while :; do
    health=$(docker inspect --format "{{.State.Health.Status}}" "$server")
    running=$(docker inspect --format "{{.State.Running}}" "$server")
    [[ $health == healthy && $running == true ]] && break
    if [[ $health == unhealthy || $running != true ]]; then
      docker logs "$server" >&2
      echo "server failed readiness: $health" >&2
      exit 1
    fi
    sleep 1
  done
  if [[ $scheme == https ]]; then
    docker exec "$server" mkdir -p /tmp/proxy-fixture
    docker cp "${fixtures[0]}" "$server:/tmp/proxy-fixture/cert.pem"
    docker cp "${fixtures[1]}" "$server:/tmp/proxy-fixture/key.pem"
    docker cp "${fixtures[2]}" "$server:/tmp/proxy-fixture/ca.pem"
  fi
  docker exec -i "$server" python3 - "$mode" "$scheme" "$expect" "$actual_image" "$revision" \
    < "$root/tests/proxy_container/driver.py" || failed=1
  docker rm -f "$server" >/dev/null
done
exit "$failed"
