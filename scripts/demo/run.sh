#!/usr/bin/env bash
# Run the README demo: start the synthetic mock API, then the scripted MCP client,
# which launches the real server over stdio with UNIFI_API_BASE_URL pointed at the mock
# and UNIFI_DRY_RUN=1. Pillow reads the snapshot size in demo.py; it is not a server dependency.
set -euo pipefail
cd "$(dirname "$0")/../.."
PORT="${DEMO_PORT:-8765}"
uv run --quiet python scripts/demo/mock_api.py --port "$PORT" &
MOCK_PID=$!
trap 'kill "$MOCK_PID" 2>/dev/null || true' EXIT
for _ in $(seq 100); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/_demo/requests" 2>/dev/null && break
  sleep 0.1
done
DEMO_MOCK_URL="http://127.0.0.1:$PORT" uv run --quiet --with pillow python scripts/demo/demo.py
