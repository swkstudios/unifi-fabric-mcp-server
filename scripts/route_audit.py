#!/usr/bin/env python3
"""Audit read tools with GET-only upstream access.

Run with UNIFI_API_KEY or UNIFI_API_KEYS configured:
    python scripts/route_audit.py --host-id CONSOLE_ID
The local-only canary has no upstream HTTP status.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

import httpx
from fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from unifi_fabric.config import Settings  # noqa: E402
from unifi_fabric.families.innerspace.innerspace_internal import get_innerspace_stats  # noqa: E402
from unifi_fabric.families.network.network import get_network_application_info  # noqa: E402
from unifi_fabric.families.site_manager import aggregation  # noqa: E402
from unifi_fabric.families.site_manager.site_manager import get_host  # noqa: E402

MANIFEST = (
    Path(__file__).resolve().parents[1] / "src/unifi_fabric/generated_api_facts/route_manifest.json"
)
# Signature of the Ubiquiti cloud connector refusal of console-internal routes.
CONNECTOR_REFUSAL_SIGNATURE = "the Connector reaches each application's public integration API"
CANARIES = {
    "integration": (
        "get_network_application_info",
        get_network_application_info,
        "/v1/connector/consoles/{host_id}/proxy/network/integration/v1/info",
    ),
    "internal": (
        "get_innerspace_stats",
        get_innerspace_stats,
        "/v1/connector/consoles/{host_id}/proxy/innerspace/api/stats",
    ),
    "site-manager": ("get_host", get_host, "/v1/hosts/{host_id}"),
}


class Observed(Exception):
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body


class GetOnlyClient:
    """Allow precisely the selected GET, with no write methods or redirects."""

    def __init__(self, client: httpx.AsyncClient, expected: str):
        self.client, self.expected = client, expected

    async def get(self, path: str, **kwargs):
        if path != self.expected or kwargs.get("params"):
            raise ValueError("canary requested an unexpected route")
        response = await self.client.get(path, follow_redirects=False)
        raise Observed(response.status_code, response.text)


class FixedRegistry:
    def __init__(self, host_id: str):
        self.host_id = host_id

    async def resolve_key_for_host(self, host):
        return None

    async def resolve_host_id(self, host, **kwargs):
        return self.host_id


def verdict(status: int, body: str) -> str:
    if 200 <= status < 300:
        return "AVAILABLE"
    if status == 403 and CONNECTOR_REFUSAL_SIGNATURE in body:
        return "REFUSED"
    return "ERROR"


async def audit(host_id: str, settings: Settings, manifest: dict) -> tuple[list[dict], int]:
    # Refuse to probe if the checked-in inventory no longer describes the canary.
    for route_class, (name, _, template) in CANARIES.items():
        expected = {
            "method": "GET",
            "path": template.replace("{host_id}", "{console_id}"),
            "route_class": route_class,
        }
        if expected not in manifest["tools"].get(name, []):
            raise ValueError("canary no longer matches the route manifest")
    local = {"method": None, "path": None, "route_class": "local-only"}
    if local not in manifest["tools"].get("list_configured_api_keys", []):
        raise ValueError("local canary no longer matches the route manifest")
    keys = settings.get_key_configs()
    if len(keys) != 1:
        raise ValueError("configure exactly one UniFi API key for the audit")
    if not re.fullmatch(r"[A-Za-z0-9_:-]+", host_id):
        raise ValueError("host id must be a single URL path segment")
    results = []
    async with httpx.AsyncClient(
        base_url=settings.api_base_url,
        headers={"X-API-KEY": keys[0].key},
        timeout=None,  # noqa: S113
    ) as http:
        for route_class, (name, tool, template) in CANARIES.items():
            path = template.format(host_id=host_id)
            try:
                await tool(GetOnlyClient(http, path), FixedRegistry(host_id), host_id)
            except Observed as observed:
                status, result = observed.status, verdict(observed.status, observed.body)
            except Exception:
                status, result = None, "ERROR"
            else:
                status, result = None, "ERROR"
            results.append(
                {"class": route_class, "canary": name, "status": status, "verdict": result}
            )
    try:
        app = FastMCP("route-audit")

        class LocalClient:
            def _key_configs(self):
                return keys

        aggregation.register(app, lambda: (LocalClient(), None))
        await app.call_tool("list_configured_api_keys", {})
        local_verdict = "AVAILABLE"
    except Exception:
        local_verdict = "ERROR"
    results.append(
        {
            "class": "local-only",
            "canary": "list_configured_api_keys",
            "status": None,
            "verdict": local_verdict,
        }
    )
    # Missing observations fail as well as regressions from the checked-in baseline.
    failed = any(
        row["verdict"] == "ERROR"
        or (manifest["baseline"].get(row["class"]) == "AVAILABLE" and row["verdict"] == "REFUSED")
        for row in results
    )
    return results, int(failed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-id", required=True, help="Console ID (not a credential)")
    args = parser.parse_args()
    try:
        manifest = json.loads(MANIFEST.read_text())
        results, code = asyncio.run(audit(args.host_id, Settings(), manifest))
    except Exception:
        print("route audit could not start; check configuration", file=sys.stderr)
        return 1
    for row in results:
        print(json.dumps(row))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
