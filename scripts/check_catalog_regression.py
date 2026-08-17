#!/usr/bin/env python3
"""Catalog regression check: registered tools vs the deployed gateway catalog (issue #190).

Compares the tools registered in ``src/unifi_fabric/server.py`` (the authoritative
FastMCP instance) against the tool catalog the MCP gateway is actually serving. A tool
registered here but missing from the deployed catalog is unreachable; a catalog entry
with no registration here is stale. Either is a silent regression that every other
static check in this repo — all of which introspect only the registered set — misses.

Two comparison modes:

  * ``--snapshot FILE``  Hermetic. Compare against a saved catalog listing (a JSON bare
                         name list, an MCP ``tools/list`` result, or a ``{"data": [...]}``
                         envelope). No network, CI-safe. This is what the pytest suite
                         exercises for the drift logic; the CLI form is handy for
                         diffing a captured snapshot.
  * ``--live --endpoint URL``  Tier-2. Fetch the live catalog from the deployed gateway
                         over MCP streamable-http (initialize -> tools/list) and compare.
                         Reads the bearer token (if any) from an env var by NAME only.

With neither, prints the registered set (base + federated names) and exits 0 — useful
for capturing a snapshot of what *should* be deployed.

Exit codes: 0 = clean (or ``--emit``), 1 = drift detected, 2 = usage / fetch error.

Credential safety: the bearer token is read from the environment by name and fed to the request
header only; it is never printed, logged, or written to disk.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from unifi_fabric._catalog_audit import (  # noqa: E402  (path set above)
    DEFAULT_GATEWAY_SLUG,
    diff_catalog,
    extract_catalog_names,
    federated_tool_name,
)


def registered_tool_names() -> list[str]:
    """Authoritative registered tool names from the imported FastMCP instance."""
    from unifi_fabric.server import mcp

    result = mcp.list_tools()
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    return [tool.name for tool in result]


def load_snapshot_names(path: str) -> list[str]:
    """Read a catalog snapshot file and return its tool names."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return extract_catalog_names(payload)


def _parse_sse(text: str) -> dict | None:
    """Return the first JSON object from an SSE body (lines starting with 'data:')."""
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
    # Some gateways answer application/json directly.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def fetch_deployed_catalog_names(
    endpoint: str,
    *,
    bearer_token: str | None = None,
    timeout: float = 15.0,
) -> list[str]:
    """Fetch the deployed catalog's tool names over MCP streamable-http.

    Performs the ``initialize`` handshake, carries the returned ``Mcp-Session-Id`` into
    a ``tools/list`` call, and drains any ``nextCursor`` pages. The bearer token, if
    provided, is placed only in the Authorization header — never printed.
    """
    import httpx

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "catalog-regression-check", "version": "0.1.0"},
        },
    }

    names: list[str] = []
    with httpx.Client(timeout=timeout) as client:
        r_init = client.post(endpoint, headers=headers, json=init_req)
        if r_init.status_code != 200:
            raise RuntimeError(
                f"initialize failed: HTTP {r_init.status_code} (body length "
                f"{len(r_init.text)})"
            )
        session_id = r_init.headers.get("mcp-session-id") or r_init.headers.get(
            "Mcp-Session-Id"
        )
        list_headers = dict(headers)
        if session_id:
            list_headers["Mcp-Session-Id"] = session_id
        # Some servers require the initialized notification before other calls.
        client.post(
            endpoint,
            headers=list_headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )

        cursor: str | None = None
        request_id = 2
        while True:
            params: dict = {}
            if cursor:
                params["cursor"] = cursor
            r_list = client.post(
                endpoint,
                headers=list_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/list",
                    "params": params,
                },
            )
            if r_list.status_code != 200:
                raise RuntimeError(
                    f"tools/list failed: HTTP {r_list.status_code} (body length "
                    f"{len(r_list.text)})"
                )
            obj = _parse_sse(r_list.text)
            if not obj or "result" not in obj:
                raise RuntimeError("tools/list returned no parseable result")
            result = obj["result"]
            for tool in result.get("tools", []):
                name = tool.get("name") if isinstance(tool, dict) else None
                if isinstance(name, str):
                    names.append(name)
            cursor = result.get("nextCursor")
            request_id += 1
            if not cursor:
                break
    return names


def _report(diff, *, emit: bool) -> int:
    if emit:
        print(f"registered tools: {len(diff.registered)}")
        for name in diff.registered:
            print(f"  {name}  ->  {federated_tool_name(name)}")
        return 0
    print(diff.summary())
    return 0 if diff.is_clean else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--gateway-slug",
        default=DEFAULT_GATEWAY_SLUG,
        help=f"Federation slug of the gateway to compare (default: {DEFAULT_GATEWAY_SLUG}).",
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--snapshot", help="Compare against a saved catalog snapshot JSON file.")
    src.add_argument("--live", action="store_true", help="Fetch the live deployed catalog.")
    parser.add_argument("--endpoint", help="Deployed gateway MCP endpoint URL (with --live).")
    parser.add_argument(
        "--bearer-env",
        default="MCP_BEARER_TOKEN",
        help="Env var NAME holding the bearer token for --live (value never printed).",
    )
    parser.add_argument(
        "--emit",
        action="store_true",
        help="Print the registered tool set (base + federated names) and exit 0.",
    )
    args = parser.parse_args(argv)

    registered = registered_tool_names()

    if args.emit or (not args.snapshot and not args.live):
        return _report(diff_catalog(registered, [], args.gateway_slug), emit=True)

    if args.snapshot:
        catalog = load_snapshot_names(args.snapshot)
    else:  # --live
        if not args.endpoint:
            parser.error("--live requires --endpoint")
        import os

        bearer = os.environ.get(args.bearer_env)
        try:
            catalog = fetch_deployed_catalog_names(args.endpoint, bearer_token=bearer)
        except Exception as exc:  # noqa: BLE001  (surface a clean CLI error)
            print(f"ERROR: could not fetch live catalog: {exc}", file=sys.stderr)
            return 2

    return _report(diff_catalog(registered, catalog, args.gateway_slug), emit=False)


if __name__ == "__main__":
    raise SystemExit(main())
