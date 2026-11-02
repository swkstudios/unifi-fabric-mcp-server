#!/usr/bin/env python3
"""Catalog regression check: registered tools vs the deployed gateway catalog.

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
                         diffing a captured snapshot. Discovery snapshots require
                         {"advertisedTools": [...five meta entries...], "domainTools":
                         [...complete describe_tool entries...]}; names and schemas
                         must match the finalized full-mode checkout registry.
  * ``--live --endpoint URL``  Tier-2. Fetch the live catalog from the deployed gateway
                         over MCP streamable-http (initialize -> tools/list) and compare.
                         Reads the bearer token (if any) from an env var by NAME only.

For mixed catalogs with overlapping gateway slugs, repeat ``--other-gateway-slug``
to supply ownership metadata. The longest matching known slug owns each federated
name. Without this option, the existing prefix-only comparison is unchanged.

With neither, prints the registered set (base + federated names) and exits 0 — useful
for capturing a snapshot of what *should* be deployed.

Exit codes: 0 = clean (or ``--emit``), 1 = drift detected, 2 = usage / fetch error.

Credential safety: the bearer token is read from the environment by name and fed to the request
header only; it is never printed, logged, or written to disk.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
from mcp_navigation import decode, domain_catalog, full_mode_catalog  # noqa: E402

from unifi_fabric._catalog_audit import (  # noqa: E402  (path set above)
    DEFAULT_GATEWAY_SLUG,
    base_tool_name,
    diff_catalog,
    extract_catalog_names,
    federated_tool_name,
)


def registered_tool_catalog() -> list[dict]:
    """Authoritative registered tool names from the imported FastMCP instance."""
    return full_mode_catalog(str(SRC))


def registered_tool_names() -> list[str]:
    return [tool["name"] for tool in registered_tool_catalog()]


def require_schema_parity(catalog: list[dict], expected: list[dict]) -> None:
    """A five-tool advertisement cannot replace complete hidden inventory evidence."""
    actual = {
        tool["name"]: {key: tool.get(key) for key in ("inputSchema", "outputSchema", "annotations")}
        for tool in catalog
    }
    baseline = {
        tool["name"]: {key: tool.get(key) for key in ("inputSchema", "outputSchema", "annotations")}
        for tool in expected
    }
    if len(actual) != len(catalog) or set(actual) != set(baseline):
        raise ValueError("hidden catalog names differ from full-mode baseline")
    mismatches = sorted(name for name in actual if actual[name] != baseline[name])
    if mismatches:
        raise ValueError(f"hidden catalog schemas differ from full-mode baseline: {mismatches}")


def load_snapshot_names(path: str, *, expected_catalog: list[dict] | None = None) -> list[str]:
    """Read a catalog snapshot file and return its tool names."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "advertisedTools" in payload:
        from mcp_navigation import discovery_mode

        if not discovery_mode(payload["advertisedTools"]):
            raise ValueError("combined snapshot requires discovery meta-tools")
        if "domainTools" not in payload:
            raise ValueError("discovery snapshot requires a complete domainTools inventory")
        payload = payload["domainTools"]
        if not isinstance(payload, list) or not all(
            isinstance(t, dict) and isinstance(t.get("inputSchema"), dict) for t in payload
        ):
            raise ValueError("discovery domainTools requires exact schemas")
        if expected_catalog is not None:
            require_schema_parity(payload, expected_catalog)
    envelope = payload
    while isinstance(envelope, dict):
        if "error" in envelope or envelope.get("nextCursor") is not None:
            raise ValueError("incomplete or invalid catalog snapshot")
        envelope = envelope.get("result")
    return extract_catalog_names(payload)


def _parse_sse(text: str, request_id: int | None = None) -> dict | None:
    """Select a JSON-RPC response by id, ignoring SSE notifications and other calls."""
    candidates = [text]
    data_lines: list[str] = []
    for line in [*text.splitlines(), ""]:
        if not line:
            if data_lines:
                candidates.append("\n".join(data_lines))
                data_lines = []
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and (request_id is None or obj.get("id") == request_id):
            return obj
    return None


def fetch_deployed_catalog_names(
    endpoint: str,
    *,
    bearer_token: str | None = None,
    gateway_slug: str = DEFAULT_GATEWAY_SLUG,
    expected_catalog: list[dict] | None = None,
    other_gateway_slugs: Iterable[str] = (),
) -> list[str]:
    """Fetch the deployed catalog's tool names over MCP streamable-http.

    Performs the ``initialize`` handshake, carries the returned ``Mcp-Session-Id`` into
    a ``tools/list`` call, and drains any ``nextCursor`` pages. The bearer token, if
    provided, is placed only in the Authorization header — never printed.
    """
    import httpx

    other_gateway_slugs = tuple(other_gateway_slugs)
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

    advertised: list[dict] = []
    with httpx.Client(timeout=None) as client:  # noqa: S113 -- await HTTP completion
        r_init = client.post(endpoint, headers=headers, json=init_req)
        if r_init.status_code != 200:
            raise RuntimeError(
                f"initialize failed: HTTP {r_init.status_code} (body length {len(r_init.text)})"
            )
        init_obj = _parse_sse(r_init.text, 1)
        if not init_obj or "error" in init_obj or not isinstance(init_obj.get("result"), dict):
            raise RuntimeError("initialize returned an invalid response")
        session_id = r_init.headers.get("mcp-session-id") or r_init.headers.get("Mcp-Session-Id")
        list_headers = dict(headers)
        if session_id:
            list_headers["Mcp-Session-Id"] = session_id
        # Some servers require the initialized notification before other calls.
        r_ready = client.post(
            endpoint,
            headers=list_headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        if not 200 <= r_ready.status_code < 300:
            raise RuntimeError("initialized notification failed")

        seen_cursors: set[str] = set()
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
                    f"tools/list failed: HTTP {r_list.status_code} (body length {len(r_list.text)})"
                )
            obj = _parse_sse(r_list.text, request_id)
            if not obj or "error" in obj or not isinstance(obj.get("result"), dict):
                raise RuntimeError("tools/list returned an incomplete or invalid response")
            result = obj["result"]
            tools = result.get("tools")
            if not isinstance(tools, list):
                raise RuntimeError("tools/list returned an incomplete tools array")
            for tool in tools:
                name = tool.get("name") if isinstance(tool, dict) else None
                if not isinstance(name, str) or not name:
                    raise RuntimeError("tools/list returned an invalid tool entry")
                advertised.append(tool)
            cursor = result.get("nextCursor")
            if cursor is not None:
                if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
                    raise RuntimeError("tools/list returned an invalid or repeated cursor")
                seen_cursors.add(cursor)
            request_id += 1
            if not cursor:
                break

        def call(name, arguments):
            nonlocal request_id
            request_id += 1
            response = client.post(
                endpoint,
                headers=list_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
            )
            return decode(response.status_code, _parse_sse(response.text, request_id))

        # CF advertises slug-prefixed names. Dispatch argument names stay native.
        def owned_base(name):
            return base_tool_name(name, gateway_slug, other_gateway_slugs=other_gateway_slugs)

        own = [tool for tool in advertised if owned_base(tool["name"])]
        wire = {owned_base(tool["name"]): tool["name"] for tool in own}
        normalized = (
            [{**tool, "name": owned_base(tool["name"])} for tool in own] if own else advertised
        )

        def discovery_call(name, arguments):
            return call(wire.get(name, name), arguments)

        discovery, catalog = domain_catalog(normalized, discovery_call)
        if discovery and expected_catalog is not None:
            require_schema_parity(catalog, expected_catalog)
        if not discovery:
            catalog = advertised
    return [tool["name"] for tool in catalog]


def compare_catalog(
    registered,
    catalog,
    gateway_slug=DEFAULT_GATEWAY_SLUG,
    *,
    other_gateway_slugs: Iterable[str] = (),
):
    """Compare app-native or CF-prefixed names through the existing gateway diff."""
    other_gateway_slugs = tuple(other_gateway_slugs)
    names = [
        federated_tool_name(name, gateway_slug) if name.isidentifier() else name
        for name in catalog
        if name.isidentifier()
        or base_tool_name(name, gateway_slug, other_gateway_slugs=other_gateway_slugs) is not None
    ]
    # Native discovery names already belong to this gateway. Apply ownership only
    # to original federated entries, before converting native names for the diff.
    return diff_catalog(registered, names, gateway_slug)


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
    parser.add_argument(
        "--other-gateway-slug",
        action="append",
        default=[],
        help="Other known gateway slug (repeatable); longest matching slug owns each name.",
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

    baseline = registered_tool_catalog()
    registered = [tool["name"] for tool in baseline]

    if args.emit or (not args.snapshot and not args.live):
        return _report(diff_catalog(registered, [], args.gateway_slug), emit=True)

    if args.snapshot:
        try:
            catalog = load_snapshot_names(args.snapshot, expected_catalog=baseline)
        except ValueError as exc:
            print(f"ERROR: invalid discovery snapshot: {exc}", file=sys.stderr)
            return 1
    else:  # --live
        if not args.endpoint:
            parser.error("--live requires --endpoint")
        bearer = os.environ.get(args.bearer_env)
        try:
            catalog = fetch_deployed_catalog_names(
                args.endpoint,
                bearer_token=bearer,
                gateway_slug=args.gateway_slug,
                expected_catalog=baseline,
                other_gateway_slugs=args.other_gateway_slug,
            )
        except Exception as exc:  # noqa: BLE001  (surface a clean CLI error)
            print(f"ERROR: could not fetch live catalog: {exc}", file=sys.stderr)
            return 2

    return _report(
        compare_catalog(
            registered, catalog, args.gateway_slug, other_gateway_slugs=args.other_gateway_slug
        ),
        emit=False,
    )


if __name__ == "__main__":
    raise SystemExit(main())
