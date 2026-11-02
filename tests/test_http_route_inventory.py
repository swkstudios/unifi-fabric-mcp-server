"""Inventory inbound HTTP routes and literal route targets in source and tests."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from unifi_fabric.access_log import B_TARGET

_OAUTH = {
    "MCP_OAUTH_ISSUER": "https://idp.test/realms/unifi",
    "MCP_OAUTH_JWKS_URI": "https://idp.test/jwks",
    "MCP_OAUTH_AUDIENCE": "unifi-fabric-mcp",
    "MCP_OAUTH_BASE_URL": "https://mcp.test",
    "MCP_OAUTH_REQUIRED_SCOPES": "unifi.read",
}


@pytest.mark.parametrize("transport", ["http", "streamable-http", "sse"])
@pytest.mark.parametrize("auth_mode", ["none", "bearer", "oauth"])
def test_all_inbound_http_routes_have_fourfold_margin(monkeypatch, transport, auth_mode):
    import unifi_fabric.server as srv

    monkeypatch.setenv("UNIFI_API_KEY", "sk-auth-http-harness")
    monkeypatch.setenv("FASTMCP_TRANSPORT", transport)
    monkeypatch.setenv("FASTMCP_STATELESS_HTTP", "false" if transport == "sse" else "true")
    monkeypatch.setenv("MCP_AUTH_MODE", auth_mode)
    if auth_mode == "bearer":
        monkeypatch.setenv("MCP_BEARER_TOKEN", "phase1-test-secret")
    elif auth_mode == "oauth":
        for name, value in _OAUTH.items():
            monkeypatch.setenv(name, value)
    importlib.reload(srv)
    try:
        app = srv.mcp.http_app(transport=transport)
        paths = {route.path for route in app.routes}
        endpoint = "/sse" if transport == "sse" else "/mcp"
        expected = {endpoint}
        targets = set()
        if transport == "sse":
            expected.add("/messages")
            targets.add("/messages?session_id=" + "0" * 32)
        if auth_mode == "oauth":
            expected.add("/.well-known/oauth-protected-resource" + endpoint)
        assert paths == expected
        targets.update(paths)
        assert targets
        assert all(len(target.encode("ascii")) < B_TARGET // 4 for target in targets)
    finally:
        # Keep shared module globals consistent after test-specific transport env.
        monkeypatch.undo()
        importlib.reload(srv)


def test_literal_route_targets_in_code_and_tests_have_fourfold_margin():
    root = Path(__file__).resolve().parents[1]
    inventory = []
    # Conservative superset: every single-line slash-prefixed string literal,
    # including upstream API routes and fixture paths. Dynamically constructed
    # legitimate inbound targets are enumerated by the runtime test above;
    # generated adversarial request heads are deliberately outside this inventory.
    for directory in (root / "src", root / "tests"):
        for path in sorted(directory.rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            # A slash that starts a fragment AFTER a substitution in an f-string (prose such
            # as f"POST {collection}/batch-delete, body ...") is the middle of a string, not
            # the start of a route target; only the first part of an f-string can be one.
            tails = {
                id(part)
                for joined in ast.walk(tree)
                if isinstance(joined, ast.JoinedStr)
                for part in joined.values[1:]
            }
            for node in ast.walk(tree):
                if id(node) in tails:
                    continue
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and node.value.startswith("/")
                    and "\n" not in node.value
                ):
                    inventory.append((str(path.relative_to(root)), node.lineno, node.value))
    assert inventory
    oversized = [
        (path, line, len(target.encode("utf-8")))
        for path, line, target in inventory
        if len(target.encode("utf-8")) >= B_TARGET // 4
    ]
    assert not oversized, oversized
