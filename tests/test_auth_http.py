"""In-process auth request-path tests for the streamable-http transport.

Phase 1 of the auth/transport/TLS matrix. Where ``test_bearer_auth.py`` exercises
the verifier object and the server-wiring decision in isolation, this module drives
the *live request path*: it builds the server's streamable-http ASGI app and sends
real MCP requests through it in-process (``httpx.ASGITransport`` -- no sockets, no
network), then asserts on the HTTP auth status the transport actually returns. This
closes the gap where bearer auth was only proven on the verifier object, never on a
real request reaching the server.

The streamable-http endpoint negotiates content via ``Accept`` / ``Content-Type`` (a
bare hit returns 406 Not Acceptable), so every request carries the streamable-http
headers and the assertions are made on the *auth* outcome -- 200 accepted vs 401
rejected -- not on transport negotiation.

The ``auth_http_client`` factory fixture (parametrised by auth mode + env) is the
reusable substrate later phases extend: the OAuth phase passes ``auth_mode="oauth"``
with the OAuth descriptor env plus a signed token in the ``Authorization`` header,
and reuses the same in-process request helpers unchanged.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Mapping

import httpx
import httpx2
import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Streamable-http requires both content types in Accept; a bare request -> 406.
_STREAMABLE_HTTP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

# Default streamable-http mount path of FastMCP's ``http_app()``.
_MCP_PATH = "/mcp"
_BASE_URL = "http://auth-harness.test"

# A minimal but valid MCP ``initialize`` request: the mandatory first request of the
# protocol, and a complete exercise of the auth middleware + transport path.
_INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "auth-http-harness", "version": "1.0"},
    },
}

# Obviously-synthetic shared secret used only by the bearer-mode tests below.
_GOOD_TOKEN = "phase1-test-secret"  # noqa: S105 -- test-only value, not a credential

# Env vars this harness owns; cleared before each app so tests stay isolated.
_OWNED_ENV = (
    "MCP_AUTH_MODE",
    "MCP_BEARER_TOKEN",
    "FASTMCP_TRANSPORT",
    "UNIFI_API_KEY",
    "UNIFI_TOOL_MODE",
)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _server_app(monkeypatch, *, auth_mode, env=None):
    """Reuse the immutable catalog and rebuild the real HTTP/auth configuration.

    Transport configuration is lazy. Re-importing all tool definitions for each
    request needlessly rebuilds their schemas; resetting the transport exercises
    the same production wiring with the catalog already registered by the server.
    Each context restores the mutable auth/cache/instruction bindings.
    """
    for var in _OWNED_ENV:
        monkeypatch.delenv(var, raising=False)
    # A non-empty API key keeps ``Settings()`` happy during lifespan startup.
    monkeypatch.setenv("UNIFI_API_KEY", "sk-auth-http-harness")
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_AUTH_MODE", auth_mode)
    # These tests initialize MCP and inspect auth/metadata, never discovery tools.
    # Full mode avoids rebuilding the discovery index and AST write audit for
    # every context; discovery behavior has its own dedicated tests.
    monkeypatch.setenv("UNIFI_TOOL_MODE", "full")
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)

    import unifi_fabric.server as srv

    monkeypatch.setattr(srv, "_mcp_transport", None)
    monkeypatch.setattr(srv, "_cache_ttl", None)
    monkeypatch.setattr(srv.mcp, "auth", None)
    monkeypatch.setattr(srv.mcp, "instructions", srv.mcp.instructions)
    monkeypatch.setattr(srv.mcp._mcp_server, "cache_hints", {})  # noqa: SLF001
    return srv.mcp.http_app()


@pytest.fixture
def auth_http_client(monkeypatch):
    """Factory fixture -> async client bound to the server's streamable-http app.

    Usage::

        async with auth_http_client("bearer", env={"MCP_BEARER_TOKEN": tok}) as client:
            resp = await post_initialize(client, authorization=f"Bearer {tok}")

    The app's lifespan is entered for the duration of the context so the
    streamable-http session manager is running; nothing touches a real socket
    (``httpx.ASGITransport`` calls the app directly). Later phases reuse this factory
    by passing a different ``auth_mode`` and the matching descriptor env.
    """

    @contextlib.asynccontextmanager
    async def _make(
        auth_mode: str,
        *,
        env: Mapping[str, str] | None = None,
        jwks: dict | None = None,
    ) -> AsyncIterator[httpx.AsyncClient]:
        from unifi_fabric import server
        from unifi_fabric.transport_security import capped_jwks_client

        unexpected_requests = []

        def serve_jwks(request):
            if jwks is None or str(request.url) != (env or {}).get("MCP_OAUTH_JWKS_URI"):
                unexpected_requests.append("unexpected JWKS request")
                raise AssertionError(unexpected_requests[-1])
            return httpx2.Response(200, json=jwks)

        async def reject_network(self, request):
            unexpected_requests.append("auth HTTP tests must use ASGI/Mock transports")
            raise AssertionError(unexpected_requests[-1])

        # Explicit transports bypass HTTPX's network transports. Guard both HTTPX
        # versions so new startup/auth I/O fails locally instead of retrying DNS.
        with monkeypatch.context() as mp:
            mp.setattr(httpx.AsyncHTTPTransport, "handle_async_request", reject_network)
            mp.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", reject_network)
            async with capped_jwks_client(inner=httpx2.MockTransport(serve_jwks)) as idp:
                mp.setattr(server, "capped_jwks_client", lambda: idp)
                app = _server_app(mp, auth_mode=auth_mode, env=env)
                async with app.router.lifespan_context(app):
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(
                        transport=transport, base_url=_BASE_URL, follow_redirects=True
                    ) as client:
                        yield client
            # Verifiers can translate transport failures into 401s. Such a caught
            # failure must still fail the test, including expected-rejection cases.
            assert not unexpected_requests

    return _make


async def post_initialize(
    client: httpx.AsyncClient, *, authorization: str | None = None
) -> httpx.Response:
    """POST the MCP ``initialize`` request with the required streamable-http headers.

    ``authorization`` is attached verbatim when provided (including a bare ``"Bearer "``
    with an empty value) so reject-path cases can assert on the exact header shape.
    """
    headers = dict(_STREAMABLE_HTTP_HEADERS)
    if authorization is not None:
        headers["Authorization"] = authorization
    return await client.post(_MCP_PATH, json=_INITIALIZE_REQUEST, headers=headers)


# ---------------------------------------------------------------------------
# auth_mode = none
# ---------------------------------------------------------------------------


class TestAuthModeNone:
    """``MCP_AUTH_MODE=none``: the live request path carries no auth gate."""

    async def test_initialize_succeeds_without_authorization(self, auth_http_client):
        async with auth_http_client("none") as client:
            resp = await post_initialize(client)
        assert resp.status_code == 200

    async def test_initialize_succeeds_with_stray_authorization(self, auth_http_client):
        # No verifier is mounted in none mode, so an unsolicited header is ignored
        # rather than rejected.
        async with auth_http_client("none") as client:
            resp = await post_initialize(client, authorization="Bearer ignored-by-none")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# auth_mode = bearer
# ---------------------------------------------------------------------------


class TestAuthModeBearer:
    """``MCP_AUTH_MODE=bearer`` + ``MCP_BEARER_TOKEN``: live 200/401 request path."""

    async def test_valid_token_accepted(self, auth_http_client):
        async with auth_http_client("bearer", env={"MCP_BEARER_TOKEN": _GOOD_TOKEN}) as client:
            resp = await post_initialize(client, authorization=f"Bearer {_GOOD_TOKEN}")
        assert resp.status_code == 200

    @pytest.mark.parametrize(
        "authorization",
        [
            pytest.param(None, id="missing-header"),
            pytest.param("Bearer not-the-token", id="wrong-token"),
            pytest.param("Bearer ", id="empty-token"),
        ],
    )
    async def test_invalid_token_rejected(self, auth_http_client, authorization):
        # Security-load-bearing: every non-matching credential must be rejected with
        # 401 at the transport boundary, before any MCP method is dispatched.
        async with auth_http_client("bearer", env={"MCP_BEARER_TOKEN": _GOOD_TOKEN}) as client:
            resp = await post_initialize(client, authorization=authorization)
        assert resp.status_code == 401


async def test_auth_context_restores_shared_catalog_state(auth_http_client):
    from unifi_fabric import server

    catalog = server.mcp
    original = (catalog.auth, server._mcp_transport, server._cache_ttl, catalog.instructions)
    async with auth_http_client("bearer", env={"MCP_BEARER_TOKEN": _GOOD_TOKEN}) as client:
        assert server.mcp is catalog
        assert (await post_initialize(client)).status_code == 401
    assert (
        catalog.auth,
        server._mcp_transport,
        server._cache_ttl,
        catalog.instructions,
    ) == original
    async with auth_http_client("none") as client:
        assert server.mcp is catalog
        assert (await post_initialize(client)).status_code == 200
    assert (
        catalog.auth,
        server._mcp_transport,
        server._cache_ttl,
        catalog.instructions,
    ) == original


@pytest.mark.parametrize("http_module", [httpx, httpx2], ids=["httpx", "httpx2"])
async def test_auth_context_reports_caught_network_attempt(auth_http_client, http_module):
    # Even a verifier that converts a transport exception into 401 cannot hide
    # unintended external I/O from this fixture's independent context-exit check.
    with pytest.raises(AssertionError, match="ASGI/Mock transports"):
        async with auth_http_client("none"):
            async with http_module.AsyncClient() as external:
                with pytest.raises(AssertionError, match="ASGI/Mock transports"):
                    await external.get("https://must-not-resolve.test/")
