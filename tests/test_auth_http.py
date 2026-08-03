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
import importlib
from collections.abc import AsyncIterator, Mapping

import httpx
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

# Env vars this harness owns; cleared before each reload so tests stay isolated.
_OWNED_ENV = (
    "MCP_AUTH_MODE",
    "MCP_BEARER_TOKEN",
    "FASTMCP_TRANSPORT",
    "UNIFI_API_KEY",
)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _reload_server_app(monkeypatch, *, auth_mode, env=None):
    """Reload ``unifi_fabric.server`` under a given auth env and return its ASGI app.

    The server builds its ``FastMCP`` instance (and therefore its auth provider) at
    import time, so the module is reloaded after the environment is set. Auth applies
    to HTTP transports only, so the transport is pinned to ``streamable-http`` to
    satisfy the fail-closed stdio reconciliation in the config layer.
    """
    for var in _OWNED_ENV:
        monkeypatch.delenv(var, raising=False)
    # A non-empty API key keeps ``Settings()`` happy when the module re-imports.
    monkeypatch.setenv("UNIFI_API_KEY", "sk-auth-http-harness")
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_AUTH_MODE", auth_mode)
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)

    import unifi_fabric.server as srv

    importlib.reload(srv)
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
        auth_mode: str, *, env: Mapping[str, str] | None = None
    ) -> AsyncIterator[httpx.AsyncClient]:
        app = _reload_server_app(monkeypatch, auth_mode=auth_mode, env=env)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url=_BASE_URL, follow_redirects=True
            ) as client:
                yield client

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
