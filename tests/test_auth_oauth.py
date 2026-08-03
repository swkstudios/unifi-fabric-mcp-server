"""OAuth 2.1 resource-server request-path tests — Phase 2 of the auth/transport/TLS matrix.

Where Phase 1 (``test_auth_http.py``) proved bearer auth on the *live* streamable-http
request path, this module does the same for ``MCP_AUTH_MODE=oauth``: it drives real MCP
``initialize`` requests through the server's in-process ASGI app and asserts on the HTTP
auth status the transport actually returns (200 accepted vs 401 rejected).

Design notes:

* Tokens are signed with FastMCP's bundled ``RSAKeyPair`` — the same JWT stack the
  ``JWTVerifier`` validates against (``joserfc``). No second JWT library (e.g. PyJWT) is
  introduced, so there is exactly one signing/verifying implementation under test.
* The production ``build_auth`` wires a **JWKS-URI** verifier (the resource server fetches
  the IdP's public keys), so the IdP JWKS endpoint is stubbed with ``respx``. The stub is
  configured with ``assert_all_mocked=False`` so the in-process ``/mcp`` requests pass
  straight through to the ASGI app, and ``assert_all_called=False`` so reject paths that
  401 *before* any JWKS fetch happens do not trip respx's call assertion.
* The harness (``auth_http_client`` factory + ``post_initialize``) is reused verbatim from
  Phase 1, imported below.

All IdP coordinates are obviously-synthetic ``.test`` hostnames; nothing here is a real
credential, endpoint, or secret.
"""

from __future__ import annotations

import pytest
import respx
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from joserfc.jwk import RSAKey

# ``auth_http_client`` is provided suite-wide via tests/conftest.py (Phase 1 harness).
from tests.test_auth_http import post_initialize

# ---------------------------------------------------------------------------
# Synthetic IdP / resource-server descriptor
# ---------------------------------------------------------------------------

_ISSUER = "https://idp.test/realms/unifi"
_JWKS_URI = "https://idp.test/realms/unifi/protocol/openid-connect/certs"
_AUDIENCE = "unifi-fabric-mcp"
_RESOURCE_BASE_URL = "https://mcp.example.test"
_REQUIRED_SCOPE = "fabric:read"

# FastMCP mounts the streamable-http app at ``/mcp``; the RFC 9728 protected-resource
# metadata is therefore published at the *path-aware* well-known URI
# ``/.well-known/oauth-protected-resource/mcp`` — NOT the bare well-known path. This
# is the FastMCP #1348 behaviour, pinned empirically by the discovery tests below.
_MCP_PATH = "/mcp"
_DISCOVERY_PATH = "/.well-known/oauth-protected-resource/mcp"
_BARE_DISCOVERY_PATH = "/.well-known/oauth-protected-resource"

# One keypair signs every token in this module; its public half is served as the JWKS.
_KEYPAIR = RSAKeyPair.generate()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _oauth_env(**overrides: str) -> dict[str, str]:
    """The complete oauth resource-server descriptor env the Phase-0 validator requires."""
    env = {
        "MCP_OAUTH_ISSUER": _ISSUER,
        "MCP_OAUTH_JWKS_URI": _JWKS_URI,
        "MCP_OAUTH_AUDIENCE": _AUDIENCE,
        "MCP_OAUTH_BASE_URL": _RESOURCE_BASE_URL,
        "MCP_OAUTH_REQUIRED_SCOPES": _REQUIRED_SCOPE,
    }
    env.update(overrides)
    return env


def _jwks_document() -> dict:
    """JWKS advertising the test keypair's public key, built with FastMCP's own JWK stack."""
    return {"keys": [RSAKey.import_key(_KEYPAIR.public_key).as_dict()]}


def _bearer(
    *,
    issuer: str = _ISSUER,
    audience: str = _AUDIENCE,
    scopes: tuple[str, ...] = (_REQUIRED_SCOPE,),
    expires_in_seconds: int = 3600,
) -> str:
    """Sign a JWT with the module keypair and wrap it as an ``Authorization`` value."""
    token = _KEYPAIR.create_token(
        issuer=issuer,
        audience=audience,
        scopes=list(scopes),
        expires_in_seconds=expires_in_seconds,
    )
    return f"Bearer {token}"


async def _initialize_oauth(auth_http_client, authorization, *, env=None):
    """Drive an oauth-mode ``initialize`` through the real request path, JWKS stubbed.

    ``respx`` mocks only the IdP JWKS endpoint; ``assert_all_mocked=False`` lets the
    in-process ``/mcp`` POST pass through to the ASGI app, and ``assert_all_called=False``
    tolerates the reject cases that never reach the JWKS fetch.
    """
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as router:
        router.get(_JWKS_URI).respond(json=_jwks_document())
        async with auth_http_client("oauth", env=env or _oauth_env()) as client:
            return await post_initialize(client, authorization=authorization)


# ---------------------------------------------------------------------------
# Accept path
# ---------------------------------------------------------------------------


class TestOAuthAccept:
    """A valid signed JWT (good issuer / audience / expiry / scopes) is accepted."""

    async def test_valid_signed_jwt_accepted(self, auth_http_client):
        resp = await _initialize_oauth(auth_http_client, _bearer())
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Reject path (security-load-bearing)
# ---------------------------------------------------------------------------


class TestOAuthReject:
    """Every malformed or non-conforming credential is rejected with 401 at the boundary.

    Each case is asserted through the live request path so the 401 originates from the
    real auth middleware, not from a verifier called in isolation.
    """

    @pytest.mark.parametrize(
        "authorization",
        [
            pytest.param(None, id="missing-header"),
            pytest.param("Bearer ", id="empty-token"),
            pytest.param("Bearer not-a-valid-jwt", id="malformed-token"),
            pytest.param(_bearer(expires_in_seconds=-1), id="expired"),
            pytest.param(_bearer(audience="wrong-audience"), id="wrong-audience"),
            pytest.param(_bearer(issuer="https://evil.test/realms/x"), id="wrong-issuer"),
            pytest.param(_bearer(scopes=()), id="insufficient-scope"),
        ],
    )
    async def test_invalid_token_rejected(self, auth_http_client, authorization):
        resp = await _initialize_oauth(auth_http_client, authorization)
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Discovery — /.well-known/oauth-protected-resource (RFC 9728 / FastMCP #1348)
# ---------------------------------------------------------------------------


class TestOAuthDiscovery:
    """RemoteAuthProvider auto-serves the protected-resource metadata document."""

    async def test_protected_resource_metadata_published(self, auth_http_client):
        # No token needed: the discovery document is an unauthenticated GET.
        async with auth_http_client("oauth", env=_oauth_env()) as client:
            resp = await client.get(_DISCOVERY_PATH)
        assert resp.status_code == 200
        meta = resp.json()
        # The metadata names the upstream authorization server and this resource.
        servers = [s.rstrip("/") for s in meta["authorization_servers"]]
        assert _ISSUER in servers
        assert meta["resource"].rstrip("/") == f"{_RESOURCE_BASE_URL}{_MCP_PATH}"

    async def test_bare_well_known_path_not_served(self, auth_http_client):
        # Pin the FastMCP #1348 behaviour: the protected-resource metadata is path-scoped
        # to the /mcp mount, so the *bare* well-known path is not served. This guards the
        # discovery contract against a silent FastMCP change to the route shape.
        async with auth_http_client("oauth", env=_oauth_env()) as client:
            resp = await client.get(_BARE_DISCOVERY_PATH)
        assert resp.status_code == 404
