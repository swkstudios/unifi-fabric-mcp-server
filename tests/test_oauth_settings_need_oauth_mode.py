"""OAuth settings never start an unauthenticated server.

An OAuth resource-server setting (``MCP_OAUTH_*``) only takes effect with
``MCP_AUTH_MODE=oauth``. Set without it, the server would start with bearer or no
authentication while the operator believes OAuth guards it, so startup is refused with
an error naming the stray settings and the missing mode.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from unifi_fabric.config import MCPTransportSettings

DESCRIPTOR = {
    "MCP_OAUTH_ISSUER": "https://idp.example.com/",
    "MCP_OAUTH_JWKS_URI": "https://idp.example.com/jwks",
    "MCP_OAUTH_AUDIENCE": "mcp",
    "MCP_OAUTH_BASE_URL": "https://mcp.example.com",
}
OPTIONAL = {
    "MCP_OAUTH_REQUIRED_SCOPES": "unifi.read",
    "MCP_OAUTH_AUTHORIZATION_SERVERS": "https://idp.example.com/",
    "MCP_OAUTH_ALGORITHM": "ES256",
}
ALL_MCP = (
    *DESCRIPTOR,
    *OPTIONAL,
    "MCP_AUTH_MODE",
    "MCP_BEARER_TOKEN",
    "MCP_OAUTH_WRITE_SCOPE",
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    for env in ALL_MCP:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")


@pytest.mark.parametrize("env", sorted({**DESCRIPTOR, **OPTIONAL}))
@pytest.mark.parametrize("mode", [None, "none", "bearer"])
def test_an_oauth_setting_outside_oauth_mode_refuses_startup(monkeypatch, env, mode) -> None:
    monkeypatch.setenv(env, {**DESCRIPTOR, **OPTIONAL}[env])
    if mode is not None:
        monkeypatch.setenv("MCP_AUTH_MODE", mode)
    if mode == "bearer":
        monkeypatch.setenv("MCP_BEARER_TOKEN", "t" * 32)
    with pytest.raises((ValidationError, ValueError)) as exc:
        MCPTransportSettings()
    text = str(exc.value)
    assert env in text
    assert "MCP_AUTH_MODE=oauth" in text


def test_a_complete_descriptor_without_the_mode_refuses_startup(monkeypatch) -> None:
    for env, value in DESCRIPTOR.items():
        monkeypatch.setenv(env, value)
    with pytest.raises((ValidationError, ValueError)) as exc:
        MCPTransportSettings()
    assert all(env in str(exc.value) for env in DESCRIPTOR)


def test_a_complete_descriptor_with_the_mode_starts_with_oauth(monkeypatch) -> None:
    for env, value in {**DESCRIPTOR, **OPTIONAL}.items():
        monkeypatch.setenv(env, value)
    monkeypatch.setenv("MCP_AUTH_MODE", "oauth")
    assert MCPTransportSettings().auth_mode == "oauth"


def test_the_defaults_are_unchanged(monkeypatch) -> None:
    assert MCPTransportSettings().auth_mode == "none"
    monkeypatch.setenv("MCP_BEARER_TOKEN", "t" * 32)
    assert MCPTransportSettings().auth_mode == "bearer"
    # The default algorithm spelled out is not an OAuth setting of its own.
    monkeypatch.setenv("MCP_OAUTH_ALGORITHM", "RS256")
    assert MCPTransportSettings().auth_mode == "bearer"
