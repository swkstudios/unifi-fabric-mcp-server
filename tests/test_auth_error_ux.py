"""Synthetic regression coverage for startup and upstream authentication errors."""

from __future__ import annotations

import subprocess
import sys
from urllib.parse import urlsplit

import httpx
import pytest
import respx

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings

# Assert diagnostics after process completion, independent of runner startup speed.


def _hostnames(text: str) -> set[str]:
    """Exact hostnames of the https URLs among the whitespace-separated tokens of ``text``."""
    parts = (urlsplit(token) for token in text.split())
    return {p.hostname for p in parts if p.scheme == "https" and p.hostname}


@pytest.mark.parametrize("entrypoint", ["module", "console"])
def test_missing_api_key_exits_with_one_actionable_line(entrypoint):
    command = (
        [sys.executable, "-m", "unifi_fabric.server"]
        if entrypoint == "module"
        else [sys.executable.rsplit("/", 1)[0] + "/unifi-fabric-mcp"]
    )
    result = subprocess.run(  # noqa: S603 -- fixed module, isolated synthetic environment
        command,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "src"},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert len(result.stderr.strip().splitlines()) == 1
    assert "UNIFI_API_KEY is not set" in result.stderr
    assert _hostnames(result.stderr) >= {"unifi.ui.com"}
    assert "README#1-join-your-fabric-and-create-an-api-key" in result.stderr


MALFORMED_KEYS = {
    "non-ascii key": ({"UNIFI_API_KEY": "synth\u00e9tic-key"}, "UNIFI_API_KEY", "non-ASCII"),
    "whitespace key": ({"UNIFI_API_KEY": "synthetic key"}, "UNIFI_API_KEY", "whitespace"),
    "keys not json": ({"UNIFI_API_KEYS": "notjson-synthetic"}, "UNIFI_API_KEYS", "not valid JSON"),
    "keys an object": ({"UNIFI_API_KEYS": '{"key": "synthetic-obj"}'}, "UNIFI_API_KEYS", "list"),
    "keys a string": ({"UNIFI_API_KEYS": '"synthetic-str"'}, "UNIFI_API_KEYS", "list"),
    "entry not object": ({"UNIFI_API_KEYS": "[12345]"}, "UNIFI_API_KEYS", "entry 0"),
    "entry no key": ({"UNIFI_API_KEYS": '[{"label": "synthetic-label"}]'}, "UNIFI_API_KEYS", "key"),
    "entry bad key": (
        {"UNIFI_API_KEYS": '[{"key": "synth\u00e9tic-entry", "label": "a"}]'},
        "UNIFI_API_KEYS",
        "non-ASCII",
    ),
}


@pytest.mark.parametrize("entrypoint", ["module", "console"])
@pytest.mark.parametrize("case", sorted(MALFORMED_KEYS))
def test_malformed_api_key_exits_with_one_actionable_line(entrypoint, case):
    env_extra, variable, reason = MALFORMED_KEYS[case]
    command = (
        [sys.executable, "-m", "unifi_fabric.server"]
        if entrypoint == "module"
        else [sys.executable.rsplit("/", 1)[0] + "/unifi-fabric-mcp"]
    )
    result = subprocess.run(  # noqa: S603 -- fixed module, isolated synthetic environment
        command,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "src", **env_extra},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    lines = result.stderr.strip().splitlines()
    assert len(lines) == 1, result.stderr
    assert variable in lines[0]
    assert reason in lines[0]
    assert "See docs/CONFIGURATION.md" in lines[0]
    # No part of the value is echoed: every synthetic value contains "synth".
    assert "synth" not in result.stderr


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("multi", [False, True])
@respx.mock
async def test_upstream_auth_body_retained_and_hint_appended(status, multi):
    keys = [
        APIKeyConfig(key="synthetic-first", label="first"),
        APIKeyConfig(key="synthetic-second", label="second"),
    ]
    settings = Settings(api_keys=keys) if multi else Settings(api_key="synthetic-only")
    client = UniFiClient(settings)
    body = '{"error":"upstream reason", "detail":"α and spaces unchanged"}\n'
    respx.get("https://api.ui.com/ea/hosts").mock(return_value=httpx.Response(status, text=body))
    try:
        with pytest.raises(UniFiConnectionError) as caught:
            await client.get("/ea/hosts", key=keys[1] if multi else None)
        text = str(caught.value)
        assert text.startswith(f"HTTP {status} from GET /ea/hosts: {body}")
        hint = text[len(f"HTTP {status} from GET /ea/hosts: {body}") :]
        assert ("UNIFI_API_KEYS" if multi else "UNIFI_API_KEY") in hint
        assert ("second" in hint) if multi else ("first" not in hint)
        assert _hostnames(hint) >= {"unifi.ui.com"}
        assert (
            "check the key's permissions, API scopes, and allowed sites"
            if status == 403
            else "check that the key is valid and has not expired or been revoked"
        ) in hint
    finally:
        await client.close()


@respx.mock
async def test_ucore_access_403_gets_no_generic_key_hint_but_a_plain_403_still_does():
    """InnerSpace refuses uCore routes to proxied requests (errors.ucore.access); the key is
    not the cause, so the key-permissions hint is skipped and the upstream body stays verbatim.
    The real body nests the code under ``error``; the flat form is kept as a second case."""
    client = UniFiClient(Settings(api_key="synthetic-only"))
    ucore = (
        '{"error":{"type":"access","code":"errors.ucore.access",'
        '"message":"Access denied for proxy","errors":[]}}'
    )
    flat = '{"errors.ucore.access":"Access denied for proxy"}'
    plain = '{"error":"forbidden"}'
    respx.get("https://api.ui.com/ea/ucore").mock(return_value=httpx.Response(403, text=ucore))
    respx.get("https://api.ui.com/ea/ucore-flat").mock(return_value=httpx.Response(403, text=flat))
    respx.get("https://api.ui.com/ea/hosts").mock(return_value=httpx.Response(403, text=plain))
    try:
        with pytest.raises(UniFiConnectionError) as ucore_err:
            await client.get("/ea/ucore")
        with pytest.raises(UniFiConnectionError) as flat_err:
            await client.get("/ea/ucore-flat")
        with pytest.raises(UniFiConnectionError) as plain_err:
            await client.get("/ea/hosts")
    finally:
        await client.close()
    assert str(ucore_err.value) == f"HTTP 403 from GET /ea/ucore: {ucore}"
    assert "Hint" not in str(ucore_err.value)
    assert ucore_err.value.status == 403
    assert str(flat_err.value) == f"HTTP 403 from GET /ea/ucore-flat: {flat}"
    assert "check the key's permissions, API scopes, and allowed sites" in str(plain_err.value)


@pytest.mark.parametrize(
    "issuer",
    [
        "https://idp.test",
        "https://idp.test/",
        "https://idp.test/realms/main",
        "https://IDP.test",
        "https://idp.test:443",
        "https://idp.test/realms/é",
        "https://idp.test/realms/%6dain",
    ],
)
async def test_oauth_discovery_and_verifier_preserve_configured_issuer(auth_http_client, issuer):
    env = {
        "MCP_OAUTH_ISSUER": issuer,
        "MCP_OAUTH_JWKS_URI": "https://idp.test/jwks",
        "MCP_OAUTH_AUDIENCE": "synthetic-audience",
        "MCP_OAUTH_BASE_URL": "https://mcp.test",
    }
    async with auth_http_client("oauth", env=env) as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert response.status_code == 200
        assert response.json()["authorization_servers"] == [issuer]
        from unifi_fabric.config import MCPTransportSettings
        from unifi_fabric.server import build_auth

        provider = build_auth(MCPTransportSettings())
        assert provider.token_verifier.issuer == issuer
        assert provider.token_verifier._validate_issuer(issuer)  # noqa: SLF001
        alternate = issuer[:-1] if issuer.endswith("/") else issuer + "/"
        assert not provider.token_verifier._validate_issuer(alternate)  # noqa: SLF001
