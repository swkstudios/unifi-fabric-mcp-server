"""3xx handling, empty/malformed settings, config error choices,
and every key's own failure in the all-failed fleet errors."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError
from pydantic import ValidationError
from pydantic_settings import SettingsError

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.audit import AuditSink, build_audit_sink
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import (
    AUDIT_LOG_FORMATS,
    LOG_LEVELS,
    APIKeyConfig,
    MCPTransportSettings,
    Settings,
)

BASE = "https://api.ui.com"
_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_REDIRECTS = (300, 301, 302, 303, 304, 307, 308)


# =========================================================================== 3xx
@pytest.fixture
def audit_client(tmp_path) -> tuple[UniFiClient, object]:
    log = tmp_path / "audit.log"
    return UniFiClient(Settings(api_key="sk-redirect-test", audit_log=str(log))), log


@pytest.mark.parametrize("status", _REDIRECTS)
@pytest.mark.parametrize("method", _METHODS)
@respx.mock
async def test_3xx_raises_with_status_and_location_and_is_not_followed(
    audit_client, method, status
):
    client, log = audit_client
    path = "/v1/sites/abc/networks/n1"
    target = respx.route(url=f"{BASE}/elsewhere").mock(return_value=httpx.Response(200, json={}))
    respx.route(method=method, url=f"{BASE}{path}").mock(
        return_value=httpx.Response(status, headers={"Location": f"{BASE}/elsewhere"})
    )
    call = getattr(client, method.lower())
    with pytest.raises(UniFiConnectionError) as exc:
        await call(path, json={"a": 1}) if method != "GET" else await call(path)
    msg = str(exc.value)
    assert f"HTTP {status} redirect from {method} {path}" in msg
    assert f"to {BASE}/elsewhere" in msg
    assert "UNIFI_API_BASE_URL" in msg
    assert not target.called, "a redirect was followed"
    if method != "GET":
        assert "the write was not re-sent" in msg
        assert f"outcome=http_{status}" in log.read_text()
        assert "outcome=success" not in log.read_text()


@respx.mock
async def test_3xx_without_location_says_so(audit_client):
    client, _log = audit_client
    respx.get(f"{BASE}/v1/hosts").mock(return_value=httpx.Response(302))
    with pytest.raises(UniFiConnectionError, match=r"to \(no Location header\)"):
        await client.get("/v1/hosts")


@respx.mock
async def test_3xx_on_binary_get_raises(audit_client):
    client, _log = audit_client
    respx.get(f"{BASE}/img").mock(return_value=httpx.Response(307, headers={"Location": "/x"}))
    with pytest.raises(UniFiConnectionError, match="HTTP 307 redirect"):
        await client.get_binary("/img")


@respx.mock
async def test_3xx_returned_as_is_when_the_caller_inspects_status(audit_client):
    client, _log = audit_client
    respx.get(f"{BASE}/v1/hosts").mock(return_value=httpx.Response(301, headers={"Location": "/y"}))
    resp = await client.request("GET", "/v1/hosts", raise_on_error=False)
    assert resp.status_code == 301


async def test_client_never_follows_redirects():
    client = UniFiClient(Settings(api_key="sk-x-1234"))
    http = await client._get_client(APIKeyConfig(key="sk-x-1234"))
    assert http.follow_redirects is False
    await client.close()


# =========================================================================== settings
def _settings_env_names() -> list[tuple[str, str]]:
    names = []
    for field, info in Settings.model_fields.items():
        alias = info.validation_alias
        names.append((alias if isinstance(alias, str) else f"UNIFI_{field.upper()}", field))
    return names


def _transport_env_names() -> list[str]:
    names = []
    for field, info in MCPTransportSettings.model_fields.items():
        alias = info.validation_alias
        names.append(alias if isinstance(alias, str) else f"MCP_{field.upper()}")
    return names


@pytest.mark.parametrize("blank", ["", "   ", "\t\n "])
@pytest.mark.parametrize("env,field", _settings_env_names())
def test_every_unifi_setting_blank_means_unset(monkeypatch, env, field, blank):
    monkeypatch.setenv(env, blank)
    assert getattr(Settings(), field) == _defaults(Settings)[field]


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("env", _transport_env_names())
def test_every_mcp_setting_blank_means_unset(monkeypatch, env, blank):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "stdio")
    monkeypatch.setenv(env, blank)
    s = MCPTransportSettings()
    assert s.auth_mode == "none" and s.tls_mode == "none" and s.cache_ttl == 300
    assert s.bearer_token == "" and s.oauth_required_scopes == []


def _defaults(cls) -> dict:
    return {
        name: (info.default_factory() if info.default_factory else info.default)
        for name, info in cls.model_fields.items()
    }


@pytest.mark.parametrize(
    "value",
    ["[{bad", "not json", "[{'key': 'k', 'label': 'a'}]", '[{"key": "k"}'],
)
def test_malformed_api_keys_names_variable_and_format(monkeypatch, value):
    monkeypatch.setenv("UNIFI_API_KEYS", value)
    with pytest.raises(SettingsError) as exc:
        Settings()
    msg = str(exc.value)
    assert "UNIFI_API_KEYS" in msg and "a JSON list of" in msg and '"key"' in msg


@pytest.mark.parametrize(
    "value,kind",
    [('{"key": "k"}', "object"), ('"k"', "string"), ("5", "number"), ('["k"]', "string")],
)
def test_wrong_shape_api_keys_names_variable_and_format(monkeypatch, value, kind):
    monkeypatch.setenv("UNIFI_API_KEYS", value)
    with pytest.raises(ValidationError) as exc:
        Settings()
    msg = str(exc.value)
    assert "UNIFI_API_KEYS" in msg and "a JSON list of" in msg and f"JSON {kind}" in msg


def test_api_keys_entry_without_string_key_is_named(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEYS", '[{"label": "a"}]')
    with pytest.raises(ValidationError, match=r'UNIFI_API_KEYS entry 0 needs a string "key"'):
        Settings()


@pytest.mark.parametrize("value", ["ftp://x", "api.ui.com", "https://", "nonsense"])
def test_malformed_base_url_names_variable_and_format(monkeypatch, value):
    monkeypatch.setenv("UNIFI_API_BASE_URL", value)
    with pytest.raises(ValidationError, match="UNIFI_API_BASE_URL must be an absolute http"):
        Settings()


def test_api_key_config_ignores_bare_env(monkeypatch):
    """APIKeyConfig is built from UNIFI_API_KEYS only, never bare KEY/LABEL env vars."""
    monkeypatch.setenv("LABEL", "from-env")
    monkeypatch.setenv("IS_ORG_KEY", "true")
    cfg = APIKeyConfig(key="sk-abc-123")
    assert cfg.label == "default" and cfg.is_org_key is False


# =========================================================================== choices
_BOOL_ENVS = (
    "UNIFI_ENABLE_CONNECTOR_WRITE",
    "UNIFI_REDACT_SECRETS",
    "UNIFI_DRY_RUN",
    "UNIFI_READ_ONLY",
    "UNIFI_PROTECT_MUTATIONS_ENABLED",
    "UNIFI_ENABLE_MOBILITY_WRITE",
    "UNIFI_ENABLE_CARRIER_FABRIC_WRITE",
    "UNIFI_ENABLE_INNERSPACE_WRITE",
)


@pytest.mark.parametrize("env", _BOOL_ENVS)
def test_invalid_bool_names_variable_and_accepted_values(monkeypatch, env):
    monkeypatch.setenv(env, "maybe")
    with pytest.raises(ValidationError) as exc:
        Settings()
    msg = str(exc.value)
    assert f"{env} must be a boolean" in msg
    for accepted in ("1", "true", "yes", "on", "0", "false", "no", "off"):
        assert accepted in msg


@pytest.mark.parametrize("env", _BOOL_ENVS)
@pytest.mark.parametrize("raw,expected", [("TRUE", True), (" on ", True), ("No", False)])
def test_valid_bool_spellings(monkeypatch, env, raw, expected):
    monkeypatch.setenv(env, raw)
    field = env.removeprefix("UNIFI_").lower()
    assert getattr(Settings(), field) is expected


def test_invalid_is_org_key_names_the_setting(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEYS", '[{"key": "sk-1", "is_org_key": "perhaps"}]')
    with pytest.raises(ValidationError, match="is_org_key must be a boolean: one of 1, true"):
        Settings()


def test_unknown_log_level_lists_levels(monkeypatch):
    monkeypatch.setenv("UNIFI_LOG_LEVEL", "VERBOSE")
    with pytest.raises(ValidationError) as exc:
        Settings()
    msg = str(exc.value)
    assert "UNIFI_LOG_LEVEL must be one of" in msg
    assert all(level in msg for level in LOG_LEVELS)


def test_log_level_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("UNIFI_LOG_LEVEL", "debug")
    assert Settings().log_level == "DEBUG"


def test_unknown_audit_log_format_fails_fast_listing_formats(monkeypatch):
    monkeypatch.setenv("UNIFI_AUDIT_LOG_FORMAT", "xml")
    with pytest.raises(ValidationError) as exc:
        Settings()
    msg = str(exc.value)
    assert "UNIFI_AUDIT_LOG_FORMAT must be one of" in msg
    assert all(fmt in msg for fmt in AUDIT_LOG_FORMATS)


def test_audit_sink_never_falls_back(tmp_path):
    s = Settings.model_construct(**{**_defaults(Settings), "audit_log": str(tmp_path / "a")})
    s.audit_log_format = "xml"
    with pytest.raises(ValueError, match="UNIFI_AUDIT_LOG_FORMAT must be one of text, json"):
        build_audit_sink(s)
    with pytest.raises(ValueError, match="must be one of"):
        AuditSink(path=str(tmp_path / "a"), fmt="yaml")


def test_audit_log_format_is_case_insensitive(monkeypatch, tmp_path):
    monkeypatch.setenv("UNIFI_AUDIT_LOG", str(tmp_path / "a.log"))
    monkeypatch.setenv("UNIFI_AUDIT_LOG_FORMAT", "JSON")
    sink = build_audit_sink(Settings())
    assert sink is not None and sink.fmt == "json"


# =========================================================================== fleet errors
def _two_key_hosts() -> dict[str, list[dict]]:
    beta = json.loads(json.dumps(uh.HOST_RECORD))
    beta["id"] = "0" * 54 + "FB0002:0000000002"
    beta["reportedState"] = dict(beta["reportedState"], hostname="beta-console", name="beta")
    return {"k-alpha": [uh.HOST_RECORD], "k-beta": [beta]}


_KEYS = [APIKeyConfig(key="k-alpha", label="alpha"), APIKeyConfig(key="k-beta", label="beta")]


async def test_list_all_clients_all_failed_names_each_keys_own_failure(monkeypatch):
    """Key alpha cannot list its sites; key beta's sites all fail on their client list.
    The error carries alpha's own failure, not only beta's site errors."""
    up = uh.FakeUpstream(
        hosts_by_key=_two_key_hosts(),
        failing_keys=frozenset({"k-alpha"}),
        fail_paths=("/clients",),
    )
    uh.install(monkeypatch, up, keys=_KEYS)
    with pytest.raises(ToolError) as exc:
        await server.mcp.call_tool("list_all_clients", {})
    msg = str(exc.value)
    assert "alpha: " in msg and "lacks scope" in msg, msg
    assert "probe failure on" in msg and "/clients" in msg, msg
    assert "1 API key(s) failed" in msg, msg
