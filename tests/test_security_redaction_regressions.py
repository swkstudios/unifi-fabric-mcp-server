"""Offline regressions for the final 0.7.0 security findings."""

import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.test_access_log import exercise
from unifi_fabric import secret_scrub
from unifi_fabric.client import UniFiClient, UniFiConnectionError, upstream_error_text
from unifi_fabric.config import Settings
from unifi_fabric.families.connector.connector import connector_write
from unifi_fabric.families.network import (
    network_controller_insights,
    network_device_operations,
    network_proav_sandbox,
    network_security_diagnostics,
)
from unifi_fabric.families.protect import protect_private
from unifi_fabric.families.site_manager import aggregation, site_manager
from unifi_fabric.read_only import ReadOnlyModeError
from unifi_fabric.redaction import REDACTION_MASK, install_response_redaction, write_redaction_scope

SECRET = "synthetic-upstream-only-credential"
BODY = {"password": SECRET, "reason": "synthetic failure", "id": "synthetic-id"}


def assert_policy(value, enabled):
    text = str(value)
    assert (SECRET not in text) if enabled else (SECRET in text)
    if enabled:
        assert REDACTION_MASK in text
    assert "synthetic failure" in text


@pytest.mark.parametrize("enabled", [False, True])
async def test_failed_protect_collection_uses_shared_error_policy(monkeypatch, enabled):
    client = SimpleNamespace(_settings=SimpleNamespace(redact_secrets=enabled))
    monkeypatch.setattr(
        protect_private.connector,
        "connector_get",
        AsyncMock(return_value={"status": 503, "body": BODY}),
    )
    with pytest.raises(UniFiConnectionError) as caught:
        await protect_private._resolve(client, AsyncMock(), "synthetic-host", "cameras", "Camera")
    assert_policy(caught.value, enabled)
    assert "HTTP 503" in str(caught.value)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("prefixed", [False, True])
@pytest.mark.parametrize("site", ["compare", "search", "topology"])
async def test_partial_errors_follow_redaction_policy(monkeypatch, enabled, site, prefixed):
    client = SimpleNamespace(
        _settings=SimpleNamespace(redact_secrets=enabled),
        list_key_labels=lambda: ["synthetic"],
        gather=lambda tasks: asyncio.gather(*tasks),
    )
    message = json.dumps(BODY)
    if prefixed:
        message = "GET /synthetic: HTTP 503: " + message + "; verify with a read"
    failure = UniFiConnectionError(message)
    registry = AsyncMock()
    if site == "compare":
        monkeypatch.setattr(
            site_manager, "get_site_health_summary", AsyncMock(side_effect=[failure, {"ok": True}])
        )
        result = await site_manager.compare_site_performance(client, registry, ["Bad", "Good"])
    elif site == "search":
        registry.get_ea_sites.return_value = [{"hostId": "synthetic-host", "siteId": "site"}]
        monkeypatch.setattr(
            site_manager,
            "_proxy_site_for_ea",
            AsyncMock(return_value={"id": "00000000-0000-4000-8000-000000000001"}),
        )
        monkeypatch.setattr(
            site_manager,
            "collect_offset",
            AsyncMock(side_effect=[failure, {"items": [], "incomplete": False}]),
        )
        result = await site_manager.search_across_sites(client, registry, "")
    else:
        monkeypatch.setattr(
            network_security_diagnostics,
            "_site",
            AsyncMock(return_value=(None, "synthetic-host", "default")),
        )
        client.get = AsyncMock(side_effect=[failure, [], {}])
        result = await network_security_diagnostics.get_unified_ip_thread_topology(
            client, registry, "synthetic-host", "default"
        )
    assert_policy(result, enabled)
    if prefixed:
        assert "GET /synthetic: HTTP 503:" in str(result)
        assert "; verify with a read" in str(result)


@pytest.mark.parametrize("enabled", [False, True])
async def test_direct_dry_run_always_scrubs_configured_key(enabled, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    own_key = "synthetic-configured-dry-run-key"
    client = UniFiClient(Settings(api_key=own_key, redact_secrets=enabled))
    try:
        response = await client.request(
            "POST",
            "/v1/synthetic/" + own_key,
            json={"note": own_key, "password": SECRET},
            params={"note": own_key},
        )
        result = response.json()
        assert own_key not in response.text
        assert result["status"] == "dry_run" and result["sent"] is False
        assert result["preview"]["body"]["note"] == "***"
        assert result["preview"]["body"]["password"] == (REDACTION_MASK if enabled else SECRET)
    finally:
        await client.close()


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("enabled", [False, True])
async def test_refused_relay_audit_omits_query_and_fragment(monkeypatch, tmp_path, fmt, enabled):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    log = tmp_path / "audit.log"
    client = UniFiClient(
        Settings(
            api_key="synthetic-key",
            audit_log=str(log),
            audit_log_format=fmt,
            redact_secrets=enabled,
        )
    )
    get_client = AsyncMock()
    monkeypatch.setattr(client, "_get_client", get_client)
    try:
        with pytest.raises(ReadOnlyModeError):
            await connector_write(
                client,
                AsyncMock(),
                "synthetic-host",
                "POST",
                "/invalid/path?unknown=" + SECRET + "#synthetic-fragment",
            )
        text = log.read_text()
        assert SECRET not in text and "synthetic-fragment" not in text and "?" not in text
        assert "/invalid/path" in text and "refused" in text
        get_client.assert_not_called()
    finally:
        await client.close()


@pytest.mark.parametrize("components", [None, {}])
def test_redaction_install_fails_closed_when_enabled(components):
    mcp = (
        SimpleNamespace()
        if components is None
        else SimpleNamespace(_local_provider=SimpleNamespace(_components=components))
    )
    with pytest.raises(RuntimeError, match="UNIFI_REDACT_SECRETS"):
        install_response_redaction(mcp, lambda: True)
    assert install_response_redaction(mcp, lambda: False) == 0


async def test_access_log_omits_bare_and_named_query_tokens(caplog):
    caplog.set_level(logging.INFO, logger="unifi_fabric.access")
    called, messages = await exercise(("/mcp?" + SECRET + "&token=" + SECRET).encode())
    assert called and messages[0]["status"] == 404
    assert SECRET not in caplog.text
    assert "/mcp" in caplog.text


@pytest.mark.parametrize("site", ["device", "proav", "insights"])
async def test_classic_fallback_uses_shared_redaction_scope(monkeypatch, site):
    body = {"meta": {"rc": "error"}, "data": BODY}
    response = httpx.Response(200, json=body)
    client = SimpleNamespace(request=AsyncMock(return_value=response))
    with write_redaction_scope(True), pytest.raises(UniFiConnectionError) as caught:
        if site == "device":
            network_device_operations._classic_ok(client, response, "GET", "/synthetic")
        elif site == "proav":
            monkeypatch.setattr(
                network_proav_sandbox, "_site", AsyncMock(return_value=(None, "host", "default"))
            )
            await network_proav_sandbox.get_port_forward_statistics(
                client, AsyncMock(), "host", "default"
            )
        else:
            await network_controller_insights._classic_get(client, "/synthetic", key=None)
    assert_policy(caught.value, True)


def test_growing_call_scope_reuses_each_secret_forms(monkeypatch):
    builds = []
    original = secret_scrub._base_forms

    def build(value):
        builds.append(value)
        return original(value)

    monkeypatch.setattr(secret_scrub, "_base_forms", build)
    values = [f"synthetic-scope-credential-{index}" for index in range(6)]
    with secret_scrub.secret_scope():
        for value in values:
            secret_scrub.add_call_secrets([value])
            assert value in secret_scrub._forms(secret_scrub.call_secret_values())
        assert builds == values
    # A new call must construct its own forms rather than retain caller credentials globally.
    with secret_scrub.secret_scope(values[:1]):
        secret_scrub._forms(secret_scrub.call_secret_values())
    assert builds == [*values, values[0]]


@pytest.mark.parametrize("enabled", [False, True])
def test_documented_error_body_policy(enabled):
    client = SimpleNamespace(_settings=SimpleNamespace(redact_secrets=enabled))
    assert_policy(upstream_error_text(BODY, client), enabled)


@pytest.mark.parametrize("enabled", [False, True])
def test_exception_error_policy_preserves_context_and_malformed_text(enabled):
    client = SimpleNamespace(_settings=SimpleNamespace(redact_secrets=enabled))
    prefix = "GET /synthetic/{invalid}: HTTP 503: "
    suffix = "; verify [with a read]"
    result = upstream_error_text(UniFiConnectionError(prefix + json.dumps(BODY) + suffix), client)
    assert result.startswith(prefix) and result.endswith(suffix)
    assert_policy(result, enabled)
    assert (
        upstream_error_text(UniFiConnectionError("plain [text] {not json}"), client)
        == "plain [text] {not json}"
    )


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("prefix", ["", "it's", 'a"b'])
@pytest.mark.parametrize(
    "case",
    [
        "host_object",
        "host_json",
        "hostname_object",
        "hostname_json",
        "site_object",
        "site_json",
        "description_object",
        "description_json",
    ],
)
async def test_fleet_failure_redacts_upstream_fields(enabled, case, prefix):
    client = UniFiClient(Settings(api_key="synthetic-key", redact_secrets=enabled))
    registry = SimpleNamespace(_client=client)
    body = {**BODY, "password": prefix + SECRET}
    value = json.dumps(body) if case.endswith("_json") else body
    host = value if case.startswith("host_") else "valid-host"
    hostname = value if case.startswith("hostname_") else "console"
    site_id = value if case.startswith("site_") else "00000000-0000-4000-8000-000000000001"
    description = value if case.startswith("description_") else "site"
    registry.get_ea_sites = AsyncMock(return_value=[{"hostId": host, "hostname": hostname}])
    registry.get_hosts = AsyncMock(return_value=[])
    registry.get_sites = AsyncMock(return_value=[{"id": site_id, "description": description}])
    if case.startswith("hostname_"):
        registry.get_sites.side_effect = RuntimeError("synthetic failure")
    client.get = AsyncMock(side_effect=RuntimeError("synthetic failure"))
    try:
        with pytest.raises(RuntimeError) as caught:
            await aggregation._list_all_clients_fleet(client, registry)
        assert_policy(caught.value, enabled)
    finally:
        await client.close()


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("prefix", ["", "it's", 'a"b'])
async def test_search_invalid_json_host_redacts_reason(enabled, prefix):
    client = UniFiClient(Settings(api_key="synthetic-key", redact_secrets=enabled))
    registry = SimpleNamespace(
        get_ea_sites=AsyncMock(
            return_value=[
                {"hostId": json.dumps({**BODY, "password": prefix + SECRET}), "siteId": "site"}
            ]
        )
    )
    try:
        with pytest.raises(RuntimeError) as caught:
            await site_manager.search_across_sites(client, registry, "")
        assert_policy(caught.value, enabled)
    finally:
        await client.close()


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("prefix", ["", "it's", 'a"b'])
@pytest.mark.parametrize("partial", [False, True])
async def test_search_json_site_id_redacts_before_repr(enabled, prefix, partial):
    from unifi_fabric.registry import FetchedRecords

    client = UniFiClient(Settings(api_key="synthetic-key", redact_secrets=enabled))
    site_id = json.dumps({**BODY, "password": prefix + SECRET})
    registry = SimpleNamespace(
        get_ea_sites=AsyncMock(
            return_value=[{"hostId": "valid-host", "siteId": site_id, "meta": {"name": "ea"}}]
        ),
        resolve_key_for_host=AsyncMock(return_value=None),
        get_sites=AsyncMock(
            return_value=FetchedRecords(
                [{"id": "00000000-0000-4000-8000-000000000001", "description": "ea"}]
                if partial
                else [],
                incomplete_reason="synthetic partial" if partial else None,
            )
        ),
    )
    try:
        with pytest.raises(RuntimeError) as caught:
            await site_manager.search_across_sites(client, registry, "")
        assert_policy(caught.value, enabled)
    finally:
        await client.close()
