"""Contract tests for the code-first placement snapshot export command."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from unifi_fabric import placement_snapshot_cli as cli
from unifi_fabric.config import APIKeyConfig

_KEY_CANARY = "sk-cli-canary-0123456789"


@pytest.fixture
def _clean_key_env(monkeypatch):
    for name in ("UNIFI_API_KEY", "UNIFI_API_KEYS", "UNIFI_MAX_CONCURRENCY"):
        monkeypatch.delenv(name, raising=False)


def test_requires_explicit_host(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--host" in captured.err
    assert "invalid arguments" in captured.err


def test_emits_exactly_one_compact_json_value_to_stdout(monkeypatch, capsys):
    async def snapshot(host):
        assert host == "HQ-Unifi"
        return {"schema_version": "unifi.placement-snapshot/v1", "floors": []}

    monkeypatch.setattr(cli, "export_snapshot", snapshot)
    assert cli.main(["--host", "HQ-Unifi"]) == 0
    captured = capsys.readouterr()
    assert captured.out == '{"schema_version":"unifi.placement-snapshot/v1","floors":[]}\n'
    assert captured.err == ""


def test_operational_failure_is_actionable_and_scrubs_key_values(
    monkeypatch, capsys, _clean_key_env
):
    monkeypatch.setenv("UNIFI_API_KEY", _KEY_CANARY)

    async def broken(host):
        raise RuntimeError(f"HTTP 502 from GET /v1/hosts (key {_KEY_CANARY})")

    monkeypatch.setattr(cli, "export_snapshot", broken)
    assert cli.main(["--host", "HQ-Unifi"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "placement snapshot export failed: RuntimeError: HTTP 502 from GET /v1/hosts (key ***)\n"
    )
    assert _KEY_CANARY not in captured.err


@respx.mock
def test_unknown_host_lists_the_valid_choices(monkeypatch, capsys, _clean_key_env):
    monkeypatch.setenv("UNIFI_API_KEY", _KEY_CANARY)
    hosts = [
        {"id": "AA:BB:CC:00:00:01:111", "reportedState": {"hostname": "HQ-Unifi"}},
        {"id": "AA:BB:CC:00:00:02:222", "reportedState": {"hostname": "Branch-Unifi"}},
    ]
    respx.get("https://api.ui.com/v1/hosts").mock(
        return_value=Response(200, json={"data": hosts, "httpStatusCode": 200})
    )
    assert cli.main(["--host", "Nope"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("placement snapshot export failed: ValueError: unknown host")
    assert "HQ-Unifi" in captured.err and "Branch-Unifi" in captured.err
    assert _KEY_CANARY not in captured.err


def test_missing_key_names_the_env_vars(capsys, _clean_key_env):
    assert cli.main(["--host", "HQ-Unifi"]) == 1
    captured = capsys.readouterr()
    assert captured.err == (
        "placement snapshot export failed: placement snapshot export requires an API key: "
        'set UNIFI_API_KEY, or UNIFI_API_KEYS to a JSON list of {"key": ..., "label": ...} '
        "objects\n"
    )


def test_empty_key_is_named_by_label(monkeypatch, capsys, _clean_key_env):
    keys = [{"key": _KEY_CANARY, "label": "acme"}, {"key": " ", "label": "globex"}]
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    assert cli.preflight_main(["--host", "HQ-Unifi"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    # The settings validator (shared with the server) names the entry and its label.
    assert "UNIFI_API_KEYS entry 1 is whitespace-only" in captured.err
    assert "'acme'" not in captured.err
    assert _KEY_CANARY not in captured.err


def test_invalid_configuration_lists_the_setting_without_values(
    monkeypatch, capsys, _clean_key_env
):
    keys = [{"key": _KEY_CANARY, "label": "dup"}, {"key": "sk-other-secret", "label": "dup"}]
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    monkeypatch.setenv("UNIFI_MAX_CONCURRENCY", "0")
    assert cli.main(["--host", "HQ-Unifi"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("placement snapshot export failed: invalid configuration: ")
    assert "max_concurrency: Value error, UNIFI_MAX_CONCURRENCY must be >= 1" in err
    assert _KEY_CANARY not in err and "sk-other-secret" not in err


def test_keyboard_interrupt_reports_interrupted(monkeypatch, capsys, _clean_key_env):
    async def interrupted(host):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "export_snapshot", interrupted)
    assert cli.main(["--host", "HQ-Unifi"]) == 1
    assert capsys.readouterr().err == "placement snapshot export failed: interrupted\n"


async def test_export_runs_with_connector_writes_enabled(monkeypatch):
    """No write fence: the GET-only export runs on a default (writes-on) deployment."""

    class WriteEnabledSettings:
        cache_ttl_seconds = 1
        cache_max_hosts = 2
        cache_max_sites = 3

        def get_key_configs(self):
            return [APIKeyConfig(key="sk-test", label="default")]

    class Client:
        def __init__(self, settings):
            self.closed = False

        async def close(self):
            self.closed = True

    client = Client(None)
    monkeypatch.setattr(cli, "Settings", WriteEnabledSettings)
    monkeypatch.setattr(cli, "UniFiClient", lambda settings: client)

    async def snapshot(passed_client, registry, host):
        return {"ok": True}

    monkeypatch.setattr(cli, "get_unifi_placement_snapshot", snapshot)
    assert await cli.export_snapshot("HQ-Unifi") == {"ok": True}
    assert client.closed is True


async def test_closes_client_after_snapshot(monkeypatch):
    class ReadOnlySettings:
        cache_ttl_seconds = 1
        cache_max_hosts = 2
        cache_max_sites = 3

        def get_key_configs(self):
            return [APIKeyConfig(key="sk-test", label="default")]

    class Client:
        def __init__(self, settings):
            self.closed = False

        async def close(self):
            self.closed = True

    client = Client(None)
    monkeypatch.setattr(cli, "Settings", ReadOnlySettings)
    monkeypatch.setattr(cli, "UniFiClient", lambda settings: client)

    async def snapshot(passed_client, registry, host):
        assert passed_client is client
        assert host == "HQ-Unifi"
        return {"ok": True}

    monkeypatch.setattr(cli, "get_unifi_placement_snapshot", snapshot)
    assert await cli.export_snapshot("HQ-Unifi") == {"ok": True}
    assert client.closed is True


def test_malformed_snapshot_refuses_without_stdout(monkeypatch, capsys):
    async def malformed(host):
        return {"invalid": float("nan")}

    monkeypatch.setattr(cli, "export_snapshot", malformed)
    assert cli.main(["--host", "HQ-Unifi"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("placement snapshot export failed: ValueError: ")
    assert "not JSON compliant" in captured.err


def test_invalid_argument_does_not_echo_secret_like_input(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--not-an-option=api_key=canary"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "api_key=canary" not in captured.err
    assert "invalid arguments" in captured.err


def test_preflight_emits_only_report_and_fails_closed_for_missing_capability(monkeypatch, capsys):
    async def preflight(host):
        assert host == "HQ-Unifi"
        return {
            "schema_version": "unifi.placement-snapshot-preflight/v1",
            "read_only": True,
            "required_capabilities": ["protect.cameras"],
            "capabilities": [{"name": "protect.cameras", "outcome": "auth_denied"}],
        }

    monkeypatch.setattr(cli, "preflight_snapshot_capabilities", preflight)

    assert cli.preflight_main(["--host", "HQ-Unifi"]) == 3
    captured = capsys.readouterr()
    assert captured.out == (
        '{"schema_version":"unifi.placement-snapshot-preflight/v1","read_only":true,'
        '"required_capabilities":["protect.cameras"],"capabilities":'
        '[{"name":"protect.cameras","outcome":"auth_denied"}]}\n'
    )
    assert captured.err == ""


def test_preflight_all_ok_exits_zero(monkeypatch, capsys):
    async def preflight(host):
        assert host == "HQ-Unifi"
        return {
            "schema_version": "unifi.placement-snapshot-preflight/v1",
            "read_only": True,
            "required_capabilities": ["protect.cameras"],
            "capabilities": [{"name": "protect.cameras", "outcome": "ok"}],
        }

    monkeypatch.setattr(cli, "preflight_snapshot_capabilities", preflight)

    assert cli.preflight_main(["--host", "HQ-Unifi"]) == 0
    captured = capsys.readouterr()
    assert '"outcome":"ok"' in captured.out
    assert captured.err == ""


async def test_preflight_runs_with_connector_writes_enabled(monkeypatch):
    """No write fence: the GET-only preflight runs on a default (writes-on) deployment."""

    class WriteEnabledSettings:
        cache_ttl_seconds = 1
        cache_max_hosts = 2
        cache_max_sites = 3

        def get_key_configs(self):
            return [APIKeyConfig(key="sk-test", label="default")]

    class Client:
        def __init__(self, settings):
            self.closed = False

        async def close(self):
            self.closed = True

    client = Client(None)
    monkeypatch.setattr(cli, "Settings", WriteEnabledSettings)
    monkeypatch.setattr(cli, "UniFiClient", lambda settings: client)

    async def preflight(passed_client, registry, host):
        return {"capabilities": []}

    monkeypatch.setattr(cli, "preflight_placement_snapshot_capabilities", preflight)
    assert await cli.preflight_snapshot_capabilities("HQ-Unifi") == {"capabilities": []}
    assert client.closed is True


async def test_preflight_closes_client_after_completed_all_ok_probe(monkeypatch):
    class ReadOnlySettings:
        cache_ttl_seconds = 1
        cache_max_hosts = 2
        cache_max_sites = 3

        def get_key_configs(self):
            return [APIKeyConfig(key="sk-test", label="default")]

    class Client:
        def __init__(self, settings):
            del settings
            self.closed = False

        async def close(self):
            self.closed = True

    client = Client(None)
    monkeypatch.setattr(cli, "Settings", ReadOnlySettings)
    monkeypatch.setattr(cli, "UniFiClient", lambda settings: client)

    async def probe(passed_client, registry, host):
        del registry
        assert passed_client is client
        assert host == "HQ-Unifi"
        return {"capabilities": [{"name": "protect.cameras", "outcome": "ok"}]}

    monkeypatch.setattr(cli, "preflight_placement_snapshot_capabilities", probe)

    assert await cli.preflight_snapshot_capabilities("HQ-Unifi") == {
        "capabilities": [{"name": "protect.cameras", "outcome": "ok"}]
    }
    assert client.closed is True


def test_preflight_operational_failure_never_echoes_a_key_value(
    monkeypatch, capsys, _clean_key_env
):
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps([{"key": _KEY_CANARY, "label": "acme"}]))

    async def broken(host):
        del host
        raise RuntimeError(f"https://example.test/?api_key={_KEY_CANARY}")

    monkeypatch.setattr(cli, "preflight_snapshot_capabilities", broken)

    assert cli.preflight_main(["--host", "HQ-Unifi"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "placement snapshot capability preflight failed: RuntimeError: "
        "https://example.test/?api_key=***\n"
    )
