"""Nested upstream values in diagnostic messages obey opt-in redaction."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.redaction import write_redaction_scope
from unifi_fabric.tools import client_records, clients, matter


@pytest.mark.parametrize(
    "describe",
    [client_records._describe_users, client_records._describe_guests, clients._describe_clients],
)
def test_describers_redact_nested_upstream_values(describe):
    value = {"password": "SYNTHETIC_SECRET"}
    row = {key: value for key in ("name", "hostname", "mac", "_id", "id", "end", "expired")}
    with write_redaction_scope(True):
        result = describe([row], None)
    assert "SYNTHETIC_SECRET" not in result
    assert "REDACTED" in result


async def test_matter_missing_node_redacts_nested_upstream_values():
    client = AsyncMock()
    client.get.return_value = {"data": [{"id": {"password": "SYNTHETIC_SECRET"}}]}
    with write_redaction_scope(True), pytest.raises(ValueError) as exc:
        await matter._matter_node_id(client, "/synthetic", None, "missing")
    assert "SYNTHETIC_SECRET" not in str(exc.value)


async def test_relay_read_error_redacts_nested_credentials():
    from unifi_fabric.tools.connector import _safe_get

    client = AsyncMock()
    client.request.side_effect = ValueError('{"password": "SYNTHETIC_SECRET"}')
    client._settings.redact_secrets = True
    with write_redaction_scope(True):
        result = await _safe_get(client, "/synthetic", None)
    assert "SYNTHETIC_SECRET" not in result["error"]


async def test_legacy_shape_error_keeps_integration_rejection():
    from unifi_fabric.client import UniFiConnectionError
    from unifi_fabric.tools.innerspace import _fetch_project_document

    client, registry = AsyncMock(), AsyncMock()
    client.get.side_effect = [UniFiConnectionError("HTTP 403 host not found"), {}]
    registry.resolve_host_id.return_value = "synthetic"
    with pytest.raises(UniFiConnectionError) as exc:
        await _fetch_project_document(client, registry, "synthetic", "3D")
    assert "HTTP 403 host not found" in " ".join(exc.value.__notes__)


async def test_device_dry_run_prepares_and_audits_body():
    from unittest.mock import MagicMock

    from unifi_fabric.tools._device_config import update_device_config

    client = MagicMock()
    client.dry_run = False
    client._dry_run_response.return_value.json.return_value = {}
    await update_device_config(
        client,
        "/synthetic",
        {},
        {"x": 1},
        {"_context": 1, "x": 1},
        AsyncMock(),
        lambda before, after: {},
        key=None,
        dry_run=True,
    )
    assert client._audit_write.call_args.kwargs["body"] == {"x": 1}
    assert client._dry_run_response.call_args.args[2] == {"x": 1}


@pytest.mark.parametrize(
    ("name", "args", "method"),
    [
        ("create_carrier_subscriber", ("synthetic",), "POST"),
        ("update_carrier_subscriber", ("synthetic",), "PATCH"),
        ("attach_carrier_subscriber_host", ("synthetic", "synthetic"), "PUT"),
        ("detach_carrier_subscriber_host", ("synthetic",), "DELETE"),
        ("assign_carrier_subscriber_plan", ("synthetic", "synthetic"), "PUT"),
        ("suspend_carrier_subscriber", ("synthetic",), "POST"),
        ("resume_carrier_subscriber", ("synthetic",), "POST"),
    ],
)
async def test_carrier_guard_names_actual_method(monkeypatch, name, args, method):
    from unifi_fabric.tools import carrier_fabric

    def refuse(verb):
        raise RuntimeError(verb)

    monkeypatch.setattr(carrier_fabric, "guard_action", refuse)
    with pytest.raises(RuntimeError, match=f"^{method}$"):
        await getattr(carrier_fabric, name)(AsyncMock(), *args)


async def test_network_choices_redact_nested_upstream_values():
    client = AsyncMock()
    client._settings.redact_secrets = True
    client.get.return_value = {
        "meta": {"rc": "ok"},
        "data": [{"name": {"password": "SYNTHETIC_SECRET"}}],
    }
    with write_redaction_scope(True), pytest.raises(ValueError) as exc:
        await client_records._resolve_network_id(client, "host", "site", "missing", key=None)
    assert "SYNTHETIC_SECRET" not in str(exc.value)


async def test_matter_invalid_native_id_redacts_nested_upstream_values():
    client = AsyncMock()
    client._settings.redact_secrets = True
    client.get.return_value = {"data": [{"id": {"password": "SYNTHETIC_SECRET"}, "_id": "valid"}]}
    with write_redaction_scope(True), pytest.raises(ValueError) as exc:
        await matter._matter_node_id(client, "/synthetic", None, "valid")
    assert "SYNTHETIC_SECRET" not in str(exc.value)
