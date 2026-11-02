"""Hints retain the upstream exception and its evidence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import network, network_dpi_policy, network_proav_sandbox
from unifi_fabric.tools._payload import upstream_hint, with_upstream_hint


class DetailedError(UniFiConnectionError):
    def __init__(self, message, *, detail):
        super().__init__(message, request_sent=True, status=404)
        self.detail = detail


def test_hint_preserves_subclass_identity_and_evidence():
    cause = ValueError("transport cause")
    error = DetailedError("upstream body", detail=object())
    error.__cause__ = cause
    detail = error.detail
    assert upstream_hint(error, "guidance") is error
    assert str(error) == "upstream body -- Hint: guidance"
    assert error.status == 404 and error.request_sent
    assert error.__cause__ is cause and error.detail is detail


@pytest.mark.parametrize("kind", ["helper", "5g", "wifi", "policy"])
async def test_hint_callers_keep_original_cause(monkeypatch, kind):
    cause = ValueError("transport cause")
    message = {
        "helper": "upstream body",
        "5g": "upstream body",
        "wifi": "upstream body too-many-wifi-broadcasts",
        "policy": "upstream body system-defined-firewall-policy-update-forbidden",
    }[kind]
    error = DetailedError(message, detail=object())
    if kind in {"wifi", "policy"}:
        error.status = 400
    error.__cause__ = cause
    client = SimpleNamespace(
        get=AsyncMock(side_effect=error),
        post=AsyncMock(side_effect=error),
        put=AsyncMock(side_effect=error),
    )
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host"),
        resolve_site_id=AsyncMock(return_value="00000000-0000-4000-8000-000000000001"),
    )
    if kind == "5g":
        monkeypatch.setattr(
            network_proav_sandbox, "_site", AsyncMock(return_value=(None, "h", "s"))
        )
        call = network_proav_sandbox.get_5g_topology(
            client, None, "host", "site", "02:00:5e:00:00:a1", 1760000000000
        )
    elif kind == "wifi":
        call = network.create_wifi_broadcast(client, registry, "host", "site", {"type": "STANDARD"})
    elif kind == "policy":
        client.get.side_effect = None
        client.get.return_value = {"enabled": True}
        call = network_dpi_policy.update_predefined_firewall_policy(
            client,
            registry,
            "host",
            "site",
            "00000000-0000-4000-8000-000000000002",
            {"enabled": False},
        )
    else:
        call = with_upstream_hint(client.get(), "guidance")
    with pytest.raises(DetailedError) as caught:
        await call
    assert caught.value is error
    assert error.__cause__ is cause
    assert error.status == (400 if kind in {"wifi", "policy"} else 404)
    assert error.request_sent and error.detail is not None
    assert str(error).startswith(message + " -- Hint: ")
