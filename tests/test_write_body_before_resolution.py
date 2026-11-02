"""Direct Integration updates refuse locally empty bodies before selector resolution."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.tools import firewall_proxy, network, network_services_proxy

UPDATES = (
    network.update_network,
    network.update_wifi_broadcast,
    network_services_proxy.update_dns_policy,
    network_services_proxy.update_traffic_matching_list,
    firewall_proxy.update_firewall_policy,
    firewall_proxy.patch_firewall_policy,
    firewall_proxy.update_firewall_zone,
    firewall_proxy.update_acl_rule,
)


@pytest.mark.parametrize("update", UPDATES, ids=lambda f: f.__name__)
@pytest.mark.parametrize(
    "body", [{}, {"_note": "read result"}, {"id": "identifier"}, {"password": REDACTION_MASK}]
)
async def test_invalid_body_precedes_direct_update_resolution(update, body, monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(
            side_effect=AssertionError("resolution before local validation")
        )
    )
    client = SimpleNamespace(put=AsyncMock(), patch=AsyncMock())
    with pytest.raises(ValueError, match="No fields provided"):
        await update(
            client,
            registry,
            "unknown-host",
            "unknown-site",
            "00000000-0000-4000-8000-000000000001",
            body,
        )
    registry.resolve_key_for_host.assert_not_awaited()
    client.put.assert_not_awaited()
    client.patch.assert_not_awaited()
