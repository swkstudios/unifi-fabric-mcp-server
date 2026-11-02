"""Consumed Network response shapes never produce invented write state."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import device_mgmt as dm
from unifi_fabric.tools import network_services_proxy as ns

BAD_ARRAYS = ["abc", None, {}, 7, [None], [7], [True], [{}], [[]]]


def registry():
    return AsyncMock(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host"),
        resolve_site_slug=AsyncMock(return_value="default"),
    )


@pytest.mark.parametrize("members", BAD_ARRAYS)
async def test_tag_upstream_members_are_string_array_before_put(members):
    client = AsyncMock()
    client.get.return_value = [{"_id": "tag", "name": "tag", "member_device_macs": members}]
    with pytest.raises(UniFiConnectionError, match="member_device_macs.*array.*strings"):
        await dm._update_device_tag(
            client, registry(), "host", "default", "tag", {"member_device_macs": []}
        )
    client.put.assert_not_called()


@pytest.mark.parametrize("excluded", BAD_ARRAYS)
@pytest.mark.parametrize("exclude", [False, True])
async def test_profile_upstream_exclusions_are_string_array_before_put(excluded, exclude):
    client = AsyncMock()
    client.get.side_effect = [
        {"data": [{"_id": "network", "external_id": "network", "name": "LAN"}]},
        {"data": [{"_id": "profile", "excluded_networkconf_ids": excluded}]},
    ]
    with pytest.raises(UniFiConnectionError, match="excluded_networkconf_ids.*array.*strings"):
        await ns._mutate_port_profile_exclusion(
            client, registry(), "host", "default", "profile", "network", exclude=exclude
        )
    client.put.assert_not_called()


@pytest.mark.parametrize("excluded", BAD_ARRAYS)
def test_tagged_network_derivation_rejects_malformed_exclusions(excluded):
    with pytest.raises(UniFiConnectionError, match="excluded_networkconf_ids.*array.*strings"):
        ns._derive_tagged_networks({"excluded_networkconf_ids": excluded}, {})


BAD_SETTINGS = [
    [],
    [{"key": "mgmt"}, {"key": "other"}],
    [{"key": "other"}],
    [{}],
    [{"key": ["mgmt"]}],
    [None],
]


@pytest.mark.parametrize("rows", BAD_SETTINGS)
async def test_setting_pre_read_requires_addressed_singleton(rows):
    client = AsyncMock()
    client.get.return_value = {"data": rows}
    with pytest.raises(UniFiConnectionError, match="mgmt.*single.*key"):
        await ns.update_setting(client, registry(), "host", "default", "mgmt", {"enabled": True})
    client.put.assert_not_called()


@pytest.mark.parametrize("rows", BAD_SETTINGS)
async def test_setting_post_read_reports_malformed_addressed_singleton(rows):
    client = AsyncMock()
    client.get.side_effect = [{"data": [{"key": "mgmt", "enabled": False}]}, {"data": rows}]
    client.put.return_value = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt"}]}
    result = await ns.update_setting(
        client, registry(), "host", "default", "mgmt", {"enabled": True}
    )
    client.put.assert_awaited_once()
    assert "mgmt" in result["_readAfterError"]
    assert "singleton" in result["_readAfterError"]


async def test_setting_valid_no_op():
    client = AsyncMock()
    client.get.return_value = {"data": [{"key": "mgmt", "enabled": True}]}
    result = await ns.update_setting(
        client, registry(), "host", "default", "mgmt", {"enabled": True}
    )
    assert result["_note"] == "no change needed"
    client.put.assert_not_called()


@pytest.mark.parametrize("excluded", BAD_ARRAYS)
async def test_created_network_bad_exclusions_report_read_after_error(excluded):
    client = AsyncMock()
    client.get.side_effect = [
        {"data": [{"_id": "network", "external_id": "created"}]},
        {
            "data": [
                {
                    "_id": "profile",
                    "tagged_vlan_mgmt": "custom",
                    "excluded_networkconf_ids": excluded,
                }
            ]
        },
    ]
    created = {"id": "created", "name": "LAN", "probe": {"verbatim": True}}
    result = await ns.annotate_auto_exclusions(client, registry(), "host", "default", created)
    assert result["id"] == created["id"]
    assert result["probe"] == created["probe"]
    assert result["_warnings"][0]["code"] == "D12_CHECK_FAILED"
    assert "excluded_networkconf_ids" in result["_readAfterError"]
    client.put.assert_not_called()


def test_valid_tag_member_arrays_normalize_macs_without_coercion():
    from unifi_fabric.tools._classic_objects import device_tag_update_body

    assert device_tag_update_body(
        {"member_device_macs": ["AA-BB-CC-DD-EE-FF"]},
        {"member_device_macs": ["aa:bb:cc:dd:ee:ff"]},
    ) == {"device_mac_additions": [], "device_mac_removals": []}
    assert device_tag_update_body({"member_device_macs": []}, {}) == {
        "device_mac_additions": [],
        "device_mac_removals": [],
    }
