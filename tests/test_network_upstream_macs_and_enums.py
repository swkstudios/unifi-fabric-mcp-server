"""Network tools: upstream MACs, exact reads and spec integer enums."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.spec_limits import argument_problems, limit_problems
from unifi_fabric.tools.device_mgmt import _classic_devmgr
from unifi_fabric.tools.vpn import _get_radius_profile, _get_vpn_server

SITE = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
DEVICE = "11111111-2222-3333-4444-555555555555"


def dependencies():
    client = AsyncMock()
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host-001"
    registry.resolve_site_id.return_value = SITE
    registry.resolve_site_slug.return_value = "default"
    return client, registry


@pytest.mark.parametrize("cmd", ["set-locate", "unset-locate", "upgrade"])
@pytest.mark.parametrize("mac", ["02:00:00:00:00:bbJUNK", "", 7, None, "invalid", "02:00:00:00:00"])
async def test_malformed_device_mac_refused_before_physical_command(cmd, mac):
    client, registry = dependencies()
    client.get.return_value = {"macAddress": mac}
    with pytest.raises(UniFiConnectionError) as caught:
        await _classic_devmgr(client, registry, "h", "s", DEVICE, cmd)
    assert "Unexpected response shape" in str(caught.value)
    assert repr(mac) in str(caught.value)
    client.post.assert_not_awaited()
    registry.resolve_site_slug.assert_not_awaited()


@pytest.mark.parametrize("mac", [" 02-00-00-00-00-BB ", "0200.0000.00BB", "0200000000BB"])
async def test_valid_upstream_mac_normalized_without_changing_target(mac):
    client, registry = dependencies()
    client.get.return_value = {"macAddress": mac}
    await _classic_devmgr(client, registry, "h", "s", DEVICE, "upgrade")
    assert client.post.call_args.kwargs["json"]["mac"] == "02:00:00:00:00:bb"


@pytest.mark.parametrize("getter", [_get_vpn_server, _get_radius_profile])
async def test_exact_id_capped_hit_is_complete_and_missing_keeps_reason(getter):
    client, registry = dependencies()
    record = {"id": "target", "name": "Exact"}
    client.paginate_max_pages = 1
    client.get.return_value = {"data": [record], "limit": 200, "totalCount": 2}
    assert await getter(client, registry, "h", "s", "target") == record
    with pytest.raises(ValueError, match="incomplete.*page cap of 1 reached"):
        await getter(client, registry, "h", "s", "absent")
    assert client.get.await_count == 2
    assert all(
        call.kwargs["params"] == {"limit": 200, "offset": 0} for call in client.get.await_args_list
    )


@pytest.mark.parametrize("tool", ["create_wifi_broadcast", "update_wifi_broadcast"])
@pytest.mark.parametrize(
    "band,rates",
    [
        ("2.4", [1000, 2000, 5500, 6000, 9000, 11000, 12000, 24000]),
        ("5", [6000, 9000, 12000, 24000]),
    ],
)
def test_wifi_basic_rates_accept_integer_and_original_string_enums(tool, band, rates):
    for rate in rates:
        for value in (rate, str(rate)):
            body = {"basicDataRateKbpsByFrequencyGHz": {band: value}}
            assert argument_problems(tool, {"broadcast": body}) == []
    for value in (True, 6000.5, 99999, "99999", "6000x"):
        body = {"basicDataRateKbpsByFrequencyGHz": {band: value}}
        assert argument_problems(tool, {"broadcast": body})


def test_integer_enum_compatibility_is_scoped_and_never_coerces_input():
    assert limit_problems(6000, {"enum": ["6000"]}, "rate")
    assert limit_problems("6000", {"enum": [6000]}, "rate")
    assert not limit_problems(6000, {"enum": [6000]}, "rate")
    body = {"basicDataRateKbpsByFrequencyGHz": {"5": 6000}}
    assert not argument_problems("create_wifi_broadcast", {"broadcast": body})
    assert type(body["basicDataRateKbpsByFrequencyGHz"]["5"]) is int


@pytest.mark.parametrize("text,number", [("06000", 6000), ("-0", 0), ("-10", -10)])
def test_integer_enum_schema_quirk_uses_decimal_value(text, number):
    limits = {"enum": [text], "integerEnum": True}
    assert not limit_problems(text, limits, "rate")
    assert not limit_problems(number, limits, "rate")
    assert limit_problems(True, limits, "rate")
