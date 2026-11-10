"""Selector integrity for every Classic diagnostics resolver caller."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.statistics import statistics as s

MAC = "02:00:5e:00:00:aa"
CALLERS = [
    (s._get_client_link_diagnostics, {"client_id": MAC}),
    (s._get_client_link_diagnostics, {"client_ids": [MAC]}),
    (s._get_device_port_state, {"device_id": MAC}),
    (s._get_device_stp_state, {"device_id": MAC}),
]


async def invoke(fn, args, rows):
    client = AsyncMock()
    client.get.return_value = {"meta": {"rc": "ok"}, "data": rows}
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host"
    registry.resolve_site_slug.return_value = "default"
    return await fn(client, registry, "host", "site", **args)


@pytest.mark.parametrize("fn,args", CALLERS)
async def test_ambiguous_mac_never_first_pick(fn, args):
    rows = [{"_id": "a", "mac": MAC, "name": "one"}, {"_id": "b", "mac": MAC, "name": "two"}]
    with pytest.raises(ValueError, match="ambiguous") as exc:
        await invoke(fn, args, rows)
    assert "one" in str(exc.value) and "two" in str(exc.value)


@pytest.mark.parametrize("fn,args", CALLERS)
@pytest.mark.parametrize("bad", [None, "bad-row", 17, []])
async def test_malformed_rows_raise_shape(fn, args, bad):
    with pytest.raises(UniFiConnectionError, match="shape"):
        await invoke(fn, args, [bad, {"_id": "a", "mac": MAC}])


@pytest.mark.parametrize("fn,args", CALLERS)
async def test_same_id_duplicate_is_one_choice(fn, args):
    row = {"_id": "a", "mac": MAC}
    await invoke(fn, args, [row, dict(row)])


@pytest.mark.parametrize("native", [None, "", 1, False, [], {}])
def test_alias_match_missing_native_id_is_explicit(native):
    from unifi_fabric.matching import find_by_id
    from unifi_fabric.shared_shapes._classic_objects import listed_record_id

    record = {"_id": native, "external_id": "external", "name": "identified"}
    selected = find_by_id([record], "external", "_id", "external_id")
    with pytest.raises(ValueError) as exc:
        listed_record_id(selected, "_id")
    assert "identified" in str(exc.value)


def test_alias_collision_never_first_pick():
    from unifi_fabric.matching import find_by_id

    with pytest.raises(ValueError, match="ambiguous") as exc:
        find_by_id(
            [{"_id": "one", "external_id": "same"}, {"_id": "two", "external_id": "same"}],
            "same",
            "_id",
            "external_id",
        )
    assert "one" in str(exc.value) and "two" in str(exc.value)


@pytest.mark.parametrize("fn,args", CALLERS)
async def test_ambiguous_fallback_ids_are_listed(fn, args):
    rows = [
        {"id": "native-a", "mac": MAC, "name": "one"},
        {"id": "native-b", "mac": MAC, "name": "two"},
    ]
    with pytest.raises(ValueError, match="ambiguous") as exc:
        await invoke(fn, args, rows)
    assert "native-a" in str(exc.value) and "native-b" in str(exc.value)


@pytest.mark.parametrize("port_table", [None, {}, "bad-table", 17, [None], [7], [{}, "bad-row"]])
@pytest.mark.parametrize("port_idx", [None, 1])
async def test_nested_port_table_shape_is_not_a_missing_port(port_table, port_idx):
    with pytest.raises(UniFiConnectionError, match="shape.*port_table"):
        await invoke(
            s._get_device_port_state,
            {"device_id": MAC, "port_idx": port_idx},
            [{"_id": "a", "mac": MAC, "port_table": port_table}],
        )


async def test_absent_port_table_is_a_device_without_ports():
    result = await invoke(s._get_device_port_state, {"device_id": MAC}, [{"_id": "a", "mac": MAC}])
    assert "port_table" not in result
    with pytest.raises(ValueError, match="valid port_idx values:.*none"):
        await invoke(
            s._get_device_port_state,
            {"device_id": MAC, "port_idx": 1},
            [{"_id": "a", "mac": MAC}],
        )
