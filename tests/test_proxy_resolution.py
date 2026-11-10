"""Properties of list-first proxy and Site Manager resolution."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.network import network_services_proxy as ns
from unifi_fabric.families.site_manager import site_manager as sm
from unifi_fabric.registry import FetchedRecords

UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
EA = {
    "hostId": "host-001",
    "siteId": "ea-site",
    "meta": {"name": "default"},
    "_resolvedSiteId": "ea-site",
}


def registry(rows=()):
    return SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host-001"),
        resolve_site_slug=AsyncMock(return_value="default"),
        get_sites=AsyncMock(return_value=rows),
        get_ea_sites=AsyncMock(return_value=rows),
    )


@pytest.mark.parametrize("bad", [None, 7, "garbage", []])
@pytest.mark.parametrize("getter", [ns.get_traffic_route, ns.get_wlan_group])
async def test_list_resolution_never_discards_nonobject_rows(bad, getter):
    rows = [{"_id": "target", "name": "ok"}, bad]
    response = rows if getter is ns.get_traffic_route else {"data": rows}
    client = SimpleNamespace(get=AsyncMock(return_value=response))
    with pytest.raises(UniFiConnectionError, match="objects"):
        await getter(client, registry(), "host", "site", "target")


@pytest.mark.parametrize("bad", [None, 7, "garbage", []])
async def test_proxy_resolution_never_discards_nonobject_rows(bad):
    with pytest.raises(UniFiConnectionError, match="objects"):
        await sm._proxy_site_for_ea(
            registry([{"id": UUID, "internalReference": "default"}, bad]), EA, None
        )


@pytest.mark.parametrize("native", [None, 7, True, [], {}])
async def test_external_network_match_requires_native_string_id(native):
    row = {"external_id": UUID, "_id": native}
    client = SimpleNamespace(get=AsyncMock(return_value={"data": [row]}))
    docs = await ns._networkconf_docs(client, "host", "default", key=None)
    assert docs == [row], "matching candidates must survive missing native identifiers"
    with pytest.raises(ValueError, match="Selected record has invalid native _id"):
        ns._match_networkconf(docs, UUID)


@pytest.mark.parametrize("native", [None, 7, True, [], {}])
async def test_proxy_match_requires_native_string_id(native):
    with pytest.raises(ValueError, match="Selected console site has no non-empty string native id"):
        await sm._proxy_site_for_ea(
            registry([{"id": native, "internalReference": "default"}]), EA, None
        )


async def test_ambiguous_internal_reference_cannot_fall_back_to_label():
    rows = [
        {"id": UUID, "internalReference": "default", "description": "default"},
        {
            "id": "11111111-2222-3333-4444-555555555555",
            "internalReference": "default",
            "description": "other",
        },
    ]
    with pytest.raises(ValueError, match="ambiguous|exactly one"):
        await sm._proxy_site_for_ea(registry(rows), EA, None)


async def test_internal_reference_success_is_complete_on_partial_list():
    rows = FetchedRecords([{"id": UUID, "internalReference": "default"}], "max pages reached")
    result = await sm._proxy_site_for_ea(registry(rows), EA, None)
    assert "_incomplete" not in result and "_incompleteReason" not in result


async def test_exact_ea_id_success_is_complete_on_partial_list():
    rows = FetchedRecords([EA], "max pages reached")
    client = SimpleNamespace(list_key_labels=lambda: ["default"], paginate_max_pages=1)
    result = await sm._resolve_ea_site_record(registry(rows), "ea-site", client)
    assert "_incomplete" not in result and "_incompleteReason" not in result


async def test_health_exact_resolution_is_complete_on_partial_lists():
    reg = registry(FetchedRecords([EA], "EA capped"))
    reg.get_sites = AsyncMock(
        return_value=FetchedRecords([{"id": UUID, "internalReference": "default"}], "proxy capped")
    )
    client = SimpleNamespace(
        list_key_labels=lambda: ["default"],
        paginate_max_pages=1,
        get=AsyncMock(return_value={"data": []}),
    )
    result = await sm.get_site_health_summary(client, reg, "ea-site")
    assert "_incomplete" not in result and "_incompleteReason" not in result


@pytest.mark.parametrize("copies", [1, 2, 3])
async def test_repeated_rows_for_one_native_proxy_id_are_one_choice(copies):
    row = {"id": UUID, "internalReference": "default"}
    result = await sm._proxy_site_for_ea(registry([dict(row) for _ in range(copies)]), EA, None)
    assert result == row


@pytest.mark.parametrize("copies", [2, 3])
def test_distinct_native_network_ids_sharing_alias_are_ambiguous(copies):
    docs = [{"_id": f"network-{i}", "external_id": UUID} for i in range(copies)]
    with pytest.raises(ValueError, match="ambiguous"):
        ns._match_networkconf(docs, UUID)


async def test_inventory_exact_resolution_is_complete_on_partial_lists(monkeypatch):
    reg = registry(FetchedRecords([EA], "EA capped"))
    reg.get_sites = AsyncMock(
        return_value=FetchedRecords([{"id": UUID, "internalReference": "default"}], "proxy capped")
    )
    client = SimpleNamespace(list_key_labels=lambda: ["default"], paginate_max_pages=1)
    monkeypatch.setattr(
        sm,
        "collect_offset",
        AsyncMock(
            return_value={
                "items": [],
                "incomplete": False,
                "incompleteReason": None,
                "envelope": {},
            }
        ),
    )
    result = await sm.get_site_inventory(client, reg, "ea-site")
    assert "_incomplete" not in result and "_incompleteReason" not in result


async def test_search_internal_reference_is_complete_on_partial_list(monkeypatch):
    reg = registry([EA])
    reg.get_sites = AsyncMock(
        return_value=FetchedRecords([{"id": UUID, "internalReference": "default"}], "proxy capped")
    )
    client = SimpleNamespace(
        list_key_labels=lambda: ["default"],
        paginate_max_pages=1,
        gather=lambda jobs: asyncio.gather(*jobs),
    )
    monkeypatch.setattr(
        sm,
        "collect_offset",
        AsyncMock(
            return_value={
                "items": [],
                "incomplete": False,
                "incompleteReason": None,
                "envelope": {},
            }
        ),
    )
    result = await sm.search_across_sites(client, reg, "switch")
    assert result["_sitesIncomplete"] == 0
    assert "proxy capped" not in str(result)


@pytest.mark.parametrize("native", [None, 7, {}, []])
def test_network_native_error_identifies_selected_record(native):
    row = {"_id": native, "external_id": UUID, "name": "Guest VLAN"}
    with pytest.raises(ValueError) as error:
        ns._match_networkconf([row], UUID)
    assert "Guest VLAN" in str(error.value)
    assert UUID in str(error.value)


@pytest.mark.parametrize("native", [None, 7, {}, []])
async def test_proxy_native_error_identifies_selected_record(native):
    row = {"id": native, "internalReference": "default", "description": "Main Office"}
    with pytest.raises(ValueError) as error:
        await sm._proxy_site_for_ea(registry([row]), EA, None)
    assert "Main Office" in str(error.value)
    assert "default" in str(error.value)
    assert "Selected console site has no non-empty string native id" in str(error.value)


@pytest.mark.parametrize("native", [None, 7, {}, []])
def test_network_name_map_native_error_is_actionable(native):
    row = {"_id": native, "external_id": UUID, "name": "Guest VLAN"}
    with pytest.raises(ValueError) as error:
        ns._name_map_from_docs([row])
    assert "Guest VLAN" in str(error.value)
    assert UUID in str(error.value)


async def test_exact_ea_id_miss_keeps_cap_reason():
    rows = FetchedRecords([EA], "max pages reached")
    client = SimpleNamespace(list_key_labels=lambda: ["default"], paginate_max_pages=1)
    with pytest.raises(ValueError, match="max pages reached"):
        await sm._resolve_ea_site_record(registry(rows), "missing-site", client)
