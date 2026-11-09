"""Fleet membership uses canonical hexadecimal IDs, retaining first-key records."""

from unittest.mock import AsyncMock, patch

import pytest

from unifi_fabric.tools.aggregation import (
    _consoles,
    _device_host,
    _fleet_summary,
    _host_record_id,
    _list_all_clients_fleet,
    _site_host,
    _unclaimed,
)


@pytest.mark.parametrize(
    "host_of,field", [(_host_record_id, "id"), (_site_host, "hostId"), (_device_host, "_hostId")]
)
def test_membership_canonical_ids(host_of, field):
    first = {field: "ABCDEF", "name": "first"}
    claimed = _consoles([first], host_of)
    assert _unclaimed([{field: "abcdef"}, {field: "other-ID"}], claimed, host_of) == [
        {field: "other-ID"}
    ]
    assert _unclaimed([{field: "OTHER-id"}], {"other-ID"}, host_of) == [{field: "OTHER-id"}]


async def test_summary_first_key_case_ids(multikey_client, multikey_registry):
    async def pages(path, *, key):
        host = "ABCDEF" if key.label == "alpha" else "abcdef"
        return {
            "/v1/hosts": [{"id": host}],
            "/v1/sites": [{"hostId": host}],
            "/v1/devices": [{"hostId": host, "devices": [{"id": "d1", "status": key.label}]}],
        }[path]

    multikey_client.paginate = AsyncMock(side_effect=pages)
    result = await _fleet_summary(multikey_client, multikey_registry)
    assert result["hosts"] == result["sites"] == result["devices"]["total"] == 1
    assert result["devices"]["byStatus"] == {"alpha": 1}


async def test_clients_queue_canonical_pairs(multikey_client, multikey_registry):
    async def pairs(registry, *, key, **kwargs):
        return [
            {
                "hostId": "ABCDEF" if key.label == "alpha" else "abcdef",
                "siteId": "ABCD" if key.label == "alpha" else "abcd",
                "hostName": "host",
                "siteName": "site",
            }
        ]

    multikey_client.get = AsyncMock(return_value={"data": [], "totalCount": 0})
    with patch("unifi_fabric.tools.aggregation._get_all_host_site_pairs", side_effect=pairs):
        await _list_all_clients_fleet(multikey_client, multikey_registry)
    assert multikey_client.get.await_count == 1
    assert multikey_client.get.call_args.kwargs["key"].label == "alpha"


async def test_host_pairs_case_ids(multikey_registry):
    from unifi_fabric.tools.aggregation import _get_all_host_site_pairs

    multikey_registry.get_ea_sites = AsyncMock(
        return_value=[{"hostId": "ABCDEF"}, {"hostId": "abcdef"}]
    )
    multikey_registry.get_hosts = AsyncMock(return_value=[{"id": "abcdef", "name": "first"}])
    multikey_registry.get_sites = AsyncMock(
        return_value=[{"id": "abcdefab-0000-4000-8000-000000000001"}]
    )
    pairs = await _get_all_host_site_pairs(multikey_registry)
    assert len(pairs) == 1
    assert pairs[0]["hostId"] == "ABCDEF"
    assert pairs[0]["hostName"] == "first"


async def test_search_sites_canonical_claim(multikey_client, multikey_registry):
    from unifi_fabric.tools.site_manager import search_across_sites

    multikey_registry.get_ea_sites = AsyncMock(
        side_effect=[
            [{"hostId": "ABCDEF", "siteId": "s1"}],
            [{"hostId": "abcdef", "siteId": "s2"}],
        ]
    )
    multikey_client.get = AsyncMock(return_value={"data": [{"name": "match"}], "totalCount": 1})
    with patch(
        "unifi_fabric.tools.site_manager._proxy_site_for_ea",
        new=AsyncMock(
            side_effect=[
                {"id": "ABCDEFAB-0000-4000-8000-000000000001"},
                {"id": "abcdefab-0000-4000-8000-000000000001"},
            ]
        ),
    ):
        result = await search_across_sites(multikey_client, multikey_registry, "match")
    assert multikey_client.get.await_count == 2
    assert len(result["data"]) == 2


@pytest.mark.parametrize(
    "class_name,method_name,api_name,args",
    [
        ("TestListHostsIntegration", "test_returns_at_least_one_host", "list_hosts", (None, None)),
        ("TestListSitesIntegration", "test_returns_sites", "list_sites", (None, None)),
        ("TestListDevicesIntegration", "test_returns_devices", "list_devices", (None, None)),
        ("TestListSDWANConfigsIntegration", "test_returns_configs", "list_sdwan_configs", (None,)),
    ],
)
async def test_integration_assertions_use_upstream_envelope(
    monkeypatch, class_name, method_name, api_name, args
):
    import runpy
    from pathlib import Path

    namespace = runpy.run_path(str(Path(__file__).with_name("test_site_manager_integration.py")))
    method = getattr(namespace[class_name](), method_name)
    monkeypatch.setitem(
        method.__func__.__globals__,
        api_name,
        AsyncMock(return_value={"data": [{"id": "first"}], "_count": 1}),
    )
    await method(*args)


async def test_clients_multi_key_skips_claimed_host_and_labels_failures(
    multikey_client, multikey_registry
):
    async def ea_sites(*, key):
        return [{"hostId": "shared"}] + ([{"hostId": "broken"}] if key.label == "beta" else [])

    async def sites(host, *, key):
        if host == "broken":
            raise ValueError("synthetic site failure")
        return [{"id": "11111111-0000-4000-8000-000000000001", "name": "site"}]

    multikey_registry.get_ea_sites = AsyncMock(side_effect=ea_sites)
    multikey_registry.get_hosts = AsyncMock(return_value=[])
    multikey_registry.get_sites = AsyncMock(side_effect=sites)
    multikey_client.get = AsyncMock(return_value={"data": [], "totalCount": 0})
    result = await _list_all_clients_fleet(multikey_client, multikey_registry)
    assert [c.args[0] for c in multikey_registry.get_sites.await_args_list] == ["shared", "broken"]
    assert result["_skipped"][0]["keyLabel"] == "beta"
    assert result["_skipped"][0]["hostId"] == "broken"
