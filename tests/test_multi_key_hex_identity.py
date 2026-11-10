"""Multi-key deduplication preserves upstream values and identity semantics."""

import pytest

from unifi_fabric.config import APIKeyConfig
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.families.site_manager.aggregation import _device_host
from unifi_fabric.registry import Registry
from unifi_fabric.shared_shapes._keys import merge_first_key, stable_id


class _TwoKeys:
    paginate_max_pages = None

    def list_key_labels(self):
        return ["alpha", "beta"]

    def get_key_by_label(self, label):
        return APIKeyConfig(key="synthetic-test-key", label=label)

    async def paginate(self, path, *, key=None, **kwargs):
        if key.label == "beta":
            raise RuntimeError("synthetic upstream unavailable")
        return [{"id": "AA:1", "reportedState": {"hostname": "hq", "name": "Head Office"}}]


@pytest.mark.parametrize("field", ["id", "hostId", "siteId", "workspace_id"])
@pytest.mark.parametrize(
    "native", ["ABCDEF0123456789ABCDEF01", "ABCDEF01-0000-4000-8000-ABCDEF000001", "AA:1"]
)
def test_identity_fields_deduplicate_hex_case_and_keep_first_upstream_record(field, native):
    first = {field: native, "name": "first"}
    second = {field: native.lower(), "name": "second"}
    result = merge_first_key([("alpha", [first]), ("beta", [second])], stable_id(field), multi=True)
    assert result == [{**first, "_keyLabel": "alpha"}]
    assert first == {field: native, "name": "first"}
    assert second == {field: native.lower(), "name": "second"}


def test_metric_names_and_nonhex_ids_keep_case_significance():
    identity = stable_id("metricType", "hostId", "siteId")
    rows = [
        ("alpha", [{"metricType": "ABC", "hostId": "AA:1", "siteId": "ABCDEF"}]),
        ("beta", [{"metricType": "abc", "hostId": "aa:1", "siteId": "abcdef"}]),
    ]
    assert len(merge_first_key(rows, identity, multi=True)) == 2
    assert stable_id("id")({"id": "Opaque-A"}) != stable_id("id")({"id": "opaque-a"})


@pytest.mark.parametrize(
    "tool,path,record,count",
    [
        ("list_hosts", "/v1/hosts", {"id": "AA:1"}, 1),
        ("list_sites", "/v1/sites", {"hostId": "AA:1", "siteId": "ABCDEF0123456789ABCDEF01"}, 1),
        (
            "list_all_sites_aggregated",
            "/v1/sites",
            {"hostId": "AA:1", "siteId": "ABCDEF0123456789ABCDEF01"},
            1,
        ),
        ("list_devices", "/v1/devices", {"hostId": "AA:1", "devices": [{"id": "ABCDEF"}]}, 1),
    ],
)
async def test_site_manager_aggregates_one_hex_identity_across_keys(tool, path, record, count):
    class Client(_TwoKeys):
        async def paginate(self, requested, *, key=None, **kwargs):
            assert requested == path
            return [
                {
                    field: value.lower()
                    if key.label == "beta" and isinstance(value, str)
                    else value
                    for field, value in record.items()
                }
            ]

    client = Client()
    registry = Registry(client)
    result = await getattr(site_manager, tool)(client, registry)
    assert result["_count"] == count
    assert len(result["data"]) == 1
    assert result["data"][0] == {**record, "_keyLabel": "alpha"}


def test_custom_device_console_identity_uses_the_same_hex_id_contract():
    first = {"_hostId": "AA:1", "id": "first"}
    second = {"_hostId": "aa:1", "id": "second"}
    assert merge_first_key([("alpha", [first]), ("beta", [second])], _device_host, multi=True) == [
        {**first, "_keyLabel": "alpha"}
    ]
