"""Stable identity and incomplete name-resolution regressions."""

import pytest

from unifi_fabric.config import APIKeyConfig
from unifi_fabric.registry import Registry


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


@pytest.mark.parametrize("selector", ["hq", "HQ", "Head Office"])
@pytest.mark.parametrize("ttl", [0, 900])
async def test_host_name_cannot_be_unambiguous_when_a_sibling_key_failed(selector, ttl):
    registry = Registry(_TwoKeys(), ttl_seconds=ttl)
    with pytest.raises(ValueError) as exc:
        await registry.resolve_key_for_host(selector)
    assert "unambiguously" in str(exc.value)
    assert "beta" in str(exc.value)
    assert "synthetic upstream unavailable" in str(exc.value)


async def test_exact_host_id_still_resolves_when_a_sibling_key_failed():
    registry = Registry(_TwoKeys())
    assert (await registry.resolve_key_for_host("aa:1")).label == "alpha"
