"""Malformed Site Manager rows stay within each API key's error boundary."""

from unittest.mock import AsyncMock, Mock

import pytest

from unifi_fabric.tools.site_manager import _resolve_ea_site_record


def registry_for(rows):
    api = Mock()
    api.list_key_labels.return_value = list(rows)
    api.get_key_by_label.side_effect = lambda label: label
    api.paginate_max_pages = None
    registry = Mock()
    registry.get_ea_sites = AsyncMock(side_effect=lambda key: rows[key])
    registry._client = api
    return registry


@pytest.mark.parametrize("bad", [[None], ["bad-row"], {}, None])
@pytest.mark.parametrize("selector", ["site-abc", "Selected"])
async def test_bad_key_does_not_hide_other_keys_matching_site(bad, selector):
    registry = registry_for(
        {
            "broken": bad,
            "healthy": [{"siteId": "site-abc", "hostId": "host-abc", "meta": {"name": "Selected"}}],
        }
    )
    result = await _resolve_ea_site_record(registry, selector)
    assert result["_resolvedSiteId"] == "site-abc"
    if selector == "site-abc":
        assert "_incomplete" not in result and "_incompleteReason" not in result
    else:
        assert result["_incomplete"] is True
        assert "broken" in result["_incompleteReason"]
        assert "shape" in result["_incompleteReason"]
    assert registry.get_ea_sites.await_count == 2


@pytest.mark.parametrize("healthy", [[], [{"siteId": "another", "hostId": "host-abc"}], [None]])
async def test_no_match_reports_every_failed_key(healthy):
    registry = registry_for({"broken-one": [None], "broken-two": [7], "healthy": healthy})
    with pytest.raises(ValueError) as caught:
        await _resolve_ea_site_record(registry, "missing")
    message = str(caught.value)
    assert "broken-one" in message and "broken-two" in message and "shape" in message
    if healthy == [None]:
        assert "healthy" in message
    assert registry.get_ea_sites.await_count == 3
