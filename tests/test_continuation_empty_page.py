"""Continuation links remain authoritative on empty numbered pages."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.recognition import list_recognition_detections, list_recognition_groups


@pytest.mark.parametrize("field", ["groups", "detections"])
@pytest.mark.parametrize("cap", [None, 2])
async def test_recognition_empty_middle_page(field, cap):
    client = UniFiClient(Settings(api_key="test-key", paginate_max_pages=cap))
    registry = Registry(client)
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="abc123")
    client.get = AsyncMock(
        side_effect=[
            {field: [{"id": "first"}], "links": {"next": "?page=2"}, "total": 2},
            {field: [], "links": {"next": "?page=3"}},
            {field: [{"id": "last"}], "links": {"next": None}},
        ]
    )
    if field == "groups":
        result = await list_recognition_groups(client, registry, "abc123", "face")
    else:
        result = await list_recognition_detections(client, registry, "abc123", "face", "face_1")
    assert result[field] == ([{"id": "first"}] if cap else [{"id": "first"}, {"id": "last"}])
    assert result["total"] == 2
    assert bool(result.get("incomplete")) == bool(cap)
    assert client.get.await_count == (2 if cap else 3)
