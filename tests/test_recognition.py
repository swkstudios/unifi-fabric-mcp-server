"""Tests for the private Protect face/vehicle recognition tools.

Covers happy path, host-not-found error translation, links.next pagination drain,
explicit single-page paging, epoch-seconds→milliseconds time windows, and base64
encoding of the image endpoints. All timestamps are runtime-relative (never hardcoded),
and every fixture value is synthetic — no real subject names appear here.
"""

from __future__ import annotations

import base64
import time
from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from unifi_fabric.client import (
    PaginationAbortedError,
    UniFiClient,
    UniFiConnectionError,
)
from unifi_fabric.config import Settings
from unifi_fabric.tools.recognition import (
    RECOGNITION_PRIVATE_BASE,
    get_recognition_group_counts,
    get_recognition_group_image,
    get_thumbnail,
    list_recognition_detections,
    list_recognition_groups,
)

HOST_ID = "host-001"
PRIVATE_BASE = RECOGNITION_PRIVATE_BASE.format(host_id=HOST_ID)

# A truncated/invalid host id returns this from the connector; the tools must reframe it
# as a host-id error rather than surface it as a confusing 403.
_HOST_NOT_FOUND = UniFiConnectionError("HTTP 403 forbidden: host not found")


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.get_bytes = AsyncMock()
    c.paginate_links = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    return r


# --- list_recognition_groups ---


class TestListRecognitionGroups:
    async def test_uses_private_recognition_path_not_integration(self, client, registry):
        client.paginate_links.return_value = []
        await list_recognition_groups(client, registry, "h", "face")
        path = client.paginate_links.call_args.args[0]
        array_field = client.paginate_links.call_args.args[1]
        assert path == f"{PRIVATE_BASE}/recognition/face/groups"
        assert array_field == "groups"
        assert "/integration/" not in path

    async def test_drains_all_groups_by_default(self, client, registry):
        client.paginate_links.return_value = [{"id": "face_1"}, {"id": "face_90"}]
        result = await list_recognition_groups(client, registry, "h", "face")
        client.paginate_links.assert_called_once()
        client.get.assert_not_called()
        assert result["count"] == 2
        assert [g["id"] for g in result["groups"]] == ["face_1", "face_90"]

    async def test_filter_and_sort_params_passed_through(self, client, registry):
        client.paginate_links.return_value = []
        await list_recognition_groups(
            client,
            registry,
            "h",
            "face",
            has_name=True,
            order_by="name",
            order_direction="asc",
        )
        params = client.paginate_links.call_args.kwargs["params"]
        assert params["hasName"] is True
        assert params["orderBy"] == "name"
        assert params["orderDirection"] == "asc"

    async def test_name_label_is_not_redacted(self, client, registry):
        # Pass-through: the group's name/matchedName labels must survive verbatim. The
        # value is synthetic and is the whole point of the tool.
        client.paginate_links.return_value = [
            {"id": "face_1", "name": "Synthetic-Label-A", "matchedName": "Synthetic-Label-A"}
        ]
        result = await list_recognition_groups(client, registry, "h", "face")
        assert result["groups"][0]["name"] == "Synthetic-Label-A"
        assert result["groups"][0]["matchedName"] == "Synthetic-Label-A"
        assert "[REDACTED]" not in str(result)

    async def test_explicit_page_fetches_single_page_and_surfaces_next(self, client, registry):
        client.get.return_value = {
            "groups": [{"id": "face_1"}],
            "links": {"prev": None, "next": "/recognition/face/groups?pageSize=200&page=3"},
        }
        result = await list_recognition_groups(client, registry, "h", "face", page=2)
        client.get.assert_called_once()
        client.paginate_links.assert_not_called()
        assert result["count"] == 1
        assert result["nextPage"] == 3

    async def test_explicit_page_last_page_has_no_next(self, client, registry):
        client.get.return_value = {"groups": [{"id": "face_4"}], "links": {"next": None}}
        result = await list_recognition_groups(client, registry, "h", "face", page=9)
        assert "nextPage" not in result

    async def test_capped_drain_marked_incomplete(self, client, registry):
        client.paginate_links.side_effect = PaginationAbortedError(
            f"{PRIVATE_BASE}/recognition/face/groups",
            2,
            "page cap of 2 reached",
            items=[{"id": "face_1"}],
        )
        result = await list_recognition_groups(client, registry, "h", "face")
        assert result["incomplete"] is True
        assert result["count"] == 1

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.paginate_links.side_effect = _HOST_NOT_FOUND
        with pytest.raises(UniFiConnectionError, match="host id"):
            await list_recognition_groups(client, registry, "h", "face")

    async def test_unsafe_type_rejected_before_network(self, client, registry):
        with pytest.raises(ValueError, match="type"):
            await list_recognition_groups(client, registry, "h", "../secrets")
        client.paginate_links.assert_not_called()
        client.get.assert_not_called()

    async def test_license_plate_type_not_pre_rejected(self, client, registry):
        # 'license-plate' passes our path-safety check; upstream decides whether it is a
        # valid type. We must not narrow the accepted set below what the API accepts.
        client.paginate_links.return_value = []
        await list_recognition_groups(client, registry, "h", "license-plate")
        path = client.paginate_links.call_args.args[0]
        assert path == f"{PRIVATE_BASE}/recognition/license-plate/groups"


# --- get_recognition_group_counts ---


class TestGetRecognitionGroupCounts:
    async def test_basic(self, client, registry):
        client.get.return_value = {"totalCount": 67, "nameNotNullCount": 6}
        result = await get_recognition_group_counts(client, registry, "h", "face")
        client.get.assert_called_once_with(f"{PRIVATE_BASE}/recognition/face/groups/counts")
        assert result["totalCount"] == 67

    async def test_non_dict_wrapped(self, client, registry):
        client.get.return_value = ["raw"]
        result = await get_recognition_group_counts(client, registry, "h", "face")
        assert result == {"data": ["raw"]}

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.get.side_effect = _HOST_NOT_FOUND
        with pytest.raises(UniFiConnectionError, match="host id"):
            await get_recognition_group_counts(client, registry, "h", "face")


# --- get_recognition_group_image (base64) ---


class TestGetRecognitionGroupImage:
    async def test_base64_encodes_raw_jpeg(self, client, registry):
        raw = b"\xff\xd8\xff\xe0synthetic-jpeg-bytes"
        client.get_bytes.return_value = raw
        result = await get_recognition_group_image(client, registry, "h", "face", "face_90")
        client.get_bytes.assert_called_once_with(
            f"{PRIVATE_BASE}/recognition/face/groups/face_90/image"
        )
        assert result["content_type"] == "image/jpeg"
        assert result["size_bytes"] == len(raw)
        assert base64.b64decode(result["image_base64"]) == raw

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.get_bytes.side_effect = _HOST_NOT_FOUND
        with pytest.raises(UniFiConnectionError, match="host id"):
            await get_recognition_group_image(client, registry, "h", "face", "face_1")


# --- list_recognition_detections ---


class TestListRecognitionDetections:
    async def test_uses_detections_path(self, client, registry):
        client.paginate_links.return_value = []
        await list_recognition_detections(client, registry, "h", "face", "face_90")
        path = client.paginate_links.call_args.args[0]
        array_field = client.paginate_links.call_args.args[1]
        assert path == f"{PRIVATE_BASE}/recognition/face/groups/face_90/detections"
        assert array_field == "detections"

    async def test_drains_all_detections_by_default(self, client, registry):
        client.paginate_links.return_value = [{"id": "d1"}, {"id": "d2"}, {"id": "d3"}]
        result = await list_recognition_detections(client, registry, "h", "face", "face_90")
        client.paginate_links.assert_called_once()
        client.get.assert_not_called()
        assert result["count"] == 3

    async def test_time_window_seconds_converted_to_milliseconds(self, client, registry):
        client.paginate_links.return_value = []
        now_s = int(time.time())
        start_s = now_s - 3600  # last hour, runtime-relative
        await list_recognition_detections(
            client, registry, "h", "face", "face_90", start=start_s, end=now_s
        )
        params = client.paginate_links.call_args.kwargs["params"]
        # Verified live: the endpoint wants epoch MILLISECONDS; the tool accepts seconds.
        assert params["start"] == start_s * 1000
        assert params["end"] == now_s * 1000

    async def test_rejects_millisecond_magnitude_start(self, client, registry):
        now_ms = int(time.time()) * 1000
        with pytest.raises(ValueError, match="milliseconds"):
            await list_recognition_detections(
                client, registry, "h", "face", "face_90", start=now_ms
            )
        client.paginate_links.assert_not_called()

    async def test_confidence_survives_passthrough(self, client, registry):
        client.paginate_links.return_value = [
            {"id": "d1", "matchedGroupConfidence": 85, "thumbnailId": "AABBCCDDEEFF-1"}
        ]
        result = await list_recognition_detections(client, registry, "h", "face", "face_90")
        assert result["detections"][0]["matchedGroupConfidence"] == 85

    async def test_explicit_page_surfaces_next(self, client, registry):
        client.get.return_value = {
            "detections": [{"id": "d1"}],
            "links": {"next": "/recognition/face/groups/face_90/detections?pageSize=200&page=2"},
        }
        result = await list_recognition_detections(client, registry, "h", "face", "face_90", page=1)
        client.get.assert_called_once()
        assert result["nextPage"] == 2

    async def test_capped_drain_marked_incomplete(self, client, registry):
        client.paginate_links.side_effect = PaginationAbortedError(
            f"{PRIVATE_BASE}/recognition/face/groups/face_90/detections",
            2,
            "page cap of 2 reached",
            items=[{"id": "d1"}],
        )
        result = await list_recognition_detections(client, registry, "h", "face", "face_90")
        assert result["incomplete"] is True
        assert result["count"] == 1

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.paginate_links.side_effect = _HOST_NOT_FOUND
        with pytest.raises(UniFiConnectionError, match="host id"):
            await list_recognition_detections(client, registry, "h", "face", "face_90")


# --- get_thumbnail (base64) ---


class TestGetThumbnail:
    async def test_base64_encodes_raw_jpeg(self, client, registry):
        raw = b"\xff\xd8\xff\xe0synthetic-thumbnail"
        client.get_bytes.return_value = raw
        result = await get_thumbnail(client, registry, "h", "AABBCCDDEEFF-1785656054573")
        client.get_bytes.assert_called_once_with(
            f"{PRIVATE_BASE}/thumbnails/AABBCCDDEEFF-1785656054573"
        )
        assert result["content_type"] == "image/jpeg"
        assert result["size_bytes"] == len(raw)
        assert base64.b64decode(result["image_base64"]) == raw

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.get_bytes.side_effect = _HOST_NOT_FOUND
        with pytest.raises(UniFiConnectionError, match="host id"):
            await get_thumbnail(client, registry, "h", "AABBCCDDEEFF-1")


# --- Real links.next drain (exercises UniFiClient.paginate_links against synthetic pages) ---

BASE_URL = "https://api.ui.com"
_DET_PATH = f"{PRIVATE_BASE}/recognition/face/groups/face_90/detections"


def _det_page(ids: list[str], next_page: int | None) -> dict:
    nxt = None if next_page is None else f"{_DET_PATH}?pageSize=2&page={next_page}"
    return {"detections": [{"id": i} for i in ids], "links": {"prev": None, "next": nxt}}


class TestPaginateLinksDrain:
    @respx.mock
    async def test_walks_pages_until_links_next_null(self):
        c = UniFiClient(Settings(api_key="sk-test"))
        route = respx.get(f"{BASE_URL}{_DET_PATH}")
        route.side_effect = [
            Response(200, json=_det_page(["a", "b"], 2)),
            Response(200, json=_det_page(["c", "d"], 3)),
            Response(200, json=_det_page(["e"], None)),
        ]
        items = await c.paginate_links(_DET_PATH, "detections", page_size=2)
        assert route.call_count == 3
        assert [i["id"] for i in items] == ["a", "b", "c", "d", "e"]
        # Pages are requested by incrementing page=1,2,3.
        assert route.calls[0].request.url.params["page"] == "1"
        assert route.calls[2].request.url.params["page"] == "3"
        await c.close()

    @respx.mock
    async def test_page_cap_raises_with_partial_items(self):
        c = UniFiClient(Settings(api_key="sk-test", paginate_max_pages=2))
        route = respx.get(f"{BASE_URL}{_DET_PATH}")
        # Every page advertises a next page, so only the cap can stop the drain.
        route.side_effect = [
            Response(200, json=_det_page(["a", "b"], 2)),
            Response(200, json=_det_page(["c", "d"], 3)),
            Response(200, json=_det_page(["e", "f"], 4)),
        ]
        with pytest.raises(PaginationAbortedError) as exc_info:
            await c.paginate_links(_DET_PATH, "detections", page_size=2)
        # The pages already paid for are carried on the exception, not thrown away.
        assert [i["id"] for i in exc_info.value.items] == ["a", "b", "c", "d"]
        await c.close()
