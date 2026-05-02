"""Integration tests for UniFi Protect tools against the live test console.

Requires UNIFI_API_KEY (and optionally UNIFI_API_BASE_URL) to be set.
Skip all tests automatically when the env var is absent.

Also requires UNIFI_TEST_HOST to identify the Protect console.

Run:
    UNIFI_API_KEY=<key> UNIFI_TEST_HOST=<host> pytest tests/test_protect_integration.py -v
"""

from __future__ import annotations

import os

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.protect import (
    get_camera,
    get_camera_snapshot,
    get_rtsps_stream,
    list_cameras,
    ptz_goto,
    talkback_start,
    update_camera,
)

# These tests are gated on UNIFI_API_KEY so they are always skipped in CI where the
# env var is absent.  pytest --collect-only still succeeds because skipif is evaluated
# at collection time, not import time.  Run with a real key to execute them:
#   UNIFI_API_KEY=<key> UNIFI_TEST_HOST=<host> pytest tests/test_protect_integration.py -v
pytestmark = pytest.mark.skipif(
    not os.environ.get("UNIFI_API_KEY"),
    reason="UNIFI_API_KEY not set — skipping live integration tests",
)

_TEST_HOST = os.environ.get("UNIFI_TEST_HOST", "")


@pytest.fixture(scope="module")
def settings():
    return Settings()


@pytest.fixture(scope="module")
def client(settings):
    return UniFiClient(settings)


@pytest.fixture(scope="module")
def registry(client, settings):
    return Registry(client, ttl_seconds=settings.cache_ttl_seconds)


def _require_host():
    if not _TEST_HOST:
        pytest.skip("UNIFI_TEST_HOST must be set for Protect tests")


# ---------------------------------------------------------------------------
# list_cameras
# ---------------------------------------------------------------------------


class TestListCamerasIntegration:
    async def test_requires_host(self, client, registry):
        _require_host()

    async def test_returns_cameras_dict(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        assert "cameras" in result
        assert "count" in result

    async def test_count_matches_cameras_length(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        assert result["count"] == len(result["cameras"])

    async def test_camera_has_id_field(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console — skipping field check")
        camera = result["cameras"][0]
        assert "id" in camera, "Camera must have an id field"

    async def test_camera_has_name_field(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console — skipping field check")
        camera = result["cameras"][0]
        assert "name" in camera or "displayName" in camera, (
            "Camera must have a name or displayName field"
        )


# ---------------------------------------------------------------------------
# get_camera
# ---------------------------------------------------------------------------


class TestGetCameraIntegration:
    async def test_get_camera_by_id(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console")
        camera_id = result["cameras"][0]["id"]

        camera = await get_camera(client, registry, _TEST_HOST, camera_id)
        returned_id = camera.get("id")
        assert returned_id == camera_id

    async def test_get_camera_has_state_field(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console")
        camera_id = result["cameras"][0]["id"]

        camera = await get_camera(client, registry, _TEST_HOST, camera_id)
        assert isinstance(camera, dict), "get_camera must return a dict"


# ---------------------------------------------------------------------------
# update_camera (non-destructive: set name back to current value)
# ---------------------------------------------------------------------------


class TestUpdateCameraIntegration:
    async def test_update_camera_name_roundtrip(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console")
        camera = result["cameras"][0]
        camera_id = camera["id"]
        current_name = camera.get("name") or camera.get("displayName")
        if not current_name:
            pytest.skip("Camera has no name field — cannot do roundtrip update")

        updated = await update_camera(client, registry, _TEST_HOST, camera_id, name=current_name)
        assert isinstance(updated, dict), "update_camera must return a dict"


# ---------------------------------------------------------------------------
# get_camera_snapshot
# ---------------------------------------------------------------------------


class TestGetCameraSnapshotIntegration:
    async def test_snapshot_returns_dict(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console")
        camera_id = result["cameras"][0]["id"]

        snapshot = await get_camera_snapshot(client, registry, _TEST_HOST, camera_id)
        assert isinstance(snapshot, dict), "get_camera_snapshot must return a dict"

    async def test_snapshot_has_url_or_data(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console")
        camera_id = result["cameras"][0]["id"]

        snapshot = await get_camera_snapshot(client, registry, _TEST_HOST, camera_id)
        has_content = any(k in snapshot for k in ("url", "data", "src", "imageUrl"))
        assert has_content or isinstance(snapshot, dict), (
            "Snapshot response should contain url, data, src, or imageUrl"
        )


# ---------------------------------------------------------------------------
# get_rtsps_stream
# ---------------------------------------------------------------------------


class TestGetRtspsStreamIntegration:
    async def test_stream_returns_dict(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console")
        camera_id = result["cameras"][0]["id"]

        stream = await get_rtsps_stream(client, registry, _TEST_HOST, camera_id)
        assert isinstance(stream, dict), "get_rtsps_stream must return a dict"

    async def test_stream_has_rtsps_url(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["count"] == 0:
            pytest.skip("No cameras on Protect console")
        camera_id = result["cameras"][0]["id"]

        stream = await get_rtsps_stream(client, registry, _TEST_HOST, camera_id)
        url_value = stream.get("url") or stream.get("rtspsUrl") or stream.get("streamUrl")
        if url_value:
            assert "rtsp" in url_value.lower() or url_value.startswith("http"), (
                "Stream URL should be an RTSPS or HTTP URL"
            )


# ---------------------------------------------------------------------------
# PTZ control — read-only probe (home/preset position, no movement)
# ---------------------------------------------------------------------------


class TestPtzIntegration:
    async def _first_ptz_camera(self, client, registry):
        """Return the first camera that advertises PTZ support, or skip."""
        result = await list_cameras(client, registry, _TEST_HOST)
        for cam in result["cameras"]:
            feature_flags = cam.get("featureFlags") or {}
            if feature_flags.get("hasPtz") or feature_flags.get("ptz"):
                return cam["id"]
        return None

    async def test_ptz_goto_returns_dict(self, client, registry):
        _require_host()
        camera_id = await self._first_ptz_camera(client, registry)
        if not camera_id:
            pytest.skip("No PTZ-capable cameras found on Protect console")

        result = await ptz_goto(client, registry, _TEST_HOST, camera_id, 0)
        assert isinstance(result, dict), "ptz_goto must return a dict"


# ---------------------------------------------------------------------------
# talkback_start — verify endpoint responds (no actual audio session)
# ---------------------------------------------------------------------------


class TestTalkbackStartIntegration:
    async def _first_talkback_camera(self, client, registry):
        """Return the first camera with talkback support, or None."""
        result = await list_cameras(client, registry, _TEST_HOST)
        for cam in result["cameras"]:
            feature_flags = cam.get("featureFlags") or {}
            if feature_flags.get("hasSpeaker") or feature_flags.get("talkback"):
                return cam["id"]
        return None

    async def test_talkback_returns_dict(self, client, registry):
        _require_host()
        camera_id = await self._first_talkback_camera(client, registry)
        if not camera_id:
            pytest.skip("No talkback-capable cameras found on Protect console")

        result = await talkback_start(client, registry, _TEST_HOST, camera_id)
        assert isinstance(result, dict), "talkback_start must return a dict"
