"""Integration tests for UniFi Protect tools against the live test console.

Requires UNIFI_API_KEY (and optionally UNIFI_API_BASE_URL) to be set.
Skip all tests automatically when the env var is absent.

Also requires UNIFI_TEST_HOST to identify the Protect console. Mutating tests require
explicit marker selection and UNIFI_TEST_ALLOW_MUTATIONS=1, with dry-run disabled; the
shared gate in tests/_live_gates.py (run from tests/conftest.py) enforces this.

Run (with UNIFI_API_KEY already in the environment, loaded from a secret store; never
type the key on the command line, where shell history keeps it):
    UNIFI_TEST_HOST=<host> pytest tests/test_protect_integration.py -v
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.protect.protect import (
    get_camera,
    get_camera_snapshot,
    get_rtsps_stream,
    list_cameras,
    ptz_goto,
    talkback_start,
    update_camera,
)
from unifi_fabric.registry import Registry
from unifi_fabric.route_secrets import MASK

# These tests are gated on UNIFI_API_KEY so they are always skipped in CI where the
# env var is absent.  pytest --collect-only still succeeds because skipif is evaluated
# at collection time, not import time.  Run them with a real key in the environment
# (loaded from a secret store, never typed on the command line):
#   UNIFI_TEST_HOST=<host> pytest tests/test_protect_integration.py -v
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("UNIFI_API_KEY"),
        reason="UNIFI_API_KEY not set — skipping live integration tests",
    ),
    # Share ONE event loop across every test in the module so the module-scoped client
    # (and its lazily-created httpx.AsyncClient) stays valid for all tests. Without this,
    # pytest-asyncio's default function-scoped loop closes after the first test and every
    # subsequent test dies in httpx teardown with "Event loop is closed".
    pytest.mark.asyncio(loop_scope="module"),
]

_TEST_HOST = os.environ.get("UNIFI_TEST_HOST", "")


@pytest.fixture(scope="module")
def settings():
    return Settings()


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def client(settings):
    c = UniFiClient(settings)
    yield c
    await c.close()


@pytest.fixture(scope="module")
def registry(client, settings):
    return Registry(client, ttl_seconds=settings.cache_ttl_seconds)


def _require_host():
    if not _TEST_HOST:
        pytest.fail("UNIFI_TEST_HOST must be set for Protect tests")


def _cameras(result: dict) -> list:
    """The camera list from a 0.7.0 list_cameras result.

    The upstream bare JSON array is returned under "result" (FastMCP's key for a list
    result); an upstream object carrying a "data" array would be returned verbatim. The
    additive "_count" is the number of cameras either way.
    """
    return result["result"] if "result" in result else result["data"]


# ---------------------------------------------------------------------------
# list_cameras
# ---------------------------------------------------------------------------


class TestListCamerasIntegration:
    async def test_requires_host(self, client, registry):
        _require_host()

    async def test_returns_cameras_dict(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        assert "result" in result or "data" in result
        assert isinstance(_cameras(result), list)
        assert "_count" in result

    async def test_count_matches_cameras_length(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        assert result["_count"] == len(_cameras(result))

    async def test_camera_has_id_field(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console — field check requires data")
        camera = _cameras(result)[0]
        assert "id" in camera, "Camera must have an id field"

    async def test_camera_has_name_field(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console — field check requires data")
        camera = _cameras(result)[0]
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
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console")
        camera_id = _cameras(result)[0]["id"]

        camera = await get_camera(client, registry, _TEST_HOST, camera_id)
        returned_id = camera.get("id")
        assert returned_id == camera_id

    async def test_get_camera_returns_dict(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console")
        camera_id = _cameras(result)[0]["id"]

        camera = await get_camera(client, registry, _TEST_HOST, camera_id)
        assert isinstance(camera, dict), "get_camera must return a dict"


# ---------------------------------------------------------------------------
# update_camera — LIVE WRITE against the production console. Setting the name back
# to its current value still issues a real update (PATCH/PUT) request to the device;
# it is NOT a read-only or "non-destructive" probe. Marked mutating and excluded from
# the unattended canary (deselected by marker: `-m 'integration and not mutating'`).
# ---------------------------------------------------------------------------


@pytest.mark.mutating
class TestUpdateCameraIntegration:
    async def test_update_camera_name_roundtrip(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console")
        camera = _cameras(result)[0]
        camera_id = camera["id"]
        current_name = camera.get("name") or camera.get("displayName")
        if not current_name:
            pytest.fail("Camera has no name field — cannot do roundtrip update")

        updated = await update_camera(client, registry, _TEST_HOST, camera_id, name=current_name)
        assert isinstance(updated, dict), "update_camera must return a dict"


# ---------------------------------------------------------------------------
# get_camera_snapshot
# ---------------------------------------------------------------------------


class TestGetCameraSnapshotIntegration:
    async def test_snapshot_returns_dict(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console")
        camera_id = _cameras(result)[0]["id"]

        snapshot = await get_camera_snapshot(client, registry, _TEST_HOST, camera_id)
        assert isinstance(snapshot, dict), "get_camera_snapshot must return a dict"

    async def test_snapshot_has_url_or_data(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console")
        camera_id = _cameras(result)[0]["id"]

        snapshot = await get_camera_snapshot(client, registry, _TEST_HOST, camera_id)
        # 0.7.0 returns the image bytes as base64 with the upstream Content-Type and size.
        assert snapshot.get("image_base64"), "Snapshot response should carry image data"
        assert snapshot.get("size_bytes", 0) > 0, "Snapshot response should report its size"


# ---------------------------------------------------------------------------
# get_rtsps_stream
# ---------------------------------------------------------------------------


class TestGetRtspsStreamIntegration:
    async def test_stream_returns_dict(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console")
        camera_id = _cameras(result)[0]["id"]

        stream = await get_rtsps_stream(client, registry, _TEST_HOST, camera_id)
        assert isinstance(stream, dict), "get_rtsps_stream must return a dict"

    async def test_stream_has_rtsps_url(self, client, registry):
        _require_host()
        result = await list_cameras(client, registry, _TEST_HOST)
        if result["_count"] == 0:
            pytest.fail("No cameras on Protect console")
        camera_id = _cameras(result)[0]["id"]

        stream = await get_rtsps_stream(client, registry, _TEST_HOST, camera_id)
        # 0.7.0 returns the upstream body verbatim: one URL (or null) per stream quality.
        # The URLs carry stream tokens, so under the opt-in UNIFI_REDACT_SECRETS they are
        # replaced by the redaction mask; booleans are asserted so no URL reaches a log.
        redacting = client._settings.redact_secrets is True
        for quality in ("high", "medium", "low", "package"):
            url_value = stream.get(quality)
            if url_value:
                if redacting:
                    ok = url_value == MASK
                else:
                    ok = "rtsp" in url_value.lower() or url_value.startswith("http")
                assert ok, f"{quality} stream URL should be an RTSPS or HTTP URL (or masked)"


# ---------------------------------------------------------------------------
# PTZ control — LIVE ACTUATION against the production console. ptz_goto(..., 0) is a
# real pan/tilt/zoom MOVE command that physically drives the camera head to preset
# slot 0; it is NOT a read-only probe and there is no "no movement" guard. It only
# appears harmless today because the test estate has no PTZ-capable camera, so the test
# skips — that is incidental, not a safety guard. Marked mutating and excluded from the
# unattended canary (deselected by marker: `-m 'integration and not mutating'`).
# ---------------------------------------------------------------------------


@pytest.mark.mutating
class TestPtzIntegration:
    async def _first_ptz_camera(self, client, registry):
        """Return the first camera that advertises PTZ support, or skip."""
        result = await list_cameras(client, registry, _TEST_HOST)
        for cam in _cameras(result):
            feature_flags = cam.get("featureFlags") or {}
            if feature_flags.get("hasPtz") or feature_flags.get("ptz"):
                return cam["id"]
        return None

    async def test_ptz_goto_returns_dict(self, client, registry):
        _require_host()
        camera_id = await self._first_ptz_camera(client, registry)
        if not camera_id:
            pytest.fail("No PTZ-capable cameras found on Protect console")

        result = await ptz_goto(client, registry, _TEST_HOST, camera_id, 0, confirm=True)
        assert isinstance(result, dict), "ptz_goto must return a dict"


# ---------------------------------------------------------------------------
# talkback_start — LIVE ACTUATION against the production console. This opens a real
# two-way audio/speaker session on the camera or doorbell (confirmed firing during
# live validation); it is NOT a passive "endpoint responds" check and it DOES start
# an audio session. The session is transient and persists no state, but it is a real
# speaker actuation in a possibly-occupied space. Marked mutating and excluded from the
# unattended canary (deselected by marker: `-m 'integration and not mutating'`).
# ---------------------------------------------------------------------------


@pytest.mark.mutating
class TestTalkbackStartIntegration:
    async def _first_talkback_camera(self, client, registry):
        """Return the first camera with talkback support, or None."""
        result = await list_cameras(client, registry, _TEST_HOST)
        for cam in _cameras(result):
            feature_flags = cam.get("featureFlags") or {}
            if feature_flags.get("hasSpeaker") or feature_flags.get("talkback"):
                return cam["id"]
        return None

    async def test_talkback_returns_dict(self, client, registry):
        _require_host()
        camera_id = await self._first_talkback_camera(client, registry)
        if not camera_id:
            pytest.fail("No talkback-capable cameras found on Protect console")

        result = await talkback_start(client, registry, _TEST_HOST, camera_id, confirm=True)
        assert isinstance(result, dict), "talkback_start must return a dict"
