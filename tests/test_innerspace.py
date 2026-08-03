"""Tests for InnerSpace floor-plan tools.

All device identifiers, coordinates, and product ids in these fixtures are
synthetic — no real hardware, MACs, IPs, host ids, or site coordinates.
"""

from __future__ import annotations

import copy
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.innerspace import (
    INNERSPACE_PROXY_BASE,
    get_innerspace_project,
    get_innerspace_summary,
    list_innerspace_devices,
)

HOST_ID = "host-001"
BASE = INNERSPACE_PROXY_BASE.format(host_id=HOST_ID)


def _sample_project(mode: str = "3D") -> dict:
    """A fully synthetic InnerSpace project document."""
    z = 2.5 if mode == "3D" else 0
    return {
        "flags": {},
        "planScales": {"height": 3.048037, "scale": 57.25241},
        "shapes": [
            {
                "type": "wall",
                "variant": "wood",
                "position": [{"x": -10.0, "y": -20.0, "z": 0}, {"x": -10.0, "y": -30.0, "z": 0}],
            },
            {
                "type": "wall",
                "variant": "drywall_heavy",
                "position": [{"x": 0.0, "y": 0.0, "z": 0}, {"x": 5.0, "y": 0.0, "z": 0}],
            },
            {
                "type": "wall",
                "variant": "door_wood",
                "position": [{"x": 5.0, "y": 0.0, "z": 0}, {"x": 6.0, "y": 0.0, "z": 0}],
            },
            {
                "type": "device",
                "mount": "ceiling",
                "productId": "prod-synthetic-1",
                "title": "AP Test 1",
                "position": [{"x": 1.0, "y": 2.0, "z": z}],
                "rotation": {"pov": [0, 0, 0, 1], "base": [0, 0, 0, 1]},
                "meta": {
                    "mac": "aa:bb:cc:00:11:22",
                    "ip": "192.0.2.55",
                    "adopted": True,
                    "thumbnail": "https://example.invalid/asset/thumb.png",
                },
            },
            {
                "type": "map",
                "position": [{"x": 0, "y": 0, "z": 0}],
                "image": "https://example.invalid/floorplan.png",
            },
            {"type": "scale", "position": [{"x": 0, "y": 0, "z": 0}]},
        ],
        "plans": [
            {"ordering": 0, "name": "Ground Floor", "scale": 57.25241},
            {"ordering": 1, "name": "First Floor", "planScale": {"scale": 60.0}},
        ],
        "products": [{"id": "prod-synthetic-1", "name": "Synthetic AP"}],
        "wallTypes": [],
        "attenuationObjectTypes": [],
        "project": {"unit": "imperial", "migrated": True},
    }


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    return r


class TestGeometryPassThrough:
    """The project document is returned verbatim — the server withholds nothing.

    These were previously redaction tests on a now-removed sanitizer; they are
    inverted to data-survival checks through the public tool.
    """

    async def test_mac_and_ip_survive_at_any_depth(self, client, registry):
        client.get.return_value = {
            "device": {"meta": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.1", "ok": 1}}
        }
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        meta = result["project"]["device"]["meta"]
        assert meta["mac"] == "aa:bb:cc:dd:ee:ff"
        assert meta["ip"] == "192.0.2.1"
        assert meta["ok"] == 1

    async def test_asset_urls_survive(self, client, registry):
        client.get.return_value = {"image": "https://example.invalid/x.png", "name": "keep"}
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        assert result["project"]["image"] == "https://example.invalid/x.png"
        assert result["project"]["name"] == "keep"

    async def test_data_uri_survives(self, client, registry):
        client.get.return_value = {"image": "data:image/png;base64,AAAA"}
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        assert result["project"]["image"] == "data:image/png;base64,AAAA"

    async def test_preserves_coordinates_and_numbers(self, client, registry):
        payload = {"position": [{"x": -10.5, "y": 2.0, "z": 2.5}]}
        client.get.return_value = copy.deepcopy(payload)
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        assert result["project"] == payload


class TestGetInnerspaceProject:
    async def test_3d_mode_passes_param(self, client, registry):
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        client.get.assert_called_once_with(f"{BASE}/project", params={"mode": "3D"})
        assert result["mode"] == "3D"

    async def test_2d_mode_passes_param(self, client, registry):
        client.get.return_value = _sample_project("2D")
        result = await get_innerspace_project(client, registry, "myhost", "2D")
        client.get.assert_called_once_with(f"{BASE}/project", params={"mode": "2D"})
        assert result["mode"] == "2D"

    async def test_default_mode_is_3d(self, client, registry):
        client.get.return_value = _sample_project("3D")
        await get_innerspace_project(client, registry, "myhost")
        client.get.assert_called_once_with(f"{BASE}/project", params={"mode": "3D"})

    async def test_2d_device_height_is_zero_3d_is_real(self, client, registry):
        client.get.return_value = _sample_project("2D")
        result_2d = await get_innerspace_project(client, registry, "myhost", "2D")
        device_2d = next(s for s in result_2d["project"]["shapes"] if s["type"] == "device")
        assert device_2d["position"][0]["z"] == 0

        client.get.return_value = _sample_project("3D")
        result_3d = await get_innerspace_project(client, registry, "myhost", "3D")
        device_3d = next(s for s in result_3d["project"]["shapes"] if s["type"] == "device")
        assert device_3d["position"][0]["z"] == 2.5

    async def test_mac_ip_and_asset_urls_survive(self, client, registry):
        # Data-survival: floor-plan asset URLs and device meta.mac/meta.ip are the
        # human-meaningful payload — they must reach the caller unchanged.
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        shapes = result["project"]["shapes"]
        device = next(s for s in shapes if s["type"] == "device")
        assert device["meta"]["mac"] == "aa:bb:cc:00:11:22"
        assert device["meta"]["ip"] == "192.0.2.55"
        assert device["meta"]["thumbnail"] == "https://example.invalid/asset/thumb.png"
        assert device["meta"]["adopted"] is True
        map_shape = next(s for s in shapes if s["type"] == "map")
        assert map_shape["image"] == "https://example.invalid/floorplan.png"
        # The identifiers are present in the serialized output — nothing is withheld.
        serialized = repr(result)
        assert "aa:bb:cc" in serialized
        assert "192.0.2.55" in serialized

    async def test_invalid_mode_rejected(self, client, registry):
        with pytest.raises(ValueError, match="Invalid mode"):
            await get_innerspace_project(client, registry, "myhost", "4D")

    async def test_resolves_host(self, client, registry):
        client.get.return_value = _sample_project("3D")
        await get_innerspace_project(client, registry, "MyHost", "3D")
        registry.resolve_host_id.assert_called_once_with("MyHost")

    async def test_truncated_host_id_403_gives_clear_message(self, client, registry):
        client.get.side_effect = UniFiConnectionError(
            "HTTP 403 from GET /v1/connector/consoles/[REDACTED]/proxy/innerspace/api/project: "
            '{"code":"forbidden","message":"forbidden: host not found"}'
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await get_innerspace_project(client, registry, "truncated-host", "3D")
        message = str(exc.value)
        assert "composite host id" in message
        assert "list_hosts" in message
        assert "does NOT mean InnerSpace is unavailable" in message

    async def test_other_errors_pass_through(self, client, registry):
        client.get.side_effect = UniFiConnectionError("HTTP 500 from GET ...: server error")
        with pytest.raises(UniFiConnectionError, match="HTTP 500"):
            await get_innerspace_project(client, registry, "myhost", "3D")


class TestGetInnerspaceSummary:
    async def test_shape_breakdown_by_type(self, client, registry):
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        assert result["shape_counts"] == {"wall": 3, "device": 1, "map": 1, "scale": 1}
        assert result["shape_total"] == 6
        assert result["wall_variants"] == {"wood": 1, "drywall_heavy": 1, "door_wood": 1}

    async def test_plan_and_dictionary_counts(self, client, registry):
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        assert result["plan_count"] == 2
        assert result["product_count"] == 1
        assert result["wall_type_count"] == 0
        assert result["attenuation_object_type_count"] == 0
        assert result["project"] == {"unit": "imperial", "migrated": True}
        assert result["plan_scales"] == {"height": 3.048037, "scale": 57.25241}

    async def test_per_plan_scale_extracted(self, client, registry):
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        scales = {p["name"]: p["scale"] for p in result["plans"]}
        assert scales == {"Ground Floor": 57.25241, "First Floor": 60.0}

    async def test_multi_floor_note_present(self, client, registry):
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        assert result["multi_floor"] is True
        assert "do NOT share a coordinate origin" in result["multi_floor_note"]

    async def test_single_floor_has_no_note(self, client, registry):
        payload = _sample_project("3D")
        payload["plans"] = [payload["plans"][0]]
        client.get.return_value = payload
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        assert result["multi_floor"] is False
        assert "multi_floor_note" not in result

    async def test_summary_does_not_leak_identifiers(self, client, registry):
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        serialized = repr(result)
        assert "aa:bb:cc" not in serialized
        assert "192.0.2.55" not in serialized


class TestListInnerspaceDevices:
    async def test_filters_device_shapes_only(self, client, registry):
        client.get.return_value = _sample_project("3D")
        result = await list_innerspace_devices(client, registry, "myhost", "3D")
        assert result["count"] == 1
        assert result["devices"][0]["type"] == "device"
        assert result["devices"][0]["title"] == "AP Test 1"

    async def test_device_meta_survives(self, client, registry):
        # Data-survival: device meta.mac / meta.ip pass through verbatim.
        client.get.return_value = _sample_project("3D")
        result = await list_innerspace_devices(client, registry, "myhost", "3D")
        meta = result["devices"][0]["meta"]
        assert meta["mac"] == "aa:bb:cc:00:11:22"
        assert meta["ip"] == "192.0.2.55"

    async def test_2d_flattens_height(self, client, registry):
        client.get.return_value = _sample_project("2D")
        result = await list_innerspace_devices(client, registry, "myhost", "2D")
        assert result["devices"][0]["position"][0]["z"] == 0
        assert result["mode"] == "2D"

    async def test_input_payload_not_mutated(self, client, registry):
        payload = _sample_project("3D")
        original = copy.deepcopy(payload)
        client.get.return_value = payload
        await list_innerspace_devices(client, registry, "myhost", "3D")
        assert payload == original
