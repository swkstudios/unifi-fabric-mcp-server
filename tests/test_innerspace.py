"""Tests for InnerSpace floor-plan tools.

All device identifiers, coordinates, and product ids in these fixtures are
synthetic — no real hardware, MACs, IPs, host ids, or site coordinates.
"""

from __future__ import annotations

import base64
import copy
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.innerspace import (
    INNERSPACE_INTEGRATION_BASE,
    INNERSPACE_PROXY_BASE,
    MAX_ASSET_INLINE_BYTES,
    get_innerspace_asset,
    get_innerspace_project,
    get_innerspace_summary,
    list_innerspace_access_points,
    list_innerspace_devices,
    list_innerspace_floor_plans,
    list_innerspace_inventory,
    list_innerspace_switches,
)

HOST_ID = "host-001"
BASE = INNERSPACE_PROXY_BASE.format(host_id=HOST_ID)  # legacy /api path (fallback)
INTEGRATION_BASE = INNERSPACE_INTEGRATION_BASE.format(host_id=HOST_ID)  # documented path (primary)


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
    c.get_binary = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
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
        # Primary path is the documented integration API; mode and key are both passed.
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/project", key=None, params={"mode": "3D"}
        )
        assert result["mode"] == "3D"

    async def test_2d_mode_passes_param(self, client, registry):
        client.get.return_value = _sample_project("2D")
        result = await get_innerspace_project(client, registry, "myhost", "2D")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/project", key=None, params={"mode": "2D"}
        )
        assert result["mode"] == "2D"

    async def test_default_mode_is_3d(self, client, registry):
        client.get.return_value = _sample_project("3D")
        await get_innerspace_project(client, registry, "myhost")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/project", key=None, params={"mode": "3D"}
        )

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
        registry.resolve_host_id.assert_called_once_with("MyHost", key=None)

    async def test_403_on_both_paths_names_causes_and_both_paths(self, client, registry):
        # When BOTH the documented integration path and the legacy /api path are
        # 403-rejected, the error must surface BOTH plausible causes (truncated host
        # id AND an upstream connector that no longer proxies the innerspace
        # namespace) and name BOTH attempted paths — a message blaming only the host
        # id is misleading after the 2026-08-09 incident.
        client.get.side_effect = UniFiConnectionError(
            "HTTP 403 from GET /v1/connector/consoles/[REDACTED]/proxy/innerspace/...: "
            '{"code":"forbidden","message":"forbidden: host not found"}'
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await get_innerspace_project(client, registry, "truncated-host", "3D")
        message = str(exc.value)
        # Cause 1 — host id.
        assert "composite host id" in message
        assert "list_hosts" in message
        # Cause 2 — connector no longer proxies the namespace for this key/EA.
        assert "no longer proxies the InnerSpace namespace" in message
        assert "EA program" in message
        # BOTH attempted paths are surfaced for reproduction.
        assert "/proxy/innerspace/integration/v1/project" in message
        assert "/proxy/innerspace/api/project" in message
        assert "does NOT mean InnerSpace is uninstalled" in message
        # Both candidate paths were actually tried.
        assert client.get.call_count == 2

    async def test_prefers_integration_path(self, client, registry):
        # Happy path: the documented integration path answers first — no fallback.
        client.get.return_value = _sample_project("3D")
        await get_innerspace_project(client, registry, "myhost", "3D")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/project", key=None, params={"mode": "3D"}
        )

    async def test_falls_back_to_legacy_on_forbidden(self, client, registry):
        # Integration path 403s (namespace not relayed) -> legacy /api path answers.
        forbidden = UniFiConnectionError(
            "HTTP 403 from GET .../proxy/innerspace/integration/v1/project: "
            '{"message":"forbidden: host not found"}'
        )
        client.get.side_effect = [forbidden, _sample_project("3D")]
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        assert result["mode"] == "3D"
        assert client.get.call_count == 2
        # Second call targeted the legacy /api path.
        second_call = client.get.call_args_list[1]
        assert second_call.args[0] == f"{BASE}/project"

    async def test_non_forbidden_error_surfaces_without_fallback(self, client, registry):
        # A 5xx on the integration path is NOT the namespace regression — surface it
        # immediately, do not mask it by falling back to the legacy path.
        client.get.side_effect = UniFiConnectionError("HTTP 500 from GET ...: server error")
        with pytest.raises(UniFiConnectionError, match="HTTP 500"):
            await get_innerspace_project(client, registry, "myhost", "3D")
        client.get.assert_called_once()

    async def test_unwraps_data_envelope_from_integration(self, client, registry):
        # The documented /v1/project wraps the project in a {"data": …} envelope;
        # get_innerspace_project must return it unwrapped.
        client.get.return_value = {"data": _sample_project("3D")}
        result = await get_innerspace_project(client, registry, "myhost", "3D")
        assert "shapes" in result["project"]
        assert "data" not in result["project"]


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

    async def test_summary_counts_through_data_envelope(self, client, registry):
        # The documented /v1/project wraps everything under {"data": …}; the summary
        # must count shapes/plans correctly after the unwrap (previously reported 0).
        client.get.return_value = {"data": _sample_project("3D")}
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        assert result["shape_total"] == 6
        assert result["plan_count"] == 2
        assert result["product_count"] == 1

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


# --- Documented Integration API schema (#178 + new read endpoints) ---------


def _integration_project() -> dict:
    """A project document shaped like the documented /v1/project schema.

    Differs from the legacy _sample_project: no top-level planScales, plans carry
    ``title``/``id`` (no embedded scale), per-plan scale lives on ``scale``-type
    shapes keyed by planId, and the project meta is {id,title,createdAt,updatedAt}
    with no unit/migrated. This is the shape issue #178 must handle.
    """
    return {
        "shapes": [
            {"type": "wall", "id": "w1", "planId": "plan-a", "variant": "concrete"},
            {"type": "device", "id": "d1", "planId": "plan-a", "productId": "p1"},
            {
                "type": "scale",
                "id": "s1",
                "planId": "plan-a",
                "scale": 57.25,
                "computedScale": 57.2,
                "height": 3.05,
                "defaultScale": False,
                "defaultHeight": True,
            },
            {
                "type": "scale",
                "id": "s2",
                "planId": "plan-b",
                "scale": None,
                "computedScale": 60.5,
                "height": 2.9,
                "defaultScale": True,
                "defaultHeight": True,
            },
        ],
        "plans": [
            {"id": "plan-a", "title": "Ground Floor", "type": "real", "ordering": 0},
            {"id": "plan-b", "title": "First Floor", "type": "real", "ordering": 1},
        ],
        "products": [{"id": "p1"}],
        "wallTypes": [],
        "attenuationObjectTypes": [],
        "project": {
            "id": "proj-1",
            "title": "Synthetic Site",
            "createdAt": "2026-08-01T00:00:00Z",
            "updatedAt": "2026-08-02T00:00:00Z",
        },
    }


class TestInnerspaceScaleMappingIssue178:
    """Scale moved onto scale-type shapes; plans/project meta reshaped (#178)."""

    async def test_per_plan_scale_from_scale_shape(self, client, registry):
        client.get.return_value = _integration_project()
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        scales = {p["name"]: p["scale"] for p in result["plans"]}
        # plan-a takes its numeric scale; plan-b falls back to computedScale.
        assert scales == {"Ground Floor": 57.25, "First Floor": 60.5}

    async def test_plan_scales_derived_when_top_level_absent(self, client, registry):
        client.get.return_value = _integration_project()
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        ps = result["plan_scales"]
        assert ps["plan-a"]["scale"] == 57.25
        assert ps["plan-a"]["height"] == 3.05
        # plan-b had a null scale -> computedScale is used for the scale value.
        assert ps["plan-b"]["scale"] == 60.5

    async def test_project_block_surfaces_new_meta_fields(self, client, registry):
        client.get.return_value = _integration_project()
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        proj = result["project"]
        assert proj["id"] == "proj-1"
        assert proj["title"] == "Synthetic Site"
        assert proj["createdAt"] == "2026-08-01T00:00:00Z"
        # unit/migrated absent in the documented schema -> null, not omitted.
        assert proj["unit"] is None
        assert proj["migrated"] is None

    async def test_legacy_payload_still_reads_embedded_scale(self, client, registry):
        # Backward-compat: the legacy /api payload (embedded plan scale + top-level
        # planScales + unit/migrated) must be unchanged by the #178 rewire.
        client.get.return_value = _sample_project("3D")
        result = await get_innerspace_summary(client, registry, "myhost", "3D")
        scales = {p["name"]: p["scale"] for p in result["plans"]}
        assert scales == {"Ground Floor": 57.25241, "First Floor": 60.0}
        assert result["plan_scales"] == {"height": 3.048037, "scale": 57.25241}
        assert result["project"] == {"unit": "imperial", "migrated": True}


# --- Integration-API-only list endpoints ------------------------------------


def _fp_response() -> dict:
    return {
        "floor_plans": [
            {
                "id": "plan-a",
                "name": "Ground Floor",
                "floor_number": 1,
                "image_url": "/proxy/innerspace/integration/v1/assets/plan-a/ground.png",
                "ppm": 57.25,
                "width": 2048,
                "height": 1536,
                "origin_x": 0,
                "origin_y": 0,
            }
        ]
    }


class TestListInnerspaceFloorPlans:
    async def test_happy_path_and_count(self, client, registry):
        client.get.return_value = _fp_response()
        result = await list_innerspace_floor_plans(client, registry, "myhost")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/floor_plans", key=None, params=None
        )
        assert result["count"] == 1
        assert result["floor_plans"][0]["ppm"] == 57.25
        # image_url passes through verbatim (asset path preserved).
        assert result["floor_plans"][0]["image_url"].endswith("/assets/plan-a/ground.png")

    async def test_site_id_filter_passed_as_param(self, client, registry):
        client.get.return_value = _fp_response()
        await list_innerspace_floor_plans(client, registry, "myhost", site_id="site-42")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/floor_plans", key=None, params={"siteId": "site-42"}
        )

    async def test_tolerates_data_envelope(self, client, registry):
        client.get.return_value = {"data": _fp_response()}
        result = await list_innerspace_floor_plans(client, registry, "myhost")
        assert result["count"] == 1

    async def test_empty_response(self, client, registry):
        client.get.return_value = {"floor_plans": []}
        result = await list_innerspace_floor_plans(client, registry, "myhost")
        assert result == {"floor_plans": [], "count": 0}

    async def test_namespace_403_gives_two_cause_error(self, client, registry):
        client.get.side_effect = UniFiConnectionError(
            "HTTP 403 from GET .../proxy/innerspace/integration/v1/floor_plans: "
            '{"message":"forbidden: host not found"}'
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await list_innerspace_floor_plans(client, registry, "myhost")
        msg = str(exc.value)
        assert "/v1/floor_plans" in msg
        assert "no longer proxies the InnerSpace namespace" in msg
        assert "works for this host to distinguish" in msg

    async def test_non_forbidden_error_surfaces(self, client, registry):
        client.get.side_effect = UniFiConnectionError("HTTP 500 from GET ...: boom")
        with pytest.raises(UniFiConnectionError, match="HTTP 500"):
            await list_innerspace_floor_plans(client, registry, "myhost")


class TestListInnerspaceAccessPoints:
    async def test_happy_path_passthrough_identifiers(self, client, registry):
        client.get.return_value = {
            "access_points": [
                {
                    "id": "ap-1",
                    "name": "AP North",
                    "model": "U6-Pro",
                    "mac": "aa:bb:cc:00:11:22",
                    "serial": "AABBCC001122",
                    "floor_plan_id": "plan-a",
                    "x": 100.5,
                    "y": 200.5,
                    "height": 2.7,
                    "azimuth": 90,
                    "mount": "ceiling",
                    "status": "connected",
                }
            ]
        }
        result = await list_innerspace_access_points(client, registry, "myhost")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/access_points", key=None, params=None
        )
        assert result["count"] == 1
        ap = result["access_points"][0]
        assert ap["mac"] == "aa:bb:cc:00:11:22"
        assert ap["serial"] == "AABBCC001122"
        assert ap["azimuth"] == 90

    async def test_site_filter(self, client, registry):
        client.get.return_value = {"access_points": []}
        await list_innerspace_access_points(client, registry, "myhost", site_id="s1")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/access_points", key=None, params={"siteId": "s1"}
        )


class TestListInnerspaceSwitches:
    async def test_happy_path(self, client, registry):
        client.get.return_value = {
            "switches": [
                {
                    "id": "sw-1",
                    "name": "Core",
                    "model": "USW-Pro-24",
                    "type": "switch",
                    "mac": "aa:bb:cc:33:44:55",
                    "serial": "AABBCC334455",
                    "floor_plan_id": "plan-a",
                    "x": 10,
                    "y": 20,
                    "status": "connected",
                }
            ]
        }
        result = await list_innerspace_switches(client, registry, "myhost")
        client.get.assert_called_once_with(f"{INTEGRATION_BASE}/v1/switches", key=None, params=None)
        assert result["count"] == 1
        assert result["switches"][0]["mac"] == "aa:bb:cc:33:44:55"


class TestListInnerspaceInventory:
    async def test_happy_path_devices_key(self, client, registry):
        client.get.return_value = {
            "devices": [
                {
                    "id": "inv-1",
                    "name": "Spare AP",
                    "model": "U6-Lite",
                    "mac": "aa:bb:cc:66:77:88",
                    "serial": "AABBCC667788",
                }
            ]
        }
        result = await list_innerspace_inventory(client, registry, "myhost")
        client.get.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/inventory", key=None, params=None
        )
        assert result["count"] == 1
        assert result["devices"][0]["serial"] == "AABBCC667788"


# --- Asset download ---------------------------------------------------------


class TestGetInnerspaceAsset:
    async def test_small_asset_returned_base64(self, client, registry):
        payload = b"\x89PNG\r\n\x1a\nsynthetic-image-bytes"
        client.get_binary.return_value = (payload, "image/png")
        result = await get_innerspace_asset(client, registry, "myhost", "plan-a", "ground.png")
        client.get_binary.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/assets/plan-a/ground.png", key=None
        )
        assert result["content_type"] == "image/png"
        assert result["size_bytes"] == len(payload)
        assert base64.b64decode(result["image_base64"]) == payload
        assert result["path"].endswith("/v1/assets/plan-a/ground.png")

    async def test_asset_group_id_forwarded_verbatim(self, client, registry):
        """#180: the {planId} segment is the asset-group id from image_url (NOT the floor
        plan's own id). Whatever id the caller passes is forwarded verbatim as the path
        segment, so callers must pass the asset-group id parsed from image_url."""
        asset_group_id = "22222222-2222-4222-8222-222222222222"
        client.get_binary.return_value = (b"x", "image/png")
        result = await get_innerspace_asset(
            client, registry, "myhost", asset_group_id, "11111111-abc.png"
        )
        client.get_binary.assert_called_once_with(
            f"{INTEGRATION_BASE}/v1/assets/{asset_group_id}/11111111-abc.png", key=None
        )
        assert result["path"].endswith(f"/v1/assets/{asset_group_id}/11111111-abc.png")
        assert result["plan_id"] == asset_group_id

    async def test_oversize_asset_omits_base64_with_note(self, client, registry, monkeypatch):
        # Force a tiny cap so a small payload trips the over-cap branch deterministically.
        monkeypatch.setattr("unifi_fabric.tools.innerspace.MAX_ASSET_INLINE_BYTES", 4, raising=True)
        client.get_binary.return_value = (b"12345", "image/jpeg")
        result = await get_innerspace_asset(client, registry, "myhost", "plan-a", "big.jpg")
        assert result["image_base64"] is None
        assert result["size_bytes"] == 5
        assert "exceeding" in result["note"]
        assert result["path"].endswith("/v1/assets/plan-a/big.jpg")

    async def test_cap_constant_is_sane(self):
        assert MAX_ASSET_INLINE_BYTES >= 1024 * 1024

    async def test_rejects_bare_dotdot(self, client, registry):
        # A whole-name ".." can never resolve to the parent directory.
        with pytest.raises(ValueError, match=r"must not be '\.' or '\.\.'"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "..")
        client.get_binary.assert_not_called()

    async def test_rejects_bare_dot(self, client, registry):
        with pytest.raises(ValueError, match=r"must not be '\.' or '\.\.'"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", ".")
        client.get_binary.assert_not_called()

    async def test_rejects_filename_with_traversal(self, client, registry):
        # "../secret" is caught by the allowlist (it contains '/'), not by name equality.
        with pytest.raises(ValueError, match="only ASCII letters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "../secret")
        client.get_binary.assert_not_called()

    async def test_rejects_filename_with_slash(self, client, registry):
        with pytest.raises(ValueError, match="only ASCII letters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "sub/dir.png")
        client.get_binary.assert_not_called()

    async def test_rejects_filename_with_backslash(self, client, registry):
        with pytest.raises(ValueError, match="only ASCII letters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "sub\\dir.png")
        client.get_binary.assert_not_called()

    async def test_rejects_percent_encoded_filename(self, client, registry):
        # A percent-encoded separator carries no literal '/' or '..'; the positive
        # allowlist excludes '%' outright, so it can never be decoded into a separator.
        with pytest.raises(ValueError, match="only ASCII letters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "%2Fetc%2Fpasswd")
        client.get_binary.assert_not_called()

    async def test_rejects_bare_percent(self, client, registry):
        with pytest.raises(ValueError, match="only ASCII letters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "a%b.png")
        client.get_binary.assert_not_called()

    @pytest.mark.parametrize("ctrl", ["\x00", "\r", "\n"])
    async def test_rejects_control_characters(self, client, registry, ctrl):
        with pytest.raises(ValueError, match="only ASCII letters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", f"a{ctrl}b.png")
        client.get_binary.assert_not_called()

    @pytest.mark.parametrize(
        "bad",
        ["a b.png", "café.png", "a;b.png", "a?b.png", "a#b.png", "a(1).png", "a&b.png"],
    )
    async def test_rejects_disallowed_characters(self, client, registry, bad):
        # Space, unicode, semicolon, '?', '#', parens, '&' are all outside the allowlist.
        with pytest.raises(ValueError, match="only ASCII letters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", bad)
        client.get_binary.assert_not_called()

    async def test_rejects_empty_filename(self, client, registry):
        with pytest.raises(ValueError, match="non-empty string"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "  ")
        client.get_binary.assert_not_called()

    async def test_rejects_overlong_filename(self, client, registry):
        with pytest.raises(ValueError, match="exceeds 255 characters"):
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "a" * 256)
        client.get_binary.assert_not_called()

    @pytest.mark.parametrize(
        "good",
        [
            "2DPreview.svg",
            "11111111-1111-4111-8111-111111111111.png",
            "ground.png",
            "a" * 255,
            "_hidden.jpg",
            "Floor-1_v2.PNG",
        ],
    )
    async def test_accepts_allowlisted_filenames(self, client, registry, good):
        # Realistic published asset filenames pass validation and reach the fetch.
        client.get_binary.return_value = (b"\x89PNG", "image/png")
        result = await get_innerspace_asset(client, registry, "myhost", "plan-a", good)
        assert result["filename"] == good
        client.get_binary.assert_awaited_once()

    async def test_rejects_bad_plan_id(self, client, registry):
        with pytest.raises(ValueError, match="plan_id"):
            await get_innerspace_asset(client, registry, "myhost", "bad/plan", "x.png")

    async def test_namespace_403_translated(self, client, registry):
        client.get_binary.side_effect = UniFiConnectionError(
            'HTTP 403 from GET .../v1/assets/plan-a/x.png: {"message":"forbidden: host not found"}'
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await get_innerspace_asset(client, registry, "myhost", "plan-a", "x.png")
        assert "works for this host to distinguish" in str(exc.value)


class TestInnerspaceReadToolsMultiKey:
    """A beta-owned (non-first) host must ride the beta key, not the default key."""

    @staticmethod
    def _wire_hosts(multikey_client):
        async def _paginate(path, *, key=None):
            return {
                "alpha": [{"id": "console-alpha-1", "name": "Alpha-HQ"}],
                "beta": [{"id": "console-beta-1", "name": "Beta-Branch"}],
            }[key.label]

        multikey_client.paginate = AsyncMock(side_effect=_paginate)

    async def test_list_floor_plans_routes_beta_host(self, multikey_client, multikey_registry):
        self._wire_hosts(multikey_client)
        captured: dict = {}

        async def _get(path, *, key=None, params=None):
            captured["key"] = key.label
            captured["path"] = path
            return {"floor_plans": [{"id": "fp-1"}]}

        multikey_client.get = AsyncMock(side_effect=_get)
        result = await list_innerspace_floor_plans(
            multikey_client, multikey_registry, "Beta-Branch"
        )
        assert captured["key"] == "beta"
        assert "console-beta-1" in captured["path"]
        assert result["count"] == 1

    async def test_get_asset_routes_beta_host(self, multikey_client, multikey_registry):
        self._wire_hosts(multikey_client)
        captured: dict = {}

        async def _get_binary(path, *, key=None, params=None):
            captured["key"] = key.label
            captured["path"] = path
            return (b"img", "image/png")

        multikey_client.get_binary = AsyncMock(side_effect=_get_binary)
        result = await get_innerspace_asset(
            multikey_client, multikey_registry, "Beta-Branch", "plan-a", "x.png"
        )
        assert captured["key"] == "beta"
        assert "console-beta-1" in captured["path"]
        assert result["content_type"] == "image/png"

    async def test_list_access_points_routes_beta_host(self, multikey_client, multikey_registry):
        self._wire_hosts(multikey_client)
        captured: dict = {}

        async def _get(path, *, key=None, params=None):
            captured["key"] = key.label
            captured["path"] = path
            return {"access_points": [{"id": "ap-1"}]}

        multikey_client.get = AsyncMock(side_effect=_get)
        result = await list_innerspace_access_points(
            multikey_client, multikey_registry, "Beta-Branch"
        )
        assert captured["key"] == "beta"
        assert "console-beta-1" in captured["path"]
        assert result["count"] == 1

    async def test_list_switches_routes_beta_host(self, multikey_client, multikey_registry):
        self._wire_hosts(multikey_client)
        captured: dict = {}

        async def _get(path, *, key=None, params=None):
            captured["key"] = key.label
            captured["path"] = path
            return {"switches": [{"id": "sw-1"}]}

        multikey_client.get = AsyncMock(side_effect=_get)
        result = await list_innerspace_switches(multikey_client, multikey_registry, "Beta-Branch")
        assert captured["key"] == "beta"
        assert "console-beta-1" in captured["path"]
        assert result["count"] == 1

    async def test_list_inventory_routes_beta_host(self, multikey_client, multikey_registry):
        self._wire_hosts(multikey_client)
        captured: dict = {}

        async def _get(path, *, key=None, params=None):
            captured["key"] = key.label
            captured["path"] = path
            return {"devices": [{"id": "inv-1"}]}

        multikey_client.get = AsyncMock(side_effect=_get)
        result = await list_innerspace_inventory(multikey_client, multikey_registry, "Beta-Branch")
        assert captured["key"] == "beta"
        assert "console-beta-1" in captured["path"]
        assert result["count"] == 1
