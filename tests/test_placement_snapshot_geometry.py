"""Placement snapshot geometry follows the pinned InnerSpace spec shapes.

Rotation components on a ``device`` shape are objects ``{x, y, z, w}`` in the spec
(``innerspace-1.3.23.json``) and in every recorded project, and per-plan scale lives on
a ``scale``-type shape rather than on the plan object. The snapshot must carry both for
real data, not only for the synthetic list/plan-scale shapes.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from unifi_fabric.client import ResponseShapeError
from unifi_fabric.families.innerspace.placement_snapshot import build_snapshot

_RECORDED = (
    Path(__file__).parent
    / "fixtures"
    / "recorded"
    / "innerspace"
    / "innerspace_integration_v1_project.json"
)
_EMPTY: dict[str, Any] = {"result": []}


def _snapshot(project: dict[str, Any]) -> dict[str, Any]:
    return build_snapshot(
        project_result={"project": project},
        cameras_result=_EMPTY,
        sensors_result=_EMPTY,
        devices_result={"data": []},
    )


def _device(rotation: Any) -> dict[str, Any]:
    return {
        "type": "device",
        "id": "placement-1",
        "title": "Lobby AP",
        "planId": "plan-a",
        "position": [{"x": 1.0, "y": 2.0, "z": 3.0}],
        "rotation": rotation,
    }


_Q = {"x": 0.1, "y": -0.2, "z": 0.3, "w": 0.9}


class TestRotationShapes:
    def test_recorded_project_rotation_reaches_every_placed_device(self) -> None:
        project = json.loads(_RECORDED.read_text())["body"]["data"]
        devices = [s for s in project["shapes"] if s.get("type") == "device"]
        assert devices, "recorded fixture must contain device shapes"
        result = _snapshot(project)
        assert len(result["placed_devices"]) == len(devices)
        for placed, shape in zip(result["placed_devices"], devices, strict=True):
            for name in ("pov", "base"):
                assert placed["rotation"][name] == {
                    axis: shape["rotation"][name][axis] for axis in ("x", "y", "z", "w")
                }
        assert not any("rotation" in key for key in result.get("_unprojected", {}))
        assert "_withheld" not in result

    @pytest.mark.parametrize(
        ("rotation", "expected"),
        [
            # spec object form, extra keys dropped (numbers only, x/y/z/w)
            (
                {"pov": {**_Q, "note": "x"}, "base": {"x": 0, "y": 0, "z": 0, "w": 1}},
                {"pov": _Q, "base": {"x": 0, "y": 0, "z": 0, "w": 1}},
            ),
            # list form is still accepted
            ({"pov": [0, 0, 0, 1], "base": [0.5, 0.5, 0.5, 0.5]}, None),
            # one component present
            ({"pov": _Q}, {"pov": _Q}),
        ],
    )
    def test_numeric_components_are_kept(self, rotation: Any, expected: Any) -> None:
        result = _snapshot({"plans": [], "shapes": [_device(rotation)]})
        assert result["placed_devices"][0]["rotation"] == (expected or rotation)
        assert "_withheld" not in result
        assert "_unprojected" not in result

    @pytest.mark.parametrize(
        "component",
        [
            {"x": 0, "y": 0, "z": 0},  # w missing
            {"x": "0", "y": 0, "z": 0, "w": 1},  # string is never coerced
            {"x": True, "y": 0, "z": 0, "w": 1},  # boolean is not a number
            "0,0,0,1",
            [0, "0", 0, 1],
            None,
        ],
    )
    def test_non_numeric_component_is_counted_not_dropped_silently(self, component: Any) -> None:
        result = _snapshot({"plans": [], "shapes": [_device({"pov": component, "base": dict(_Q)})]})
        assert result["placed_devices"][0]["rotation"] == {"base": _Q}
        assert result["_unprojected"]["placed_devices.rotation.pov"] == {"not_numeric": 1}
        assert "_withheld" not in result

    @pytest.mark.parametrize("bad", [math.nan, math.inf])
    def test_non_finite_axis_is_a_shape_error(self, bad: float) -> None:
        with pytest.raises(ResponseShapeError, match=r"rotation\.pov\.w"):
            _snapshot({"plans": [], "shapes": [_device({"pov": {**_Q, "w": bad}, "base": _Q})]})


class TestFloorScale:
    def test_recorded_project_floor_carries_its_scale_shape(self) -> None:
        project = json.loads(_RECORDED.read_text())["body"]["data"]
        scale_shapes = {
            s["planId"]: s["scale"]
            for s in project["shapes"]
            if s.get("type") == "scale" and s.get("planId")
        }
        assert scale_shapes, "recorded fixture must contain a scale shape"
        floors = {f["source_id"]: f for f in _snapshot(project)["floors"]}
        for plan_id, scale in scale_shapes.items():
            assert floors[plan_id]["scale"] == scale
        # A plan with no scale shape still has no scale (never invented).
        for plan_id, floor in floors.items():
            if plan_id not in scale_shapes:
                assert "scale" not in floor

    @pytest.mark.parametrize(
        ("plan", "shapes", "expected"),
        [
            # the plan's own scale wins over a scale shape
            ({"id": "p", "scale": 10}, [{"type": "scale", "planId": "p", "scale": 99}], 10),
            ({"id": "p", "planScale": {"scale": 11}}, [{"type": "scale", "planId": "p"}], 11),
            # spec shape: scale on the scale shape
            ({"id": "p"}, [{"type": "scale", "planId": "p", "scale": 3.5}], 3.5),
            # computedScale is the fallback when scale is absent
            ({"id": "p"}, [{"type": "scale", "planId": "p", "computedScale": 4}], 4),
            # a scale shape for another plan or with a null planId is not used
            ({"id": "p"}, [{"type": "scale", "planId": "q", "scale": 5}], None),
            ({"id": "p"}, [{"type": "scale", "planId": None, "scale": 5}], None),
            # a non-number scale is never coerced
            ({"id": "p"}, [{"type": "scale", "planId": "p", "scale": "5"}], None),
        ],
    )
    def test_scale_source_order(self, plan: Any, shapes: Any, expected: Any) -> None:
        floor = _snapshot({"plans": [plan], "shapes": shapes})["floors"][0]
        assert floor.get("scale") == expected
