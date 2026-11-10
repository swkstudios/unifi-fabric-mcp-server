"""One plan-scale reader: the placement snapshot and the InnerSpace summary agree.

Every scale shape a floor plan can carry (the legacy ``scale`` / ``planScale`` /
``planScales``, each as a number or as an object with ``scale``; the documented ``scale``
shape for the plan id; none) yields the same floor scale in
``get_unifi_placement_snapshot`` as in ``get_innerspace_summary``, because both read it
with :func:`unifi_fabric.families.innerspace.innerspace._plan_scale`.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from unifi_fabric.families.innerspace import innerspace, placement_snapshot
from unifi_fabric.families.innerspace.placement_snapshot import build_snapshot

_EMPTY: dict[str, Any] = {"data": []}

_EMBEDDED: list[dict[str, Any]] = [
    {},
    {"scale": 10},
    {"scale": {"scale": 11}},
    {"planScale": 12},
    {"planScale": {"scale": 13}},
    {"planScales": 14},
    {"planScales": {"scale": 15}},
    {"scale": "16"},  # a string is never coerced
    {"planScale": {"scale": "17"}},
    {"scale": {"other": 1}, "planScale": {"scale": 18}},
]
_SHAPES: list[list[dict[str, Any]]] = [
    [],
    [{"type": "scale", "planId": "p", "scale": 3.5}],
    [{"type": "scale", "planId": "p", "computedScale": 4}],
    [{"type": "scale", "planId": "q", "scale": 5}],
]


def _floor_scale(plan: dict[str, Any], shapes: list[dict[str, Any]]) -> Any:
    snap = build_snapshot(
        project_result={"project": {"plans": [plan], "shapes": shapes}},
        cameras_result=_EMPTY,
        sensors_result=_EMPTY,
        devices_result=_EMPTY,
    )
    return snap["floors"][0].get("scale")


@pytest.mark.parametrize(
    ("embedded", "shapes"),
    list(itertools.product(_EMBEDDED, _SHAPES)),
    ids=[
        f"{sorted(e)}-{len(s) and s[0].get('planId')}"
        for e, s in itertools.product(_EMBEDDED, _SHAPES)
    ],
)
def test_placement_floor_scale_matches_the_innerspace_summary(embedded, shapes):
    plan = {"id": "p", "name": "Floor", **embedded}
    expected = innerspace._plan_scale(plan, innerspace._scale_by_plan(shapes))
    assert _floor_scale(plan, shapes) == expected, plan


def test_placement_reads_the_plan_scale_through_the_shared_helper(monkeypatch):
    calls: list[dict[str, Any]] = []
    real = innerspace._plan_scale

    def spy(plan: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        calls.append(plan)
        return real(plan, *args, **kwargs)

    monkeypatch.setattr(innerspace, "_plan_scale", spy)
    _floor_scale({"id": "p", "planScales": {"scale": 2}}, [])
    assert calls, "the placement snapshot read the plan scale with its own copy"
    assert placement_snapshot is not None
