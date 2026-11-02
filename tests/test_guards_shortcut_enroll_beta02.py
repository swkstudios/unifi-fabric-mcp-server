"""P02: delete and enroll tools reject bad arguments before any request."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh


async def _run(monkeypatch, name, **override):
    up = uh.FakeUpstream()
    args = tool_args.generated_args(cti.TOOLS[name])
    args.update(override)
    with pytest.raises(ToolError):
        await cti._call(monkeypatch, name, up, args=args)
    assert up.served == [], [s.path for s in up.served]


async def test_delete_camera_shortcut_rejects_an_empty_list(monkeypatch):
    await _run(monkeypatch, "delete_camera_shortcut", shortcut_ids=[])


@pytest.mark.parametrize("step", ["enroll", "cancel"])
@pytest.mark.parametrize(
    "extra", [{"fingerprint_id": "3"}, {"ulp_id": "u-1"}, {"fields": {"name": "card"}}]
)
async def test_enroll_doorbell_credential_rejects_assign_only_fields(monkeypatch, step, extra):
    base = {"fingerprint_id": None, "ulp_id": None, "fields": None}
    await _run(monkeypatch, "enroll_doorbell_credential", step=step, **{**base, **extra})


async def test_enroll_doorbell_credential_assign_still_sends(monkeypatch):
    up = uh.FakeUpstream()
    args = tool_args.generated_args(cti.TOOLS["enroll_doorbell_credential"])
    args.update(step="assign", fingerprint_id="3", ulp_id="u-1", fields={"name": "card"})
    await cti._call(monkeypatch, "enroll_doorbell_credential", up, args=args)
    assert [w.method for w in up.writes()] == ["POST"]
