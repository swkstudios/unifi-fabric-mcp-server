"""NET-B: the listed tools return the deletion_result dry-run shape.

Under dry-run policy each listed tool returns ``{status: "dry_run", deleted: false, message,
response: <client preview>}`` - never the bare client preview - and sends no write.
"""

from __future__ import annotations

import pytest

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from unifi_fabric.client import is_dry_run_preview

DELETE_TOOLS = ["remove_client_fixed_ip"]


@pytest.mark.parametrize("name", DELETE_TOOLS)
async def test_delete_dry_run_is_the_deletion_result_shape(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await cti._call(monkeypatch, name, up, env={"UNIFI_WRITE_POLICY": "dry-run"})
    )
    assert up.writes() == [], name
    assert isinstance(payload, dict), payload
    assert payload["status"] == "dry_run", payload
    assert payload["deleted"] is False, payload
    assert isinstance(payload["message"], str) and payload["message"], payload
    assert is_dry_run_preview(payload["response"]), payload
