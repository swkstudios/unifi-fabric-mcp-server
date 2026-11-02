"""N12: update_digital_twin_layout keeps ``_verified`` for a non-object write body."""

from __future__ import annotations

from typing import Any

from unifi_fabric.tools import network_proav_sandbox as mod


class _Client:
    async def get(self, path: str, **_: Any) -> Any:
        return {"a": 1}

    async def put(self, path: str, **_: Any) -> Any:
        return "ok"


async def test_update_digital_twin_layout_wraps_a_non_object_body(monkeypatch):
    async def site(*_: Any) -> Any:
        return None, "host", "default"

    monkeypatch.setattr(mod, "_site", site)
    result = await mod.update_digital_twin_layout(_Client(), None, "h", "s", {"a": 2})
    assert result["response"] == "ok"
    assert result["_verified"] is False
