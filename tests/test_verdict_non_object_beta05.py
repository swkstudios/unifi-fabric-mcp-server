"""P05: update_protect_automation keeps ``_verified`` for a non-object write body."""

from __future__ import annotations

from typing import Any

from unifi_fabric.tools import protect_automation_backup as mod


class _Client:
    async def get(self, path: str, **_: Any) -> Any:
        return [{"id": "abc", "name": "old"}]

    async def patch(self, path: str, **_: Any) -> Any:
        return "ok"


async def test_update_protect_automation_wraps_a_non_object_body(monkeypatch):
    async def resolve(*_: Any) -> Any:
        return None, "host"

    async def known(*_: Any) -> Any:
        return {"id": "abc", "name": "old"}

    monkeypatch.setattr(mod, "_resolve", resolve)
    monkeypatch.setattr(mod, "_known", known)
    monkeypatch.setattr(mod, "_require_mutations", lambda: None)
    monkeypatch.setattr(mod, "guard_action", lambda *_: None)
    result = await mod._update_protect_automation(_Client(), None, "h", "abc", {"name": "new"})
    assert result["response"] == "ok"
    assert result["_verified"] is False
