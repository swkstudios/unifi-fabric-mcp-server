"""N09: a non-object write body keeps ``_verified`` under ``response``."""

from __future__ import annotations

from typing import Any

from unifi_fabric.tools import network_switching_power as mod


class _Client:
    def __init__(self, put_body: Any) -> None:
        self.put_body = put_body

    async def get(self, path: str, **_: Any) -> Any:
        return [{"_id": "abc", "name": "old"}]

    async def put(self, path: str, **_: Any) -> Any:
        return self.put_body


async def test_verified_update_wraps_a_non_object_body():
    result = await mod._verified_update(_Client("ok"), "/c", None, "abc", {"name": "new"}, "policy")
    assert result["response"] == "ok"
    assert result["_verified"] is False
