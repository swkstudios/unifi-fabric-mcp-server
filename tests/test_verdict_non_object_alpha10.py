"""N10: configure_wifi_wan keeps ``_verified`` / ``_readAfter`` for a non-object write body."""

from __future__ import annotations

from typing import Any

from unifi_fabric.tools import network_wifi_radio as mod

_WAN = {"_id": "0123456789abcdef01234567", "purpose": "wan", "name": "WAN"}


class _Client:
    dry_run = False


async def test_configure_wifi_wan_wraps_a_non_object_body(monkeypatch):
    async def site(*_: Any) -> Any:
        return None, "host", "default"

    async def records(*_: Any, **__: Any) -> Any:
        return [dict(_WAN)]

    async def update(*_: Any, **__: Any) -> Any:
        return "ok"

    monkeypatch.setattr(mod, "_site", site)
    monkeypatch.setattr(mod, "networkconf_records", records)
    monkeypatch.setattr(mod.network, "update_wan_interface", update)
    monkeypatch.setattr(mod, "guard_action", lambda *_: None)
    result = await mod.configure_wifi_wan(
        _Client(), None, "h", "s", True, True, 1, "ssid", "OPEN", "RADIO_NA"
    )
    assert result["response"] == "ok"
    assert "_verified" in result and "_readAfter" in result
