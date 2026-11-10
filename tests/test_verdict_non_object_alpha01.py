"""N01: a non-object write body keeps the additive ``_verified`` verdict under ``response``."""

from __future__ import annotations

from unifi_fabric.families.network import network_controller_admin as mod


def test_verified_wraps_a_non_object_body():
    assert mod._verified("ok", True, None) == {"response": "ok", "_verified": True}
    assert mod._verified(None, None, "boom") == {
        "response": None,
        "_verified": None,
        "_readAfterError": "boom",
    }


def test_verified_keeps_an_object_body_verbatim():
    assert mod._verified({"a": 1}, False, None) == {"a": 1, "_verified": False}
