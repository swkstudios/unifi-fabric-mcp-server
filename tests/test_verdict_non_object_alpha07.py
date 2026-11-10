"""N07: a non-object write body keeps ``_verified`` / ``_readAfter`` under ``response``."""

from __future__ import annotations

from unifi_fabric.families.vpn import network_vpn_dns as mod


def test_with_verdict_wraps_a_non_object_body():
    result = mod._with_verdict("ok", {"name": "x"}, True, None)
    assert result["response"] == "ok"
    assert result["_verified"] is True
    assert result["_readAfter"] == {"name": "x"}


def test_with_verdict_keeps_an_object_body_verbatim():
    result = mod._with_verdict({"a": 1}, {"a": 1}, True, None)
    assert result["a"] == 1 and "response" not in result
