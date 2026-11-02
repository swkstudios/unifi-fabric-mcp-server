"""N08: a non-object write body keeps ``_verified`` under ``response``."""

from __future__ import annotations

from unifi_fabric.tools import network_routing_topology as mod


def test_with_verdict_wraps_a_non_object_body():
    result = mod._with_verdict("ok", {"name": "x"}, {"name": "x"}, None)
    assert result["response"] == "ok"
    assert result["_verified"] is True


def test_with_verdict_keeps_an_object_body_verbatim():
    result = mod._with_verdict({"a": 1}, {"a": 1}, {"a": 1}, None)
    assert result["a"] == 1 and "response" not in result
