"""N05: a non-object PUT body keeps the additive verdict keys under ``response``."""

from __future__ import annotations

from unifi_fabric.tools import network_clients_guests as mod


def test_classic_update_result_wraps_a_non_object_body():
    result = mod._classic_update_result("ok", {"name": "x"}, {"name": "x"}, None)
    assert result["response"] == "ok"
    assert result["_verified"] is True


def test_classic_update_result_reports_an_unverified_non_object_body():
    result = mod._classic_update_result([1], {"name": "x"}, {"name": "y"}, None)
    assert result["response"] == [1]
    assert result["_verified"] is False
