"""Offline checks for the live Protect test safety gates."""

from types import SimpleNamespace

import pytest

from tests import test_protect_integration as live


def test_live_host_precondition_fails(monkeypatch):
    monkeypatch.setattr(live, "_TEST_HOST", "")
    with pytest.raises(pytest.fail.Exception, match="UNIFI_TEST_HOST"):
        live._require_host()


def test_mutating_requires_opt_in_and_real_write_mode(monkeypatch):
    request = SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda _: True))
    with pytest.raises(pytest.fail.Exception, match="UNIFI_TEST_ALLOW_MUTATIONS"):
        live._authorize_live_mutation.__wrapped__(request)
    monkeypatch.setenv("UNIFI_TEST_ALLOW_MUTATIONS", "1")
    monkeypatch.setenv("UNIFI_DRY_RUN", "1")
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-test")
    with pytest.raises(pytest.fail.Exception, match="UNIFI_DRY_RUN"):
        live._authorize_live_mutation.__wrapped__(request)
    monkeypatch.setenv("UNIFI_DRY_RUN", "0")
    live._authorize_live_mutation.__wrapped__(request)
