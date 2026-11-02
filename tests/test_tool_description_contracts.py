"""Descriptions stay aligned with returned identifiers and conditional results."""

import logging
from pathlib import Path

import pytest

from tests import test_invariants_carrier_devices_and_relay_writes as relay_tests
from unifi_fabric import server
from unifi_fabric.tools import carrier_fabric, connector


@pytest.mark.parametrize(
    "name",
    [
        "list_mobility_admins",
        "list_mobility_devices",
        "get_mobility_device",
        "list_mobility_clients",
        "update_mobility_device_name",
        "update_mobility_device_network",
        "update_mobility_device_wireless",
    ],
)
def test_workspace_identifier_description(name):
    assert "list_mobility_workspaces (workspace_id)" in getattr(server, name).__doc__


@pytest.mark.parametrize(
    "name", ["allow_network_on_port_profile", "exclude_network_on_port_profile"]
)
def test_profile_note_description_is_conditional(name):
    description = getattr(server, name).__doc__
    assert "_profileNote" in description
    assert "only when" in description


@pytest.mark.parametrize(
    "function", [server.update_carrier_subscriber, carrier_fabric.update_carrier_subscriber]
)
def test_carrier_metadata_null_alone_is_documented_no_op(function):
    assert "metadata=null alone is a no-op" in function.__doc__


async def test_relay_audit_helper_resets_logging_cache_and_restores_level(monkeypatch):
    log = logging.getLogger(connector.__name__)
    original = log.level
    try:
        log.setLevel(logging.ERROR)
        assert not log.isEnabledFor(logging.INFO)

        async def call(*args):
            log.info("connector-relay-audit synthetic")
            return {}

        monkeypatch.setattr(relay_tests, "_call", call)
        monkeypatch.setattr(relay_tests.sc, "conformance_args", lambda tool: {})
        monkeypatch.setattr(relay_tests.uh, "result_payload", lambda result: result)
        _, audit = await relay_tests._relay(monkeypatch, "synthetic", None)
        assert len(audit) == 1
        assert log.level == logging.ERROR
        assert not log.isEnabledFor(logging.INFO)
    finally:
        log.setLevel(original)


def test_changelog_discloses_sibling_key_name_resolution_rule():
    section = (Path(__file__).resolve().parents[1] / "docs" / "MIGRATING-0.7.md").read_text()
    assert "Host-name selectors" in section
    assert "every configured key" in section
    assert "exact console id" in section
