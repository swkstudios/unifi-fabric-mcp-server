"""Metadata command semantics drive classification; other POSTs fail closed."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests import test_cross_tool_invariants as cti
from unifi_fabric import _read_only_audit as audit
from unifi_fabric import read_only, refusals

READ_COMMANDS = {
    "firmware": {"list-cached", "list-available"},
    "backup": {"list-backups"},
    "devmgr": {"speedtest-status"},
}


@given(
    route=st.sampled_from(["firmware", "backup", "devmgr", "devmgr/upgrade-all", "other"]),
    command=st.one_of(
        st.sampled_from(
            [
                "list-cached",
                "list-available",
                "list-backups",
                "speedtest-status",
                "speedtest",
                "backup",
                "upgrade",
                "force-provision",
            ]
        ),
        st.text(max_size=30),
    ),
)
def test_metadata_post_classification_by_route_and_command(route, command):
    expected = command in READ_COMMANDS.get(route, set())
    path = f"/v1/connector/consoles/test/proxy/network/api/s/default/cmd/{route}"
    assert read_only.is_write_request("POST", path, {"cmd": command}) is (not expected)


@given(route=st.sampled_from(["firmware", "backup", "devmgr"]), command=st.text(max_size=30))
def test_command_body_cannot_authorize_a_read_post(route, command):
    """Only a listed read command's exact body is a read; any other body is a write."""
    path = f"/v1/connector/consoles/test/proxy/network/api/s/default/cmd/{route}"
    assert read_only.is_write_request("POST", path)
    if command not in READ_COMMANDS[route]:
        assert read_only.is_write_request("POST", path, {"cmd": command})
    for listed in READ_COMMANDS[route]:
        assert read_only.is_write_request("POST", path, {"cmd": listed, "x": command})


def test_registered_metadata_reads_and_physical_writes():
    reads = {"list_backups", "list_device_firmware", "get_speedtest_status"}
    writes = {
        "provision_device",
        "migrate_device",
        "cancel_rolling_upgrade",
        "advanced_adopt_device",
        "run_speedtest",
        "upgrade_all_devices",
        "start_rolling_upgrade",
        "move_device_to_site",
        "create_backup",
        "export_site",
    }
    tools = [cti.TOOLS[name] for name in reads | writes]
    assert reads | writes == {tool.name for tool in tools}
    classifications = audit.classify_tool_verbs(tools)
    assert all(not classifications[name] for name in reads)
    assert audit.derive_write_tools(tools) == writes
    for tool in tools:
        hint = tool.annotations.model_dump(by_alias=True)["readOnlyHint"]
        assert hint is (tool.name in reads), tool.name


@pytest.mark.parametrize(
    ("message", "site", "category"),
    [
        (
            "mac must be a device MAC, for example aa:bb:cc:dd:ee:ff",
            "tools/device_commands.py:advanced_adopt_device",
            refusals.SELECTOR_SYNTAX,
        ),
        (
            "Request timed out: -- Command outcome is unknown",
            "client.py:UniFiClient._request",
            refusals.UPSTREAM_JUDGED,
        ),
        (
            "Request timed out: -- outcome unknown; read back before retrying",
            "client.py:UniFiClient._request",
            refusals.UPSTREAM_JUDGED,
        ),
        (
            "Scheduled-task lookup is incomplete; cannot resolve an id safely.",
            "tools/scheduled_tasks.py:_resolve",
            refusals.UPSTREAM_JUDGED,
        ),
        (
            '{"meta": {"rc": "error", "msg": "no permission"}}',
            "tools/_classic_objects.py:checked_classic_response",
            refusals.UPSTREAM_JUDGED,
        ),
    ],
)
def test_command_raise_sites_have_r15_categories(message, site, category):
    refusal = refusals.classify(message)
    assert refusal is not None
    assert refusal.category == category
    assert site in refusal.sites
