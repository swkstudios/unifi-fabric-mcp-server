"""Protect 7.x removed routes: the tools that cannot work are gone, the remapped ones route.

Evidence: the Protect 7.3.74 server (service.js route table) serves ``GET /locks`` and
``POST /locks/:id/unlock`` and no door-lock calibrate, autoClose, lock or close route; it
serves the former ``nvr/restore-pg-dump`` handler unchanged at
``nvr/restore-database-backup`` (so ``restore_protect_database`` is remapped, not removed),
and has no case-asset ``snapshot`` (``download`` streams the asset's own file or builds a PDF), no
``nvr/reboot``, no ``users/:id/notifications`` PATCH (``PATCH /users/:id`` deletes the
notification fields from the body) and no camera adoption QR route.
"""

from __future__ import annotations

import json

import pytest

from tests.test_tool_schema_contract import _tools
from unifi_fabric.families.protect import (
    protect_automation_backup,
    protect_camera_recording,
    protect_device_lifecycle,
    protect_events_cases,
    protect_private,
    protect_users_assets,
)
from unifi_fabric.families.protect._protect_device_types import DEVICE_ROUTES, ProtectDeviceType
from unifi_fabric.generated_api_facts import _api_source_table

REMOVED = {
    "calibrate_door_lock": protect_device_lifecycle,
    "set_door_lock_auto_close": protect_device_lifecycle,
    "get_protect_case_asset_snapshot": protect_events_cases,
    "reboot_nvr": protect_private,
    "update_protect_user_notifications": protect_users_assets,
    "get_camera_adoption_qr": protect_camera_recording,
}


def test_removed_names_are_tool_shaped_not_every_backticked_word():
    """A Removed section also backticks routes and modules (``trafficrules``,
    ``protect_camera_recording``); only tool-name shapes count as removed tools."""
    from tests.removed_tools import FIXTURES, removed_since_release

    live = {tool.name for tool in _tools()}
    removed = removed_since_release(live)
    assert set(REMOVED) <= removed
    assert not removed & {"trafficrules", "protect_camera_recording"}
    snapshots = {
        name
        for path in FIXTURES.glob("tool_input_schemas_v*.json")
        for name in json.loads(path.read_text(encoding="utf-8"))["schemas"]
    }
    verbs = {name.split("_", 1)[0] for name in live | snapshots}
    stray = sorted(
        n for n in removed - snapshots if "_" not in n or n.split("_", 1)[0] not in verbs
    )
    assert stray == []


@pytest.mark.parametrize("name", sorted(REMOVED))
def test_removed_tool_is_not_registered_or_importable_or_classified(name):
    assert name not in {tool.name for tool in _tools()}
    module = REMOVED[name]
    assert not hasattr(module, name) and not hasattr(module, f"_{name}")
    assert name not in _api_source_table.TOOL_API_SOURCES


def test_the_remapped_and_replacement_tools_remain():
    names = {tool.name for tool in _tools()}
    # list/unlock are remapped to /locks; the console reboot and the mute tool are the
    # 7.x-served routes that cover what reboot_nvr and the notifications update aimed at.
    assert {
        "list_door_locks",
        "set_door_lock_state",
        "reboot_unifi_os_console",
        "set_protect_notifications_muted",
        "restore_protect_backup",
        "restore_protect_database",
    } <= names


def test_door_locks_map_to_the_7x_locks_collection_only():
    routes = DEVICE_ROUTES[ProtectDeviceType.DOORLOCK]
    assert routes.collection == "locks"
    assert dict(routes.actions) == {
        "readopt": "POST",
        "unadopt": "POST",
        "locate": "POST",
        "unlock": "POST",
    }
    assert not {"calibrate", "autoClose", "open", "close", "lock", "reboot"} & set(routes.actions)


def test_door_lock_tools_are_stated_as_hermetic_only_in_coverage():
    # No lock on the estate: the /locks tools are route-proven and hermetic only, and the
    # coverage page must say so in a paragraph of its own, like the other no-console entries.
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docs" / "COVERAGE.md").read_text()
    paragraphs = [p for p in text.split("\n\n") if "list_door_locks" in p]
    assert paragraphs, "docs/COVERAGE.md does not mention list_door_locks"
    (paragraph,) = paragraphs
    assert "set_door_lock_state" in paragraph
    assert "hermetic" in paragraph and "no door lock" in paragraph.lower()
    assert "/locks" in paragraph


def test_door_lock_descriptions_name_the_7x_locks_route_not_every_door_lock():
    # /locks is the Protect 7.x Thread lock model: the descriptions must say they cover the
    # locks Protect 7.x manages under /locks, not "every" door lock or older lock products.
    tools = {tool.name: " ".join((tool.description or "").split()) for tool in _tools()}
    listing = tools["list_door_locks"]
    assert "every UniFi door lock" not in listing
    assert "locks Protect 7.x manages under /locks" in listing
    assert "older door-lock products" in listing
    unlock = tools["set_door_lock_state"]
    assert "a UniFi door lock" not in unlock
    assert "lock Protect 7.x manages under /locks" in unlock


def test_restore_protect_database_is_remapped_to_the_7x_route_and_classified_a_write():
    assert hasattr(protect_automation_backup, "_restore_protect_database")
    assert _api_source_table.TOOL_API_SOURCES["restore_protect_database"] == (
        "site_manager/official",
        "protect/private",
    )
    tool = {tool.name: tool for tool in _tools()}["restore_protect_database"]
    assert tool.annotations.readOnlyHint is False
    assert tool.annotations.destructiveHint is True


def test_restore_protect_database_is_stated_as_hermetic_only_in_coverage():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docs" / "COVERAGE.md").read_text()
    paragraphs = [p for p in text.split("\n\n") if "restore_protect_database" in p]
    assert paragraphs, "docs/COVERAGE.md does not mention restore_protect_database"
    (paragraph,) = paragraphs
    assert "hermetic" in paragraph and "nvr/restore-database-backup" in paragraph
    assert "not run" in paragraph
