"""Arm-profile writes resolve the caller's id against ``GET /v1/arm-profiles`` first.

The collection has no ``GET /{id}``, so every arm-profile tool that names one profile
reads the list: an id the list does not carry fails before any write (naming the valid
ids), a hex id matches case-insensitively, and the write addresses the profile by the
id the list reports. ``update_arm_profile_settings`` (the selection) now follows the
same rule as ``update_arm_profile`` and ``get_arm_profile``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests._protect_writes import assert_write, resp
from unifi_fabric.families.protect.protect import (
    PROTECT_PROXY_BASE,
    get_arm_profile,
    update_arm_profile,
    update_arm_profile_settings,
)

HOST_ID = "host-arm-001"
BASE = PROTECT_PROXY_BASE.format(host_id=HOST_ID)
LOWER = "66d025b301ebc903e80003ea"
OTHER = "66d025b301ebc903e80003eb"
PROFILES = [{"id": LOWER, "name": "Home"}, {"id": OTHER, "name": "Away"}]


@pytest.fixture()
def client():
    c = AsyncMock()
    c.request = AsyncMock(return_value=resp({}))
    c.get = AsyncMock()
    c.dry_run = False
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    return r


async def _settings(client, registry, wanted):
    return await update_arm_profile_settings(client, registry, "h", wanted)


async def _update(client, registry, wanted):
    return await update_arm_profile(client, registry, "h", wanted, name="Renamed")


async def _get(client, registry, wanted):
    return await get_arm_profile(client, registry, "h", wanted)


@pytest.mark.parametrize("call", [_settings, _update, _get], ids=["settings", "update", "get"])
async def test_unknown_id_fails_before_any_write_naming_valid_ids(client, registry, call):
    client.get.side_effect = [PROFILES]
    with pytest.raises(ValueError, match=rf"not found.*'{LOWER}'.*'{OTHER}'"):
        await call(client, registry, "does-not-exist")
    client.request.assert_not_called()
    # Only the list was read: no NVR read-before for an id that names nothing.
    assert [c.args[0] for c in client.get.call_args_list] == [f"{BASE}/arm-profiles"]


async def test_settings_upper_case_id_already_selected_is_noop(client, registry):
    client.get.side_effect = [PROFILES, {"armMode": {"armProfileId": LOWER}}]
    result = await _settings(client, registry, LOWER.upper())
    assert result["status"] == "noop"
    client.request.assert_not_called()


async def test_settings_upper_case_id_sends_upstream_spelling_and_verifies(client, registry):
    client.get.side_effect = [
        PROFILES,
        {"armMode": {"armProfileId": OTHER}},
        {"armMode": {"armProfileId": LOWER}},
    ]
    result = await _settings(client, registry, LOWER.upper())
    assert_write(client, "PATCH", f"{BASE}/arm-profiles/settings", json={"armProfileId": LOWER})
    assert result["status"] == "updated"
    assert result["verified"] is True


async def test_settings_nvr_reporting_upper_case_selection_is_noop(client, registry):
    # The comparison with the NVR's armProfileId uses the same id rule both ways.
    client.get.side_effect = [PROFILES, {"armMode": {"armProfileId": LOWER.upper()}}]
    result = await _settings(client, registry, LOWER)
    assert result["status"] == "noop"
    client.request.assert_not_called()


async def test_update_upper_case_id_addresses_upstream_spelling(client, registry):
    client.get.side_effect = [PROFILES, [{**PROFILES[0], "name": "Renamed"}, PROFILES[1]]]
    result = await _update(client, registry, LOWER.upper())
    assert_write(
        client,
        "PATCH",
        f"{BASE}/arm-profiles/{LOWER}",
        json={"name": "Renamed"},
    )
    assert result["status"] == "updated"


async def test_settings_body_id_is_held_to_the_spec_not_to_path_rules(client, registry):
    # armProfileId travels only in the body (spec: string): an id the list carries with
    # characters a URL path segment would refuse is selected and sent as listed.
    odd = "probe.id:zz~9"
    client.get.side_effect = [
        [{"id": odd}],
        {"armMode": {"armProfileId": LOWER}},
        {"armMode": {"armProfileId": odd}},
    ]
    result = await _settings(client, registry, odd)
    assert_write(client, "PATCH", f"{BASE}/arm-profiles/settings", json={"armProfileId": odd})
    assert result["verified"] is True
