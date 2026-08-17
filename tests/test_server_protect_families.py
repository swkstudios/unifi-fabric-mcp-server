"""Delegation tests for the extended Protect family @mcp.tool() wrappers (issue #185).

Each server wrapper is a thin pass-through to ``unifi_fabric.tools.protect``; the guard,
confirm, and env-gate logic lives in that module and is tested in
``test_protect_families``. These tests execute every wrapper once (so registration and
argument wiring are exercised) and assert it forwards ``client``/``registry`` and its
arguments to the right delegate, threading ``confirm``/optional kwargs through unchanged.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from unifi_fabric import server

HOST = "myhost"


@pytest.fixture()
def globs():
    c, r = AsyncMock(), AsyncMock()
    server._client, server._registry = c, r
    yield c, r
    server._client = None
    server._registry = None


# (wrapper name == delegate name, wrapper kwargs, expected delegate *args after host,
#  expected delegate **kwargs)
CASES = [
    ("list_arm_profiles", {}, (), {}),
    ("get_arm_profile", {"arm_profile_id": "a"}, ("a",), {}),
    ("update_arm_profile_settings", {"arm_profile_id": "a"}, ("a",), {}),
    ("list_sirens", {}, (), {}),
    ("get_siren", {"siren_id": "s"}, ("s",), {}),
    ("list_fobs", {}, (), {}),
    ("get_fob", {"fob_id": "f"}, ("f",), {}),
    ("list_relays", {}, (), {}),
    ("get_relay", {"relay_id": "r"}, ("r",), {}),
    ("list_speakers", {}, (), {}),
    ("get_speaker", {"speaker_id": "sp"}, ("sp",), {}),
    ("list_bridges", {}, (), {}),
    ("get_bridge", {"bridge_id": "b"}, ("b",), {}),
    ("list_link_stations", {}, (), {}),
    ("get_link_station", {"link_station_id": "ls"}, ("ls",), {}),
    ("list_alarm_hubs", {}, (), {}),
    ("get_alarm_hub", {"alarm_hub_id": "ah"}, ("ah",), {}),
    ("list_protect_users", {}, (), {}),
    ("get_protect_user", {"user_id": "u"}, ("u",), {}),
    ("list_ulp_users", {}, (), {}),
    ("get_ulp_user", {"ulp_user_id": "ulp"}, ("ulp",), {}),
    ("get_protect_application_info", {}, (), {}),
]


@pytest.mark.parametrize("name,kwargs,d_args,d_kwargs", CASES)
async def test_read_wrapper_delegates(globs, name, kwargs, d_args, d_kwargs):
    client, registry = globs
    expected = {"ok": name}
    with patch.object(server.protect, name, new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = expected
        result = await getattr(server, name)(HOST, **kwargs)
    mock_fn.assert_awaited_once_with(client, registry, HOST, *d_args, **d_kwargs)
    assert result is expected


# Settings-expansion wrappers: settings dict is splatted into **fields on the delegate.
SETTINGS_CASES = [
    ("update_siren", "siren_id", "s"),
    ("update_fob", "fob_id", "f"),
    ("update_relay", "relay_id", "r"),
    ("update_speaker", "speaker_id", "sp"),
    ("update_bridge", "bridge_id", "b"),
    ("update_link_station", "link_station_id", "ls"),
    ("update_alarm_hub", "alarm_hub_id", "ah"),
    ("update_arm_profile", "arm_profile_id", "a"),
]


@pytest.mark.parametrize("name,id_kw,id_val", SETTINGS_CASES)
async def test_update_wrapper_splats_settings(globs, name, id_kw, id_val):
    client, registry = globs
    expected = {"status": "updated"}
    with patch.object(server.protect, name, new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = expected
        result = await getattr(server, name)(HOST, **{id_kw: id_val}, settings={"name": "x"})
    mock_fn.assert_awaited_once_with(client, registry, HOST, id_val, name="x")
    assert result is expected


async def test_create_arm_profile_splats_settings(globs):
    client, registry = globs
    with patch.object(server.protect, "create_arm_profile", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {"id": "arm-9"}
        result = await server.create_arm_profile(HOST, "Night", settings={"activationDelay": 5})
    mock_fn.assert_awaited_once_with(client, registry, HOST, "Night", activationDelay=5)
    assert result == {"id": "arm-9"}


# Confirm-threading wrappers (single-id physical actions + delete).
CONFIRM_CASES = [
    ("delete_arm_profile", {"arm_profile_id": "a"}, ("a",), {"confirm": True}),
    ("enable_arm", {}, (), {"confirm": True}),
    ("disable_arm", {}, (), {"confirm": True}),
    ("siren_play", {"siren_id": "s", "duration": 10}, ("s",), {"confirm": True, "duration": 10}),
    ("siren_stop", {"siren_id": "s"}, ("s",), {"confirm": True}),
    (
        "siren_test_sound",
        {"siren_id": "s", "volume": 50},
        ("s",),
        {"confirm": True, "volume": 50},
    ),
    (
        "speaker_test_sound",
        {"speaker_id": "sp", "volume": 30},
        ("sp",),
        {"confirm": True, "volume": 30},
    ),
]


@pytest.mark.parametrize("name,kwargs,d_args,d_kwargs", CONFIRM_CASES)
async def test_confirm_wrapper_threads_confirm(globs, name, kwargs, d_args, d_kwargs):
    client, registry = globs
    expected = {"status": "ok"}
    with patch.object(server.protect, name, new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = expected
        result = await getattr(server, name)(HOST, confirm=True, **kwargs)
    mock_fn.assert_awaited_once_with(client, registry, HOST, *d_args, **d_kwargs)
    assert result is expected


async def test_relay_activate_output_wrapper(globs):
    client, registry = globs
    with patch.object(server.protect, "relay_activate_output", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {"status": "ok"}
        await server.relay_activate_output(
            HOST, "r1", "2", confirm=True, state="on", pulse_duration=3000
        )
    mock_fn.assert_awaited_once_with(
        client, registry, HOST, "r1", "2", confirm=True, state="on", pulse_duration=3000
    )


async def test_alarm_hub_trigger_output_wrapper(globs):
    client, registry = globs
    with patch.object(
        server.protect, "alarm_hub_trigger_output", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = {"status": "ok"}
        await server.alarm_hub_trigger_output(
            HOST, "ah1", "1", confirm=True, enable=True, delay=0, duration=5000
        )
    mock_fn.assert_awaited_once_with(
        client, registry, HOST, "ah1", "1", confirm=True, enable=True, delay=0, duration=5000
    )


async def test_pos_ingest_transaction_wrapper(globs):
    client, registry = globs
    txn = {"type": "sale", "externalId": "ext-1", "amount": 5}
    with patch.object(server.protect, "pos_ingest_transaction", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {"id": "evt-1"}
        result = await server.pos_ingest_transaction(HOST, "cam-1", txn, confirm=True)
    mock_fn.assert_awaited_once_with(client, registry, HOST, "cam-1", txn, confirm=True)
    assert result == {"id": "evt-1"}
