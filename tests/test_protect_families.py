"""Hermetic fixture tests for the extended Protect Integration API families.

Covers arm profiles (+settings/enable/disable), sirens, fobs, relays, speakers, bridges,
link stations, alarm hubs, Protect users, ULP users, application metadata, and POS
transaction ingestion. Every test is hermetic — no live credentials, HTTP fully mocked —
and asserts the exact Fabric proxy URL/method, owning-key routing, upstream pass-through
(including unknown/future fields), unsupported-endpoint error propagation, the confirm
guards (with no-request behaviour), the read-before/no-op/read-after settings flow, the
UNIFI_PROTECT_MUTATIONS_ENABLED env gate, that side-effecting writes disable 429
auto-retry (max_retries=0), and the POS idempotency/validation guardrails.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests._protect_writes import assert_write, resp
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.tools.protect import (
    PROTECT_MUTATIONS_ENV,
    PROTECT_PROXY_BASE,
    alarm_hub_trigger_output,
    create_arm_profile,
    delete_arm_profile,
    disable_arm,
    enable_arm,
    get_alarm_hub,
    get_arm_profile,
    get_bridge,
    get_fob,
    get_link_station,
    get_protect_application_info,
    get_protect_user,
    get_relay,
    get_siren,
    get_speaker,
    get_ulp_user,
    list_alarm_hubs,
    list_arm_profiles,
    list_bridges,
    list_fobs,
    list_link_stations,
    list_protect_users,
    list_relays,
    list_sirens,
    list_speakers,
    list_ulp_users,
    pos_ingest_transaction,
    protect_mutations_enabled,
    relay_activate_output,
    siren_play,
    siren_stop,
    siren_test_sound,
    speaker_test_sound,
    update_alarm_hub,
    update_arm_profile,
    update_arm_profile_settings,
    update_bridge,
    update_fob,
    update_link_station,
    update_relay,
    update_siren,
    update_speaker,
)

HOST_ID = "host-fam-001"
BASE = PROTECT_PROXY_BASE.format(host_id=HOST_ID)
KEY = APIKeyConfig(key="k-owner", label="owner", is_org_key=True)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.request = AsyncMock(return_value=resp({}))
    c.get = AsyncMock()
    c.post = AsyncMock(return_value={})
    c.patch = AsyncMock(return_value={})
    c.delete = AsyncMock(return_value=None)
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    return r


@pytest.fixture()
def keyed_registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=KEY)
    return r


# --- Uniform list/get/update families ------------------------------------------------

# (list_fn, get_fn, update_fn, family_path, plural_key, id_name)
_UNIFORM = [
    (list_sirens, get_siren, update_siren, "sirens", "sirens", "siren_id"),
    (list_fobs, get_fob, update_fob, "fobs", "fobs", "fob_id"),
    (list_relays, get_relay, update_relay, "relays", "relays", "relay_id"),
    (list_speakers, get_speaker, update_speaker, "speakers", "speakers", "speaker_id"),
    (list_bridges, get_bridge, update_bridge, "bridges", "bridges", "bridge_id"),
    (
        list_link_stations,
        get_link_station,
        update_link_station,
        "link-stations",
        "link_stations",
        "link_station_id",
    ),
    (list_alarm_hubs, get_alarm_hub, update_alarm_hub, "alarm-hubs", "alarm_hubs", "alarm_hub_id"),
]


@pytest.mark.parametrize("list_fn,_g,_u,family,plural,_idn", _UNIFORM)
async def test_family_list_url_and_shape(client, registry, list_fn, _g, _u, family, plural, _idn):
    client.get.return_value = [{"id": "a", "futureField": 1}, {"id": "b"}]
    result = await list_fn(client, registry, "myhost")
    client.get.assert_called_once_with(f"{BASE}/{family}", key=None)
    # a bare array body is the result under FastMCP's list key, never an invented plural
    assert result == {"result": [{"id": "a", "futureField": 1}, {"id": "b"}], "_count": 2}
    assert plural not in result


@pytest.mark.parametrize("list_fn,_g,_u,family,plural,_idn", _UNIFORM)
async def test_family_list_envelope(client, registry, list_fn, _g, _u, family, plural, _idn):
    client.get.return_value = {"data": [{"id": "z"}]}
    result = await list_fn(client, registry, "h")
    # an object body is returned verbatim (its own data key), plus the additive _count
    assert result == {"data": [{"id": "z"}], "_count": 1}


@pytest.mark.parametrize("_l,get_fn,_u,family,_p,_idn", _UNIFORM)
async def test_family_get_url_and_passthrough(client, registry, _l, get_fn, _u, family, _p, _idn):
    client.get.return_value = {"id": "item-1", "unknownFuture": {"nested": True}}
    result = await get_fn(client, registry, "h", "item-1")
    client.get.assert_called_once_with(f"{BASE}/{family}/item-1", key=None)
    assert result == {"id": "item-1", "unknownFuture": {"nested": True}}


@pytest.mark.parametrize("_l,get_fn,_u,family,_p,_idn", _UNIFORM)
async def test_family_get_non_object_raises(client, registry, _l, get_fn, _u, family, _p, _idn):
    client.get.return_value = ["raw"]
    with pytest.raises(UniFiConnectionError, match="expected an object, got array"):
        await get_fn(client, registry, "h", "item-1")


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_update_read_patch_readafter(
    client, registry, _l, _g, upd_fn, family, _p, _idn
):
    # before differs -> PATCH sent (with 429 retry disabled), read-after confirms.
    client.get.side_effect = [{"id": "x", "name": "old"}, {"id": "x", "name": "new"}]
    result = await upd_fn(client, registry, "h", "x", name="new")
    assert_write(client, "PATCH", f"{BASE}/{family}/x", key=None, json={"name": "new"})
    assert client.get.call_count == 2
    assert result["status"] == "updated"
    assert result["verified"] is True
    assert result["before"] == {"id": "x", "name": "old"}
    assert result["after"] == {"id": "x", "name": "new"}
    assert result["response"] == {}


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
@pytest.mark.parametrize(
    "body,expected",
    [
        (resp({"id": "x", "name": "new", "extra": 1}), {"id": "x", "name": "new", "extra": 1}),
        (resp(), None),
        (resp(text="accepted"), "accepted"),
    ],
)
async def test_family_update_returns_patch_body_verbatim(
    client, registry, _l, _g, upd_fn, family, _p, _idn, body, expected
):
    client.get.side_effect = [{"id": "x", "name": "old"}, {"id": "x", "name": "new"}]
    client.request.return_value = body
    result = await upd_fn(client, registry, "h", "x", name="new")
    assert result["response"] == expected
    assert result["verified"] is True


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_update_read_after_shape_checked_like_read_before(
    client, registry, _l, _g, upd_fn, family, _p, _idn
):
    client.get.side_effect = [{"id": "x", "name": "old"}, ["not", "an", "object"]]
    # The PATCH already happened: a read-after of the wrong shape is reported (the one
    # safe read-after), never raised as if the write had failed.
    result = await upd_fn(client, registry, "h", "x", name="new")
    assert result["status"] == "updated" and result["verified"] is None
    assert "expected an object, got array of 3" in result["readAfterError"]


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_update_noop_skips_write(client, registry, _l, _g, upd_fn, family, _p, _idn):
    client.get.return_value = {"id": "x", "name": "same"}
    result = await upd_fn(client, registry, "h", "x", name="same")
    client.request.assert_not_called()
    assert result["status"] == "noop"
    assert result["resource"] == {"id": "x", "name": "same"}
    assert client.get.call_count == 1


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_update_gate_disabled_no_request(
    monkeypatch, client, registry, _l, _g, upd_fn, family, _p, _idn
):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "0")
    with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
        await upd_fn(client, registry, "h", "x", name="new")
    client.get.assert_not_called()
    client.request.assert_not_called()


# --- Owning-key routing --------------------------------------------------------------


async def test_list_threads_owning_key(client, keyed_registry):
    client.get.return_value = []
    await list_sirens(client, keyed_registry, "myhost")
    keyed_registry.resolve_host_id.assert_called_once_with("myhost", key=KEY)
    client.get.assert_called_once_with(f"{BASE}/sirens", key=KEY)


async def test_action_threads_owning_key(client, keyed_registry):
    await siren_play(client, keyed_registry, "myhost", "s1", confirm=True)
    keyed_registry.resolve_host_id.assert_called_once_with("myhost", key=KEY)
    assert_write(client, "POST", f"{BASE}/sirens/s1/play", key=KEY, json={})


async def test_update_threads_owning_key(client, keyed_registry):
    client.get.side_effect = [{"id": "s1", "name": "a"}, {"id": "s1", "name": "b"}]
    await update_siren(client, keyed_registry, "myhost", "s1", name="b")
    assert_write(client, "PATCH", f"{BASE}/sirens/s1", key=KEY, json={"name": "b"})


# --- Unsupported endpoint / version errors pass through ------------------------------


async def test_unsupported_family_error_propagates(client, registry):
    client.get.side_effect = UniFiConnectionError("HTTP 404: not found")
    with pytest.raises(UniFiConnectionError):
        await list_sirens(client, registry, "h")


async def test_unsupported_action_error_propagates(client, registry):
    client.request.side_effect = UniFiConnectionError("HTTP 501: not implemented")
    with pytest.raises(UniFiConnectionError):
        await enable_arm(client, registry, "h", confirm=True)


# --- Physical action confirm guards (all writes disable 429 auto-retry) -------------

# (fn, args, kwargs, expected_url_suffix, expected_body)
_ACTIONS = [
    (siren_play, ("s1",), {"confirm": True}, "/sirens/s1/play", {}),
    (siren_play, ("s1",), {"confirm": True, "duration": 10}, "/sirens/s1/play", {"duration": 10}),
    (siren_stop, ("s1",), {"confirm": True}, "/sirens/s1/stop", None),
    (
        siren_test_sound,
        ("s1",),
        {"confirm": True, "volume": 50},
        "/sirens/s1/test-sound",
        {"volume": 50},
    ),
    (speaker_test_sound, ("sp1",), {"confirm": True}, "/speakers/sp1/test-sound", {}),
    (enable_arm, (), {"confirm": True}, "/arm-profiles/enable", None),
    (disable_arm, (), {"confirm": True}, "/arm-profiles/disable", None),
]


@pytest.mark.parametrize("fn,args,kwargs,suffix,body", _ACTIONS)
async def test_action_executes_with_confirm_no_retry(
    client, registry, fn, args, kwargs, suffix, body
):
    result = await fn(client, registry, "h", *args, **kwargs)
    assert_write(client, "POST", f"{BASE}{suffix}", key=None, json=body)
    assert result == {"status": "sent", "response": {}}


@pytest.mark.parametrize("fn,args,kwargs,suffix,body", _ACTIONS)
async def test_action_runs_without_confirm(client, registry, fn, args, kwargs, suffix, body):
    no_confirm = {k: v for k, v in kwargs.items() if k != "confirm"}
    result = await fn(client, registry, "h", *args, **no_confirm)
    assert_write(client, "POST", f"{BASE}{suffix}", key=None, json=body)
    assert result == {"status": "sent", "response": {}}


@pytest.mark.parametrize("fn,args,kwargs,suffix,body", _ACTIONS)
async def test_action_gate_disabled_beats_confirm(
    monkeypatch, client, registry, fn, args, kwargs, suffix, body
):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "off")
    with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
        await fn(client, registry, "h", *args, **kwargs)  # confirm=True present
    client.request.assert_not_called()


@pytest.mark.parametrize("fn,args,kwargs,suffix,body", _ACTIONS)
@pytest.mark.parametrize(
    "upstream,expected",
    [(resp(), None), (resp(text="OK"), "OK"), (resp(None), None), (resp([1, 2]), [1, 2])],
)
async def test_action_body_returned_verbatim_never_raised(
    client, registry, fn, args, kwargs, suffix, body, upstream, expected
):
    client.request.return_value = upstream
    result = await fn(client, registry, "h", *args, **kwargs)
    assert result == {"status": "sent", "response": expected}


# --- Relay + alarm-hub output actions (two path IDs) --------------------------------


async def test_relay_activate_output_url_and_body(client, registry):
    result = await relay_activate_output(
        client, registry, "h", "r1", "1", confirm=True, state="on", pulse_duration=3000
    )
    assert_write(
        client,
        "POST",
        f"{BASE}/relays/r1/outputs/1/activate",
        key=None,
        json={"state": "on", "pulseDuration": 3000},
    )
    assert result == {"status": "sent", "response": {}}


async def test_relay_activate_output_toggle_empty_body(client, registry):
    await relay_activate_output(client, registry, "h", "r1", "1", confirm=True)
    assert_write(client, "POST", f"{BASE}/relays/r1/outputs/1/activate", key=None, json={})


async def test_relay_activate_runs_without_confirm(client, registry):
    await relay_activate_output(client, registry, "h", "r1", "1")
    assert_write(client, "POST", f"{BASE}/relays/r1/outputs/1/activate", key=None, json={})


async def test_alarm_hub_trigger_output_url_and_body(client, registry):
    await alarm_hub_trigger_output(
        client, registry, "h", "ah1", "1", confirm=True, enable=True, delay=0, duration=5000
    )
    assert_write(
        client,
        "POST",
        f"{BASE}/alarm-hubs/ah1/outputs/1/trigger",
        key=None,
        json={"enable": True, "delay": 0, "duration": 5000},
    )


async def test_alarm_hub_trigger_runs_without_confirm(client, registry):
    await alarm_hub_trigger_output(client, registry, "h", "ah1", "1")
    assert_write(client, "POST", f"{BASE}/alarm-hubs/ah1/outputs/1/trigger", key=None, json={})


# --- Arm profiles (list-based get/update, settings, create, delete) -----------------


async def test_list_arm_profiles_url(client, registry):
    client.get.return_value = [{"id": "arm-1", "name": "Home", "newField": 9}]
    result = await list_arm_profiles(client, registry, "h")
    client.get.assert_called_once_with(f"{BASE}/arm-profiles", key=None)
    assert result == {"result": [{"id": "arm-1", "name": "Home", "newField": 9}], "_count": 1}


async def test_get_arm_profile_filters_list(client, registry):
    client.get.return_value = [{"id": "arm-1"}, {"id": "arm-2", "name": "Away"}]
    result = await get_arm_profile(client, registry, "h", "arm-2")
    client.get.assert_called_once_with(f"{BASE}/arm-profiles", key=None)
    assert result == {"id": "arm-2", "name": "Away"}


async def test_get_arm_profile_missing_raises(client, registry):
    client.get.return_value = [{"id": "arm-1"}]
    with pytest.raises(ValueError, match="not found"):
        await get_arm_profile(client, registry, "h", "nope")


async def test_get_arm_profile_unknown_id_lists_valid_ids(client, registry):
    client.get.return_value = [{"id": "arm-1"}, {"id": "arm-2"}]
    with pytest.raises(ValueError) as exc:
        await get_arm_profile(client, registry, "h", "nope")
    assert "'arm-1'" in str(exc.value) and "'arm-2'" in str(exc.value)


async def test_update_arm_profile_unknown_id_fails_before_patch(client, registry):
    client.get.return_value = [{"id": "arm-1"}, {"id": "arm-2"}]
    with pytest.raises(ValueError) as exc:
        await update_arm_profile(client, registry, "h", "nope", name="x")
    assert "'arm-1'" in str(exc.value) and "'arm-2'" in str(exc.value)
    client.request.assert_not_called()  # no PATCH


async def test_update_arm_profile_partial_nested_update_verifies(client, registry):
    before = {"id": "arm-1", "sirenSettings": {"siren": False, "lights": True}}
    after = {"id": "arm-1", "sirenSettings": {"siren": True, "lights": True}}
    client.get.side_effect = [[before], [after]]
    result = await update_arm_profile(client, registry, "h", "arm-1", sirenSettings={"siren": True})
    assert_write(
        client,
        "PATCH",
        f"{BASE}/arm-profiles/arm-1",
        key=None,
        json={"sirenSettings": {"siren": True}},
    )
    assert result["verified"] is True


async def test_update_arm_profile_equal_nested_leaf_is_noop(client, registry):
    client.get.return_value = [{"id": "arm-1", "sirenSettings": {"siren": True, "lights": False}}]
    result = await update_arm_profile(client, registry, "h", "arm-1", sirenSettings={"siren": True})
    client.request.assert_not_called()
    assert result["status"] == "noop"


async def test_create_arm_profile_url_and_body_no_retry(client, registry):
    client.request.return_value = resp({"id": "arm-9", "name": "Night"})
    result = await create_arm_profile(
        client,
        registry,
        "h",
        "Night",
        activationDelay=30,
        recordEverything=True,
        automations=[],
        schedules=[],
    )
    assert_write(
        client,
        "POST",
        f"{BASE}/arm-profiles",
        key=None,
        json={
            "name": "Night",
            "activationDelay": 30,
            "recordEverything": True,
            "automations": [],
            "schedules": [],
        },
    )
    assert result == {"status": "created", "response": {"id": "arm-9", "name": "Night"}}


async def test_create_arm_profile_empty_name_rejected(client, registry):
    with pytest.raises(ValueError, match="name"):
        await create_arm_profile(client, registry, "h", "")
    client.request.assert_not_called()


async def test_create_arm_profile_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "false")
    with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
        await create_arm_profile(client, registry, "h", "Night")
    client.request.assert_not_called()


async def test_update_arm_profile_readafter(client, registry):
    client.get.side_effect = [[{"id": "arm-1", "name": "old"}], [{"id": "arm-1", "name": "new"}]]
    result = await update_arm_profile(client, registry, "h", "arm-1", name="new")
    assert_write(client, "PATCH", f"{BASE}/arm-profiles/arm-1", key=None, json={"name": "new"})
    assert result["status"] == "updated"
    assert result["verified"] is True
    assert result["after"] == {"id": "arm-1", "name": "new"}


async def test_update_arm_profile_noop(client, registry):
    client.get.return_value = [{"id": "arm-1", "name": "same"}]
    result = await update_arm_profile(client, registry, "h", "arm-1", name="same")
    client.request.assert_not_called()
    assert result["status"] == "noop"


async def test_delete_arm_profile_runs_without_confirm(client, registry):
    client.get.return_value = [{"id": "arm-1"}]  # found in the list first
    result = await delete_arm_profile(client, registry, "h", "arm-1")
    client.delete.assert_called_once_with(f"{BASE}/arm-profiles/arm-1", key=None)
    assert result == {"deleted": True, "message": "Arm profile arm-1 deleted.", "response": None}


async def test_delete_arm_profile_with_confirm_no_retry(client, registry):
    client.get.return_value = [{"id": "arm-1"}]  # found in the list first
    result = await delete_arm_profile(client, registry, "h", "arm-1", confirm=True)
    client.delete.assert_called_once_with(f"{BASE}/arm-profiles/arm-1", key=None)
    assert result == {"deleted": True, "message": "Arm profile arm-1 deleted.", "response": None}


async def test_delete_arm_profile_unknown_id_sends_no_delete(client, registry):
    client.get.return_value = [{"id": "arm-1"}, {"id": "arm-2"}]
    with pytest.raises(ValueError, match="arm-9.*arm-1.*arm-2"):
        await delete_arm_profile(client, registry, "h", "arm-9")
    client.delete.assert_not_called()


async def test_delete_arm_profile_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "no")
    with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
        await delete_arm_profile(client, registry, "h", "arm-1", confirm=True)
    client.delete.assert_not_called()


async def test_arm_settings_select_readafter(client, registry):
    client.get.side_effect = [
        [{"id": "arm-1"}, {"id": "arm-2"}],
        {"armMode": {"armProfileId": "arm-1"}},
        {"armMode": {"armProfileId": "arm-2"}},
    ]
    result = await update_arm_profile_settings(client, registry, "h", "arm-2")
    assert_write(
        client,
        "PATCH",
        f"{BASE}/arm-profiles/settings",
        key=None,
        json={"armProfileId": "arm-2"},
    )
    assert result["status"] == "updated"
    assert result["verified"] is True


async def test_arm_settings_noop_when_already_selected(client, registry):
    client.get.side_effect = [
        [{"id": "arm-1"}, {"id": "arm-2"}],
        {"armMode": {"armProfileId": "arm-2"}},
    ]
    result = await update_arm_profile_settings(client, registry, "h", "arm-2")
    client.request.assert_not_called()
    assert result["status"] == "noop"
    assert client.get.call_count == 2


async def test_arm_settings_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "0")
    with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
        await update_arm_profile_settings(client, registry, "h", "arm-2")
    client.get.assert_not_called()
    client.request.assert_not_called()


# --- Protect users vs ULP users vs application metadata (read-only) -----------------


async def test_list_protect_users_url(client, registry):
    client.get.return_value = [{"id": "u1", "firstName": "A"}]
    result = await list_protect_users(client, registry, "h")
    client.get.assert_called_once_with(f"{BASE}/users", key=None)
    assert result == {"result": [{"id": "u1", "firstName": "A"}], "_count": 1}


async def test_get_protect_user_url(client, registry):
    client.get.return_value = {"id": "u1", "roleName": "admin", "futureFlag": 1}
    result = await get_protect_user(client, registry, "h", "u1")
    client.get.assert_called_once_with(f"{BASE}/users/u1", key=None)
    assert result == {"id": "u1", "roleName": "admin", "futureFlag": 1}


async def test_list_ulp_users_distinct_path(client, registry):
    client.get.return_value = [{"id": "ulp-1", "email": "a@example.com"}]
    result = await list_ulp_users(client, registry, "h")
    client.get.assert_called_once_with(f"{BASE}/ulp-users", key=None)
    assert result == {"result": [{"id": "ulp-1", "email": "a@example.com"}], "_count": 1}


async def test_get_ulp_user_url(client, registry):
    client.get.return_value = {"id": "ulp-1", "fullName": "A B"}
    result = await get_ulp_user(client, registry, "h", "ulp-1")
    client.get.assert_called_once_with(f"{BASE}/ulp-users/ulp-1", key=None)
    assert result == {"id": "ulp-1", "fullName": "A B"}


async def test_get_protect_application_info_url(client, registry):
    client.get.return_value = {"applicationVersion": "7.2.105", "capabilities": {"pos": True}}
    result = await get_protect_application_info(client, registry, "h")
    client.get.assert_called_once_with(f"{BASE}/meta/info", key=None)
    assert result == {"applicationVersion": "7.2.105", "capabilities": {"pos": True}}


# --- POS transaction ingestion -------------------------------------------------------


def _txn(**over):
    base = {"type": "sale", "externalId": "ext-123", "amount": 42.50}
    base.update(over)
    return base


async def test_pos_ingest_url_body_no_retry(client, registry):
    client.request.return_value = resp({"id": "evt-1"})
    txn = _txn(currency="USD", lineItems=[{"title": "Coffee", "quantity": 1}])
    result = await pos_ingest_transaction(client, registry, "h", "cam-1", txn, confirm=True)
    assert_write(client, "POST", f"{BASE}/pos/cameras/cam-1/transactions", key=None, json=txn)
    assert result == {"status": "sent", "response": {"id": "evt-1"}}


async def test_pos_ingest_runs_without_confirm(client, registry):
    client.request.return_value = resp({"id": "evt-1"})
    result = await pos_ingest_transaction(client, registry, "h", "cam-1", _txn())
    client.request.assert_called_once()
    assert result == {"status": "sent", "response": {"id": "evt-1"}}


async def test_pos_ingest_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "0")
    with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
        await pos_ingest_transaction(client, registry, "h", "cam-1", _txn(), confirm=True)
    client.request.assert_not_called()


async def test_pos_ingest_bad_type_rejected(client, registry):
    with pytest.raises(ValueError, match="type"):
        await pos_ingest_transaction(
            client, registry, "h", "cam-1", _txn(type="void"), confirm=True
        )
    client.request.assert_not_called()


async def test_pos_ingest_missing_external_id_rejected(client, registry):
    txn = {"type": "sale", "amount": 1}
    with pytest.raises(ValueError, match="externalId"):
        await pos_ingest_transaction(client, registry, "h", "cam-1", txn, confirm=True)
    client.request.assert_not_called()


async def test_pos_ingest_missing_amount_rejected(client, registry):
    txn = {"type": "sale", "externalId": "ext-1"}
    with pytest.raises(ValueError, match="amount"):
        await pos_ingest_transaction(client, registry, "h", "cam-1", txn, confirm=True)
    client.request.assert_not_called()


async def test_pos_ingest_empty_body_reported_not_raised(client, registry):
    client.request.return_value = resp()
    result = await pos_ingest_transaction(client, registry, "h", "cam-1", _txn(), confirm=True)
    assert result == {"status": "sent", "response": None}


async def test_pos_ingest_rejects_bad_camera_id(client, registry):
    with pytest.raises(ValueError):
        await pos_ingest_transaction(client, registry, "h", "../bad", _txn(), confirm=True)
    client.request.assert_not_called()


# --- Env gate helper ----------------------------------------------------------------


def test_gate_default_on_when_unset(monkeypatch):
    monkeypatch.delenv(PROTECT_MUTATIONS_ENV, raising=False)
    assert protect_mutations_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off", "Off"])
def test_gate_off_values(monkeypatch, value):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, value)
    assert protect_mutations_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "", "   "])
def test_gate_on_values(monkeypatch, value):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, value)
    assert protect_mutations_enabled() is True


# --- validate_id rejects unsafe ids on new tools ------------------------------------


async def test_get_siren_rejects_bad_id(client, registry):
    with pytest.raises(ValueError):
        await get_siren(client, registry, "h", "../etc/passwd")
    client.get.assert_not_called()


async def test_relay_activate_rejects_bad_output_id(client, registry):
    with pytest.raises(ValueError):
        await relay_activate_output(client, registry, "h", "r1", "bad/id", confirm=True)
    client.request.assert_not_called()


async def test_create_arm_profile_name_repeated_in_settings_is_accepted(client, registry):
    # Regression: a settings dict that also carried ``name`` raised a Python TypeError
    # (duplicate keyword) before any request. An identical repeat is now accepted.
    client.request.return_value = resp({"id": "arm-10"})
    await create_arm_profile(
        client,
        registry,
        "h",
        "Night",
        name="Night",
        activationDelay=0,
        recordEverything=False,
        automations=[],
        schedules=[],
    )
    body = client.request.call_args.kwargs["json"]
    assert body["name"] == "Night"
    assert list(body).count("name") == 1


async def test_create_arm_profile_conflicting_name_rejected(client, registry):
    with pytest.raises(ValueError, match="given twice with different values"):
        await create_arm_profile(client, registry, "h", "Night", name="Day")
    client.request.assert_not_called()


async def test_create_arm_profile_server_wrapper_accepts_name_in_settings(monkeypatch):
    from unifi_fabric import server

    sent = {}

    async def fake(client, registry, host, name, /, **fields):
        sent.update(host=host, name=name, fields=fields)
        return {"ok": True}

    monkeypatch.setattr(server, "_require", lambda: (object(), object()))
    monkeypatch.setattr(server.protect, "create_arm_profile", fake)
    await server.create_arm_profile("h", "Night", settings={"name": "Night", "schedules": []})
    assert sent["fields"] == {"name": "Night", "schedules": []}


def test_settings_splat_functions_cannot_collide_with_their_own_params():
    # The whole class: any Protect helper that splats caller settings as **fields must
    # make its own parameters positional-only, so a settings key such as "host" or
    # "name" lands in the request body instead of raising TypeError.
    import inspect

    from unifi_fabric.tools import protect

    offenders = []
    for name, fn in inspect.getmembers(protect, inspect.iscoroutinefunction):
        params = list(inspect.signature(fn).parameters.values())
        if any(p.kind is p.VAR_KEYWORD for p in params):
            named = [p for p in params if p.kind is not p.VAR_KEYWORD]
            if any(p.kind is not p.POSITIONAL_ONLY for p in named):
                offenders.append(name)
    assert offenders == []


async def test_create_liveview_name_repeated_in_settings_is_accepted(client, registry):
    from unifi_fabric.tools.protect import create_liveview

    client.request.return_value = resp({"id": "lv-1"})
    await create_liveview(client, registry, "h", "Front", name="Front", layout=4, slots=[])
    body = client.request.call_args.kwargs["json"]
    assert body == {"name": "Front", "layout": 4, "slots": []}


# --- Deep-subset verification (partial nested updates) -------------------------------


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_partial_nested_update_verified(
    client, registry, _l, _g, upd_fn, family, _p, _idn
):
    # A partial nested update changes one leaf; the siblings it does not name stay as
    # they were. Every requested leaf matching the read-after is verified.
    before = {"id": "x", "ledSettings": {"isEnabled": False, "blinkRate": 3}}
    after = {"id": "x", "ledSettings": {"isEnabled": True, "blinkRate": 3}}
    client.get.side_effect = [before, after]
    result = await upd_fn(client, registry, "h", "x", ledSettings={"isEnabled": True})
    assert_write(
        client,
        "PATCH",
        f"{BASE}/{family}/x",
        key=None,
        json={"ledSettings": {"isEnabled": True}},
    )
    assert result["status"] == "updated"
    assert result["verified"] is True


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_nested_update_not_applied_is_unverified(
    client, registry, _l, _g, upd_fn, family, _p, _idn
):
    before = {"id": "x", "ledSettings": {"isEnabled": False, "blinkRate": 3}}
    client.get.side_effect = [before, before]
    result = await upd_fn(client, registry, "h", "x", ledSettings={"isEnabled": True})
    assert result["verified"] is False


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_equal_nested_leaf_is_noop(client, registry, _l, _g, upd_fn, family, _p, _idn):
    # Every requested leaf already holds its value: no PATCH, even though the whole
    # nested object has other keys too.
    client.get.return_value = {"id": "x", "ledSettings": {"isEnabled": True, "blinkRate": 3}}
    result = await upd_fn(client, registry, "h", "x", ledSettings={"isEnabled": True})
    client.request.assert_not_called()
    assert result["status"] == "noop"


def test_requested_leaves_match_semantics():
    from unifi_fabric.tools._results import requested_leaves_match as m

    assert m({"osd": {"isDateEnabled": True}}, {"osd": {"isDateEnabled": True, "x": 1}})
    assert not m({"osd": {"isDateEnabled": True}}, {"osd": {"isDateEnabled": False}})
    assert not m({"osd": {"isDateEnabled": True}}, {"osd": "flat"})
    assert m({"a": {"b": {"c": 1}}}, {"a": {"b": {"c": 1, "d": 2}, "e": 3}})
    assert not m({"lst": [1]}, {"lst": [1, 2]})  # lists are leaves, compared whole
    assert not m({"gone": None}, {})  # an absent key cannot confirm an explicit null
    assert m({"gone": None}, {"gone": None})
    assert m({"name": "n"}, {"name": "n", "other": 1})


async def test_arm_profile_missing_read_after_preserves_patch_response(client, registry):
    client.get.side_effect = [[{"id": "arm-1", "name": "before"}], []]
    evidence = {"saved": True, "opaqueWriteEvidence": [1, 2, 3]}
    client.request.return_value = resp(evidence)
    result = await update_arm_profile(client, registry, "h", "arm-1", name="after")
    assert result["response"] == evidence
    assert result["verified"] is None
    assert result["after"] is None
    assert "not found" in result["readAfterError"]


@pytest.mark.parametrize(
    "read_after", [{}, {"armMode": None}, {"armMode": []}, {"armMode": "invalid"}]
)
async def test_arm_settings_invalid_read_after_preserves_patch_response(
    client, registry, read_after
):
    client.get.side_effect = [
        [{"id": "arm-1"}, {"id": "arm-2"}],
        {"armMode": {"armProfileId": "arm-1"}},
        read_after,
    ]
    evidence = {"saved": True, "opaqueWriteEvidence": [1, 2, 3]}
    client.request.return_value = resp(evidence)
    result = await update_arm_profile_settings(client, registry, "h", "arm-2")
    assert result["response"] == evidence
    assert result["verified"] is None
    assert result["after"] is None
    assert "armMode" in result["readAfterError"]
