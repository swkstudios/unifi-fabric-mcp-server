"""Hermetic fixture tests for the extended Protect Integration API families (issue #185).

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
    assert result[plural] == [{"id": "a", "futureField": 1}, {"id": "b"}]
    assert result["count"] == 2


@pytest.mark.parametrize("list_fn,_g,_u,family,plural,_idn", _UNIFORM)
async def test_family_list_envelope(client, registry, list_fn, _g, _u, family, plural, _idn):
    client.get.return_value = {"data": [{"id": "z"}]}
    result = await list_fn(client, registry, "h")
    assert result[plural] == [{"id": "z"}]
    assert result["count"] == 1


@pytest.mark.parametrize("_l,get_fn,_u,family,_p,_idn", _UNIFORM)
async def test_family_get_url_and_passthrough(client, registry, _l, get_fn, _u, family, _p, _idn):
    client.get.return_value = {"id": "item-1", "unknownFuture": {"nested": True}}
    result = await get_fn(client, registry, "h", "item-1")
    client.get.assert_called_once_with(f"{BASE}/{family}/item-1", key=None)
    assert result == {"id": "item-1", "unknownFuture": {"nested": True}}


@pytest.mark.parametrize("_l,get_fn,_u,family,_p,_idn", _UNIFORM)
async def test_family_get_non_dict_wrapped(client, registry, _l, get_fn, _u, family, _p, _idn):
    client.get.return_value = ["raw"]
    result = await get_fn(client, registry, "h", "item-1")
    assert result == {"data": ["raw"]}


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_update_read_patch_readafter(
    client, registry, _l, _g, upd_fn, family, _p, _idn
):
    # before differs -> PATCH sent (with 429 retry disabled), read-after confirms.
    client.get.side_effect = [{"id": "x", "name": "old"}, {"id": "x", "name": "new"}]
    result = await upd_fn(client, registry, "h", "x", name="new")
    client.patch.assert_called_once_with(
        f"{BASE}/{family}/x", key=None, json={"name": "new"}, max_retries=0
    )
    assert client.get.call_count == 2
    assert result["status"] == "updated"
    assert result["verified"] is True
    assert result["before"] == {"id": "x", "name": "old"}
    assert result["after"] == {"id": "x", "name": "new"}


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_update_noop_skips_write(client, registry, _l, _g, upd_fn, family, _p, _idn):
    client.get.return_value = {"id": "x", "name": "same"}
    result = await upd_fn(client, registry, "h", "x", name="same")
    client.patch.assert_not_called()
    assert result["status"] == "noop"
    assert result["resource"] == {"id": "x", "name": "same"}
    assert client.get.call_count == 1


@pytest.mark.parametrize("_l,_g,upd_fn,family,_p,_idn", _UNIFORM)
async def test_family_update_gate_disabled_no_request(
    monkeypatch, client, registry, _l, _g, upd_fn, family, _p, _idn
):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "0")
    result = await upd_fn(client, registry, "h", "x", name="new")
    assert result["status"] == "disabled"
    client.get.assert_not_called()
    client.patch.assert_not_called()


# --- Owning-key routing --------------------------------------------------------------


async def test_list_threads_owning_key(client, keyed_registry):
    client.get.return_value = []
    await list_sirens(client, keyed_registry, "myhost")
    keyed_registry.resolve_host_id.assert_called_once_with("myhost", key=KEY)
    client.get.assert_called_once_with(f"{BASE}/sirens", key=KEY)


async def test_action_threads_owning_key(client, keyed_registry):
    await siren_play(client, keyed_registry, "myhost", "s1", confirm=True)
    keyed_registry.resolve_host_id.assert_called_once_with("myhost", key=KEY)
    client.post.assert_called_once_with(f"{BASE}/sirens/s1/play", key=KEY, json={}, max_retries=0)


async def test_update_threads_owning_key(client, keyed_registry):
    client.get.side_effect = [{"id": "s1", "name": "a"}, {"id": "s1", "name": "b"}]
    await update_siren(client, keyed_registry, "myhost", "s1", name="b")
    client.patch.assert_called_once_with(
        f"{BASE}/sirens/s1", key=KEY, json={"name": "b"}, max_retries=0
    )


# --- Unsupported endpoint / version errors pass through ------------------------------


async def test_unsupported_family_error_propagates(client, registry):
    client.get.side_effect = UniFiConnectionError("HTTP 404: not found")
    with pytest.raises(UniFiConnectionError):
        await list_sirens(client, registry, "h")


async def test_unsupported_action_error_propagates(client, registry):
    client.post.side_effect = UniFiConnectionError("HTTP 501: not implemented")
    with pytest.raises(UniFiConnectionError):
        await enable_arm(client, registry, "h", confirm=True)


# --- Physical action confirm guards (all writes disable 429 auto-retry) -------------

# (fn, args, kwargs, expected_url_suffix, expected_body)
_ACTIONS = [
    (siren_play, ("s1",), {"confirm": True}, "/sirens/s1/play", {}),
    (siren_play, ("s1",), {"confirm": True, "duration": 10}, "/sirens/s1/play", {"duration": 10}),
    (siren_stop, ("s1",), {"confirm": True}, "/sirens/s1/stop", {}),
    (
        siren_test_sound,
        ("s1",),
        {"confirm": True, "volume": 50},
        "/sirens/s1/test-sound",
        {"volume": 50},
    ),
    (speaker_test_sound, ("sp1",), {"confirm": True}, "/speakers/sp1/test-sound", {}),
    (enable_arm, (), {"confirm": True}, "/arm-profiles/enable", {}),
    (disable_arm, (), {"confirm": True}, "/arm-profiles/disable", {}),
]


@pytest.mark.parametrize("fn,args,kwargs,suffix,body", _ACTIONS)
async def test_action_executes_with_confirm_no_retry(
    client, registry, fn, args, kwargs, suffix, body
):
    result = await fn(client, registry, "h", *args, **kwargs)
    client.post.assert_called_once_with(f"{BASE}{suffix}", key=None, json=body, max_retries=0)
    assert result == {}


@pytest.mark.parametrize("fn,args,kwargs,suffix,body", _ACTIONS)
async def test_action_blocked_without_confirm(client, registry, fn, args, kwargs, suffix, body):
    no_confirm = {k: v for k, v in kwargs.items() if k != "confirm"}
    result = await fn(client, registry, "h", *args, **no_confirm)
    assert result["status"] == "not_executed"
    client.post.assert_not_called()


@pytest.mark.parametrize("fn,args,kwargs,suffix,body", _ACTIONS)
async def test_action_gate_disabled_beats_confirm(
    monkeypatch, client, registry, fn, args, kwargs, suffix, body
):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "off")
    result = await fn(client, registry, "h", *args, **kwargs)  # confirm=True present
    assert result["status"] == "disabled"
    client.post.assert_not_called()


async def test_action_post_204_fallback_status_ok(client, registry):
    client.post.return_value = None
    result = await siren_stop(client, registry, "h", "s1", confirm=True)
    assert result == {"status": "ok"}


# --- Relay + alarm-hub output actions (two path IDs) --------------------------------


async def test_relay_activate_output_url_and_body(client, registry):
    result = await relay_activate_output(
        client, registry, "h", "r1", "2", confirm=True, state="on", pulse_duration=3000
    )
    client.post.assert_called_once_with(
        f"{BASE}/relays/r1/outputs/2/activate",
        key=None,
        json={"state": "on", "pulseDuration": 3000},
        max_retries=0,
    )
    assert result == {}


async def test_relay_activate_output_toggle_empty_body(client, registry):
    await relay_activate_output(client, registry, "h", "r1", "2", confirm=True)
    client.post.assert_called_once_with(
        f"{BASE}/relays/r1/outputs/2/activate", key=None, json={}, max_retries=0
    )


async def test_relay_activate_requires_confirm(client, registry):
    result = await relay_activate_output(client, registry, "h", "r1", "2")
    assert result["status"] == "not_executed"
    client.post.assert_not_called()


async def test_alarm_hub_trigger_output_url_and_body(client, registry):
    await alarm_hub_trigger_output(
        client, registry, "h", "ah1", "1", confirm=True, enable=True, delay=0, duration=5000
    )
    client.post.assert_called_once_with(
        f"{BASE}/alarm-hubs/ah1/outputs/1/trigger",
        key=None,
        json={"enable": True, "delay": 0, "duration": 5000},
        max_retries=0,
    )


async def test_alarm_hub_trigger_requires_confirm(client, registry):
    result = await alarm_hub_trigger_output(client, registry, "h", "ah1", "1")
    assert result["status"] == "not_executed"
    client.post.assert_not_called()


# --- Arm profiles (list-based get/update, settings, create, delete) -----------------


async def test_list_arm_profiles_url(client, registry):
    client.get.return_value = [{"id": "arm-1", "name": "Home", "newField": 9}]
    result = await list_arm_profiles(client, registry, "h")
    client.get.assert_called_once_with(f"{BASE}/arm-profiles", key=None)
    assert result == {"arm_profiles": [{"id": "arm-1", "name": "Home", "newField": 9}], "count": 1}


async def test_get_arm_profile_filters_list(client, registry):
    client.get.return_value = [{"id": "arm-1"}, {"id": "arm-2", "name": "Away"}]
    result = await get_arm_profile(client, registry, "h", "arm-2")
    client.get.assert_called_once_with(f"{BASE}/arm-profiles", key=None)
    assert result == {"id": "arm-2", "name": "Away"}


async def test_get_arm_profile_missing_raises(client, registry):
    client.get.return_value = [{"id": "arm-1"}]
    with pytest.raises(ValueError, match="not found"):
        await get_arm_profile(client, registry, "h", "nope")


async def test_create_arm_profile_url_and_body_no_retry(client, registry):
    client.post.return_value = {"id": "arm-9", "name": "Night"}
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
    client.post.assert_called_once_with(
        f"{BASE}/arm-profiles",
        key=None,
        json={
            "name": "Night",
            "activationDelay": 30,
            "recordEverything": True,
            "automations": [],
            "schedules": [],
        },
        max_retries=0,
    )
    assert result == {"id": "arm-9", "name": "Night"}


async def test_create_arm_profile_empty_name_rejected(client, registry):
    with pytest.raises(ValueError, match="name"):
        await create_arm_profile(client, registry, "h", "")
    client.post.assert_not_called()


async def test_create_arm_profile_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "false")
    result = await create_arm_profile(client, registry, "h", "Night")
    assert result["status"] == "disabled"
    client.post.assert_not_called()


async def test_update_arm_profile_readafter(client, registry):
    client.get.side_effect = [[{"id": "arm-1", "name": "old"}], [{"id": "arm-1", "name": "new"}]]
    result = await update_arm_profile(client, registry, "h", "arm-1", name="new")
    client.patch.assert_called_once_with(
        f"{BASE}/arm-profiles/arm-1", key=None, json={"name": "new"}, max_retries=0
    )
    assert result["status"] == "updated"
    assert result["verified"] is True
    assert result["after"] == {"id": "arm-1", "name": "new"}


async def test_update_arm_profile_noop(client, registry):
    client.get.return_value = [{"id": "arm-1", "name": "same"}]
    result = await update_arm_profile(client, registry, "h", "arm-1", name="same")
    client.patch.assert_not_called()
    assert result["status"] == "noop"


async def test_delete_arm_profile_requires_confirm(client, registry):
    result = await delete_arm_profile(client, registry, "h", "arm-1")
    assert result["status"] == "not_executed"
    client.delete.assert_not_called()


async def test_delete_arm_profile_with_confirm_no_retry(client, registry):
    result = await delete_arm_profile(client, registry, "h", "arm-1", confirm=True)
    client.delete.assert_called_once_with(f"{BASE}/arm-profiles/arm-1", key=None, max_retries=0)
    assert result == {"status": "deleted", "id": "arm-1"}


async def test_delete_arm_profile_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "no")
    result = await delete_arm_profile(client, registry, "h", "arm-1", confirm=True)
    assert result["status"] == "disabled"
    client.delete.assert_not_called()


async def test_arm_settings_select_readafter(client, registry):
    client.get.side_effect = [
        {"armMode": {"armProfileId": "arm-1"}},
        {"armMode": {"armProfileId": "arm-2"}},
    ]
    result = await update_arm_profile_settings(client, registry, "h", "arm-2")
    client.patch.assert_called_once_with(
        f"{BASE}/arm-profiles/settings", key=None, json={"armProfileId": "arm-2"}, max_retries=0
    )
    assert result["status"] == "updated"
    assert result["verified"] is True


async def test_arm_settings_noop_when_already_selected(client, registry):
    client.get.return_value = {"armMode": {"armProfileId": "arm-2"}}
    result = await update_arm_profile_settings(client, registry, "h", "arm-2")
    client.patch.assert_not_called()
    assert result["status"] == "noop"
    assert client.get.call_count == 1


async def test_arm_settings_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "0")
    result = await update_arm_profile_settings(client, registry, "h", "arm-2")
    assert result["status"] == "disabled"
    client.get.assert_not_called()
    client.patch.assert_not_called()


# --- Protect users vs ULP users vs application metadata (read-only) -----------------


async def test_list_protect_users_url(client, registry):
    client.get.return_value = [{"id": "u1", "firstName": "A"}]
    result = await list_protect_users(client, registry, "h")
    client.get.assert_called_once_with(f"{BASE}/users", key=None)
    assert result == {"users": [{"id": "u1", "firstName": "A"}], "count": 1}


async def test_get_protect_user_url(client, registry):
    client.get.return_value = {"id": "u1", "roleName": "admin", "futureFlag": 1}
    result = await get_protect_user(client, registry, "h", "u1")
    client.get.assert_called_once_with(f"{BASE}/users/u1", key=None)
    assert result == {"id": "u1", "roleName": "admin", "futureFlag": 1}


async def test_list_ulp_users_distinct_path(client, registry):
    client.get.return_value = [{"id": "ulp-1", "email": "a@example.com"}]
    result = await list_ulp_users(client, registry, "h")
    client.get.assert_called_once_with(f"{BASE}/ulp-users", key=None)
    assert result == {"ulp_users": [{"id": "ulp-1", "email": "a@example.com"}], "count": 1}


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
    client.post.return_value = {"id": "evt-1"}
    txn = _txn(currency="USD", lineItems=[{"title": "Coffee", "quantity": 1}])
    result = await pos_ingest_transaction(client, registry, "h", "cam-1", txn, confirm=True)
    client.post.assert_called_once_with(
        f"{BASE}/pos/cameras/cam-1/transactions", key=None, json=txn, max_retries=0
    )
    assert result == {"id": "evt-1"}


async def test_pos_ingest_requires_confirm(client, registry):
    result = await pos_ingest_transaction(client, registry, "h", "cam-1", _txn())
    assert result["status"] == "not_executed"
    client.post.assert_not_called()


async def test_pos_ingest_gate_disabled(monkeypatch, client, registry):
    monkeypatch.setenv(PROTECT_MUTATIONS_ENV, "0")
    result = await pos_ingest_transaction(client, registry, "h", "cam-1", _txn(), confirm=True)
    assert result["status"] == "disabled"
    client.post.assert_not_called()


async def test_pos_ingest_bad_type_rejected(client, registry):
    with pytest.raises(ValueError, match="type"):
        await pos_ingest_transaction(
            client, registry, "h", "cam-1", _txn(type="void"), confirm=True
        )
    client.post.assert_not_called()


async def test_pos_ingest_missing_external_id_rejected(client, registry):
    txn = {"type": "sale", "amount": 1}
    with pytest.raises(ValueError, match="externalId"):
        await pos_ingest_transaction(client, registry, "h", "cam-1", txn, confirm=True)
    client.post.assert_not_called()


async def test_pos_ingest_missing_amount_rejected(client, registry):
    txn = {"type": "sale", "externalId": "ext-1"}
    with pytest.raises(ValueError, match="amount"):
        await pos_ingest_transaction(client, registry, "h", "cam-1", txn, confirm=True)
    client.post.assert_not_called()


async def test_pos_ingest_204_fallback_carries_external_id(client, registry):
    client.post.return_value = None
    result = await pos_ingest_transaction(client, registry, "h", "cam-1", _txn(), confirm=True)
    assert result == {"status": "ok", "externalId": "ext-123"}


async def test_pos_ingest_rejects_bad_camera_id(client, registry):
    with pytest.raises(ValueError):
        await pos_ingest_transaction(client, registry, "h", "../bad", _txn(), confirm=True)
    client.post.assert_not_called()


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
    client.post.assert_not_called()
