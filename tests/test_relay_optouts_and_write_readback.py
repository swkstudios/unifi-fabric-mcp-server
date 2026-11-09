"""Relay opt-outs, single-send relayed mutations, and write read-back.

* the connector relay honours every per-area write opt-out (Protect, Mobility,
  Carrier Fabric) before any upstream call.
* a relayed mutation is sent once (no 429 auto-retry).
* requested_leaves_match never treats a bool and an int as equal.
* Protect updates with no field to send fail before any upstream call.
* a Carrier write answered with a stub body is read back with a GET.
Plus: Carrier byte-counted length limits and the POS externalId minLength 1.

Every test is hermetic: the HTTP layer is mocked.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from tests._protect_writes import resp
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.tools import carrier_fabric, connector, mobility, protect
from unifi_fabric.tools._results import leaf_equal, requested_leaves_match
from unifi_fabric.tools.carrier_fabric import (
    CARRIER_BASE,
    create_carrier_subscriber,
    update_carrier_subscriber,
)
from unifi_fabric.tools.protect import (
    PROTECT_MUTATIONS_ENV,
    pos_ingest_transaction,
    update_arm_profile,
    update_camera,
    update_siren,
)

HOST_ID = "aabbccddeeff0000:12345"
BASE = "https://api.ui.com"
SID = "11111111-1111-4111-8111-111111111111"
SUBS = f"{BASE}{CARRIER_BASE}/subscribers"
SUB = f"{SUBS}/{SID}"


class _Resp:
    def __init__(self, status: int = 200, body: bytes = b'{"ok": true}') -> None:
        self.status_code = status
        self.content = body
        self.text = body.decode()
        self.headers = {"content-type": "application/json"}

    def json(self):
        import json

        return json.loads(self.content)


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value="site-uuid")
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


@pytest.fixture()
def relay_client():
    c = AsyncMock()
    c.request = AsyncMock(return_value=_Resp())
    return c


@pytest.fixture()
def protect_client():
    c = AsyncMock()
    c.request = AsyncMock(return_value=resp({}))
    c.get = AsyncMock()
    return c


# --- relay honours every per-area opt-out -------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "path",
    ["protect/integration/v1/sirens/abc/play", "protect/api/cameras/abc"],
)
async def test_relay_protect_mutation_refused_under_protect_opt_out(
    monkeypatch, relay_client, registry, method, path
):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", PROTECT_MUTATIONS_ENV)
    with pytest.raises(ValueError, match=PROTECT_MUTATIONS_ENV):
        await connector.connector_write(
            relay_client, registry, "h", method, path, body={}, write_enabled=True
        )
    relay_client.request.assert_not_called()
    registry.resolve_key_for_host.assert_not_called()


async def test_relay_protect_get_still_runs_under_protect_opt_out(
    monkeypatch, relay_client, registry
):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", PROTECT_MUTATIONS_ENV)
    res = await connector.connector_get(
        relay_client, registry, "h", "protect/integration/v1/sirens"
    )
    assert res["status"] == 200


async def test_relay_network_mutation_unaffected_by_protect_opt_out(
    monkeypatch, relay_client, registry
):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", PROTECT_MUTATIONS_ENV)
    res = await connector.connector_write(
        relay_client,
        registry,
        "h",
        "POST",
        "network/api/s/{site}/cmd/devmgr",
        site="Default",
        body={"cmd": "x"},
    )
    assert res["status"] == 200


async def test_relay_protect_mutation_runs_by_default(monkeypatch, relay_client, registry):
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
    monkeypatch.delenv(PROTECT_MUTATIONS_ENV, raising=False)
    res = await connector.connector_write(
        relay_client, registry, "h", "POST", "protect/integration/v1/sirens/abc/play", body={}
    )
    assert res["status"] == 200


@pytest.mark.parametrize(
    ("env_var", "route_class"),
    [
        (PROTECT_MUTATIONS_ENV, "protect-integration"),
        (mobility.WRITE_ENABLED_ENV, "mobility-future"),
        (carrier_fabric.WRITE_ENABLED_ENV, "carrier-future"),
    ],
)
def test_area_opt_out_check_covers_every_area(monkeypatch, env_var, route_class):
    # Mobility and Carrier have no relay route class today; any added under their prefix
    # is gated by the same table.
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", env_var)
    with pytest.raises(ValueError, match=env_var):
        connector._check_area_opt_out("POST", route_class)
    connector._check_area_opt_out("POST", "network-classic")  # never another area's
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS")
    connector._check_area_opt_out("POST", route_class)


def test_area_opt_out_table_lists_every_area_flag():
    envs = {env for _p, env, _e, _r in connector._AREA_OPT_OUTS}
    assert envs == {
        "family:network=deny",
        PROTECT_MUTATIONS_ENV,
        mobility.WRITE_ENABLED_ENV,
        carrier_fabric.WRITE_ENABLED_ENV,
        "family:innerspace=deny",
    }


# --- relayed mutations are sent once ------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_relayed_mutation_disables_429_retry(relay_client, registry, method):
    await connector.connector_write(
        relay_client, registry, "h", method, "protect/integration/v1/sirens/abc/play", body={}
    )
    writes = [c for c in relay_client.request.call_args_list if c.args[0] == method]
    assert len(writes) == 1
    # The client's one retry rule: a non-GET is sent once; no per-call override.
    assert all("max_retries" not in c.kwargs for c in relay_client.request.call_args_list)


@respx.mock
async def test_relayed_mutation_429_is_one_attempt_and_surfaced(registry):
    client = UniFiClient(Settings(api_key="sk-test"))
    route = respx.post(
        f"{BASE}/v1/connector/consoles/{HOST_ID}/proxy/protect/integration/v1/sirens/abc/play"
    ).mock(return_value=httpx.Response(429, json={"error": "slow down"}))
    from unifi_fabric.client import RateLimitError

    with pytest.raises(RateLimitError, match="NOT retried"):
        await connector.connector_write(
            client, registry, "h", "POST", "protect/integration/v1/sirens/abc/play", body={}
        )
    assert route.call_count == 1
    await client.close()


# --- bool is never equal to int -----------------------------------------------


@pytest.mark.parametrize(
    ("requested", "actual"),
    [
        ({"a": 1}, {"a": True}),
        ({"a": True}, {"a": 1}),
        ({"a": 0}, {"a": False}),
        ({"a": False}, {"a": 0}),
        ({"a": 1.0}, {"a": True}),
        ({"a": [1, 0]}, {"a": [True, False]}),
        ({"a": [{"x": 1}]}, {"a": [{"x": True}]}),
        ({"n": {"deep": True}}, {"n": {"deep": 1}}),
    ],
)
def test_bool_and_int_never_match(requested, actual):
    assert not requested_leaves_match(requested, actual)


@pytest.mark.parametrize(
    ("requested", "actual"),
    [
        ({"a": True}, {"a": True}),
        ({"a": False}, {"a": False}),
        ({"a": 1}, {"a": 1}),
        ({"a": 1}, {"a": 1.0}),
        ({"a": [True, 2]}, {"a": [True, 2]}),
    ],
)
def test_same_typed_values_still_match(requested, actual):
    assert requested_leaves_match(requested, actual)


def test_missing_is_not_null_unless_the_spec_omits_it():
    # A missing read-back field is not an explicit null, except where the pinned schema
    # documents that it omits the unset value.
    assert not requested_leaves_match({"a": None}, {})
    assert requested_leaves_match(
        {"serviceAddress": None}, {}, spec="carrier-fabric-1.0.0.json", schema="Subscriber"
    )


def test_leaf_equal_bool_identity():
    assert leaf_equal(True, True) and not leaf_equal(True, False)
    assert not leaf_equal(1, True) and not leaf_equal(True, 1)


async def test_int_over_bool_is_not_a_noop_and_not_verified(protect_client, registry):
    protect_client.get.side_effect = [{"id": "s1", "on": True}, {"id": "s1", "on": True}]
    res = await update_siren(protect_client, registry, "h", "s1", on=1)
    protect_client.request.assert_called_once()  # not a false no-op
    assert res["status"] == "updated"
    assert res["verified"] is False  # true does not confirm 1


# --- Protect updates with nothing to send -------------------------------------


@pytest.mark.parametrize("fn", [update_siren, update_camera])
async def test_empty_update_fails_before_any_call(protect_client, registry, fn):
    with pytest.raises(ValueError, match="No fields provided"):
        await fn(protect_client, registry, "h", "s1")
    protect_client.get.assert_not_called()
    protect_client.request.assert_not_called()
    registry.resolve_key_for_host.assert_not_called()


@pytest.mark.parametrize(
    "fields",
    [{"password": REDACTION_MASK}, {"a": REDACTION_MASK, "nested": {"key": REDACTION_MASK}}],
)
async def test_all_masked_update_fails_naming_the_mask(
    protect_client, registry, fields, monkeypatch
):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    with pytest.raises(ValueError, match="redaction mask") as exc:
        await update_siren(protect_client, registry, "h", "s1", **fields)
    assert "No fields provided" in str(exc.value)
    protect_client.get.assert_not_called()
    protect_client.request.assert_not_called()


async def test_partly_masked_update_still_sends_the_rest(protect_client, registry, monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    protect_client.get.side_effect = [{"id": "s1", "name": "a"}, {"id": "s1", "name": "b"}]
    res = await update_siren(protect_client, registry, "h", "s1", name="b", password=REDACTION_MASK)
    assert res["status"] == "updated"
    sent = protect_client.request.call_args.kwargs["json"]
    assert sent == {"name": "b"}


async def test_empty_arm_profile_update_fails_before_any_call(protect_client, registry):
    with pytest.raises(ValueError, match="No fields provided"):
        await update_arm_profile(protect_client, registry, "h", "a1")
    protect_client.get.assert_not_called()
    protect_client.request.assert_not_called()


async def test_all_masked_arm_profile_update_fails(protect_client, registry, monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    with pytest.raises(ValueError, match="redaction mask"):
        await update_arm_profile(protect_client, registry, "h", "a1", secret=REDACTION_MASK)
    protect_client.get.assert_not_called()
    protect_client.request.assert_not_called()


# --- a stub Carrier write body is read back -----------------------------------


def _sub(**over):
    base = {"id": SID, "subscriberNumber": "SN-1", "name": "old"}
    base.update(over)
    return {"data": base, "traceId": "t"}


@pytest.mark.parametrize("stub", [{}, {"httpStatusCode": 204}, {"data": {}}, {"data": {"x": 1}}])
def test_stub_is_not_a_resource(stub):
    assert carrier_fabric._carries_resource(stub) is False


def test_resource_envelope_carries_resource():
    assert carrier_fabric._carries_resource(_sub()) is True


@respx.mock
@pytest.mark.parametrize("stub", [{}, {"httpStatusCode": 204}])
async def test_update_with_stub_body_reads_back(monkeypatch, stub):
    monkeypatch.delenv(carrier_fabric.WRITE_ENABLED_ENV, raising=False)
    client = UniFiClient(Settings(api_key="sk-single"))
    get = respx.get(SUB).mock(
        side_effect=[httpx.Response(200, json=_sub()), httpx.Response(200, json=_sub(name="new"))]
    )
    respx.patch(SUB).mock(return_value=httpx.Response(200, json=stub))
    res = await update_carrier_subscriber(client, SID, name="new")
    assert get.call_count == 2  # read-before + read-back
    assert res["subscriber"] == _sub(name="new")
    assert res["verified"] is True
    assert res["response"] == stub
    await client.close()


@respx.mock
async def test_create_with_stub_body_reports_no_subscriber(monkeypatch):
    monkeypatch.delenv(carrier_fabric.WRITE_ENABLED_ENV, raising=False)
    client = UniFiClient(Settings(api_key="sk-single"))
    respx.post(SUBS).mock(return_value=httpx.Response(201, json={"httpStatusCode": 204}))
    res = await create_carrier_subscriber(client, "SN-1")
    assert res["subscriber"] is None
    assert res["response"] == {"httpStatusCode": 204}
    await client.close()


# --- Carrier length limits are UTF-8 bytes ----------------------------------------


@respx.mock
@pytest.mark.parametrize(
    ("field", "limit"),
    [("name", 128), ("email", 255), ("notes", 4096), ("service_address", 1024)],
)
async def test_carrier_limit_counts_utf8_bytes(monkeypatch, field, limit):
    monkeypatch.delenv(carrier_fabric.WRITE_ENABLED_ENV, raising=False)
    client = UniFiClient(Settings(api_key="sk-single"))
    post = respx.post(SUBS).mock(return_value=httpx.Response(201, json=_sub()))
    # Exactly at the limit in bytes (two-byte characters): accepted.
    await create_carrier_subscriber(client, "SN-1", **{field: "é" * (limit // 2)})
    assert post.call_count == 1
    # One more two-byte character: within the character count, over the byte limit.
    with pytest.raises(ValueError, match="bytes of UTF-8"):
        await create_carrier_subscriber(client, "SN-1", **{field: "é" * (limit // 2 + 1)})
    with pytest.raises(ValueError, match="bytes of UTF-8"):
        await update_carrier_subscriber(client, SID, **{field: "é" * (limit // 2 + 1)})
    assert post.call_count == 1
    # ASCII at the limit: accepted (never stricter than the spec).
    await create_carrier_subscriber(client, "SN-1", **{field: "a" * limit})
    assert post.call_count == 2
    await client.close()


# --- POS externalId: spec minLength 1 ---------------------------------------------


async def test_pos_whitespace_external_id_is_sent(monkeypatch, protect_client, registry):
    monkeypatch.delenv(PROTECT_MUTATIONS_ENV, raising=False)
    txn = {"type": "sale", "externalId": " ", "amount": 1}
    await pos_ingest_transaction(protect_client, registry, "h", "cam1", txn)
    assert protect_client.request.call_args.kwargs["json"] == txn


async def test_pos_empty_external_id_is_refused(protect_client, registry):
    with pytest.raises(ValueError, match="externalId"):
        await pos_ingest_transaction(
            protect_client, registry, "h", "cam1", {"type": "sale", "externalId": "", "amount": 1}
        )
    protect_client.request.assert_not_called()


def test_protect_module_exports_the_reason():
    assert PROTECT_MUTATIONS_ENV in protect.MUTATIONS_DISABLED_REASON
