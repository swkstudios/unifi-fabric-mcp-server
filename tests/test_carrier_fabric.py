"""Tests for the UniFi Carrier / ISP Fabric tools (cloud, api.ui.com/v1/carrier).

Not testable against the maintainer's live hardware; hermetic/spec-conformance tested
only: the Carrier Fabric is not deployed here (no ISP
organization, no ISP-type API key), so there is and can be no live coverage. Every
test is hermetic — each request is mocked with respx against a real ``UniFiClient``
built from the EXACT OpenAPI v1.0.0 request/response shapes, so paths, cursor
pagination, selected-key routing, write bodies, the read-before/no-op/read-after
flow, the fail-closed write gate, and upstream-error pass-through are all asserted
against the spec, NOT against a live console (never claim live-verified: all
assertions are against mock shapes, not a production console).

The write gate (``UNIFI_ENABLE_CARRIER_FABRIC_WRITE``) is fail-closed / OFF by
default; the autouse hermetic-env fixture strips ``UNIFI_*`` so it is unset here.
Tests that exercise a real (mocked) write opt in via the ``enable_writes`` fixture.
All ids are synthetic and no real value appears here.
"""

from __future__ import annotations

import json as _json

import pytest
import respx
from httpx import Response

from unifi_fabric.client import PaginationAbortedError, UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import carrier_fabric
from unifi_fabric.tools.carrier_fabric import (
    CARRIER_BASE,
    WRITE_ENABLED_ENV,
    assign_carrier_subscriber_plan,
    attach_carrier_subscriber_host,
    create_carrier_subscriber,
    detach_carrier_subscriber_host,
    get_carrier_service_plan,
    get_carrier_subscriber,
    list_carrier_service_plans,
    list_carrier_subscribers,
    resume_carrier_subscriber,
    suspend_carrier_subscriber,
    update_carrier_subscriber,
)

BASE = "https://api.ui.com"
SID = "11111111-1111-4111-8111-111111111111"
PID = "22222222-2222-4222-8222-222222222222"
SUBS = f"{BASE}{CARRIER_BASE}/subscribers"
PLANS = f"{BASE}{CARRIER_BASE}/service-plans"
SUB = f"{SUBS}/{SID}"


@pytest.fixture()
def client():
    return UniFiClient(Settings(api_key="sk-single"))


@pytest.fixture()
def enable_writes(monkeypatch):
    """Opt in to the fail-closed write gate for tests that exercise a real (mocked) write."""
    monkeypatch.setenv(WRITE_ENABLED_ENV, "1")


@pytest.fixture()
def multikey():
    return UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-alpha", label="alpha", is_org_key=False),
                APIKeyConfig(key="sk-beta", label="beta", is_org_key=True),
            ]
        )
    )


def _subscriber(**over):
    base = {
        "id": SID,
        "orgId": "org-1",
        "subscriberNumber": "SN-1000",
        "name": "Acme Cafe",
        "email": "billing@acme.example",
        "notes": None,
        "serviceAddress": "1 High St",
        "planId": None,
        "hostId": None,
        "state": "pending_assignment",
        "suspended": False,
        "suspendReason": None,
        "suspendedAt": None,
        "metadata": {},
        "activatedAt": None,
        "createdAt": "2026-08-14T00:00:00Z",
        "updatedAt": "2026-08-14T00:00:00Z",
    }
    base.update(over)
    return base


def _sub_response(**over):
    return {"data": _subscriber(**over), "traceId": "t-1"}


def _plan(**over):
    base = {
        "id": PID,
        "orgId": "org-1",
        "name": "Residential 1G",
        "status": "active",
        "downloadMbps": 1000,
        "uploadMbps": 1000,
        "metadata": {},
        "createdAt": "2026-08-14T00:00:00Z",
        "updatedAt": "2026-08-14T00:00:00Z",
        "archivedAt": None,
    }
    base.update(over)
    return base


# --- Reads -------------------------------------------------------------------


class TestReads:
    @respx.mock
    async def test_list_subscribers_drains_cursor_pages(self, client):
        route = respx.get(SUBS)
        route.side_effect = [
            Response(
                200,
                json={
                    "data": [_subscriber(id=f"s-{i}") for i in range(2)],
                    "meta": {"nextCursor": "CUR2", "limit": 500, "hasMore": True},
                    "traceId": "t",
                },
            ),
            Response(
                200,
                json={
                    "data": [_subscriber(id="s-2", extra_field="kept")],
                    "meta": {"nextCursor": None, "limit": 500, "hasMore": False},
                    "traceId": "t",
                },
            ),
        ]
        result = await list_carrier_subscribers(client)
        assert result["count"] == 3
        assert route.call_count == 2
        # page 1 requests documented max limit and no cursor; page 2 carries meta.nextCursor.
        assert route.calls[0].request.url.params["limit"] == "500"
        assert "cursor" not in route.calls[0].request.url.params
        assert route.calls[1].request.url.params["cursor"] == "CUR2"
        assert result["subscribers"][2]["extra_field"] == "kept"

    @respx.mock
    async def test_list_subscribers_filters(self, client):
        route = respx.get(SUBS).mock(
            return_value=Response(200, json={"data": [], "meta": {"hasMore": False}})
        )
        await list_carrier_subscribers(client, plan_id=PID, suspended=True, sort="-createdAt")
        params = route.calls[0].request.url.params
        assert params["planId"] == PID
        assert params["suspended"] == "true"
        assert params["sort"] == "-createdAt"

    async def test_list_subscribers_bad_sort(self, client):
        with pytest.raises(ValueError):
            await list_carrier_subscribers(client, sort="oldest")

    @respx.mock
    async def test_list_subscribers_stall_aborts(self, client):
        # A gateway that keeps returning the same nextCursor must not loop forever.
        respx.get(SUBS).mock(
            return_value=Response(
                200,
                json={"data": [_subscriber()], "meta": {"nextCursor": "SAME", "hasMore": True}},
            )
        )
        with pytest.raises(PaginationAbortedError):
            await list_carrier_subscribers(client)

    @respx.mock
    async def test_get_subscriber_unwraps_envelope(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(state="installed")))
        result = await get_carrier_subscriber(client, SID)
        assert result["subscriber"]["id"] == SID
        assert result["subscriber"]["state"] == "installed"

    @respx.mock
    async def test_list_service_plans(self, client):
        respx.get(PLANS).mock(
            return_value=Response(200, json={"data": [_plan(), _plan(id="p-2")], "traceId": "t"})
        )
        result = await list_carrier_service_plans(client)
        assert result["count"] == 2
        assert result["service_plans"][0]["status"] == "active"

    @respx.mock
    async def test_get_service_plan_unwraps(self, client):
        respx.get(f"{PLANS}/{PID}").mock(
            return_value=Response(200, json={"data": _plan(), "traceId": "t"})
        )
        result = await get_carrier_service_plan(client, PID)
        assert result["service_plan"]["id"] == PID


# --- Selected-key routing ----------------------------------------------------


class TestKeyRouting:
    @respx.mock
    async def test_key_label_routes_on_that_key(self, multikey):
        route = respx.get(SUBS).mock(
            return_value=Response(200, json={"data": [], "meta": {"hasMore": False}})
        )
        await list_carrier_subscribers(multikey, key_label="beta")
        assert route.calls[0].request.headers["x-api-key"] == "sk-beta"

    @respx.mock
    async def test_default_key_when_label_omitted(self, multikey):
        route = respx.get(SUBS).mock(
            return_value=Response(200, json={"data": [], "meta": {"hasMore": False}})
        )
        await list_carrier_subscribers(multikey)
        assert route.calls[0].request.headers["x-api-key"] == "sk-alpha"

    async def test_unknown_key_label_raises(self, multikey):
        with pytest.raises(KeyError):
            await list_carrier_subscribers(multikey, key_label="nope")


# --- Validation --------------------------------------------------------------


class TestValidation:
    async def test_bad_subscriber_id(self, client):
        with pytest.raises(ValueError):
            await get_carrier_subscriber(client, "bad/../id")

    @pytest.mark.parametrize("num", ["", "x" * 33])
    async def test_create_subscriber_number_length(self, client, num):
        with pytest.raises(ValueError):
            await create_carrier_subscriber(client, num, confirm=True)

    async def test_create_name_too_long(self, client):
        with pytest.raises(ValueError):
            await create_carrier_subscriber(client, "SN-1", name="x" * 129, confirm=True)

    async def test_create_bad_metadata(self, client):
        with pytest.raises(ValueError):
            await create_carrier_subscriber(client, "SN-1", metadata=["nope"], confirm=True)

    async def test_patch_requires_a_field(self, client):
        with pytest.raises(ValueError):
            await update_carrier_subscriber(client, SID, confirm=True)

    async def test_attach_bad_host(self, client):
        with pytest.raises(ValueError):
            await attach_carrier_subscriber_host(client, SID, "", confirm=True)

    async def test_assign_bad_plan_id(self, client):
        with pytest.raises(ValueError):
            await assign_carrier_subscriber_plan(client, SID, "bad/../plan", confirm=True)


# --- Write gate is fail-closed (OFF by default) ------------------------------


class TestWriteGate:
    def test_writes_gated_off_by_default(self):
        assert carrier_fabric._writes_enabled() is False

    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
    def test_truthy_enable(self, monkeypatch, val):
        monkeypatch.setenv(WRITE_ENABLED_ENV, val)
        assert carrier_fabric._writes_enabled() is True

    @pytest.mark.parametrize("val", ["0", "false", "no", "off", ""])
    def test_falsey_keep_disabled(self, monkeypatch, val):
        monkeypatch.setenv(WRITE_ENABLED_ENV, val)
        assert carrier_fabric._writes_enabled() is False

    @respx.mock
    async def test_confirmed_create_blocked_when_gate_unset(self, client):
        post = respx.post(SUBS).mock(return_value=Response(201, json=_sub_response()))
        result = await create_carrier_subscriber(client, "SN-1", confirm=True)
        assert result["status"] == "disabled"
        assert not post.called

    @respx.mock
    async def test_confirmed_patch_blocked_when_gate_unset(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(name="New")))
        result = await update_carrier_subscriber(client, SID, name="New", confirm=True)
        assert result["status"] == "disabled"
        assert not patch.called


# --- create -----------------------------------------------------------------


class TestCreate:
    @respx.mock
    async def test_unconfirmed_previews_body_no_write(self, client):
        post = respx.post(SUBS)
        result = await create_carrier_subscriber(client, "SN-9", name="New Co", plan_id=PID)
        assert result["status"] == "unconfirmed"
        assert result["proposed"] == {"subscriberNumber": "SN-9", "name": "New Co", "planId": PID}
        assert not post.called

    @respx.mock
    async def test_confirmed_create_sends_documented_body(self, client, enable_writes):
        post = respx.post(SUBS).mock(return_value=Response(201, json=_sub_response(id="s-new")))
        result = await create_carrier_subscriber(
            client,
            "SN-9",
            name="New Co",
            email="a@b.example",
            notes="vip",
            service_address="2 Low St",
            plan_id=PID,
            metadata={"crm": "x"},
            confirm=True,
        )
        assert post.call_count == 1
        assert _json.loads(post.calls[0].request.content) == {
            "subscriberNumber": "SN-9",
            "name": "New Co",
            "email": "a@b.example",
            "notes": "vip",
            "serviceAddress": "2 Low St",
            "planId": PID,
            "metadata": {"crm": "x"},
        }
        assert result["status"] == "created"
        assert result["subscriber"]["id"] == "s-new"


# --- patch (partial update) --------------------------------------------------


class TestPatch:
    @respx.mock
    async def test_no_op_when_all_fields_match(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Same")))
        patch = respx.patch(SUB)
        result = await update_carrier_subscriber(client, SID, name="Same", confirm=True)
        assert result["status"] == "no_op"
        assert not patch.called

    @respx.mock
    async def test_unconfirmed_previews(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        result = await update_carrier_subscriber(client, SID, name="New")
        assert result["status"] == "unconfirmed"
        assert result["proposed"] == {"name": "New"}

    @respx.mock
    async def test_updated_read_before_and_after(self, client, enable_writes):
        get = respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(name="New")))
        result = await update_carrier_subscriber(client, SID, name="New", confirm=True)
        assert get.call_count == 1  # read-before; read-after comes from the PATCH body
        assert _json.loads(patch.calls[0].request.content) == {"name": "New"}
        assert result["status"] == "updated"
        assert result["changed"] == {"name": {"from": "Old", "to": "New"}}
        assert result["subscriber"]["name"] == "New"

    @respx.mock
    async def test_explicit_null_clears_nullable_field(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=PID)))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        result = await update_carrier_subscriber(client, SID, plan_id=None, confirm=True)
        assert _json.loads(patch.calls[0].request.content) == {"planId": None}
        assert result["status"] == "updated"


# --- host attach / detach ----------------------------------------------------


class TestHost:
    @respx.mock
    async def test_attach_no_op_when_already_linked(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-1")))
        put = respx.put(f"{SUB}/host")
        result = await attach_carrier_subscriber_host(client, SID, "H-1", confirm=True)
        assert result["status"] == "no_op"
        assert not put.called

    @respx.mock
    async def test_attach_writes_and_reports_prev_host(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-old")))
        put = respx.put(f"{SUB}/host").mock(
            return_value=Response(
                200, json={"data": _subscriber(hostId="H-new"), "prevHostId": "H-old"}
            )
        )
        result = await attach_carrier_subscriber_host(client, SID, "H-new", confirm=True)
        assert _json.loads(put.calls[0].request.content) == {"hostId": "H-new"}
        assert result["status"] == "attached"
        assert result["prev_host_id"] == "H-old"
        assert result["verified"] is True

    @respx.mock
    async def test_detach_no_op_when_unlinked(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId=None)))
        result = await detach_carrier_subscriber_host(client, SID, confirm=True)
        assert result["status"] == "no_op"

    @respx.mock
    async def test_detach_writes_and_decodes_delete_body(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-1")))
        delete = respx.delete(f"{SUB}/host").mock(
            return_value=Response(200, json={"data": _subscriber(hostId=None), "prevHostId": "H-1"})
        )
        result = await detach_carrier_subscriber_host(client, SID, confirm=True)
        assert delete.call_count == 1
        assert result["status"] == "detached"
        assert result["prev_host_id"] == "H-1"
        assert result["verified"] is True


# --- plan assignment ---------------------------------------------------------


class TestPlan:
    @respx.mock
    async def test_no_op_when_already_on_plan(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=PID)))
        result = await assign_carrier_subscriber_plan(client, SID, PID, confirm=True)
        assert result["status"] == "no_op"

    @respx.mock
    async def test_assign_writes(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        put = respx.put(f"{SUB}/plan").mock(
            return_value=Response(200, json=_sub_response(planId=PID))
        )
        result = await assign_carrier_subscriber_plan(client, SID, PID, confirm=True)
        assert _json.loads(put.calls[0].request.content) == {"planId": PID}
        assert result["status"] == "assigned"
        assert result["verified"] is True


# --- suspend / resume --------------------------------------------------------


class TestSuspendResume:
    @respx.mock
    async def test_suspend_no_op_when_already_suspended(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=True)))
        result = await suspend_carrier_subscriber(client, SID, confirm=True)
        assert result["status"] == "no_op"

    @respx.mock
    async def test_suspend_with_reason_sends_body(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=False)))
        post = respx.post(f"{SUB}/suspend").mock(
            return_value=Response(200, json=_sub_response(suspended=True))
        )
        result = await suspend_carrier_subscriber(client, SID, reason="nonpayment", confirm=True)
        assert _json.loads(post.calls[0].request.content) == {"reason": "nonpayment"}
        assert result["status"] == "suspended"
        assert result["verified"] is True

    @respx.mock
    async def test_suspend_without_reason_sends_no_body(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=False)))
        post = respx.post(f"{SUB}/suspend").mock(
            return_value=Response(200, json=_sub_response(suspended=True))
        )
        await suspend_carrier_subscriber(client, SID, confirm=True)
        assert post.calls[0].request.content in (b"", b"null")

    @respx.mock
    async def test_resume_no_op_when_not_suspended(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=False)))
        result = await resume_carrier_subscriber(client, SID, confirm=True)
        assert result["status"] == "no_op"

    @respx.mock
    async def test_resume_unconfirmed(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=True)))
        result = await resume_carrier_subscriber(client, SID)
        assert result["status"] == "unconfirmed"

    @respx.mock
    async def test_resume_writes(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=True)))
        post = respx.post(f"{SUB}/resume").mock(
            return_value=Response(200, json=_sub_response(suspended=False))
        )
        result = await resume_carrier_subscriber(client, SID, confirm=True)
        assert post.call_count == 1
        assert result["status"] == "resumed"
        assert result["verified"] is True


# --- Upstream error pass-through (missing subscription / scope) --------------


class TestErrorPassthrough:
    @respx.mock
    async def test_insufficient_scope_surfaces_on_read(self, client):
        respx.get(SUBS).mock(
            return_value=Response(
                403,
                json={
                    "error": {"code": "insufficient_scope", "message": "key lacks read scope"},
                    "traceId": "t",
                },
            )
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await list_carrier_subscribers(client)
        assert "403" in str(exc.value)

    @respx.mock
    async def test_unauthorized_surfaces_on_get(self, client):
        respx.get(SUB).mock(
            return_value=Response(
                401, json={"error": {"code": "unauthorized", "message": "bad key"}, "traceId": "t"}
            )
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await get_carrier_subscriber(client, SID)
        assert "401" in str(exc.value)

    @respx.mock
    async def test_write_read_before_forbidden_skips_write(self, client, enable_writes):
        # Missing subscription / scope lands on the read-before GET; no PUT is issued.
        respx.get(SUB).mock(
            return_value=Response(
                403, json={"error": {"code": "insufficient_scope"}, "traceId": "t"}
            )
        )
        put = respx.put(f"{SUB}/plan").mock(return_value=Response(200, json=_sub_response()))
        with pytest.raises(UniFiConnectionError):
            await assign_carrier_subscriber_plan(client, SID, PID, confirm=True)
        assert not put.called

    @respx.mock
    async def test_write_conflict_surfaces_on_put(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId=None)))
        respx.put(f"{SUB}/host").mock(
            return_value=Response(
                409,
                json={"error": {"code": "gateway_already_attached"}, "traceId": "t"},
            )
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await attach_carrier_subscriber_host(client, SID, "H-1", confirm=True)
        assert "409" in str(exc.value)


# --- Branch coverage: gate-off, unconfirmed, and validation on every write ---


class TestGateOffAllWrites:
    @respx.mock
    async def test_attach_disabled_when_gate_unset(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId=None)))
        put = respx.put(f"{SUB}/host").mock(return_value=Response(200, json=_sub_response()))
        result = await attach_carrier_subscriber_host(client, SID, "H-1", confirm=True)
        assert result["status"] == "disabled"
        assert not put.called

    @respx.mock
    async def test_detach_disabled_when_gate_unset(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-1")))
        result = await detach_carrier_subscriber_host(client, SID, confirm=True)
        assert result["status"] == "disabled"

    @respx.mock
    async def test_assign_disabled_when_gate_unset(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        result = await assign_carrier_subscriber_plan(client, SID, PID, confirm=True)
        assert result["status"] == "disabled"

    @respx.mock
    async def test_suspend_disabled_when_gate_unset(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=False)))
        result = await suspend_carrier_subscriber(client, SID, confirm=True)
        assert result["status"] == "disabled"

    @respx.mock
    async def test_resume_disabled_when_gate_unset(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=True)))
        result = await resume_carrier_subscriber(client, SID, confirm=True)
        assert result["status"] == "disabled"


class TestUnconfirmedAllWrites:
    @respx.mock
    async def test_attach_unconfirmed(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-old")))
        result = await attach_carrier_subscriber_host(client, SID, "H-new")
        assert result["status"] == "unconfirmed"
        assert result["current_host_id"] == "H-old"

    @respx.mock
    async def test_detach_unconfirmed(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-1")))
        result = await detach_carrier_subscriber_host(client, SID)
        assert result["status"] == "unconfirmed"
        assert result["current_host_id"] == "H-1"

    @respx.mock
    async def test_assign_unconfirmed(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        result = await assign_carrier_subscriber_plan(client, SID, PID)
        assert result["status"] == "unconfirmed"

    @respx.mock
    async def test_suspend_unconfirmed(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=False)))
        result = await suspend_carrier_subscriber(client, SID, reason="x")
        assert result["status"] == "unconfirmed"
        assert result["proposed_reason"] == "x"


class TestMoreValidation:
    async def test_validate_len_non_string(self, client):
        with pytest.raises(ValueError):
            await create_carrier_subscriber(client, 12345, confirm=True)  # type: ignore[arg-type]

    async def test_list_bad_suspended_type(self, client):
        with pytest.raises(ValueError):
            await list_carrier_subscribers(client, suspended="yes")  # type: ignore[arg-type]

    async def test_suspend_bad_reason_type(self, client):
        with pytest.raises(ValueError):
            await suspend_carrier_subscriber(client, SID, reason=5, confirm=True)  # type: ignore[arg-type]

    @respx.mock
    async def test_patch_all_fields_serialised(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response()))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response()))
        await update_carrier_subscriber(
            client,
            SID,
            subscriber_number="SN-2",
            name="N",
            email="e@x.example",
            notes="note",
            service_address="addr",
            plan_id=PID,
            metadata={"k": "v"},
            confirm=True,
        )
        assert _json.loads(patch.calls[0].request.content) == {
            "subscriberNumber": "SN-2",
            "name": "N",
            "email": "e@x.example",
            "notes": "note",
            "serviceAddress": "addr",
            "planId": PID,
            "metadata": {"k": "v"},
        }

    @respx.mock
    async def test_patch_bad_metadata(self, client):
        with pytest.raises(ValueError):
            await update_carrier_subscriber(client, SID, metadata="nope", confirm=True)  # type: ignore[arg-type]

    async def test_create_email_too_long(self, client):
        with pytest.raises(ValueError):
            await create_carrier_subscriber(client, "SN-1", email="e" * 256, confirm=True)

    async def test_create_notes_and_addr_limits(self, client):
        with pytest.raises(ValueError):
            await create_carrier_subscriber(client, "SN-1", notes="n" * 4097, confirm=True)
        with pytest.raises(ValueError):
            await create_carrier_subscriber(
                client, "SN-1", service_address="a" * 1025, confirm=True
            )
