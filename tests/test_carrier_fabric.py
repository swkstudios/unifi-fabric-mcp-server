"""Tests for the UniFi Carrier / ISP Fabric tools (cloud, api.ui.com/v1/carrier).

Spec-conformance tested only: no live Carrier Fabric organization is available to
test against. Every
test is hermetic — each request is mocked with respx against a real ``UniFiClient``
built from the EXACT OpenAPI v1.0.0 request/response shapes, so paths, cursor
pagination, selected-key routing, write bodies, the read-before/no-op/read-after
flow, the write gate, and upstream-error pass-through are all asserted
against the spec, NOT against a live console (never claim live-verified: all
assertions are against mock shapes, not a production console).

The write gate (``UNIFI_ENABLE_CARRIER_FABRIC_WRITE``) is ON by default
(opt out with ``UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0``); the autouse hermetic-env
fixture strips ``UNIFI_*`` so tests that exercise a real (mocked) write re-assert
ON via the ``enable_writes`` fixture.
All ids are synthetic and no real value appears here.
"""

from __future__ import annotations

import json as _json

import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
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
    """Writes are enabled by default; this keeps the opt-out explicitly on."""
    monkeypatch.setenv(WRITE_ENABLED_ENV, "1")


@pytest.fixture()
def disable_writes(monkeypatch):
    """Explicitly opt OUT of writes (set the env var to a falsey value)."""
    monkeypatch.setenv(WRITE_ENABLED_ENV, "0")


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
        assert result["_count"] == 3
        assert route.call_count == 2
        # page 1 requests documented max limit and no cursor; page 2 carries meta.nextCursor.
        assert route.calls[0].request.url.params["limit"] == "500"
        assert "cursor" not in route.calls[0].request.url.params
        assert route.calls[1].request.url.params["cursor"] == "CUR2"
        assert result["data"][2]["extra_field"] == "kept"

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
        result = await list_carrier_subscribers(client)
        # The gathered pages are kept and the stop reason surfaced, not discarded.
        assert result["incomplete"] is True
        assert "repeated" in result["incompleteReason"]
        assert result["_count"] == len(result["data"]) >= 1

    @respx.mock
    async def test_list_subscribers_no_default_page_limit(self, client):
        # 30 pages with fresh cursors drain completely: there is no built-in page cap.
        pages = [
            Response(
                200,
                json={
                    "data": [_subscriber(id=f"s-{i}")],
                    "meta": {"nextCursor": f"C{i}", "hasMore": i < 29},
                },
            )
            for i in range(30)
        ]
        respx.get(SUBS).mock(side_effect=pages)
        result = await list_carrier_subscribers(client)
        assert len(result["data"]) == 30

    @respx.mock
    async def test_list_subscribers_opt_in_page_cap(self):
        capped = UniFiClient(Settings(api_key="sk-single", paginate_max_pages=2))
        respx.get(SUBS).mock(
            side_effect=lambda request: Response(
                200,
                json={
                    "data": [_subscriber(id="s-" + request.url.params.get("cursor", ""))],
                    "meta": {
                        "nextCursor": request.url.params.get("cursor", "") + "x",
                        "hasMore": True,
                    },
                },
            )
        )
        result = await list_carrier_subscribers(capped)
        assert result["incomplete"] is True
        assert (
            result["incompleteReason"]
            == "UNIFI_PAGINATE_MAX_PAGES page cap of 2 reached (total unknown)"
        )
        assert result["_count"] == 2

    @respx.mock
    async def test_get_subscriber_returns_envelope_verbatim(self, client):
        body = _sub_response(state="installed")
        respx.get(SUB).mock(return_value=Response(200, json=body))
        result = await get_carrier_subscriber(client, SID)
        assert result == body
        assert result["data"]["id"] == SID
        assert result["data"]["state"] == "installed"

    @respx.mock
    async def test_list_service_plans(self, client):
        respx.get(PLANS).mock(
            return_value=Response(200, json={"data": [_plan(), _plan(id="p-2")], "traceId": "t"})
        )
        result = await list_carrier_service_plans(client)
        assert result["_count"] == 2
        assert result["data"][0]["status"] == "active"

    @respx.mock
    async def test_get_service_plan_returns_envelope_verbatim(self, client):
        respx.get(f"{PLANS}/{PID}").mock(
            return_value=Response(200, json={"data": _plan(), "traceId": "t"})
        )
        result = await get_carrier_service_plan(client, PID)
        assert result == {"data": _plan(), "traceId": "t"}


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
        with pytest.raises(ValueError, match="valid labels"):
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


# --- Write gate is ON by default (opt out UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0)


class TestWriteGate:
    def test_writes_enabled_by_default(self):
        assert carrier_fabric.writes_enabled() is True

    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on", "", "   "])
    def test_truthy_or_unset_enables(self, monkeypatch, val):
        monkeypatch.setenv(WRITE_ENABLED_ENV, val)
        assert carrier_fabric.writes_enabled() is True

    @pytest.mark.parametrize("val", ["0", "false", "no", "off"])
    def test_explicit_falsey_disables(self, monkeypatch, val):
        monkeypatch.setenv(WRITE_ENABLED_ENV, val)
        assert carrier_fabric.writes_enabled() is False

    @respx.mock
    async def test_create_runs_when_gate_unset(self, client):
        post = respx.post(SUBS).mock(return_value=Response(201, json=_sub_response()))
        result = await create_carrier_subscriber(client, "SN-1", confirm=True)
        assert result["status"] == "created"
        assert post.called

    @respx.mock
    async def test_patch_runs_when_gate_unset(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(name="New")))
        result = await update_carrier_subscriber(client, SID, name="New", confirm=True)
        assert result["status"] == "updated"
        assert patch.called


# --- create -----------------------------------------------------------------


class TestCreate:
    @respx.mock
    async def test_runs_without_confirm(self, client):
        post = respx.post(SUBS).mock(return_value=Response(201, json=_sub_response(id="s-new")))
        result = await create_carrier_subscriber(client, "SN-9", name="New Co", plan_id=PID)
        assert result["status"] == "created"
        assert post.called

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
        assert result["subscriber"]["data"]["id"] == "s-new"


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
    async def test_runs_without_confirm(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(name="New")))
        result = await update_carrier_subscriber(client, SID, name="New")
        assert result["status"] == "updated"
        assert patch.called

    @respx.mock
    async def test_updated_read_before_and_after(self, client, enable_writes):
        get = respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(name="New")))
        result = await update_carrier_subscriber(client, SID, name="New", confirm=True)
        assert get.call_count == 1  # read-before; read-after comes from the PATCH body
        assert _json.loads(patch.calls[0].request.content) == {"name": "New"}
        assert result["status"] == "updated"
        assert result["changed"] == {"name": {"from": "Old", "to": "New"}}
        assert result["subscriber"]["data"]["name"] == "New"

    @respx.mock
    async def test_explicit_null_clears_nullable_field(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=PID)))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        result = await update_carrier_subscriber(client, SID, plan_id=None, confirm=True)
        assert _json.loads(patch.calls[0].request.content) == {"planId": None}
        assert result["status"] == "updated"

    @respx.mock
    async def test_metadata_null_leaves_unchanged_is_not_compared(self, client, enable_writes):
        # Per spec, metadata=null leaves metadata unchanged: it is sent as given, but is
        # no change to compare, so it never makes an applied update look unverified.
        respx.get(SUB).mock(
            return_value=Response(200, json=_sub_response(name="Old", metadata={"k": 1}))
        )
        patch = respx.patch(SUB).mock(
            return_value=Response(200, json=_sub_response(name="New", metadata={"k": 1}))
        )
        result = await update_carrier_subscriber(client, SID, name="New", metadata=None)
        assert _json.loads(patch.calls[0].request.content) == {"name": "New", "metadata": None}
        assert result["verified"] is True
        assert result["changed"] == {"name": {"from": "Old", "to": "New"}}

    @respx.mock
    async def test_metadata_null_alone_is_a_no_op(self, client, enable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(metadata={"k": 1})))
        patch = respx.patch(SUB)
        result = await update_carrier_subscriber(client, SID, metadata=None)
        assert result["status"] == "no_op"
        assert not patch.called


class TestUpdateClearFieldsTool:
    """The MCP tool clears nullable fields through ``clear_fields`` (explicit JSON null)."""

    @pytest.fixture()
    def tool(self, monkeypatch, client):
        from unifi_fabric import server

        monkeypatch.setattr(server, "_require", lambda: (client, object()))
        return server.update_carrier_subscriber

    @respx.mock
    async def test_clear_fields_sends_explicit_null(self, tool, enable_writes):
        respx.get(SUB).mock(
            return_value=Response(200, json=_sub_response(email="a@b.example", planId=PID))
        )
        patch = respx.patch(SUB).mock(
            return_value=Response(200, json=_sub_response(email=None, planId=None))
        )
        result = await tool(SID, clear_fields=["email", "plan_id"])
        assert _json.loads(patch.calls[0].request.content) == {"email": None, "planId": None}
        assert result["status"] == "updated"
        assert result["verified"] is True

    @respx.mock
    @pytest.mark.parametrize("field", ["name", "email", "notes", "service_address", "plan_id"])
    async def test_every_nullable_field_is_clearable(self, tool, enable_writes, field):
        wire = {"service_address": "serviceAddress", "plan_id": "planId"}.get(field, field)
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(**{wire: "x"})))
        after = _sub_response(**{wire: None})
        if field == "service_address":
            after["data"].pop(wire)
        patch = respx.patch(SUB).mock(return_value=Response(200, json=after))
        result = await tool(SID, clear_fields=[field])
        assert result["verified"] is True
        assert _json.loads(patch.calls[0].request.content) == {wire: None}

    @respx.mock
    async def test_omitted_nullable_field_stays_unchanged(self, tool, enable_writes):
        # Omission leaves the nullable email field out of the PATCH body.
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response(name="New")))
        await tool(SID, name="New")
        assert _json.loads(patch.calls[0].request.content) == {"name": "New"}

    @pytest.mark.parametrize("field", ["subscriber_number", "metadata", "bogus"])
    async def test_unclearable_field_rejected_before_any_call(self, tool, field):
        with respx.mock(assert_all_called=False) as mock:
            get = mock.get(SUB)
            with pytest.raises(ValueError, match="cannot be cleared"):
                await tool(SID, clear_fields=[field])
        assert not get.called

    async def test_clear_and_value_for_same_field_rejected(self, tool):
        with respx.mock(assert_all_called=False) as mock:
            get = mock.get(SUB)
            with pytest.raises(ValueError, match="one or the other"):
                await tool(SID, name="New", clear_fields=["name"])
        assert not get.called


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
        assert result["_prev_host_id"] == "H-old"
        assert result["verified"] is True
        assert result["response"] == {"data": _subscriber(hostId="H-new"), "prevHostId": "H-old"}
        assert result["changed"] == {"hostId": {"from": "H-old", "to": "H-new"}}

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
        assert result["_prev_host_id"] == "H-1"
        assert result["verified"] is True
        assert result["response"] == {"data": _subscriber(hostId=None), "prevHostId": "H-1"}


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
            return_value=Response(
                200, json=_sub_response(suspended=True, suspendReason="nonpayment")
            )
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
    async def test_resume_runs_without_confirm(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=True)))
        post = respx.post(f"{SUB}/resume").mock(
            return_value=Response(200, json=_sub_response(suspended=False))
        )
        result = await resume_carrier_subscriber(client, SID)
        assert result["status"] == "resumed"
        assert post.called

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


# --- Branch coverage: gate-off, no-confirm, and validation on every write ---


class TestGateOffAllWrites:
    """Opt-out retained: writes refuse when UNIFI_ENABLE_CARRIER_FABRIC_WRITE is set off."""

    @respx.mock
    async def test_attach_disabled_when_gate_off(self, client, disable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId=None)))
        put = respx.put(f"{SUB}/host").mock(return_value=Response(200, json=_sub_response()))
        with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
            await attach_carrier_subscriber_host(client, SID, "H-1", confirm=True)
        assert not put.called

    @respx.mock
    async def test_detach_disabled_when_gate_off(self, client, disable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-1")))
        with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
            await detach_carrier_subscriber_host(client, SID, confirm=True)

    @respx.mock
    async def test_assign_disabled_when_gate_off(self, client, disable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
            await assign_carrier_subscriber_plan(client, SID, PID, confirm=True)

    @respx.mock
    async def test_suspend_disabled_when_gate_off(self, client, disable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=False)))
        with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
            await suspend_carrier_subscriber(client, SID, confirm=True)

    @respx.mock
    async def test_resume_disabled_when_gate_off(self, client, disable_writes):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=True)))
        with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
            await resume_carrier_subscriber(client, SID, confirm=True)


class TestNoConfirmAllWrites:
    """No gate: every write proceeds without confirm (writes enabled by default)."""

    @respx.mock
    async def test_attach_runs_without_confirm(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-old")))
        put = respx.put(f"{SUB}/host").mock(
            return_value=Response(200, json=_sub_response(hostId="H-new"))
        )
        result = await attach_carrier_subscriber_host(client, SID, "H-new")
        assert result["status"] == "attached"
        assert put.called

    @respx.mock
    async def test_detach_runs_without_confirm(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId="H-1")))
        delete = respx.delete(f"{SUB}/host").mock(
            return_value=Response(200, json=_sub_response(hostId=None))
        )
        result = await detach_carrier_subscriber_host(client, SID)
        assert result["status"] == "detached"
        assert delete.called

    @respx.mock
    async def test_assign_runs_without_confirm(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        put = respx.put(f"{SUB}/plan").mock(
            return_value=Response(200, json=_sub_response(planId=PID))
        )
        result = await assign_carrier_subscriber_plan(client, SID, PID)
        assert result["status"] == "assigned"
        assert put.called

    @respx.mock
    async def test_suspend_runs_without_confirm(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=False)))
        post = respx.post(f"{SUB}/suspend").mock(
            return_value=Response(200, json=_sub_response(suspended=True))
        )
        result = await suspend_carrier_subscriber(client, SID, reason="x")
        assert result["status"] == "suspended"
        assert post.called


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
            subscriber_number="  SN-2  ",
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


# --- Cursor drain guards (single-key, multi-key, page-capped, all-fail) ---------


def _page(ids, cursor=None, has_more=None):
    meta = {}
    if cursor is not None:
        meta["nextCursor"] = cursor
    if has_more is not None:
        meta["hasMore"] = has_more
    return {"data": [_subscriber(id=i) for i in ids], "meta": meta}


class TestCursorDrainGuards:
    @respx.mock
    async def test_has_more_without_cursor_is_incomplete_not_complete(self, client):
        respx.get(SUBS).mock(return_value=Response(200, json=_page(["s-1"], has_more=True)))
        result = await list_carrier_subscribers(client)
        assert result["incomplete"] is True
        assert "nextCursor" in result["incompleteReason"]
        assert [s["id"] for s in result["data"]] == ["s-1"]

    @respx.mock
    async def test_repeated_page_is_dropped_and_flagged(self, client):
        respx.get(SUBS).mock(
            side_effect=[
                Response(200, json=_page(["s-1", "s-2"], cursor="A", has_more=True)),
                Response(200, json=_page(["s-1", "s-2"], cursor="B", has_more=True)),
            ]
        )
        result = await list_carrier_subscribers(client)
        assert result["incomplete"] is True
        assert "repeated page" in result["incompleteReason"]
        assert [s["id"] for s in result["data"]] == ["s-1", "s-2"]

    @respx.mock
    async def test_cursor_cycle_terminates_as_incomplete(self, client):
        def _serve(request):
            cursor = request.url.params.get("cursor")
            nxt = {None: "A", "A": "B", "B": "A"}[cursor]
            return Response(200, json=_page([f"s-{cursor}"], cursor=nxt, has_more=True))

        route = respx.get(SUBS).mock(side_effect=_serve)
        result = await list_carrier_subscribers(client)
        assert route.call_count == 3  # first page, A, B; the second A is never followed
        assert result["incomplete"] is True
        assert "cycle" in result["incompleteReason"]
        assert [s["id"] for s in result["data"]] == ["s-None", "s-A", "s-B"]

    @respx.mock
    async def test_non_object_meta_raises(self, client):
        respx.get(SUBS).mock(return_value=Response(200, json={"data": [], "meta": [1]}))
        with pytest.raises(UniFiConnectionError, match="'meta'"):
            await list_carrier_subscribers(client)

    @respx.mock
    async def test_multi_key_guard_keeps_other_key_and_names_label(self, multikey):
        def _serve(request):
            if request.headers["x-api-key"] == "sk-alpha":
                return Response(200, json=_page(["a-1"], has_more=True))
            return Response(200, json=_page(["b-1"], has_more=False))

        respx.get(SUBS).mock(side_effect=_serve)
        result = await list_carrier_subscribers(multikey)
        assert {s["id"] for s in result["data"]} == {"a-1", "b-1"}
        assert result["incomplete"] is True
        assert result["incompleteReason"].startswith("alpha: ")

    @respx.mock
    async def test_page_capped_multi_key_flags_capped_key(self):
        multikey = UniFiClient(
            Settings(
                api_keys=[
                    APIKeyConfig(key="sk-alpha", label="alpha", is_org_key=False),
                    APIKeyConfig(key="sk-beta", label="beta", is_org_key=True),
                ],
                paginate_max_pages=1,
            )
        )

        def _serve(request):
            if request.headers["x-api-key"] == "sk-alpha":
                return Response(200, json=_page(["a-1"], cursor="N", has_more=True))
            return Response(200, json=_page(["b-1"], has_more=False))

        respx.get(SUBS).mock(side_effect=_serve)
        result = await list_carrier_subscribers(multikey)
        assert {s["id"] for s in result["data"]} == {"a-1", "b-1"}
        assert (
            result["incompleteReason"]
            == "alpha: UNIFI_PAGINATE_MAX_PAGES page cap of 1 reached (total unknown)"
        )

    @respx.mock
    async def test_all_keys_failing_is_an_error(self, multikey):
        respx.get(SUBS).mock(
            return_value=Response(403, json={"error": {"code": "insufficient_scope"}})
        )
        with pytest.raises(Exception, match="insufficient_scope"):
            await list_carrier_subscribers(multikey)


# --- Envelope shape ----------------------------------------------------------


class TestEnvelopeShape:
    @pytest.mark.parametrize("inner", [None, [1, 2], "text", 7])
    @respx.mock
    async def test_non_object_data_raises_on_read(self, client, inner):
        respx.get(SUB).mock(return_value=Response(200, json={"data": inner, "traceId": "t"}))
        with pytest.raises(UniFiConnectionError, match="expected 'data' to be an object") as exc:
            await get_carrier_subscriber(client, SID)
        assert "traceId" not in str(exc.value)  # names the shape, does not quote the body

    @respx.mock
    async def test_non_object_data_raises_on_read_before(self, client):
        respx.get(SUB).mock(return_value=Response(200, json={"data": ["x"]}))
        put = respx.put(f"{SUB}/plan")
        with pytest.raises(UniFiConnectionError, match="expected 'data' to be an object"):
            await assign_carrier_subscriber_plan(client, SID, PID)
        assert not put.called

    @respx.mock
    async def test_object_without_data_key_is_the_resource(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_subscriber(name="Bare")))
        result = await get_carrier_subscriber(client, SID)
        assert result == _subscriber(name="Bare")

    @respx.mock
    async def test_non_object_body_raises_with_shape(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=["a", "b"]))
        with pytest.raises(UniFiConnectionError, match="array of 2 item"):
            await get_carrier_subscriber(client, SID)


# --- Uniform write results --------------------------------------------------


class TestWriteResults:
    @respx.mock
    async def test_create_carries_response_and_changed(self, client):
        body = {"data": _subscriber(subscriberNumber="SN-9"), "traceId": "t-9"}
        respx.post(SUBS).mock(return_value=Response(201, json=body))
        result = await create_carrier_subscriber(client, "SN-9")
        assert result["response"] == body
        assert result["changed"] == {"subscriberNumber": {"from": None, "to": "SN-9"}}

    @respx.mock
    async def test_update_carries_response_changed_and_verified(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        body = _sub_response(name="New")
        respx.patch(SUB).mock(return_value=Response(200, json=body))
        result = await update_carrier_subscriber(client, SID, name="New")
        assert result["response"] == body
        assert result["changed"] == {"name": {"from": "Old", "to": "New"}}
        assert result["verified"] is True

    @respx.mock
    async def test_assign_carries_response(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(planId=None)))
        body = _sub_response(planId=PID)
        respx.put(f"{SUB}/plan").mock(return_value=Response(200, json=body))
        result = await assign_carrier_subscriber_plan(client, SID, PID)
        assert result["response"] == body
        assert result["changed"] == {"planId": {"from": None, "to": PID}}

    @respx.mock
    async def test_suspend_reports_changed_and_response(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response()))
        body = _sub_response(suspended=True, suspendReason="non-payment")
        respx.post(f"{SUB}/suspend").mock(return_value=Response(200, json=body))
        result = await suspend_carrier_subscriber(client, SID, reason="non-payment")
        assert result["changed"] == {
            "suspended": {"from": False, "to": True},
            "suspendReason": {"from": None, "to": "non-payment"},
        }
        assert result["verified"] is True
        assert result["response"] == body

    @respx.mock
    async def test_resume_reports_changed_and_response(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(suspended=True)))
        body = _sub_response(suspended=False)
        respx.post(f"{SUB}/resume").mock(return_value=Response(200, json=body))
        result = await resume_carrier_subscriber(client, SID)
        assert result["changed"] == {"suspended": {"from": True, "to": False}}
        assert result["verified"] is True
        assert result["response"] == body

    @respx.mock
    async def test_attach_prev_host_null_on_fresh_attach(self, client):
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(hostId=None)))
        body = {"data": _subscriber(hostId="H-1"), "prevHostId": None, "traceId": "t"}
        respx.put(f"{SUB}/host").mock(return_value=Response(200, json=body))
        result = await attach_carrier_subscriber_host(client, SID, "H-1")
        assert result["_prev_host_id"] is None
        assert result["response"] == body


# --- Gate first --------------------------------------------------------------

_INVALID_WRITE_CALLS = [
    (create_carrier_subscriber, ("",), {}),
    (update_carrier_subscriber, ("../bad",), {}),
    (attach_carrier_subscriber_host, ("../bad", ""), {}),
    (detach_carrier_subscriber_host, ("../bad",), {}),
    (assign_carrier_subscriber_plan, ("../bad", "../bad"), {}),
    (suspend_carrier_subscriber, ("../bad",), {"reason": 5}),
    (resume_carrier_subscriber, ("../bad",), {}),
]


@pytest.mark.parametrize("fn,args,kwargs", _INVALID_WRITE_CALLS)
async def test_gate_is_checked_before_field_validation(client, disable_writes, fn, args, kwargs):
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ValueError, match=WRITE_ENABLED_ENV):
            await fn(client, *args, **kwargs)
        assert not router.calls


# --- A write body that is not the resource is reported, never raised ---------------


class TestNonResourceWriteBody:
    @respx.mock
    async def test_empty_patch_body_reads_the_subscriber_back(self, client):
        get = respx.get(SUB).mock(
            side_effect=[
                Response(200, json=_sub_response(name="Old")),
                Response(200, json=_sub_response(name="New")),
            ]
        )
        respx.patch(SUB).mock(return_value=Response(204))
        result = await update_carrier_subscriber(client, SID, name="New")
        assert get.call_count == 2  # read-before + read-after
        assert result["response"] is None
        assert result["subscriber"]["data"]["name"] == "New"
        assert result["verified"] is True

    @respx.mock
    async def test_text_delete_body_is_returned_verbatim(self, client):
        respx.get(SUB).mock(
            side_effect=[
                Response(200, json=_sub_response(hostId="H-1")),
                Response(200, json=_sub_response(hostId=None)),
            ]
        )
        respx.delete(f"{SUB}/host").mock(return_value=Response(200, text="detached"))
        result = await detach_carrier_subscriber_host(client, SID)
        assert result["response"] == "detached"
        assert result["_prev_host_id"] is None
        assert result["verified"] is True

    @respx.mock
    async def test_empty_create_body_reports_null_subscriber(self, client):
        respx.post(SUBS).mock(return_value=Response(201))
        result = await create_carrier_subscriber(client, "SN-1")
        assert result == {
            "status": "created",
            "changed": {"subscriberNumber": {"from": None, "to": "SN-1"}},
            "subscriber": None,
            "response": None,
        }

    @respx.mock
    async def test_multi_key_read_after_rides_the_owning_key(self, multikey):
        seen: list[str] = []

        def _get(request):
            seen.append(request.headers["x-api-key"])
            if request.headers["x-api-key"] == "sk-alpha":
                return Response(404, json={"error": {"code": "subscriber_not_found"}})
            return Response(200, json=_sub_response(suspended=len(seen) > 2))

        respx.get(SUB).mock(side_effect=_get)
        post = respx.post(f"{SUB}/suspend").mock(return_value=Response(204))
        result = await suspend_carrier_subscriber(multikey, SID)
        assert post.calls[0].request.headers["x-api-key"] == "sk-beta"
        assert seen[-1] == "sk-beta"  # the read-after uses the key that owns the subscriber
        assert result["verified"] is True
        assert result["response"] is None


# --- Suspend reason no-op, create key routing -----------------------------------------------


class TestSuspendReasonNoOp:
    """A no-op is only asserted when the sent change is already applied: an already
    suspended subscriber with a DIFFERENT reason gets the write (upstream decides)."""

    @respx.mock
    async def test_same_reason_is_no_op(self, client):
        respx.get(SUB).mock(
            return_value=Response(
                200, json=_sub_response(suspended=True, suspendReason="nonpayment")
            )
        )
        post = respx.post(f"{SUB}/suspend")
        result = await suspend_carrier_subscriber(client, SID, reason="nonpayment")
        assert result["status"] == "no_op"
        assert not post.called

    @respx.mock
    async def test_different_reason_is_sent(self, client):
        respx.get(SUB).mock(
            return_value=Response(
                200, json=_sub_response(suspended=True, suspendReason="nonpayment")
            )
        )
        post = respx.post(f"{SUB}/suspend").mock(
            return_value=Response(
                200, json=_sub_response(suspended=True, suspendReason="chargeback")
            )
        )
        result = await suspend_carrier_subscriber(client, SID, reason="chargeback")
        assert _json.loads(post.calls[0].request.content) == {"reason": "chargeback"}
        assert result["status"] == "suspended"
        assert result["changed"] == {"suspendReason": {"from": "nonpayment", "to": "chargeback"}}

    @respx.mock
    async def test_different_reason_upstream_error_passes_through(self, client):
        respx.get(SUB).mock(
            return_value=Response(200, json=_sub_response(suspended=True, suspendReason="a"))
        )
        respx.post(f"{SUB}/suspend").mock(
            return_value=Response(409, json={"error": {"code": "already_suspended-probe"}})
        )
        with pytest.raises(UniFiConnectionError, match="already_suspended-probe"):
            await suspend_carrier_subscriber(client, SID, reason="b")


class TestCreateKeyRouting:
    """create_carrier_subscriber never silently creates under the first configured key."""

    @respx.mock
    async def test_single_key_no_label_uses_default_key(self, client):
        post = respx.post(SUBS).mock(return_value=Response(201, json=_sub_response()))
        await create_carrier_subscriber(client, "SN-1")
        assert post.calls[0].request.headers["x-api-key"] == "sk-single"

    @respx.mock
    async def test_multi_key_no_label_no_plan_fails_listing_labels(self, multikey):
        post = respx.post(SUBS)
        with pytest.raises(ValueError, match="alpha, beta"):
            await create_carrier_subscriber(multikey, "SN-1")
        assert not post.called

    @respx.mock
    async def test_multi_key_plan_routes_to_owning_key(self, multikey):
        def plan(request):
            if request.headers["x-api-key"] == "sk-beta":
                return Response(200, json={"data": {"id": PID}, "traceId": "t"})
            return Response(404, json={"error": {"code": "service_plan_not_found"}})

        respx.get(f"{PLANS}/{PID}").mock(side_effect=plan)
        post = respx.post(SUBS).mock(return_value=Response(201, json=_sub_response()))
        await create_carrier_subscriber(multikey, "SN-1", plan_id=PID)
        assert post.calls[0].request.headers["x-api-key"] == "sk-beta"

    @respx.mock
    async def test_multi_key_plan_on_no_key_is_an_error(self, multikey):
        respx.get(f"{PLANS}/{PID}").mock(
            return_value=Response(404, json={"error": {"code": "service_plan_not_found"}})
        )
        post = respx.post(SUBS)
        with pytest.raises(RuntimeError, match="service_plan_not_found"):
            await create_carrier_subscriber(multikey, "SN-1", plan_id=PID)
        assert not post.called

    @respx.mock
    async def test_multi_key_label_wins(self, multikey):
        plan = respx.get(f"{PLANS}/{PID}")
        post = respx.post(SUBS).mock(return_value=Response(201, json=_sub_response()))
        await create_carrier_subscriber(multikey, "SN-1", plan_id=PID, key_label="beta")
        assert post.calls[0].request.headers["x-api-key"] == "sk-beta"
        assert not plan.called

    async def test_multi_key_unknown_label_lists_valid(self, multikey):
        with pytest.raises(ValueError, match="valid labels"):
            await create_carrier_subscriber(multikey, "SN-1", key_label="nope")


# --- Write results embed bodies verbatim (nothing unwrapped) -------------------------


class TestWriteResultEnvelope:
    @respx.mock
    async def test_update_embeds_the_full_write_body_as_read_after(self, client):
        written = _sub_response(name="New")
        respx.get(SUB).mock(return_value=Response(200, json=_sub_response(name="Old")))
        respx.patch(SUB).mock(return_value=Response(200, json=written))
        result = await update_carrier_subscriber(client, SID, name="New")
        assert result["subscriber"] == written  # traceId kept beside data
        assert result["response"] == written

    @respx.mock
    async def test_non_resource_write_body_embeds_full_get_body(self, client):
        after = _sub_response(name="New")
        respx.get(SUB).side_effect = [
            Response(200, json=_sub_response(name="Old")),
            Response(200, json=after),
        ]
        respx.patch(SUB).mock(return_value=Response(204))
        result = await update_carrier_subscriber(client, SID, name="New")
        assert result["subscriber"] == after
        assert result["response"] is None
        assert result["verified"] is True

    @respx.mock
    async def test_read_before_identity_mismatch_is_upstream_judged_and_sends_no_write(
        self, client
    ):
        from unifi_fabric import refusals
        from unifi_fabric.refusal_audit import upstream_caused

        respx.get(SUB).mock(
            return_value=Response(
                200, json=_sub_response(id="00000000-0000-4000-8000-00000000beef")
            )
        )
        patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub_response()))
        with pytest.raises(UniFiConnectionError) as exc:
            await update_carrier_subscriber(client, SID, name="New")
        assert not patch.called
        assert "read '00000000-0000-4000-8000-00000000beef'" in str(exc.value)
        assert "no write was sent" in str(exc.value)
        refusal = refusals.classify(str(exc.value))
        assert refusal is not None
        assert refusal.id == "carrier-subscriber-read-before-identity"
        assert refusal.category == refusals.UPSTREAM_JUDGED
        assert upstream_caused(exc.value)

    @respx.mock
    async def test_no_op_embeds_full_read_before_body(self, client):
        before = _sub_response(name="Same")
        respx.get(SUB).mock(return_value=Response(200, json=before))
        result = await update_carrier_subscriber(client, SID, name="Same")
        assert result == {
            "status": "no_op",
            "reason": "Every provided field already matches the subscriber; no write performed.",
            "subscriber": before,
        }

    @respx.mock
    async def test_create_embeds_the_full_201_body(self, client):
        created = _sub_response(id="s-new", subscriberNumber="SN-9")
        respx.post(SUBS).mock(return_value=Response(201, json=created))
        result = await create_carrier_subscriber(client, "SN-9")
        assert result["subscriber"] == created
        assert result["response"] == created


@pytest.mark.parametrize("limit", [-1, 0, True, 1.5])
async def test_subscriber_invalid_limit_rejected_before_request(client, limit):
    with pytest.raises(ValueError):
        await list_carrier_subscribers(client, limit=limit)
