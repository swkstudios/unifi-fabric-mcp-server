"""N05 review regressions: real server catalog, client and registry; HTTP only is synthetic."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pytest
from fastmcp import Client

from tests import upstream_harness as uh
from tests.test_network_clients_guests import READ_TOOLS, WRITE_TOOLS
from unifi_fabric import server
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.registry import Registry
from unifi_fabric.tools import network_clients_guests as ncg

UUID = "00000000-0000-4000-8000-0000000000c1"
OTHER = "00000000-0000-4000-8000-0000000000c2"
MAC = "02:00:00:00:05:01"
MISSING_MAC = "02:00:00:00:05:ff"
RECORD_ID = "00000000-0000-4000-8000-0000000000e1"
SECRET = "synthetic-review-password-value"
OK = {"meta": {"rc": "ok"}, "data": [], "upstream": True}


def page(rows, total=None):
    return {
        "offset": 0,
        "limit": 200,
        "count": len(rows),
        "totalCount": len(rows) if total is None else total,
        "data": rows,
    }


class ReviewUpstream:
    def __init__(self):
        self.seen = []
        self.clients = [{"id": UUID, "macAddress": MAC, "name": "synthetic-guest"}]
        self.known = [{"mac": MAC, "name": "synthetic-offline"}]
        self.total = None
        self.response: Any = OK
        self.status = 200
        self.records = [
            {"_id": RECORD_ID, "name": "old", "enabled": False, "nested": {"flag": False}}
        ]
        self.applied = True
        self.read_failure = False
        self.wrote = False
        self.fail_labels = set()

    def __call__(self, req):
        self.seen.append(req)
        path = req.url.path
        if path == "/v1/hosts":
            if req.headers.get("X-API-KEY") in self.fail_labels:
                return httpx.Response(403, json={"error": "synthetic-denied"})
            return httpx.Response(200, json={"data": [uh.HOST_RECORD]})
        if path.endswith("/integration/v1/sites"):
            return httpx.Response(
                200,
                json=page([{"id": uh.SITE_ID, "name": "Default", "internalReference": "default"}]),
            )
        if req.method == "GET":
            if path.endswith("/clients"):
                return httpx.Response(200, json=page(self.clients, self.total))
            if path.endswith("/stat/alluser"):
                return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": self.known})
            if "/rest/" in path:
                if self.wrote and self.read_failure:
                    return httpx.Response(503, json={"error": "synthetic-read-after-failure"})
                return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": self.records})
            return httpx.Response(self.status, json=self.response)
        self.wrote = True
        if req.method == "PUT" and self.applied:
            self.records = [json.loads(req.content)]
        return httpx.Response(self.status, json=self.response)

    def writes(self):
        return [req for req in self.seen if req.method != "GET"]


def install(monkeypatch, up, **settings):
    c = uh.install(monkeypatch, up, **settings)
    assert isinstance(server._registry, Registry)
    return c


async def call(monkeypatch, up, fn, *args, **kwargs):
    c = install(monkeypatch, up)
    try:
        return await fn(c, server._registry, uh.HOST, "Default", *args, **kwargs)
    finally:
        await c.close()


async def test_real_server_tools_list_contains_all_23_n05_tools(monkeypatch):
    up = ReviewUpstream()
    # tools/list advertises the domain tools in full mode; discovery (the default since
    # fe400517) advertises only the meta-tools.
    c = install(monkeypatch, up, tool_mode="full")
    try:
        async with Client(server.mcp) as mcp_client:
            names = {tool.name for tool in await mcp_client.list_tools()}
        assert len(READ_TOOLS | WRITE_TOOLS) == 23
        assert READ_TOOLS | WRITE_TOOLS <= names
        from unifi_fabric.families import build_family_index

        index = build_family_index()
        assert {index[name] for name in READ_TOOLS | WRITE_TOOLS} == {"network"}
    finally:
        await c.close()


@pytest.mark.parametrize("fn", [ncg.authorize_guest, ncg.revoke_guest_access])
async def test_incomplete_client_resolution_never_selects_a_write_target(monkeypatch, fn):
    up = ReviewUpstream()
    up.total = 500
    c = install(monkeypatch, up, paginate_max_pages=1)
    try:
        with pytest.raises(ValueError, match="incomplete"):
            await fn(c, server._registry, uh.HOST, "Default", MAC)
        assert not up.writes()
    finally:
        await c.close()


@pytest.mark.parametrize("fn", [ncg.authorize_guest, ncg.revoke_guest_access])
@pytest.mark.parametrize("selector", [OTHER, MISSING_MAC])
async def test_unknown_guest_selector_lists_choices_before_write(monkeypatch, fn, selector):
    up = ReviewUpstream()
    with pytest.raises(ValueError, match="valid|choices") as exc:
        await call(monkeypatch, up, fn, selector)
    assert MAC in str(exc.value)
    assert not up.writes()


@pytest.mark.parametrize("bad", ["bad-ap", "02:00:00:00:0a:01/evil", 7])
async def test_invalid_ap_mac_fails_before_resolution(monkeypatch, bad):
    up = ReviewUpstream()
    with pytest.raises(ValueError, match="ap_mac"):
        await call(monkeypatch, up, ncg.authorize_guest, UUID, ap_mac=bad)
    assert not up.seen


@pytest.mark.parametrize(
    "fn,args",
    [
        (ncg.set_client_icon, (UUID, {"image": object()})),
        (ncg.set_client_fingerprint_override, (UUID, {"override": object()})),
        (ncg.create_dhcp_option, ({"value": object()},)),
        (ncg.update_dhcp_option, (RECORD_ID, {"value": object()})),
        (ncg.create_hotspot_package, ({"value": object()},)),
        (ncg.update_hotspot_package, (RECORD_ID, {"value": object()})),
        (ncg.reset_guest_access_settings, ({"value": object()},)),
        (ncg.report_incorrect_wifi_experience, ("client", UUID, "POOR_LATENCY", object())),
    ],
)
async def test_non_json_write_body_fails_before_resolution(monkeypatch, fn, args):
    up = ReviewUpstream()
    with pytest.raises(ValueError, match="JSON|serialis"):
        await call(monkeypatch, up, fn, *args)
    assert not up.seen


@pytest.mark.parametrize("fn", [ncg.authorize_guest, ncg.revoke_guest_access])
@pytest.mark.parametrize(
    "body",
    [
        {"meta": {"rc": "ok"}, "data": [1], "route": "upstream-owned"},
        [],
        True,
        "upstream-text",
        None,
    ],
)
async def test_guest_success_shapes_are_verbatim_with_only_additive_keys(monkeypatch, fn, body):
    up = ReviewUpstream()
    up.response = body
    result = await call(monkeypatch, up, fn, MAC)
    if fn is ncg.revoke_guest_access:
        assert result["deleted"] is True
        assert result["response"] == body
        assert set(result) == {"deleted", "message", "response"}
    elif isinstance(body, dict):
        assert {k: v for k, v in result.items() if not k.startswith("_")} == body
        assert result["_route"] == "official"
    else:
        assert result == body


@pytest.mark.parametrize("fn", [ncg.get_hotspot_settings, ncg.list_hotspot_payments])
@pytest.mark.parametrize("redact", [False, True])
async def test_hotspot_400_password_follows_opt_in_while_logs_are_always_scrubbed(
    monkeypatch, caplog, fn, redact
):
    up = ReviewUpstream()
    up.status = 400
    up.response = {"password": SECRET, "message": "rejected " + SECRET}
    c = install(monkeypatch, up, redact_secrets=redact)
    try:
        with caplog.at_level(logging.DEBUG), pytest.raises(UniFiConnectionError) as exc:
            await fn(c, server._registry, uh.HOST, "Default")
        assert (SECRET in str(exc.value)) is (not redact)
    finally:
        await c.close()
    assert SECRET not in caplog.text


@pytest.mark.parametrize("fn", [ncg.get_hotspot_settings, ncg.list_hotspot_payments])
@pytest.mark.parametrize("redact", [False, True])
async def test_hotspot_success_password_is_opt_in_only(monkeypatch, fn, redact):
    up = ReviewUpstream()
    up.response = {"password": SECRET, "nested": [{"x_password": SECRET}]}
    c = install(monkeypatch, up, redact_secrets=redact)
    try:
        result = await fn(c, server._registry, uh.HOST, "Default")
        assert (SECRET in json.dumps(result)) is (not redact)
    finally:
        await c.close()


@pytest.mark.parametrize("fn", [ncg.update_dhcp_option, ncg.update_hotspot_package])
@pytest.mark.parametrize(
    "applied,fields",
    [
        (True, {"name": "new", "nested": {"flag": 1}}),
        (False, {"enabled": 0}),
        (False, {"nested": {"flag": 0}}),
    ],
)
async def test_classic_update_verification_is_type_strict(monkeypatch, fn, applied, fields):
    up = ReviewUpstream()
    up.applied = applied
    result = await call(monkeypatch, up, fn, RECORD_ID, fields)
    assert result["_verified"] is applied
    assert {k: v for k, v in result.items() if not k.startswith("_")} == OK
    assert len([r for r in up.seen if r.method == "GET" and "/rest/" in r.url.path]) == 2


@pytest.mark.parametrize("fn", [ncg.update_dhcp_option, ncg.update_hotspot_package])
async def test_classic_read_after_failure_preserves_applied_write(monkeypatch, fn):
    up = ReviewUpstream()
    up.read_failure = True
    result = await call(monkeypatch, up, fn, RECORD_ID, {"name": "new"})
    assert result["_verified"] is None
    assert "503" in result["_readAfterError"]
    assert up.wrote


@pytest.mark.parametrize("all_fail", [False, True])
async def test_real_registry_multi_key_owner_and_all_fail(monkeypatch, all_fail):
    up = ReviewUpstream()
    keys = [
        APIKeyConfig(key="synthetic-alpha", label="alpha"),
        APIKeyConfig(key="synthetic-beta", label="beta"),
    ]
    up.fail_labels = {"synthetic-alpha", "synthetic-beta"} if all_fail else {"synthetic-alpha"}
    c = install(monkeypatch, up, keys=keys)
    try:
        if all_fail:
            with pytest.raises(RuntimeError, match="all 2 configured"):
                await ncg.authorize_guest(c, server._registry, uh.HOST, "Default", MAC)
            assert not up.writes()
        else:
            result = await ncg.authorize_guest(c, server._registry, uh.HOST_ID, "Default", MAC)
            assert result["_route"] == "official"
            assert all(r.headers["X-API-KEY"] == "synthetic-beta" for r in up.writes())
    finally:
        await c.close()


@pytest.mark.parametrize(
    "fn,args",
    [
        (ncg.set_client_icon, (UUID, {"nested": {"password": SECRET}})),
        (ncg.set_client_fingerprint_override, (UUID, {"nested": {"password": SECRET}})),
        (ncg.create_dhcp_option, ({"nested": {"password": SECRET}},)),
        (ncg.update_dhcp_option, (RECORD_ID, {"nested": {"password": SECRET}})),
        (ncg.create_hotspot_package, ({"nested": {"password": SECRET}},)),
        (ncg.update_hotspot_package, (RECORD_ID, {"nested": {"password": SECRET}})),
        (ncg.reset_guest_access_settings, ({"nested": {"password": SECRET}},)),
    ],
)
@pytest.mark.parametrize("redact", [False, True])
async def test_every_arbitrary_write_body_follows_opt_in_while_logs_are_scrubbed(
    monkeypatch, caplog, fn, args, redact
):
    up = ReviewUpstream()
    up.status = 400
    up.response = {"message": "submitted value " + SECRET}
    c = install(monkeypatch, up, redact_secrets=redact)
    try:
        with caplog.at_level(logging.DEBUG), pytest.raises(UniFiConnectionError) as exc:
            await fn(c, server._registry, uh.HOST, "Default", *args)
        assert (SECRET in str(exc.value)) is (not redact)
    finally:
        await c.close()
    assert SECRET not in caplog.text
    assert len(up.writes()) == 1


@pytest.mark.parametrize(
    "tool,arg",
    [
        ("set_client_icon", "icon"),
        ("set_client_fingerprint_override", "override"),
        ("create_dhcp_option", "option"),
        ("update_dhcp_option", "fields"),
        ("create_hotspot_package", "package"),
        ("update_hotspot_package", "fields"),
        ("reset_guest_access_settings", "body"),
    ],
)
def test_registered_typed_body_arguments_bind_nested_scrub_scope(tool, arg):
    from unifi_fabric.route_secrets import tool_call_secrets

    assert SECRET in tool_call_secrets(tool, {arg: {"nested": [{"password": SECRET}]}})


@pytest.mark.parametrize(
    "fn,args",
    [
        (ncg.set_client_icon, ({"image": "synthetic"},)),
        (ncg.set_client_fingerprint_override, ({"name": "synthetic"},)),
        (ncg.report_incorrect_wifi_experience, ("POOR_LATENCY",)),
    ],
)
@pytest.mark.parametrize("selector", [OTHER, MISSING_MAC])
async def test_every_client_addressed_write_rejects_unknown_selector(
    monkeypatch, fn, args, selector
):
    up = ReviewUpstream()
    actual_args = (
        ("client", selector, *args)
        if fn is ncg.report_incorrect_wifi_experience
        else (selector, *args)
    )
    with pytest.raises(ValueError, match="valid|choices") as exc:
        await call(monkeypatch, up, fn, *actual_args)
    assert MAC in str(exc.value)
    assert not up.writes()


@pytest.mark.parametrize(
    "body", [[], True, "upstream-text", None, {"route": "upstream-owned", "data": [1]}]
)
async def test_real_mcp_guest_call_keeps_bare_upstream_shape(monkeypatch, body):
    up = ReviewUpstream()
    up.response = body
    c = install(monkeypatch, up)
    try:
        async with Client(server.mcp) as mcp_client:
            result = await mcp_client.call_tool(
                "authorize_guest", {"host": uh.HOST, "site": "Default", "client": MAC}
            )
        payload = uh.result_payload(result)
        # FastMCP supplies a structured-content envelope for arrays and null.
        if not isinstance(body, dict) and isinstance(payload, dict) and set(payload) == {"result"}:
            payload = payload["result"]
        if isinstance(body, dict):
            assert {k: v for k, v in payload.items() if not k.startswith("_")} == body
        else:
            assert payload == body
    finally:
        await c.close()


@pytest.mark.parametrize("tool", ["get_hotspot_settings", "list_hotspot_payments"])
@pytest.mark.parametrize("redact", [False, True])
async def test_real_mcp_hotspot_error_follows_opt_in_while_logs_are_scrubbed(
    monkeypatch, caplog, tool, redact
):
    up = ReviewUpstream()
    up.status = 400
    up.response = {"password": SECRET, "message": "rejected " + SECRET}
    c = install(monkeypatch, up, redact_secrets=redact)
    try:
        with caplog.at_level(logging.DEBUG):
            async with Client(server.mcp) as mcp_client:
                result = await mcp_client.call_tool(
                    tool, {"host": uh.HOST, "site": "Default"}, raise_on_error=False
                )
        assert result.is_error
        assert (SECRET in str(result.content)) is (not redact)
        assert SECRET not in caplog.text
    finally:
        await c.close()
