"""N05 review regressions through the production catalog and a mock HTTP transport.

The real Registry performs console/site/client enumeration. No test calls register().
All identifiers, keys, and submitted secret sentinels are synthetic.
"""

from __future__ import annotations

import copy
import json
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastmcp import Client

from unifi_fabric import server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry

HOST = "n05-synthetic-console"
SITE = "N05 Synthetic Site"
SITE_ID = "00000000-0000-4000-8000-000000000051"
CLIENT_ID = "00000000-0000-4000-8000-000000000052"
UNKNOWN_ID = "00000000-0000-4000-8000-000000000099"
RECORD_ID = "000000000000000000000053"
MAC = "02:00:00:00:05:01"
UNKNOWN_MAC = "02:00:00:00:05:ff"
NET = f"/v1/connector/consoles/{HOST}/proxy/network"
OFFICIAL = f"{NET}/integration/v1/sites/{SITE_ID}"
CLASSIC = f"{NET}/api/s/default"
TOOLS = {
    "authorize_guest",
    "revoke_guest_access",
    "get_local_client",
    "list_client_traffic_controls",
    "get_client_insights",
    "get_client_observability",
    "set_client_icon",
    "set_client_fingerprint_override",
    "report_incorrect_wifi_experience",
    "list_dhcp_leases",
    "list_dhcp_excluded_ips",
    "list_dhcp_options",
    "create_dhcp_option",
    "update_dhcp_option",
    "delete_dhcp_option",
    "get_hotspot_settings",
    "list_hotspot_payments",
    "list_hotspot_authorizations",
    "create_hotspot_package",
    "update_hotspot_package",
    "delete_hotspot_package",
    "delete_guest_portal_file",
    "reset_guest_access_settings",
}
CLIENT_ROW = {"id": CLIENT_ID, "macAddress": MAC, "mac": MAC, "name": "synthetic-phone"}
KEYS = [
    APIKeyConfig(key="n05-synthetic-alpha", label="alpha"),
    APIKeyConfig(key="n05-synthetic-beta", label="beta"),
]


def page(rows: list[dict[str, Any]], total: int | None = None) -> dict[str, Any]:
    return {
        "offset": 0,
        "limit": 200,
        "count": len(rows),
        "totalCount": len(rows) if total is None else total,
        "data": rows,
    }


class Upstream:
    def __init__(self) -> None:
        self.seen: list[httpx.Request] = []
        self.routes: dict[tuple[str, str], Any] = {}
        self.fail_keys: set[str] = set()
        self.clients = [copy.deepcopy(CLIENT_ROW)]
        self.client_total: int | None = None

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        path = req.url.path
        label = "alpha" if req.headers.get("X-API-KEY") == KEYS[0].key else "beta"
        if path == "/v1/hosts":
            if label in self.fail_keys:
                return httpx.Response(400, json={"error": f"synthetic {label} unavailable"})
            hosts = [] if label == "alpha" else [{"id": HOST, "name": "N05 Synthetic Console"}]
            return httpx.Response(200, json={"data": hosts})
        if path == f"{NET}/integration/v1/sites":
            return httpx.Response(
                200, json=page([{"id": SITE_ID, "name": SITE, "internalReference": "default"}])
            )
        if (req.method, path) in self.routes:
            body = self.routes[(req.method, path)]
            body = body(req) if callable(body) else body
            return body if isinstance(body, httpx.Response) else httpx.Response(200, json=body)
        if req.method == "GET" and path == f"{OFFICIAL}/clients":
            return httpx.Response(200, json=page(self.clients, self.client_total))
        if req.method == "GET" and path == f"{OFFICIAL}/clients/{CLIENT_ID}":
            return httpx.Response(200, json=CLIENT_ROW)
        if req.method == "GET" and path in {f"{CLASSIC}/stat/alluser", f"{CLASSIC}/stat/sta"}:
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": self.clients})
        return httpx.Response(404, json={"error": "unexpected synthetic request", "path": path})

    def writes(self) -> list[httpx.Request]:
        return [req for req in self.seen if req.method != "GET"]


@asynccontextmanager
async def session(monkeypatch, up: Upstream, **options: Any):
    settings = Settings(api_keys=KEYS, **options)

    async def get_client(self: UniFiClient, key: APIKeyConfig) -> httpx.AsyncClient:
        if key.label not in self._clients:
            self._clients[key.label] = httpx.AsyncClient(
                base_url=settings.api_base_url,
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(up),
            )
        return self._clients[key.label]

    monkeypatch.setattr(UniFiClient, "_get_client", get_client)
    monkeypatch.setattr(server, "_settings", settings)
    async with Client(server.mcp, mode="legacy") as client:
        # Lifespan creates these production dependencies, not a stub registry.
        assert isinstance(server._registry, Registry)
        yield client


async def call(mcp_client: Client, name: str, **args: Any) -> Any:
    result = await mcp_client.call_tool(name, {"host": HOST, "site": SITE, **args})
    return json.loads(result.content[0].text)


async def test_n05_all_23_tools_are_in_the_real_server_catalog(monkeypatch):
    # tools/list advertises the domain tools in full mode; discovery (the default since
    # fe400517) advertises only the meta-tools.
    async with session(monkeypatch, Upstream(), tool_mode="full") as client:
        names = {tool.name for tool in await client.list_tools()}
    assert len(TOOLS) == 23
    assert TOOLS <= names, sorted(TOOLS - names)


@pytest.mark.parametrize(
    "name,arg",
    [
        ("authorize_guest", "client"),
        ("revoke_guest_access", "guest"),
        ("set_client_icon", "target_id"),
        ("set_client_fingerprint_override", "client"),
        ("report_incorrect_wifi_experience", "target"),
    ],
)
@pytest.mark.parametrize("selector", [UNKNOWN_ID, UNKNOWN_MAC])
async def test_n05_unknown_client_selectors_refuse_before_writes(monkeypatch, name, arg, selector):
    up = Upstream()
    extra = {"icon": {"id": 12}} if name == "set_client_icon" else {}
    if name == "report_incorrect_wifi_experience":
        extra = {"target_type": "client", "reason": "synthetic poor score"}
    async with session(monkeypatch, up) as client:
        with pytest.raises(Exception) as caught:
            await call(client, name, **{arg: selector}, **extra)
    message = str(caught.value)
    assert "valid" in message.lower(), message
    assert CLIENT_ID in message or MAC in message, message
    assert up.writes() == []


@pytest.mark.parametrize(
    "name,arg", [("authorize_guest", "client"), ("revoke_guest_access", "guest")]
)
async def test_n05_capped_client_resolution_never_selects_a_write_target(monkeypatch, name, arg):
    up = Upstream()
    up.client_total = 201
    async with session(monkeypatch, up, paginate_max_pages=1) as client:
        with pytest.raises(Exception) as caught:
            await call(client, name, **{arg: MAC})
    assert any(word in str(caught.value).lower() for word in ("incomplete", "cap", "partial"))
    assert up.writes() == []


@pytest.mark.parametrize("ap_mac", ["not-a-mac", "02:00:00:00:05", "02:00:00:00:05:zz"])
async def test_n05_invalid_ap_mac_refuses_before_any_request(monkeypatch, ap_mac):
    up = Upstream()
    async with session(monkeypatch, up) as client:
        with pytest.raises(Exception):
            await call(client, "authorize_guest", client=MAC, ap_mac=ap_mac)
    assert up.seen == []


@pytest.mark.parametrize(
    "name,body_args",
    [
        ("create_dhcp_option", {"option": {"nested": {"bad": object()}}}),
        ("update_dhcp_option", {"option_id": RECORD_ID, "fields": {"nested": {"bad": object()}}}),
        ("create_hotspot_package", {"package": {"nested": {"bad": object()}}}),
        (
            "update_hotspot_package",
            {"package_id": RECORD_ID, "fields": {"nested": {"bad": object()}}},
        ),
        ("reset_guest_access_settings", {"body": {"nested": {"bad": object()}}}),
        (
            "set_client_fingerprint_override",
            {"client": MAC, "override": {"nested": {"bad": object()}}},
        ),
    ],
)
async def test_n05_non_json_body_refuses_before_any_resolution(monkeypatch, name, body_args):
    up = Upstream()
    async with session(monkeypatch, up):
        # A non-JSON object cannot cross MCP's JSON wire. Invoke its REAL catalog path
        # directly to exercise server-side validation rather than client serialization.
        with pytest.raises(Exception):
            await server.mcp.call_tool(name, {"host": HOST, "site": SITE, **body_args})
    assert up.seen == []


@pytest.mark.parametrize(
    "name,arg", [("authorize_guest", "client"), ("revoke_guest_access", "guest")]
)
async def test_n05_guest_response_preserves_every_upstream_field(monkeypatch, name, arg):
    up = Upstream()
    upstream = {
        "meta": {"rc": "ok"},
        "data": [{"probe": "synthetic-result"}],
        "route": "upstream-route",
        "reason": "upstream-reason",
        "extra": [1, False, None],
    }
    up.routes[("POST", f"{OFFICIAL}/clients/{CLIENT_ID}/actions")] = upstream
    async with session(monkeypatch, up) as client:
        result = await call(client, name, **{arg: MAC})
    if name == "revoke_guest_access":
        assert result["deleted"] is True
        assert result["message"] == "Guest access revoked."
        assert result["response"] == upstream
    else:
        assert {k: v for k, v in result.items() if not k.startswith("_")} == upstream
    assert len(up.writes()) == 1


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize(
    "name,args,path",
    [
        (
            "reset_guest_access_settings",
            {"body": {}},
            f"{NET}/v2/api/site/default/settings/guest-access/reset",
        ),
        ("create_hotspot_package", {"package": {}}, f"{CLASSIC}/rest/hotspotpackage"),
        ("create_dhcp_option", {"option": {}}, f"{CLASSIC}/rest/dhcpoption"),
    ],
)
async def test_n05_submitted_secrets_cannot_leak_in_400_errors(
    monkeypatch, redact, name, args, path
):
    up = Upstream()
    sentinels = {
        "password": "n05-portal-secret-617",
        "payment_key": "n05-payment-secret-618",
        "radius_secret": "n05-radius-secret-0000",
    }
    body_name = next(iter(args))
    args = {body_name: dict(sentinels)}
    up.routes[("POST", path)] = httpx.Response(
        400, json={"error": "invalid synthetic settings", "detail": list(sentinels.values())}
    )
    async with session(monkeypatch, up, redact_secrets=redact) as client:
        with pytest.raises(Exception) as caught:
            await call(client, name, **args)
    text = str(caught.value)
    assert "invalid synthetic settings" in text
    assert all((value not in text) is redact for value in sentinels.values()), text
    assert len(up.writes()) == 1


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize(
    "name,path",
    [
        ("get_hotspot_settings", f"{NET}/api/stat/s/default/hotspotconfig"),
        ("list_hotspot_payments", f"{CLASSIC}/stat/payment"),
    ],
)
async def test_n05_hotspot_read_400_secret_fields_respect_redaction_policy(
    monkeypatch, redact, name, path
):
    up = Upstream()
    sentinel = "n05-submitted-password-620"
    up.routes[("GET", path)] = httpx.Response(
        400, json={"error": "synthetic portal error", "password": sentinel}
    )
    async with session(monkeypatch, up, redact_secrets=redact) as client:
        with pytest.raises(Exception) as caught:
            await call(client, name)
    assert "synthetic portal error" in str(caught.value)
    assert (sentinel not in str(caught.value)) is redact


@pytest.mark.parametrize(
    "name,collection,id_arg",
    [
        ("update_dhcp_option", "dhcpoption", "option_id"),
        ("update_hotspot_package", "hotspotpackage", "package_id"),
    ],
)
@pytest.mark.parametrize("matches", [True, False])
async def test_n05_classic_update_rereads_and_compares_typed_nested_leaves(
    monkeypatch,
    name,
    collection,
    id_arg,
    matches,
):
    up = Upstream()
    reads = 0
    fields = {"name": "changed", "nested": {"flag": True, "count": 1, "values": [False, 2]}}
    original = {"_id": RECORD_ID, "name": "before", "nested": {"flag": False, "count": 0}}
    after = {**original, **copy.deepcopy(fields)}
    if not matches:
        after["nested"]["flag"] = 1
        after["nested"]["count"] = True
        after["nested"]["values"][0] = 0

    def listing(req):
        nonlocal reads
        reads += 1
        return {"meta": {"rc": "ok"}, "data": [original if reads == 1 else after]}

    upstream = {"meta": {"rc": "ok"}, "data": [{"_id": RECORD_ID}], "probe": "put-response"}
    up.routes[("GET", f"{CLASSIC}/rest/{collection}")] = listing
    up.routes[("GET", f"{CLASSIC}/rest/{collection}/{RECORD_ID}")] = {
        "meta": {"rc": "ok"},
        "data": [after],
    }
    up.routes[("PUT", f"{CLASSIC}/rest/{collection}/{RECORD_ID}")] = upstream
    async with session(monkeypatch, up) as client:
        result = await call(client, name, **{id_arg: RECORD_ID}, fields=fields)
    assert {k: v for k, v in result.items() if not k.startswith("_")} == upstream
    assert result["_verified"] is matches
    if matches:
        assert "_unverifiedFields" not in result
    else:
        assert result["_unverifiedFields"] == [
            "nested.flag",
            "nested.count",
            "nested.values[0]",
        ]
    assert len(up.writes()) == 1
    assert any(req.method == "GET" for req in up.seen[up.seen.index(up.writes()[0]) + 1 :])


@pytest.mark.parametrize("fail_keys", [{"alpha"}, {"alpha", "beta"}])
async def test_n05_real_registry_multikey_failure_isolation(monkeypatch, fail_keys):
    up = Upstream()
    up.fail_keys = fail_keys
    upstream = {"meta": {"rc": "ok"}, "data": [{"probe": "beta-owned-result"}]}
    up.routes[("GET", f"{CLASSIC}/rest/dhcpoption")] = upstream
    async with session(monkeypatch, up) as client:
        if len(fail_keys) == 2:
            with pytest.raises(Exception, match="(?i)all 2 configured API keys failed") as caught:
                await call(client, "list_dhcp_options")
            assert "alpha:" in str(caught.value) and "beta:" in str(caught.value)
        else:
            assert await call(client, "list_dhcp_options") == upstream
    hosts = [req for req in up.seen if req.url.path == "/v1/hosts"]
    assert len(hosts) == 2
    targets = [req for req in up.seen if req.url.path != "/v1/hosts"]
    if len(fail_keys) == 2:
        assert targets == []
    else:
        assert targets and all(req.headers["X-API-KEY"] == KEYS[1].key for req in targets)


async def test_n05_unknown_guest_session_refuses_with_valid_choices(monkeypatch):
    up = Upstream()
    up.routes[("GET", f"{CLASSIC}/stat/authorization")] = {
        "meta": {"rc": "ok"},
        "data": [{"_id": RECORD_ID, "mac": MAC}],
    }
    async with session(monkeypatch, up) as client:
        with pytest.raises(Exception) as caught:
            await call(client, "revoke_guest_access", guest=UNKNOWN_ID, target_type="guest_session")
    assert "valid" in str(caught.value).lower()
    assert RECORD_ID in str(caught.value)
    assert up.writes() == []


@pytest.mark.parametrize(
    "name,args,path,collection",
    [
        (
            "delete_dhcp_option",
            {"option_id": RECORD_ID},
            f"{CLASSIC}/rest/dhcpoption/{RECORD_ID}",
            "dhcpoption",
        ),
        (
            "delete_hotspot_package",
            {"package_id": RECORD_ID},
            f"{CLASSIC}/rest/hotspotpackage/{RECORD_ID}",
            "hotspotpackage",
        ),
        (
            "delete_guest_portal_file",
            {"file_id": RECORD_ID},
            f"{CLASSIC}/rest/portalfile/{RECORD_ID}",
            "portalfile",
        ),
        (
            "set_client_icon",
            {"target_id": MAC},
            f"{NET}/v2/api/site/default/clients/{MAC}/ai-icon",
            None,
        ),
        (
            "set_client_fingerprint_override",
            {"client": MAC},
            f"{NET}/v2/api/site/default/station/{MAC}/fingerprint_override",
            None,
        ),
    ],
)
async def test_n05_delete_results_report_description_and_preserve_raw_response(
    monkeypatch, name, args, path, collection
):
    up = Upstream()
    upstream = {
        "meta": {"rc": "ok"},
        "data": [None],
        "deleted": "upstream-value",
        "response": {"probe": 3},
    }
    if collection:
        up.routes[("GET", f"{CLASSIC}/rest/{collection}")] = {
            "meta": {"rc": "ok"},
            "data": [{"_id": RECORD_ID}],
        }
    up.routes[("DELETE", path)] = upstream
    async with session(monkeypatch, up) as client:
        result = await call(client, name, **args)
    assert result["deleted"] is True
    assert result["response"] == upstream
    assert isinstance(result["message"], str) and result["message"]
    assert len(up.writes()) == 1


@pytest.mark.parametrize(
    "name,collection,id_arg",
    [
        ("update_dhcp_option", "dhcpoption", "option_id"),
        ("update_hotspot_package", "hotspotpackage", "package_id"),
    ],
)
async def test_n05_successful_update_reports_readback_failure_without_losing_write_result(
    monkeypatch,
    name,
    collection,
    id_arg,
):
    up = Upstream()
    reads = 0

    def listing(req):
        nonlocal reads
        reads += 1
        if reads > 1:
            return httpx.Response(400, json={"error": "synthetic readback unavailable"})
        return {"meta": {"rc": "ok"}, "data": [{"_id": RECORD_ID, "name": "before"}]}

    upstream = {"meta": {"rc": "ok"}, "data": [{"_id": RECORD_ID}], "probe": "successful-write"}
    up.routes[("GET", f"{CLASSIC}/rest/{collection}")] = listing
    up.routes[("PUT", f"{CLASSIC}/rest/{collection}/{RECORD_ID}")] = upstream
    async with session(monkeypatch, up) as client:
        result = await call(client, name, **{id_arg: RECORD_ID}, fields={"name": "changed"})
    assert {k: v for k, v in result.items() if not k.startswith("_")} == upstream
    assert "synthetic readback unavailable" in str(result["_readAfterError"])
    # The write applied but the re-read failed: unknown (null), never false (rule 11).
    assert result["_verified"] is None
    assert "_unverifiedFields" not in result
    assert len(up.writes()) == 1
