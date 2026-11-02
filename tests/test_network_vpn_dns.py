"""Network VPN and DNS tools: routes, validation, verification, drains and registration.

Hermetic: synthetic upstream bodies only, no controller is contacted.
"""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Any

import httpx
import pytest

from tests import upstream_harness as uh
from unifi_fabric import refusals, route_secrets, server
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.tools import network_vpn_dns as vd
from unifi_fabric.tools._classic_cmd import ClassicCommandError

HOST = "console-a"
SITE = "Default"
RECORD = "65f1c0ffee0123456789abcd"
OTHER = "65f1c0ffee0123456789abce"
SERVER = "65f1c0ffee0123456789abc0"
SERVER_EXT = "00000000-0000-4000-8000-0000000000c0"
USER = "65f1c0ffee0123456789abc1"
BASE = "/v1/connector/consoles/host-1/proxy/network"
V2 = f"{BASE}/v2/api/site/default"
CMD = f"{BASE}/api/s/default/cmd/sitemgr"
NETWORKCONF = f"{BASE}/api/s/default/rest/networkconf"

TOOL_NAMES = {
    "list_static_dns_records",
    "create_static_dns_record",
    "update_static_dns_record",
    "delete_static_dns_record",
    "list_doh_servers",
    "get_ipsec_settings",
    "update_ipsec_settings",
    "list_vpn_users",
    "list_vpn_connections",
    "get_openvpn_client_config",
    "restart_vpn_server",
    "list_wireguard_users",
    "list_wireguard_used_subnets",
    "create_wireguard_users",
    "update_wireguard_users",
    "delete_wireguard_users",
    "create_teleport_invitation",
    "revoke_teleport_invitation",
    "query_teleport_invitations",
    "remove_teleport_client",
    "list_magic_site_vpn",
    "create_site_vpn",
    "delete_site_vpn",
    "control_site_vpn",
}
READS = {
    "list_static_dns_records",
    "list_doh_servers",
    "get_ipsec_settings",
    "list_vpn_users",
    "list_vpn_connections",
    "get_openvpn_client_config",
    "list_wireguard_users",
    "list_wireguard_used_subnets",
    "list_magic_site_vpn",
}


class Registry:
    def __init__(self) -> None:
        self.calls = 0

    async def resolve_key_for_host(self, host: str) -> None:
        assert host == HOST
        self.calls += 1
        return None

    async def resolve_host_id(self, host: str, *, key: None) -> str:
        self.calls += 1
        return "host-1"

    async def resolve_site_slug(self, site: str, host_id: str, *, key: None) -> str:
        assert (site, host_id) == (SITE, "host-1")
        self.calls += 1
        return "default"


def _preview(method: str, path: str, body: Any) -> dict[str, Any]:
    return {
        "status": "dry_run",
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": method, "path": path, "params": None, "body": body},
    }


class Client:
    """A synthetic upstream: list bodies by path suffix, every write recorded."""

    def __init__(self, *, dry_run: bool = False, max_pages: int | None = None) -> None:
        self.dry_run = dry_run
        self.paginate_max_pages = max_pages
        self.calls: list[tuple[str, str, Any]] = []
        self.dns = [{"_id": RECORD, "key": "nas.example.com", "value": "192.0.2.20"}]
        self.ipsec: dict[str, Any] = {"enabled": False, "nested": {"keep": 1, "mode": "a"}}
        self.users = [{"_id": USER, "name": "laptop-01", "interface_ip": "192.0.2.10"}]
        self.pages: list[Any] = [{"data": [], "page_number": 0}]
        self.classic_rc = "ok"
        self.openvpn: tuple[bytes, str] = (b'{"openvpn_configuration": "cfg"}', "application/json")

    # --- reads -----------------------------------------------------------------
    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None))
        if path == NETWORKCONF:
            return {
                "meta": {"rc": "ok"},
                "data": [
                    {"_id": SERVER, "external_id": SERVER_EXT, "purpose": "remote-user-vpn"},
                    {"_id": OTHER, "purpose": "wan"},
                ],
            }
        if path == f"{V2}/static-dns":
            return copy.deepcopy(self.dns)
        if path == f"{V2}/settings/ipsec":
            return copy.deepcopy(self.ipsec)
        if path == f"{V2}/wireguard/{SERVER}/users":
            return copy.deepcopy(self.users)
        return {"path": path}

    # --- writes ----------------------------------------------------------------
    def _write(self, method: str, path: str, body: Any) -> Any:
        self.calls.append((method, path, body))
        if self.dry_run:
            return _preview(method, path, body)
        if path == f"{V2}/static-dns/{RECORD}" and method == "PUT":
            self.dns = [body]
        if path == f"{V2}/settings/ipsec":
            self.ipsec = body
        if path.endswith("/users/batch") and method == "PUT":
            self.users = body
        if path.endswith("/teleport/invitation-history"):
            number = body["pageNumber"]
            return copy.deepcopy(self.pages[number]) if number < len(self.pages) else {"data": []}
        return {"echo": body, "path": path}

    async def post(self, path: str, *, key: None, json: Any = None, params: Any = None) -> Any:
        return self._write("POST", path, json)

    async def put(self, path: str, *, key: None, json: Any = None, params: Any = None) -> Any:
        return self._write("PUT", path, json)

    async def delete(self, path: str, *, key: None, json: Any = None, params: Any = None) -> Any:
        return self._write("DELETE", path, json)

    async def request(self, method: str, path: str, *, key: None, json: Any = None) -> Any:
        req = httpx.Request(method, "https://api.example.invalid" + path)
        if method == "GET":
            self.calls.append(("GET", path, None))
            content, ctype = self.openvpn
            return httpx.Response(
                200, content=content, headers={"content-type": ctype}, request=req
            )
        self.calls.append((method, path, json))
        if self.dry_run:
            return httpx.Response(200, json=_preview(method, path, json), request=req)
        body = {"meta": {"rc": self.classic_rc, "msg": "api.err.Synthetic"}, "data": []}
        return httpx.Response(200, json=body, request=req)

    def writes(self) -> list[tuple[str, str, Any]]:
        return [call for call in self.calls if call[0] != "GET"]


def _sent(client: Client) -> set[tuple[str, str]]:
    return {(method, path.removeprefix(BASE)) for method, path, _ in client.calls}


# --------------------------------------------------------------------------- routes


async def test_every_tool_uses_its_inventoried_route() -> None:
    client, registry = Client(), Registry()
    client.pages = [{"data": [{"id": "inv-1"}]}, {"data": []}]
    await vd.list_static_dns_records(client, registry, HOST, SITE)
    await vd.create_static_dns_record(client, registry, HOST, SITE, {"key": "a.example.com"})
    await vd.update_static_dns_record(client, registry, HOST, SITE, RECORD, {"value": "x"})
    await vd.delete_static_dns_record(client, registry, HOST, SITE, RECORD)
    await vd.list_doh_servers(client, registry, HOST, SITE)
    await vd.get_ipsec_settings(client, registry, HOST, SITE)
    await vd.update_ipsec_settings(client, registry, HOST, SITE, {"enabled": True})
    await vd.list_vpn_users(client, registry, HOST, SITE)
    await vd.list_vpn_connections(client, registry, HOST, SITE)
    await vd.get_openvpn_client_config(client, registry, HOST, SITE, SERVER)
    await vd.restart_vpn_server(client, registry, HOST, SITE, SERVER)
    await vd.list_wireguard_users(client, registry, HOST, SITE)
    await vd.list_wireguard_users(client, registry, HOST, SITE, SERVER_EXT)
    await vd.list_wireguard_used_subnets(client, registry, HOST, SITE)
    await vd.create_wireguard_users(client, registry, HOST, SITE, SERVER, [{"name": "a"}])
    await vd.update_wireguard_users(
        client, registry, HOST, SITE, SERVER, [{"_id": USER, "name": "b"}]
    )
    await vd.delete_wireguard_users(client, registry, HOST, SITE, SERVER, [USER])
    await vd.create_teleport_invitation(client, registry, HOST, SITE)
    await vd.revoke_teleport_invitation(client, registry, HOST, SITE, RECORD)
    await vd.query_teleport_invitations(client, registry, HOST, SITE)
    await vd.remove_teleport_client(client, registry, HOST, SITE, RECORD)
    await vd.list_magic_site_vpn(client, registry, HOST, SITE)
    await vd.create_site_vpn(client, registry, HOST, SITE, {"site": "branch-1"})
    await vd.delete_site_vpn(client, registry, HOST, SITE, "branch-vpn", "branch-1")
    await vd.control_site_vpn(client, registry, HOST, SITE, "disable", "branch-vpn", "branch-1")

    v2 = "/v2/api/site/default"
    assert _sent(client) == {
        ("GET", f"{v2}/static-dns"),
        ("POST", f"{v2}/static-dns"),
        ("PUT", f"{v2}/static-dns/{RECORD}"),
        ("DELETE", f"{v2}/static-dns/{RECORD}"),
        ("GET", f"{v2}/settings/doh/available-server-names"),
        ("GET", f"{v2}/settings/ipsec"),
        ("POST", f"{v2}/settings/ipsec"),
        ("GET", f"{v2}/vpn/users"),
        ("GET", f"{v2}/vpn/connections"),
        ("GET", "/api/s/default/rest/networkconf"),
        ("GET", f"{v2}/vpn/openvpn/{SERVER}/configuration"),
        ("POST", f"{v2}/vpn/{SERVER}/restart"),
        ("GET", f"{v2}/wireguard/users"),
        ("GET", f"{v2}/wireguard/{SERVER}/users"),
        ("GET", f"{v2}/wireguard/users/existing-subnets"),
        ("POST", f"{v2}/wireguard/{SERVER}/users/batch"),
        ("PUT", f"{v2}/wireguard/{SERVER}/users/batch"),
        ("POST", f"{v2}/wireguard/{SERVER}/users/batch_delete"),
        ("POST", f"{v2}/teleport/token"),
        ("DELETE", f"{v2}/teleport/token/{RECORD}"),
        ("POST", f"{v2}/teleport/invitation-history"),
        ("DELETE", f"{v2}/teleport/client/{RECORD}"),
        ("GET", f"{v2}/magicsitetositevpn/configs"),
        ("POST", "/api/s/default/cmd/sitemgr"),
    }
    cmds = [body for method, path, body in client.calls if path == CMD]
    assert cmds == [
        {"cmd": "add-site-vpn", "site": "branch-1"},
        {"cmd": "delete-site-vpn", "name": "branch-vpn", "site": "branch-1"},
        {"cmd": "disable-site-vpn", "name": "branch-vpn", "site": "branch-1"},
    ]
    restart = [b for m, p, b in client.calls if p.endswith("/restart")]
    assert restart == [{"cmd": "restart-vpn"}]


async def test_reads_pass_the_upstream_body_through_verbatim() -> None:
    client, registry = Client(), Registry()
    assert await vd.list_static_dns_records(client, registry, HOST, SITE) == client.dns
    assert await vd.get_ipsec_settings(client, registry, HOST, SITE) == client.ipsec
    assert await vd.list_vpn_users(client, registry, HOST, SITE) == {"path": f"{V2}/vpn/users"}


async def test_creates_send_the_free_form_body_verbatim() -> None:
    client, registry = Client(), Registry()
    record = {"key": "nas.example.com", "value": "192.0.2.20", "record_type": "A", "x": [1]}
    users = [{"name": "laptop-01", "public_key": "synthetic-public", "preshared_key": "s"}]
    await vd.create_static_dns_record(client, registry, HOST, SITE, copy.deepcopy(record))
    await vd.create_wireguard_users(client, registry, HOST, SITE, SERVER, copy.deepcopy(users))
    await vd.create_teleport_invitation(client, registry, HOST, SITE, {"note": "n"})
    bodies = [body for _m, _p, body in client.writes()]
    assert bodies == [record, users, {"note": "n"}]


# --------------------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: vd.list_static_dns_records(c, r, HOST, " "),
        lambda c, r: vd.list_doh_servers(c, r, "", SITE),
        lambda c, r: vd.update_static_dns_record(c, r, HOST, SITE, "../x", {"value": "x"}),
        lambda c, r: vd.update_static_dns_record(c, r, HOST, SITE, RECORD, {}),
        lambda c, r: vd.update_static_dns_record(c, r, HOST, SITE, RECORD, {"_id": RECORD}),
        lambda c, r: vd.delete_static_dns_record(c, r, HOST, SITE, "a/b"),
        lambda c, r: vd.create_static_dns_record(c, r, HOST, SITE, {"ttl": float("nan")}),
        lambda c, r: vd.update_ipsec_settings(c, r, HOST, SITE, {}),
        lambda c, r: vd.update_ipsec_settings(c, r, HOST, SITE, {"x": float("inf")}),
        lambda c, r: vd.get_openvpn_client_config(c, r, HOST, SITE, "a b"),
        lambda c, r: vd.restart_vpn_server(c, r, HOST, SITE, ""),
        lambda c, r: vd.list_wireguard_users(c, r, HOST, SITE, "x?y"),
        lambda c, r: vd.update_wireguard_users(c, r, HOST, SITE, SERVER, [{"name": "x"}]),
        lambda c, r: vd.update_wireguard_users(c, r, HOST, SITE, SERVER, [{"_id": USER}]),
        lambda c, r: vd.update_wireguard_users(c, r, HOST, SITE, SERVER, [{"_id": "a/b", "n": 1}]),
        lambda c, r: vd.delete_wireguard_users(c, r, HOST, SITE, SERVER, [{"name": "x"}]),
        lambda c, r: vd.create_teleport_invitation(c, r, HOST, SITE, {"x": float("nan")}),
        lambda c, r: vd.revoke_teleport_invitation(c, r, HOST, SITE, "../x"),
        lambda c, r: vd.remove_teleport_client(c, r, HOST, SITE, "x#y"),
        lambda c, r: vd.create_site_vpn(c, r, HOST, SITE, {"cmd": "delete-site"}),
        lambda c, r: vd.create_site_vpn(c, r, HOST, SITE, {"x": float("nan")}),
        lambda c, r: vd.control_site_vpn(c, r, HOST, SITE, "restart"),  # type: ignore[arg-type]
        lambda c, r: vd.control_site_vpn(c, r, HOST, SITE, "enable", params={"cmd": "x"}),
    ],
)
async def test_invalid_input_makes_zero_requests_and_is_a_registered_refusal(call) -> None:
    client, registry = Client(), Registry()
    with pytest.raises(ValueError) as exc:
        await call(client, registry)
    assert client.calls == [] and registry.calls == 0
    assert refusals.classify(str(exc.value)) is not None, str(exc.value)


async def test_empty_batches_are_refused_before_any_request() -> None:
    client, registry = Client(), Registry()
    for call in (
        vd.create_wireguard_users,
        vd.update_wireguard_users,
        vd.delete_wireguard_users,
    ):
        with pytest.raises(ValueError, match="names no WireGuard user"):
            await call(client, registry, HOST, SITE, SERVER, [])
    assert client.writes() == []


async def test_unknown_ids_fail_listing_the_choices_and_write_nothing() -> None:
    client, registry = Client(), Registry()
    with pytest.raises(ValueError, match=rf"not found; valid: .*{RECORD}"):
        await vd.update_static_dns_record(client, registry, HOST, SITE, OTHER, {"value": "x"})
    with pytest.raises(ValueError, match=rf"not found; valid: .*{RECORD}"):
        await vd.delete_static_dns_record(client, registry, HOST, SITE, OTHER)
    with pytest.raises(ValueError, match=rf"VPN server .*not found; valid: .*{SERVER}"):
        await vd.restart_vpn_server(client, registry, HOST, SITE, OTHER)
    with pytest.raises(ValueError, match=rf"WireGuard user\(s\) '{OTHER}' not found.*{USER}"):
        await vd.delete_wireguard_users(client, registry, HOST, SITE, SERVER, [OTHER])
    with pytest.raises(ValueError, match="not found"):
        await vd.update_wireguard_users(
            client, registry, HOST, SITE, SERVER, [{"_id": OTHER, "name": "x"}]
        )
    assert client.writes() == []


async def test_vpn_server_resolves_the_integration_id_to_the_classic_id() -> None:
    client, registry = Client(), Registry()
    await vd.restart_vpn_server(client, registry, HOST, SITE, SERVER_EXT)
    assert client.writes()[0][1] == f"{V2}/vpn/{SERVER}/restart"


async def test_unexpected_list_shape_raises_without_a_write() -> None:
    client, registry = Client(), Registry()
    client.users = {"unexpected": True}  # type: ignore[assignment]
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await vd.delete_wireguard_users(client, registry, HOST, SITE, SERVER, [USER])
    client.ipsec = ["not", "an", "object"]  # type: ignore[assignment]
    with pytest.raises(UniFiConnectionError, match="No write was sent"):
        await vd.update_ipsec_settings(client, registry, HOST, SITE, {"enabled": True})
    assert client.writes() == []


# --------------------------------------------------------------------------- updates


async def test_static_dns_update_merges_leaves_and_verifies() -> None:
    client, registry = Client(), Registry()
    result = await vd.update_static_dns_record(
        client, registry, HOST, SITE, RECORD.upper(), {"value": "192.0.2.21", "_note": "x"}
    )
    method, path, body = client.writes()[0]
    assert (method, path) == ("PUT", f"{V2}/static-dns/{RECORD}")
    assert body == {"_id": RECORD, "key": "nas.example.com", "value": "192.0.2.21"}
    assert result["_verified"] is True
    assert result["echo"] == body


async def test_ipsec_update_deep_merges_and_reports_an_unapplied_leaf() -> None:
    client, registry = Client(), Registry()
    result = await vd.update_ipsec_settings(
        client, registry, HOST, SITE, {"nested": {"mode": "b"}, "enabled": True}
    )
    sent = client.writes()[0][2]
    assert sent == {"enabled": True, "nested": {"keep": 1, "mode": "b"}}
    assert result["_verified"] is True

    class Sticky(Client):
        def _write(self, method: str, path: str, body: Any) -> Any:
            self.calls.append((method, path, body))
            return {"ok": True}  # accepted but never applied

    sticky = Sticky()
    result = await vd.update_ipsec_settings(sticky, Registry(), HOST, SITE, {"enabled": 1})
    assert result["_verified"] is False  # 1 is not True, and the stored value is False


async def test_read_after_failure_keeps_the_write_and_reports_unknown() -> None:
    class Failing(Client):
        reads = 0

        async def get(self, path: str, *, key: None, params: Any = None) -> Any:
            if path == f"{V2}/settings/ipsec":
                self.reads += 1
                if self.reads > 1:
                    raise UniFiConnectionError("synthetic read-after failure")
            return await super().get(path, key=key, params=params)

    client = Failing()
    result = await vd.update_ipsec_settings(client, Registry(), HOST, SITE, {"enabled": True})
    assert result["_verified"] is None
    assert "synthetic read-after failure" in result["_readAfterError"]
    assert result["echo"] == {"enabled": True, "nested": {"keep": 1, "mode": "a"}}


async def test_wireguard_update_puts_merged_records_and_verifies_each_user() -> None:
    client, registry = Client(), Registry()
    result = await vd.update_wireguard_users(
        client, registry, HOST, SITE, SERVER, [{"_id": USER.upper(), "name": "laptop-02"}]
    )
    method, path, body = client.writes()[0]
    assert (method, path) == ("PUT", f"{V2}/wireguard/{SERVER}/users/batch")
    assert body == [{"_id": USER, "name": "laptop-02", "interface_ip": "192.0.2.10"}]
    assert result["_verified"] is True
    assert result["_readAfter"] == {USER: body[0]}


async def test_wireguard_update_with_a_changed_leaf_is_not_verified() -> None:
    class Ignoring(Client):
        def _write(self, method: str, path: str, body: Any) -> Any:
            self.calls.append((method, path, body))
            return {"ok": True}

    client = Ignoring()
    result = await vd.update_wireguard_users(
        client, Registry(), HOST, SITE, SERVER, [{"_id": USER, "name": "laptop-02"}]
    )
    assert result["_verified"] is False


# --------------------------------------------------------------------------- dry-run


async def test_every_write_returns_the_bare_dry_run_preview() -> None:
    client, registry = Client(dry_run=True), Registry()
    results = [
        await vd.create_static_dns_record(client, registry, HOST, SITE, {"key": "a"}),
        await vd.update_static_dns_record(client, registry, HOST, SITE, RECORD, {"value": "x"}),
        await vd.delete_static_dns_record(client, registry, HOST, SITE, RECORD),
        await vd.update_ipsec_settings(client, registry, HOST, SITE, {"enabled": True}),
        await vd.restart_vpn_server(client, registry, HOST, SITE, SERVER),
        await vd.create_wireguard_users(client, registry, HOST, SITE, SERVER, [{"name": "a"}]),
        await vd.update_wireguard_users(
            client, registry, HOST, SITE, SERVER, [{"_id": USER, "name": "b"}]
        ),
        await vd.delete_wireguard_users(client, registry, HOST, SITE, SERVER, [USER]),
        await vd.create_teleport_invitation(client, registry, HOST, SITE),
        await vd.revoke_teleport_invitation(client, registry, HOST, SITE, RECORD),
        await vd.query_teleport_invitations(client, registry, HOST, SITE),
        await vd.remove_teleport_client(client, registry, HOST, SITE, RECORD),
        await vd.create_site_vpn(client, registry, HOST, SITE, {"site": "b"}),
        await vd.delete_site_vpn(client, registry, HOST, SITE, "n", "b"),
        await vd.control_site_vpn(client, registry, HOST, SITE, "rebuild"),
    ]
    deletions = 0
    for result in results:
        if "deleted" in result:
            # A delete/remove/revoke returns the deletion_result dry-run shape.
            assert set(result) == {"status", "deleted", "message", "response"}, result
            assert result["status"] == "dry_run" and result["deleted"] is False
            assert result["message"]
            result = result["response"]
            deletions += 1
        assert set(result) == {"status", "dryRun", "message", "preview"}, result
        assert result["status"] == "dry_run" and result["dryRun"] is True
        assert "verified" not in result and "_verified" not in result
        assert set(result["preview"]) == {"method", "path", "params", "body"}
    assert deletions == 5


# --------------------------------------------------------------------------- deletes


async def test_deletes_report_the_upstream_body() -> None:
    client, registry = Client(), Registry()
    result = await vd.delete_static_dns_record(client, registry, HOST, SITE, RECORD)
    assert result["deleted"] is True and result["response"]["path"].endswith(RECORD)
    result = await vd.delete_wireguard_users(
        client, registry, HOST, SITE, SERVER, [{"_id": USER, "name": "laptop-01"}]
    )
    assert result["response"]["echo"] == [{"_id": USER, "name": "laptop-01"}]
    result = await vd.remove_teleport_client(client, registry, HOST, SITE, RECORD, {"a": 1})
    assert result["response"]["echo"] == {"a": 1}
    result = await vd.delete_site_vpn(client, registry, HOST, SITE, "branch-vpn", "branch-1")
    assert result["deleted"] is True and result["response"]["meta"]["rc"] == "ok"


# --------------------------------------------------------------------------- Classic rc


async def test_site_vpn_commands_require_an_affirmative_meta_rc() -> None:
    client, registry = Client(), Registry()
    client.classic_rc = "error"
    for call in (
        vd.create_site_vpn(client, registry, HOST, SITE, {"site": "branch-1"}),
        vd.delete_site_vpn(client, registry, HOST, SITE, "branch-vpn", "branch-1"),
        vd.control_site_vpn(client, registry, HOST, SITE, "enable", "branch-vpn", "branch-1"),
    ):
        with pytest.raises(ClassicCommandError, match="api.err.Synthetic"):
            await call


# --------------------------------------------------------------------------- OpenVPN


async def test_openvpn_config_text_json_and_binary() -> None:
    client, registry = Client(), Registry()
    assert await vd.get_openvpn_client_config(client, registry, HOST, SITE, SERVER) == {
        "openvpn_configuration": "cfg"
    }
    client.openvpn = (b"client\ndev tun\n", "application/x-openvpn-profile")
    assert (
        await vd.get_openvpn_client_config(client, registry, HOST, SITE, SERVER)
        == "client\ndev tun\n"
    )
    client.openvpn = (b"plain utf-8", "application/octet-stream")
    assert await vd.get_openvpn_client_config(client, registry, HOST, SITE, SERVER) == (
        "plain utf-8"
    )
    client.openvpn = (b"\xff\xfe\x00binary", "application/octet-stream")
    assert await vd.get_openvpn_client_config(client, registry, HOST, SITE, SERVER) == {
        "bodyBase64": "//4AYmluYXJ5",
        "contentType": "application/octet-stream",
        "sizeBytes": 9,
    }


# --------------------------------------------------------------------------- Teleport drain


async def test_invitation_history_drains_every_page() -> None:
    client, registry = Client(), Registry()
    client.pages = [
        {"data": [{"id": "a"}], "total": 3},
        {"data": [{"id": "b"}], "total": 3},
        {"data": [{"id": "c"}], "total": 3},
    ]
    result = await vd.query_teleport_invitations(client, registry, HOST, SITE, page_size=1000)
    assert result["data"] == [{"id": "a"}, {"id": "b"}, {"id": "c"}]
    assert result["total"] == 3 and result["_count"] == 3 and result["_pages"] == 3
    assert "incomplete" not in result
    sent = [b for m, p, b in client.calls if p.endswith("invitation-history")]
    assert sent == [
        {"pageNumber": 0, "pageSize": 1000},
        {"pageNumber": 1, "pageSize": 1},
        {"pageNumber": 2, "pageSize": 1},
    ]
    assert result["_pageSize"] == {
        "requested": 1000,
        "sent": [1000, 1, 1],
        "effective": 1,
        "returned": 3,
    }


async def test_invitation_history_bare_pages_and_single_page() -> None:
    client, registry = Client(), Registry()
    client.pages = [[{"id": "a"}], []]
    result = await vd.query_teleport_invitations(client, registry, HOST, SITE)
    assert result == {"data": [{"id": "a"}], "_count": 1, "_pages": 2}
    client.pages = [{"data": [{"id": "a"}]}, {"data": [{"id": "b"}], "page_number": 1}]
    page = await vd.query_teleport_invitations(client, registry, HOST, SITE, page_number=1)
    assert page == {"data": [{"id": "b"}], "page_number": 1}


@pytest.mark.parametrize(
    "pages,max_pages,reason",
    [
        ([{"data": [{"id": "a"}]}, {"data": [{"id": "a"}]}], None, "repeated page 0"),
        ([{"data": [{"id": "a"}]}, {"data": [{"id": "b"}]}], 2, "page cap of 2"),
        ([{"data": [{"id": "a"}]}, {"unexpected": 1}], None, "without a records array"),
    ],
)
async def test_invitation_history_stopped_drain_is_marked_incomplete(
    pages, max_pages, reason
) -> None:
    client, registry = Client(max_pages=max_pages), Registry()
    client.pages = pages + [{"data": [{"id": f"x{n}"}]} for n in range(5)]
    result = await vd.query_teleport_invitations(client, registry, HOST, SITE)
    assert result["incomplete"] is True and reason in result["incompleteReason"]
    assert result["data"][0] == {"id": "a"}


async def test_invitation_history_unrecognised_envelope_is_incomplete_verbatim() -> None:
    client, registry = Client(), Registry()
    client.pages = [{"items": [{"id": "a"}]}]
    result = await vd.query_teleport_invitations(client, registry, HOST, SITE)
    assert result["items"] == [{"id": "a"}] and "drainNote" not in result
    assert result["_pages"] == 1 and "no 'data' array" in result["_drainNote"]
    client.pages = [[]]
    assert await vd.query_teleport_invitations(client, registry, HOST, SITE) == []
    client.pages = ["text body"]
    assert await vd.query_teleport_invitations(client, registry, HOST, SITE) == "text body"


# --------------------------------------------------------------------------- secrets


@pytest.mark.parametrize(
    "method,path,field",
    [
        ("POST", f"{V2}/settings/ipsec", "x_ipsec_pre_shared_key"),
        ("GET", f"{V2}/settings/ipsec", "x_ipsec_pre_shared_key"),
        ("POST", f"{V2}/wireguard/{SERVER}/users/batch", "preshared_key"),
        ("PUT", f"{V2}/wireguard/{SERVER}/users/batch", "private_key"),
        ("POST", f"{V2}/teleport/token", "token"),
        ("POST", f"{V2}/teleport/invitation-history", "token"),
        ("GET", f"{V2}/vpn/openvpn/{SERVER}/configuration", "openvpn_configuration"),
        ("POST", CMD, "x_ipsec_pre_shared_key"),
    ],
)
def test_credential_routes_are_registered(method, path, field) -> None:
    entries = route_secrets.matching(method, path)
    request = {n for e in entries for n in e.request_fields}
    response = {n for e in entries for n in e.response_fields}
    assert field in request | response
    body = {"outer": [{field: "synthetic-secret-value"}]}
    # Pass-through by default: the body object comes back unchanged.
    assert route_secrets.mask_response_body(method, path, body, redact_secrets=False) is body
    assert route_secrets.mask_request_body(method, path, body, redact_secrets=False) is body
    # Masked only under the UNIFI_REDACT_SECRETS opt-in.
    if field in response:
        masked = route_secrets.mask_response_body(method, path, body, redact_secrets=True)
        assert "synthetic-secret-value" not in json.dumps(masked)
    if field in request:
        masked = route_secrets.mask_request_body(method, path, body, redact_secrets=True)
        assert "synthetic-secret-value" not in json.dumps(masked)


# --------------------------------------------------------------------------- registration


def test_registration_names_annotations_and_descriptions() -> None:
    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools()) if t.name in TOOL_NAMES}
    assert set(tools) == TOOL_NAMES
    for name, tool in tools.items():
        assert tool.annotations.read_only_hint is (name in READS), name
        assert tool.annotations.destructive_hint is (name not in READS), name
        assert len(tool.description) <= 2048
        assert {"host", "site"} <= set(tool.parameters["required"]), name
        if name not in READS:
            assert "confirm" in tool.parameters["properties"], name
            assert "dry-run preview" in " ".join(tool.description.split()), name
            assert "simulat" not in tool.description, name


# --------------------------------------------------------------------------- multi-key


async def test_beta_owned_host_rides_the_beta_key(
    monkeypatch, multikey_client, multikey_registry
) -> None:
    up = uh.FakeUpstream(hosts_by_key={"k-alpha": [], "k-beta": [copy.deepcopy(uh.HOST_RECORD)]})

    async def http_session(key):
        if key.label not in multikey_client._clients:
            multikey_client._clients[key.label] = httpx.AsyncClient(
                base_url=multikey_client._settings.api_base_url,
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(up),
            )
        return multikey_client._clients[key.label]

    monkeypatch.setattr(multikey_client, "_get_client", http_session)
    await vd.list_static_dns_records(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    await vd.create_teleport_invitation(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    served = [s for s in up.served if not s.resolution]
    assert len(served) == 2
    assert all(s.api_key == "k-beta" for s in served)
    assert served[0].path.endswith("/v2/api/site/default/static-dns")
    assert served[1].method == "POST" and served[1].path.endswith("/teleport/token")
    await multikey_client.close()
