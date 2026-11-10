"""Network security / diagnostics / IP-Thread topology tools (GS3 N11).

Hermetic: synthetic upstream bodies only (documentation MACs 02:00:5e:..., TEST-NET
addresses, zero ids); no controller is contacted.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

import httpx
import pytest

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.families.network import network_security_diagnostics as nsd
from unifi_fabric.read_only import ReadOnlyModeError

HOST = "console-a"
SITE = "Default"
CERT_ID = "0000000000000000000000c1"
PROFILE_ID = "0000000000000000000000d1"
ALERT_ID = "65f1c0ffee0123456789abcd"
V2 = "/v1/connector/consoles/host-1/proxy/network/v2/api/site/default"

READS = {
    "list_ssl_inspection_catalog",
    "list_ssl_inspection_certificates",
    "list_ssl_inspection_profiles",
    "get_ssl_inspection_settings",
    "list_ips_categories",
    "get_ips_signature_status",
    "get_system_log_settings",
    "get_packet_capture_status",
    "get_ping_test_results",
    "get_unified_ip_thread_topology",
}
WRITES = {
    "create_ssl_inspection_certificate",
    "delete_ssl_inspection_certificate",
    "activate_ssl_inspection_certificate",
    "create_ssl_inspection_profile",
    "update_ssl_inspection_profile",
    "delete_ssl_inspection_profile",
    "update_ssl_inspection_settings",
    "update_ips_signatures",
    "update_system_log_settings",
    "mark_critical_logs_read",
    "acknowledge_critical_alert",
    "control_packet_capture",
    "control_ping_test",
}


class Registry:
    def __init__(self) -> None:
        self.calls = 0

    async def resolve_key_for_host(self, host: str) -> None:
        assert host == HOST
        self.calls += 1

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
    """A synthetic client: list GETs answer ``rows``, setting GETs answer ``setting``."""

    def __init__(
        self,
        *,
        rows: Any = None,
        setting: Any = None,
        after: Any = None,
        dry_run: bool = False,
        bodies: dict[str, Any] | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.rows = (
            rows
            if rows is not None
            else [
                {"_id": CERT_ID, "name": "mcp-gs3-n11-ca"},
                {"_id": PROFILE_ID, "name": "mcp-gs3-n11-profile", "rules": {"a": 1, "b": 2}},
            ]
        )
        self.setting = setting if setting is not None else {"enabled": False, "nested": {"x": 1}}
        self.after = after
        self.bodies = bodies or {}
        self.calls: list[tuple[str, str, Any, Any]] = []
        self.audited: list[tuple[str, str]] = []

    def audit_refusal(self, *, tool: str, reason: str) -> None:
        self.audited.append((tool, reason))

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        suffix = path.removeprefix(V2)
        if suffix in self.bodies:
            body = self.bodies[suffix]
            if isinstance(body, BaseException):
                raise body
            return copy.deepcopy(body)
        writes = [c for c in self.calls if c[0] != "GET"]
        if writes and self.after is not None:
            return copy.deepcopy(self.after)
        if suffix.endswith(("/certificates", "/profiles")):
            return copy.deepcopy(self.rows)
        if suffix.endswith("/setting"):
            return copy.deepcopy(self.setting)
        return {"path": suffix}

    def _write(self, method: str, path: str, body: Any) -> Any:
        self.calls.append((method, path, body, None))
        if self.dry_run:
            return _preview(method, path, body)
        return {"echo": body, "path": path.removeprefix(V2)}

    async def post(self, path: str, *, key: None, json: Any = None) -> Any:
        return self._write("POST", path, json)

    async def put(self, path: str, *, key: None, json: Any = None) -> Any:
        return self._write("PUT", path, json)

    async def delete(self, path: str, *, key: None) -> Any:
        return self._write("DELETE", path, None)


# --------------------------------------------------------------------------- registration


def test_every_tool_is_registered_with_derived_annotations() -> None:
    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
    assert READS | WRITES <= set(tools)
    assert len(READS | WRITES) == 23
    for name in READS:
        assert tools[name].annotations.read_only_hint is True, name
    for name in WRITES:
        assert tools[name].annotations.read_only_hint is False, name
        assert tools[name].annotations.destructive_hint is True, name
    for name in READS | WRITES:
        assert len(tools[name].description or "") <= 2048, name
    assert "commission_matter_node" not in READS | WRITES


# --------------------------------------------------------------------------- routes


async def test_every_tool_uses_its_inventoried_v2_route() -> None:
    client, registry = Client(), Registry()
    for catalog in nsd.SSL_CATALOGS:
        await nsd.list_ssl_inspection_catalog(client, registry, HOST, SITE, catalog)
    await nsd.list_ssl_inspection_certificates(client, registry, HOST, SITE)
    await nsd.list_ssl_inspection_certificates(client, registry, HOST, SITE, True)
    await nsd.create_ssl_inspection_certificate(client, registry, HOST, SITE, "upload", {"a": 1})
    await nsd.create_ssl_inspection_certificate(client, registry, HOST, SITE, "generate", {"a": 1})
    await nsd.delete_ssl_inspection_certificate(client, registry, HOST, SITE, CERT_ID)
    await nsd.activate_ssl_inspection_certificate(client, registry, HOST, SITE, CERT_ID)
    await nsd.list_ssl_inspection_profiles(client, registry, HOST, SITE)
    await nsd.create_ssl_inspection_profile(client, registry, HOST, SITE, {"name": "p"})
    await nsd.update_ssl_inspection_profile(client, registry, HOST, SITE, PROFILE_ID, {"x": 1})
    await nsd.delete_ssl_inspection_profile(client, registry, HOST, SITE, PROFILE_ID)
    await nsd.get_ssl_inspection_settings(client, registry, HOST, SITE)
    await nsd.update_ssl_inspection_settings(client, registry, HOST, SITE, {"enabled": True})
    await nsd.list_ips_categories(client, registry, HOST, SITE)
    await nsd.get_ips_signature_status(client, registry, HOST, SITE)
    await nsd.update_ips_signatures(client, registry, HOST, SITE)
    await nsd.get_system_log_settings(client, registry, HOST, SITE)
    await nsd.update_system_log_settings(client, registry, HOST, SITE, {"enabled": True})
    await nsd.mark_critical_logs_read(client, registry, HOST, SITE)
    await nsd.acknowledge_critical_alert(client, registry, HOST, SITE, ALERT_ID)
    await nsd.control_packet_capture(client, registry, HOST, SITE, "start")
    await nsd.control_packet_capture(client, registry, HOST, SITE, "stop", "capture-0001")
    await nsd.get_packet_capture_status(client, registry, HOST, SITE, "capture-0001")
    await nsd.control_ping_test(client, registry, HOST, SITE, "start", "02:00:5e:00:00:a1")
    await nsd.control_ping_test(client, registry, HOST, SITE, "stop", "02:00:5e:00:00:a1")
    await nsd.get_ping_test_results(client, registry, HOST, SITE, "02:00:5e:00:00:a1")
    await nsd.get_unified_ip_thread_topology(client, registry, HOST, SITE)

    sent = {(method, path.removeprefix(V2)) for method, path, _, _ in client.calls}
    ping = "02%3A00%3A5e%3A00%3A00%3Aa1"
    assert sent == {
        ("GET", "/ssl-inspection/categories"),
        ("GET", "/ssl-inspection/file-extensions"),
        ("GET", "/ssl-inspection/search-engines"),
        ("GET", "/ssl-inspection/profiles/defaults"),
        ("GET", "/ssl-inspection/profiles/usage"),
        ("GET", "/ssl-inspection/setting/defaults"),
        ("GET", "/ssl-inspection/certificates"),
        ("GET", "/ssl-inspection/certificates/active"),
        ("POST", "/ssl-inspection/certificates"),
        ("POST", "/ssl-inspection/certificates/generate"),
        ("DELETE", f"/ssl-inspection/certificates/{CERT_ID}"),
        ("POST", f"/ssl-inspection/certificates/{CERT_ID}/activate"),
        ("GET", "/ssl-inspection/profiles"),
        ("POST", "/ssl-inspection/profiles"),
        ("PUT", f"/ssl-inspection/profiles/{PROFILE_ID}"),
        ("DELETE", f"/ssl-inspection/profiles/{PROFILE_ID}"),
        ("GET", "/ssl-inspection/setting"),
        ("PUT", "/ssl-inspection/setting"),
        ("GET", "/settings/ips/available-categories"),
        ("GET", "/settings/ips/suricata"),
        ("POST", "/settings/ips/suricata-upgrade"),
        ("GET", "/system-log/setting"),
        ("PUT", "/system-log/setting"),
        ("PUT", "/system-log/critical/mark-all-as-read"),
        ("PUT", f"/system-log/critical/{ALERT_ID}/mark-as-read"),
        ("POST", "/pcap-start"),
        ("POST", "/pcap-stop/capture-0001"),
        ("GET", "/pcap-status/capture-0001"),
        ("POST", f"/ping-start/{ping}"),
        ("POST", f"/ping-stop/{ping}"),
        ("GET", f"/ping/{ping}"),
        ("GET", "/matter/nodes"),
        ("GET", "/thread-networks"),
        ("GET", "/topology/snapshot/live"),
    }


async def test_free_form_bodies_are_sent_exactly_as_given() -> None:
    client, registry = Client(), Registry()
    certificate = {"name": "mcp-gs3-n11-ca", "nested": {"keep": [1, "two"]}}
    await nsd.create_ssl_inspection_certificate(
        client, registry, HOST, SITE, "upload", copy.deepcopy(certificate)
    )
    await nsd.control_packet_capture(client, registry, HOST, SITE, "start", None, {"opt": 1})
    await nsd.control_packet_capture(client, registry, HOST, SITE, "stop", "capture-0001")
    await nsd.mark_critical_logs_read(client, registry, HOST, SITE, {"opt": True})
    await nsd.control_ping_test(client, registry, HOST, SITE, "start", "t1", {"opt": "v"})
    bodies = [body for method, _, body, _ in client.calls if method != "GET"]
    assert bodies == [
        certificate,
        {"opt": 1, "cmd": "pcap-start"},
        {"cmd": "pcap-stop"},
        {"opt": True},
        {"opt": "v"},
    ]


async def test_memory_optimized_query_is_sent_only_when_given() -> None:
    client, registry = Client(), Registry()
    await nsd.list_ips_categories(client, registry, HOST, SITE)
    await nsd.list_ips_categories(client, registry, HOST, SITE, False)
    await nsd.list_ips_categories(client, registry, HOST, SITE, True)
    assert [c[3] for c in client.calls] == [
        None,
        {"memoryOptimized": "false"},
        {"memoryOptimized": "true"},
    ]


async def test_reads_return_upstream_bodies_verbatim() -> None:
    body = {"data": [{"_id": CERT_ID, "private_key": "synthetic-not-a-key"}], "extra": 1}
    client = Client(bodies={"/ssl-inspection/certificates/active": body})
    result = await nsd.list_ssl_inspection_certificates(client, Registry(), HOST, SITE, True)
    assert result == body
    listed = await nsd.list_ssl_inspection_certificates(Client(), Registry(), HOST, SITE)
    assert listed == Client().rows


# --------------------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "call,match",
    [
        (lambda c, r: nsd.list_ssl_inspection_catalog(c, r, HOST, SITE, "x"), "catalog must"),
        (
            lambda c, r: nsd.list_ssl_inspection_certificates(c, r, HOST, SITE, "yes"),
            "active_only must be a boolean",
        ),
        (
            lambda c, r: nsd.create_ssl_inspection_certificate(c, r, HOST, SITE, "x", {"a": 1}),
            "mode must be one of",
        ),
        (
            lambda c, r: nsd.create_ssl_inspection_certificate(c, r, HOST, SITE, "upload", []),
            "certificate must be a JSON object",
        ),
        (
            lambda c, r: nsd.create_ssl_inspection_certificate(c, r, HOST, SITE, "upload", {}),
            "^No fields provided",
        ),
        (
            lambda c, r: nsd.create_ssl_inspection_profile(c, r, HOST, SITE, {"_note": 1}),
            "^No fields provided",
        ),
        (
            lambda c, r: nsd.update_ssl_inspection_profile(c, r, HOST, SITE, PROFILE_ID, {}),
            "^No fields provided",
        ),
        (
            lambda c, r: nsd.update_ssl_inspection_profile(c, r, HOST, SITE, "a/b", {"x": 1}),
            "profile_id",
        ),
        (
            lambda c, r: nsd.update_ssl_inspection_settings(c, r, HOST, SITE, {}),
            "^No fields provided",
        ),
        (
            lambda c, r: nsd.update_system_log_settings(c, r, HOST, SITE, "x"),
            "changes must be a JSON object",
        ),
        (
            lambda c, r: nsd.delete_ssl_inspection_certificate(c, r, HOST, SITE, ""),
            "certificate_id",
        ),
        (
            lambda c, r: nsd.activate_ssl_inspection_certificate(c, r, HOST, SITE, "../x"),
            "certificate_id",
        ),
        (
            lambda c, r: nsd.delete_ssl_inspection_profile(c, r, HOST, SITE, "a?b"),
            "profile_id",
        ),
        (
            lambda c, r: nsd.list_ips_categories(c, r, HOST, SITE, 1),
            "memory_optimized must be a boolean",
        ),
        (
            lambda c, r: nsd.mark_critical_logs_read(c, r, HOST, SITE, ["x"]),
            "body must be a JSON object",
        ),
        (
            lambda c, r: nsd.acknowledge_critical_alert(c, r, HOST, SITE, ""),
            "alert_id",
        ),
        (
            lambda c, r: nsd.acknowledge_critical_alert(c, r, HOST, SITE, "../mark-all-as-read"),
            "alert_id",
        ),
        (
            lambda c, r: nsd.acknowledge_critical_alert(c, r, HOST, SITE, "a\nb"),
            "alert_id",
        ),
        (
            lambda c, r: nsd.control_packet_capture(c, r, HOST, SITE, "pause"),
            "action must be one of",
        ),
        (
            lambda c, r: nsd.control_packet_capture(c, r, HOST, SITE, "start", "capture-1"),
            "capture_id is for action='stop'",
        ),
        (
            lambda c, r: nsd.control_packet_capture(c, r, HOST, SITE, "stop"),
            "capture_id is required",
        ),
        (
            lambda c, r: nsd.control_packet_capture(c, r, HOST, SITE, "stop", "c1", {"a": 1}),
            "options is for action='start'",
        ),
        (
            lambda c, r: nsd.control_packet_capture(
                c, r, HOST, SITE, "start", None, {"cmd": "pcap-stop"}
            ),
            "must not override cmd",
        ),
        (
            lambda c, r: nsd.control_packet_capture(c, r, HOST, SITE, "start", None, "x"),
            "options must be a JSON object",
        ),
        (
            lambda c, r: nsd.get_packet_capture_status(c, r, HOST, SITE, ".."),
            "capture_id",
        ),
        (
            lambda c, r: nsd.control_ping_test(c, r, HOST, SITE, "go", "t1"),
            "action must be one of",
        ),
        (lambda c, r: nsd.control_ping_test(c, r, HOST, SITE, "start", ""), "target"),
        (lambda c, r: nsd.get_ping_test_results(c, r, HOST, SITE, "a\nb"), "target"),
        (lambda c, r: nsd.get_unified_ip_thread_topology(c, r, " ", SITE), "host"),
        (lambda c, r: nsd.get_ssl_inspection_settings(c, r, HOST, ""), "site"),
    ],
)
async def test_invalid_arguments_are_refused_before_any_request(call, match) -> None:
    client, registry = Client(), Registry()
    with pytest.raises(ValueError, match=match):
        await call(client, registry)
    assert client.calls == []
    assert registry.calls == 0


@pytest.mark.parametrize("capture_id", ["", "   "])
async def test_blank_capture_id_on_start_names_nothing(capture_id) -> None:
    client = Client()
    await nsd.control_packet_capture(client, Registry(), HOST, SITE, "start", capture_id, {})
    assert [c[2] for c in client.calls] == [{"cmd": "pcap-start"}]


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: nsd.delete_ssl_inspection_certificate(c, r, HOST, SITE, "0" * 24),
        lambda c, r: nsd.activate_ssl_inspection_certificate(c, r, HOST, SITE, "0" * 24),
        lambda c, r: nsd.update_ssl_inspection_profile(c, r, HOST, SITE, "0" * 24, {"x": 1}),
        lambda c, r: nsd.delete_ssl_inspection_profile(c, r, HOST, SITE, "0" * 24),
    ],
)
async def test_unknown_id_lists_valid_choices_and_sends_no_write(call) -> None:
    client = Client()
    with pytest.raises(ValueError, match="not found; valid: .*" + CERT_ID):
        await call(client, Registry())
    assert all(method == "GET" for method, *_ in client.calls)


async def test_id_or_underscore_id_selects_and_path_uses_underscore_id() -> None:
    rows = [{"_id": CERT_ID, "id": "00000000-0000-4000-8000-0000000000c1", "name": "n"}]
    client = Client(rows=rows)
    await nsd.activate_ssl_inspection_certificate(
        client, Registry(), HOST, SITE, "00000000-0000-4000-8000-0000000000c1"
    )
    assert client.calls[-1][1].endswith(f"/certificates/{CERT_ID}/activate")


async def test_unreadable_list_is_an_upstream_shape_error_without_write() -> None:
    client = Client(bodies={"/ssl-inspection/profiles": "text"})
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await nsd.delete_ssl_inspection_profile(client, Registry(), HOST, SITE, PROFILE_ID)
    assert [m for m, *_ in client.calls] == ["GET"]


@pytest.mark.parametrize("tool", sorted(WRITES))
async def test_read_only_mode_refuses_every_write_before_any_request(monkeypatch, tool) -> None:
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    client, registry = Client(), Registry()
    args: dict[str, tuple[Any, ...]] = {
        "create_ssl_inspection_certificate": ("generate", {"a": 1}),
        "delete_ssl_inspection_certificate": (CERT_ID,),
        "activate_ssl_inspection_certificate": (CERT_ID,),
        "create_ssl_inspection_profile": ({"a": 1},),
        "update_ssl_inspection_profile": (PROFILE_ID, {"a": 1}),
        "delete_ssl_inspection_profile": (PROFILE_ID,),
        "update_ssl_inspection_settings": ({"a": 1},),
        "update_system_log_settings": ({"a": 1},),
        "acknowledge_critical_alert": (ALERT_ID,),
        "control_packet_capture": ("start",),
        "control_ping_test": ("start", "t1"),
    }
    with pytest.raises(ReadOnlyModeError):
        await getattr(nsd, tool)(client, registry, HOST, SITE, *args.get(tool, ()))
    assert client.calls == [] and registry.calls == 0
    assert client.audited == [(tool, "UNIFI_WRITE_POLICY")]


# --------------------------------------------------------------------------- writes


async def test_profile_update_merges_and_verifies_leaf_by_leaf() -> None:
    applied = {"_id": PROFILE_ID, "name": "mcp-gs3-n11-profile", "rules": {"a": 9, "b": 2}}
    client = Client(after=[applied])
    result = await nsd.update_ssl_inspection_profile(
        client, Registry(), HOST, SITE, PROFILE_ID, {"rules": {"a": 9}}
    )
    put = next(c for c in client.calls if c[0] == "PUT")
    assert put[2] == applied  # the whole stored record, the requested leaf merged in
    assert result["_verified"] is True and result["_readAfter"] == applied
    assert result["echo"] == applied  # the upstream write body stays verbatim


async def test_profile_update_reports_unverified_fields_type_strict() -> None:
    after = [{"_id": PROFILE_ID, "enabled": 1}]
    client = Client(after=after)
    result = await nsd.update_ssl_inspection_profile(
        client, Registry(), HOST, SITE, PROFILE_ID, {"enabled": True, "absent": None}
    )
    assert result["_verified"] is False
    assert result["_unverifiedFields"] == ["absent", "enabled"]


async def test_profile_missing_after_update_is_unknown_with_reason() -> None:
    client = Client(after=[{"_id": "0000000000000000000000ff"}])
    result = await nsd.update_ssl_inspection_profile(
        client, Registry(), HOST, SITE, PROFILE_ID, {"x": 1}
    )
    assert result["_verified"] is None
    assert "is not in GET" in result["_readAfterError"]


@pytest.mark.parametrize("setting", [{"enabled": False}, [{"enabled": False}]])
async def test_setting_update_accepts_object_or_one_record_array(setting) -> None:
    client = Client(setting=setting, after=setting)
    result = await nsd.update_system_log_settings(client, Registry(), HOST, SITE, {"enabled": True})
    put = next(c for c in client.calls if c[0] == "PUT")
    assert put[2] == {"enabled": True}
    assert result["_verified"] is False  # the read-after still shows the old value


@pytest.mark.parametrize("setting", [[], [{"a": 1}, {"b": 2}], "text"])
async def test_unreadable_setting_sends_no_write(setting) -> None:
    client = Client(bodies={"/system-log/setting": setting})
    with pytest.raises(UniFiConnectionError, match="not one setting object.*no write was sent"):
        await nsd.update_system_log_settings(client, Registry(), HOST, SITE, {"enabled": True})
    assert [m for m, *_ in client.calls] == ["GET"]


async def test_dry_run_returns_previews_and_never_verifies_or_deletes() -> None:
    client = Client(dry_run=True)
    registry = Registry()
    update = await nsd.update_ssl_inspection_settings(client, registry, HOST, SITE, {"a": 1})
    assert update["status"] == "dry_run" and "_verified" not in update
    assert update["preview"]["body"] == {"enabled": False, "nested": {"x": 1}, "a": 1}
    deleted = await nsd.delete_ssl_inspection_profile(client, registry, HOST, SITE, PROFILE_ID)
    assert deleted["status"] == "dry_run" and deleted["deleted"] is False
    assert sum(1 for c in client.calls if c[0] == "GET") == 2  # read-befores only


async def test_real_client_dry_run_preview_carries_body(monkeypatch) -> None:
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up, dry_run=True)
    res = await server.mcp.call_tool(
        "create_ssl_inspection_certificate",
        {"host": uh.HOST, "site": uh.SITE, "mode": "upload", "certificate": {"name": "n"}},
    )
    payload = uh.result_payload(res)
    assert payload["status"] == "dry_run" and payload["dryRun"] is True
    assert payload["message"] == DRY_RUN_MESSAGE
    assert payload["preview"]["body"] == {"name": "n"}
    assert payload["preview"]["path"].endswith("/ssl-inspection/certificates")
    assert not up.writes()


async def test_physical_actions_are_sent_once_on_429(monkeypatch) -> None:
    up = uh.FakeUpstream(write_status=429, error_body='{"error":"slow down"}')
    uh.install(monkeypatch, up)
    for name, args in (
        ("update_ips_signatures", {}),
        ("control_packet_capture", {"action": "start"}),
        ("control_ping_test", {"action": "start", "target": "t1"}),
    ):
        before = len(up.writes())
        with pytest.raises(Exception):  # noqa: B017 - any surfaced 429 error
            await server.mcp.call_tool(name, {"host": uh.HOST, "site": uh.SITE, **args})
        assert len(up.writes()) - before == 1, name


# --------------------------------------------------------------------------- topology

NODES = [
    {"node_id": 11, "client_id": "02:00:5e:00:00:b1", "status": "online"},
    {"node_id": 12, "client_id": None},
    {"node_id": 13, "client_id": "0000000000000000000000e3"},
    {"node_id": None, "client_id": ""},
    "not-an-object",
]
NETWORKS = [
    {
        "name": "thread-net-1",
        "extended_pan_id": "0000000000fa0003",
        "border_routers": [
            {
                "mac": "02-00-5E-00-00-B1",
                "name": "br-1",
                "ip": "192.0.2.21",
                "host": "host-0001",
                "network_name": "thread-net-1",
                "last_seen_at": 1791753474653,
            },
            {"mac": "02:00:5e:00:00:b2", "name": "br-2", "ip": "192.0.2.22"},
            {"mac": "02:00:5e:00:00:b3", "name": "br-3"},
            {"mac": None, "name": "br-4"},
        ],
    }
]
SNAPSHOT = {
    "default_lan_network_id": "0000000000000000000000f1",
    "edges": [],
    "gateway_mac": "02:00:5e:00:00:01",
    "isp_data": {},
    "mclag_data": {},
    "site_settings": {},
    "usw_wan_devices": [],
    "vertices": [
        {"id": "02:00:5e:00:00:b1", "mac": "02:00:5e:00:00:b1", "ip": "192.0.2.21"},
        {"id": "v2", "mac": "02:00:5e:00:00:b2", "ip": "192.0.2.22", "type": "CLIENT"},
        {"id": "v3", "_id": "0000000000000000000000e3", "mac": "02:00:5e:00:00:c3"},
    ],
}
SOURCES = {
    "/matter/nodes": NODES,
    "/thread-networks": NETWORKS,
    "/topology/snapshot/live": SNAPSHOT,
}


async def test_topology_keeps_bodies_verbatim_and_reports_join_states() -> None:
    client = Client(bodies=copy.deepcopy(SOURCES))
    result = await nsd.get_unified_ip_thread_topology(client, Registry(), HOST, SITE)
    assert result["_matterNodes"] == NODES
    assert result["_threadNetworks"] == NETWORKS
    assert result["_topologySnapshot"] == SNAPSHOT
    assert all(s["ok"] and s["method"] == "GET" for s in result["_sources"].values())
    join = result["_join"]
    states = [row["joinState"] for row in join["matterNodes"]]
    assert states == [
        "topology_and_thread_matched",
        "no_topology_vertex",
        "topology_matched",
        "no_identity",
        "not_an_object",
    ]
    first, second, third = join["matterNodes"][:3]
    assert first["identityUsed"] == "client_id"
    assert first["threadBorderRouter"] == "[0].border_routers[0]"
    assert second["identityUsed"] == "node_id"
    assert third["topology"]["matchedField"] == "_id"
    assert third["threadBorderRouter"] is None
    routers = {r["name"]: r for r in join["threadBorderRouters"]}
    assert routers["br-1"]["joinState"] == "matter_node_linked"
    assert routers["br-1"]["matterNodes"] == ["[0]"]
    # br-2 is on the IP topology but no Matter node maps to it: never called a Matter node
    assert routers["br-2"]["joinState"] == "topology_matched_no_matter_node"
    assert routers["br-2"]["matterNodes"] == []
    assert routers["br-3"]["joinState"] == "unmatched"
    assert routers["br-4"]["joinState"] == "no_mac"
    summary = join["summary"]
    assert summary["threadBorderRouters"] == 4
    assert summary["threadBorderRoutersLinkedToMatterNode"] == 1
    assert summary["matterNodesOnThreadBorderRouter"] == 1
    assert result["_warnings"][0]["code"] == "EPOCH_MILLISECONDS"


async def test_topology_node_id_fallback_matches_vertex_node_id() -> None:
    bodies = copy.deepcopy(SOURCES)
    bodies["/topology/snapshot/live"]["vertices"].append({"node_id": 12, "mac": "bad"})
    client = Client(bodies=bodies)
    result = await nsd.get_unified_ip_thread_topology(client, Registry(), HOST, SITE)
    row = result["_join"]["matterNodes"][1]
    assert row["identityUsed"] == "node_id"
    assert row["joinState"] == "topology_matched"
    assert row["topology"]["matchedField"] == "node_id"


async def test_topology_partial_failure_reports_provenance_and_joins_the_rest() -> None:
    bodies: dict[str, Any] = copy.deepcopy(SOURCES)
    bodies["/topology/snapshot/live"] = UniFiConnectionError("synthetic 500 full reason body")
    client = Client(bodies=bodies)
    result = await nsd.get_unified_ip_thread_topology(client, Registry(), HOST, SITE)
    source = result["_sources"]["topologySnapshot"]
    assert source["ok"] is False and "synthetic 500 full reason body" in source["error"]
    assert result["_topologySnapshot"] is None
    assert {r["joinState"] for r in result["_join"]["matterNodes"][:3]} == {"topology_unavailable"}
    assert result["_join"]["summary"]["topologyVertices"] is None


async def test_topology_all_sources_failing_raises_the_first_error() -> None:
    bodies = {path: UniFiConnectionError(f"synthetic failure {path}") for path in SOURCES}
    client = Client(bodies=bodies)
    with pytest.raises(UniFiConnectionError, match="/matter/nodes"):
        await nsd.get_unified_ip_thread_topology(client, Registry(), HOST, SITE)


# --------------------------------------------------------------------------- multi-key


async def test_multikey_routes_beta_owned_host_on_beta_key(
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
    await nsd.get_ips_signature_status(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    await nsd.update_ips_signatures(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    await nsd.get_unified_ip_thread_topology(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    nonresolution = [s for s in up.served if not s.resolution]
    assert len(nonresolution) == 5
    assert all(s.api_key == "k-beta" for s in nonresolution)
    await multikey_client.close()


class PagedSslClient(Client):
    """Offset envelopes place the addressed object beyond the first page."""

    paginate_max_pages = None

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        rows = [{"_id": f"{index:024x}", "name": f"mcp-profile-{index}"} for index in range(1, 5)]
        target = {"_id": PROFILE_ID, "name": "mcp-profile-target", "enabled": False}
        if any(call[0] == "PUT" for call in self.calls):
            target["enabled"] = True
        rows.append(target)
        offset = (params or {}).get("offset", 0)
        return {
            "data": copy.deepcopy(rows[offset : offset + 2]),
            "offset": offset,
            "limit": 2,
            "totalCount": len(rows),
        }


@pytest.mark.parametrize(
    "operation",
    [
        "update_ssl_inspection_profile",
        "delete_ssl_inspection_profile",
        "delete_ssl_inspection_certificate",
        "activate_ssl_inspection_certificate",
    ],
)
async def test_ssl_write_resolves_ids_on_later_pages(operation) -> None:
    client = PagedSslClient()
    args = ({"enabled": True},) if operation.startswith("update") else ()
    result = await getattr(nsd, operation)(client, Registry(), HOST, SITE, PROFILE_ID, *args)
    writes = [call for call in client.calls if call[0] != "GET"]
    assert len(writes) == 1
    assert PROFILE_ID in writes[0][1]
    assert any((call[3] or {}).get("offset") == 4 for call in client.calls if call[0] == "GET")
    if operation.startswith("update"):
        assert result["_verified"] is True
        assert result["_readAfter"]["_id"] == PROFILE_ID
        assert result["echo"]["enabled"] is True


async def test_ssl_profile_read_after_drains_later_pages() -> None:
    class MovedAfterWriteClient(PagedSslClient):
        async def get(self, path: str, *, key: None, params: Any = None) -> Any:
            if not any(call[0] == "PUT" for call in self.calls):
                self.calls.append(("GET", path, None, params))
                return [{"_id": PROFILE_ID, "enabled": False}]
            return await super().get(path, key=key, params=params)

    client = MovedAfterWriteClient()
    result = await nsd.update_ssl_inspection_profile(
        client, Registry(), HOST, SITE, PROFILE_ID, {"enabled": True}
    )
    assert result["_verified"] is True
    assert result["_readAfter"] == {
        "_id": PROFILE_ID,
        "name": "mcp-profile-target",
        "enabled": True,
    }
    assert result["echo"] == {"_id": PROFILE_ID, "enabled": True}


class CappedSslClient(PagedSslClient):
    """The paged listing under a UNIFI_PAGINATE_MAX_PAGES cap that stops before the target."""

    paginate_max_pages = 2


@pytest.mark.parametrize(
    "operation",
    [
        "update_ssl_inspection_profile",
        "delete_ssl_inspection_profile",
        "delete_ssl_inspection_certificate",
        "activate_ssl_inspection_certificate",
    ],
)
async def test_ssl_lookup_on_a_capped_listing_says_it_stopped_short(operation) -> None:
    client = CappedSslClient()
    args = ({"enabled": True},) if operation.startswith("update") else ()
    with pytest.raises(ValueError) as exc:
        await getattr(nsd, operation)(client, Registry(), HOST, SITE, PROFILE_ID, *args)
    message = str(exc.value)
    assert f"{PROFILE_ID!r} not found; valid: " in message
    assert "The listing stopped short after 4 records" in message
    assert "UNIFI_PAGINATE_MAX_PAGES page cap of 2 reached" in message
    assert "may exist past them" in message and "No write was sent." in message
    assert [call for call in client.calls if call[0] != "GET"] == []


async def test_ssl_profile_read_after_on_a_capped_listing_says_it_stopped_short() -> None:
    class CappedAfterWriteClient(CappedSslClient):
        async def get(self, path: str, *, key: None, params: Any = None) -> Any:
            if not any(call[0] == "PUT" for call in self.calls):
                self.calls.append(("GET", path, None, params))
                return [{"_id": PROFILE_ID, "enabled": False}]
            return await super().get(path, key=key, params=params)

    client = CappedAfterWriteClient()
    result = await nsd.update_ssl_inspection_profile(
        client, Registry(), HOST, SITE, PROFILE_ID, {"enabled": True}
    )
    assert result["_verified"] is None
    error = result["_readAfterError"]
    assert f"profile {PROFILE_ID} is not in GET" in error
    assert "the listing stopped short (UNIFI_PAGINATE_MAX_PAGES page cap of 2 reached" in error
    assert "the update is not shown to have failed" in error
    assert len([call for call in client.calls if call[0] == "PUT"]) == 1


# --------------------------------------------------------------- one critical alert


async def test_acknowledge_critical_alert_puts_one_alert_with_an_empty_object() -> None:
    client = Client()
    result = await nsd.acknowledge_critical_alert(client, Registry(), HOST, SITE, ALERT_ID)
    assert client.calls == [("PUT", f"{V2}/system-log/critical/{ALERT_ID}/mark-as-read", {}, None)]
    assert result == {"echo": {}, "path": f"/system-log/critical/{ALERT_ID}/mark-as-read"}


async def test_acknowledge_critical_alert_never_reaches_the_mark_all_route() -> None:
    client = Client()
    await nsd.acknowledge_critical_alert(client, Registry(), HOST, SITE, "mark-all-as-read")
    # The id is one path segment of the single-alert route, never the bulk route.
    assert client.calls[0][1] == f"{V2}/system-log/critical/mark-all-as-read/mark-as-read"


async def test_acknowledge_critical_alert_encodes_the_id_as_one_segment() -> None:
    client = Client()
    await nsd.acknowledge_critical_alert(client, Registry(), HOST, SITE, "a b?c#d")
    assert client.calls[0][1] == f"{V2}/system-log/critical/a%20b%3Fc%23d/mark-as-read"


async def test_acknowledge_critical_alert_dry_run_previews_and_sends_nothing_more() -> None:
    client = Client(dry_run=True)
    result = await nsd.acknowledge_critical_alert(client, Registry(), HOST, SITE, ALERT_ID)
    assert result["status"] == "dry_run" and result["preview"]["method"] == "PUT"
    assert result["preview"]["body"] == {}
    assert [c[0] for c in client.calls] == ["PUT"]


async def test_acknowledge_critical_alert_is_a_derived_single_put_write() -> None:
    tools = {t.name: t for t in await server.mcp.list_tools()}
    tool = tools["acknowledge_critical_alert"]
    hints = tool.annotations
    assert hints.read_only_hint is False and hints.destructive_hint is True
    assert hints.idempotent_hint is True  # one PUT
    props = tool.parameters["properties"]
    assert set(props) == {"host", "site", "alert_id"}
    assert all(p.get("description") for p in props.values())


async def test_acknowledge_critical_alert_denied_policy_is_audited_with_zero_calls(
    monkeypatch,
) -> None:
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    client, registry = Client(), Registry()
    with pytest.raises(ReadOnlyModeError):
        await nsd.acknowledge_critical_alert(client, registry, HOST, SITE, ALERT_ID)
    assert client.calls == [] and registry.calls == 0
    assert client.audited == [("acknowledge_critical_alert", "UNIFI_WRITE_POLICY")]


async def test_acknowledge_critical_alert_validates_before_the_write_gate_and_any_request() -> None:
    client, registry = Client(), Registry()
    for bad in ("", "..", "a\nb"):
        with pytest.raises(ValueError, match="alert_id"):
            await nsd.acknowledge_critical_alert(client, registry, HOST, SITE, bad)
    assert client.calls == [] and registry.calls == 0 and client.audited == []
