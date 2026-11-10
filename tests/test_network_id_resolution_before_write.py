"""Network writes resolve their target id before writing.

An update or delete on a Classic REST or v2 collection resolves its id in the
collection's list first. The controller answers a DELETE on an unknown id with HTTP 200, so
without the check a deletion that never happened is reported. The set of such tools is
derived from the registry (every write tool whose PUT/DELETE lands on a Classic or v2 item
route named by one of its arguments), and each one, given an id absent from its list, sends
no write and fails listing the valid ids, with and without dry-run policy.

The purpose-scoped networkconf updates pin ``purpose`` in the body through one helper,
so ``purpose: null`` is never forwarded.

Id case: a hex id the caller typed in another case is matched
case-insensitively, and the write then addresses the record by the upstream ``_id`` -- the
URL and a body ``_id`` naming it -- never by the caller's spelling (the registry-wide
property is ``test_cross_tool_invariants`` (br)).

get_historical_stats accepts every interval and scope the controller accepts (live
probes on Network 11.0.81) and rejects anything else listing them.
"""

from __future__ import annotations

import functools
import json
import logging
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import class_axis, tool_batches
from unifi_fabric.client import UniFiConnectionError, is_dry_run_preview
from unifi_fabric.families.network import network_services_proxy
from unifi_fabric.families.statistics import statistics
from unifi_fabric.matching import with_upstream_id
from unifi_fabric.shared_shapes._classic_objects import require_listed_record, with_purpose

TOOLS = cti.TOOLS
ABSENT_ID = "0000000000000000000000ff"

# Keyed, not id-addressed: update_setting writes the setting group named by setting_key and
# reads rest/setting/{key} before its PUT; the controller answers that read for an unknown
# key with HTTP 400 api.err.Invalid (live-verified on Network 11.0.81), so no PUT is sent.
# The harness serves every key, so test_unknown_setting_key_fails_on_the_read checks it.
KEYED = {"update_setting": "setting_key"}

# Id-addressed writes whose collection has no read route in the Network 11.0.81 route
# inventory, so the id cannot be resolved before the write and is passed through for the
# upstream to judge (live confirmation pending): ProAV groups (only the audio/video matrix
# reads, whose shape is unrecorded), visual-programming/virtual-network (no GET route), and
# Teleport client/invitation deletes. The latter exposes no client GET collection; invitation
# history is a write-classed POST, so using it as a pre-delete resolver would add a write-like
# request and defeat the validation-before-write invariant.
# bulk_update_objects is not id-addressed: object_type selects the generic Classic group
# endpoint rather than a member of a collection.
UNLISTED = {
    "bulk_update_objects": "object_type",
    "update_proav_group": "group_id",
    "delete_proav_group": "group_id",
    "manage_virtual_network": "virtual_network_id",
    "remove_teleport_client": "client_id",
    "revoke_teleport_invitation": "invitation_id",
}

# The Classic REST / v2 item writes, plus the ones that already resolved their id: the derived
# set must hold every one of them (a derivation that silently loses a tool fails here).
NAMED = {
    "update_port_forward",
    "delete_port_forward",
    "update_traffic_route",
    "delete_traffic_route",
    "update_hotspot_operator",
    "delete_hotspot_operator",
    "update_user",
    "update_dynamic_dns",
    "update_wlan_config",
    "update_port_profile",
    "allow_network_on_port_profile",
    "exclude_network_on_port_profile",
    "update_device_tag",
    "delete_device_tag",
    "update_vpn_server",
    "delete_vpn_server",
    "update_site_to_site_tunnel",
    "delete_site_to_site_tunnel",
    "update_wan_interface",
}


def _item_writes(up: uh.FakeUpstream) -> list[uh.Served]:
    return [
        s
        for s in up.writes()
        if s.method in ("PUT", "DELETE") and uh.family(s.path) in ("classic", "v2")
    ]


_ID_WRITE_SEEN: dict[str, str | None] = {}
_ID_WRITE_FAILURES: dict[str, str] = {}
# Explicit exceptions require a reason; no generated write calls are exempt.
_ALLOWED_FAILURES: dict[str, str] = {}


async def _id_write_arg_for(name: str) -> str | None:
    """The id argument of one write tool whose Classic / v2 PUT or DELETE lands on an item
    route whose last segment is one of its string arguments (else None). Observed per
    tool at test EXECUTION, never by dispatching the catalog at collection."""
    if name in _ID_WRITE_SEEN:
        return _ID_WRITE_SEEN[name]
    found: str | None = None
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        args = tool_args.generated_args(TOOLS[name])
        up = uh.FakeUpstream()
        failed = False
        with pytest.MonkeyPatch.context() as mp:
            for k, v in tool_args.TOOL_ENV.get(name, {}).items():
                mp.setenv(k, v)
            uh.install(mp, up)
            try:
                await uh.server.mcp.call_tool(name, args)
            except Exception as exc:  # noqa: BLE001 - report every failed generated call
                _ID_WRITE_FAILURES[name] = str(exc)
                failed = True
        if not failed:
            for served in _item_writes(up):
                last = served.path.rstrip("/").rsplit("/", 1)[-1]
                hits = [a for a, v in args.items() if isinstance(v, str) and v == last]
                if not hits and uh.is_detail(served.path):
                    # the id argument is mapped to another id before the write (a
                    # networkconf Integration id written under its Classic _id): the tool's
                    # one id argument
                    hits = [
                        a
                        for a, v in args.items()
                        if a.endswith("_id") and a != "host_id" and isinstance(v, str)
                    ]
                    hits = hits if len(hits) == 1 else []
                if hits:
                    found = hits[0]
    finally:
        logging.disable(previous)
    _ID_WRITE_SEEN[name] = found
    return found


async def _derive() -> dict[str, str]:
    out: dict[str, str] = {}
    for name in cti.WRITE_TOOLS:
        arg = await _id_write_arg_for(name)
        if arg is not None:
            out[name] = arg
    assert set(_ID_WRITE_FAILURES) == set(_ALLOWED_FAILURES), _ID_WRITE_FAILURES
    return out


@functools.cache
def _lz_ID_WRITES():
    return cti._run_coroutine(_derive())


@functools.cache
def _lz_RESOLVED():
    return sorted(n for n in _lz_ID_WRITES() if n not in KEYED and n not in UNLISTED)


async def _is_resolved(name: str) -> bool:
    return name not in KEYED and name not in UNLISTED and await _id_write_arg_for(name) is not None


def test_derived_set_holds_every_named_tool():
    assert NAMED <= set(_lz_ID_WRITES()), sorted(NAMED - set(_lz_ID_WRITES()))
    assert set(KEYED) <= set(_lz_ID_WRITES()), "a KEYED exemption no longer applies: drop it"
    assert {n: _lz_ID_WRITES()[n] for n in KEYED} == KEYED
    assert {n: _lz_ID_WRITES().get(n) for n in UNLISTED} == UNLISTED, "an UNLISTED exemption moved"


@class_axis("name", lambda: cti.WRITE_TOOLS, member=_is_resolved, dry_run=lambda: [False, True])
async def test_absent_id_sends_no_write_and_lists_valid_ids(monkeypatch, name, dry_run):
    arg = await _id_write_arg_for(name)
    args = {**tool_args.generated_args(TOOLS[name]), arg: ABSENT_ID}
    up = uh.FakeUpstream()
    env = {"UNIFI_WRITE_POLICY": "dry-run"} if dry_run else None
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, name, up, args, env=env)
    text = str(exc.value)
    assert "not found" in text and ABSENT_ID in text, f"{name}: {text}"
    assert "id=" in text, f"{name}: valid ids not listed: {text}"
    assert up.writes() == [], f"{name}: write sent for an absent id: {up.writes()}"
    assert any(s.method == "GET" and not s.resolution for s in up.served), name


@tool_batches("name", lambda: cti.WRITE_TOOLS, member=_is_resolved)
async def test_known_id_under_dry_run_previews_after_the_resolution_read(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await cti._call(monkeypatch, name, up, env={"UNIFI_WRITE_POLICY": "dry-run"})
    )
    assert up.writes() == [], name
    assert any(s.method == "GET" and not s.resolution for s in up.served), name
    preview = payload if is_dry_run_preview(payload) else (payload or {}).get("response")
    assert is_dry_run_preview(preview), f"{name}: {payload}"
    assert preview["preview"]["method"] in ("PUT", "DELETE"), preview


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("name", sorted(UNLISTED))
async def test_unlisted_write_passes_the_id_through_without_a_resolution_read(
    monkeypatch, name, dry_run
):
    """An UNLISTED write has no list to resolve against: it reads nothing of its own and
    addresses the item URL named by its argument (one write; under dry-run, the preview
    of that write and no write)."""
    args = {**tool_args.generated_args(TOOLS[name]), UNLISTED[name]: ABSENT_ID}
    up = uh.FakeUpstream()
    env = {"UNIFI_WRITE_POLICY": "dry-run"} if dry_run else None
    payload = uh.result_payload(await cti._call(monkeypatch, name, up, args, env=env))
    own_reads = [s.path for s in up.served if s.method == "GET" and not s.resolution]
    assert own_reads == [], f"{name}: resolution read before the write: {own_reads}"
    if dry_run:
        assert up.writes() == [], f"{name}: write sent under dry-run: {up.writes()}"
        preview = payload if is_dry_run_preview(payload) else (payload or {}).get("response")
        assert is_dry_run_preview(preview), f"{name}: {payload}"
        assert preview["preview"]["method"] in ("PUT", "DELETE"), preview
        assert preview["preview"]["path"].endswith(f"/{ABSENT_ID}"), preview
    else:
        writes = [(s.method, s.path) for s in up.writes()]
        assert len(writes) == 1, f"{name}: {writes}"
        method, path = writes[0]
        assert method in ("PUT", "DELETE") and path.endswith(f"/{ABSENT_ID}"), writes


@pytest.mark.parametrize("name", sorted(UNLISTED))
async def test_unlisted_write_on_an_absent_id_reports_the_upstream_404(monkeypatch, name):
    """The upstream judges an UNLISTED id: its 404 for an absent id is an error carrying
    the upstream body verbatim, never a success."""
    body = json.dumps({"error": "synthetic object not found", "code": "NOT_FOUND"})
    args = {**tool_args.generated_args(TOOLS[name]), UNLISTED[name]: ABSENT_ID}
    up = uh.FakeUpstream(write_status=404, error_body=body)
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, name, up, args)
    text = str(exc.value)
    assert "HTTP 404" in text and body in text, f"{name}: {text}"
    writes = up.writes()
    assert len(writes) == 1 and writes[0].status == 404, f"{name}: {writes}"
    assert writes[0].path.endswith(f"/{ABSENT_ID}"), writes[0].path


@pytest.mark.parametrize("dry_run", [False, True])
async def test_unknown_setting_key_fails_on_the_read(monkeypatch, dry_run):
    up = uh.FakeUpstream(fail_paths=("/rest/setting/",), error_body="api.err.Invalid")
    env = {"UNIFI_WRITE_POLICY": "dry-run"} if dry_run else None
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, "update_setting", up, env=env)
    assert "/rest/setting/" in str(exc.value), exc.value
    assert up.writes() == [], up.writes()


class _ListClient:
    def __init__(self, body: Any) -> None:
        self.body = body
        self.calls: list[str] = []

    async def get(self, path: str, *, key: Any = None) -> Any:
        self.calls.append(path)
        return self.body


@pytest.mark.parametrize(
    "body",
    [
        {"meta": {"rc": "ok"}, "data": [None, {"_id": "a1", "name": "Ünïcode "}, 7]},
        [None, {"_id": "a1", "name": "Ünïcode "}, 7],
    ],
)
@pytest.mark.parametrize("wanted", ["zz", "a1"])
async def test_lookup_non_objects_raise_shape_error_before_matching(body, wanted):
    with pytest.raises(
        UniFiConnectionError,
        match="Unexpected response shape from GET /p: row 0 expected an object, got NoneType",
    ):
        await require_listed_record(
            _ListClient(body), "/p", wanted, key=None, kind="Thing", list_tool="list_things"
        )


@pytest.mark.parametrize(
    "body",
    [
        {"meta": {"rc": "ok"}, "data": [{"_id": "a1", "name": "Ünïcode "}]},
        [{"_id": "a1", "name": "Ünïcode "}],
    ],
)
async def test_lookup_valid_rows_show_names_verbatim(body):
    client = _ListClient(body)
    with pytest.raises(ValueError) as exc:
        await require_listed_record(
            client, "/p", "zz", key=None, kind="Thing", list_tool="list_things"
        )
    text = str(exc.value)
    assert "'Ünïcode ' (_id=a1)" in text
    assert "list_things" in text and "No write was sent" in text
    found = await require_listed_record(
        client, "/p", "a1", key=None, kind="Thing", list_tool="list_things"
    )
    assert found == {"_id": "a1", "name": "Ünïcode "}


@pytest.mark.parametrize("body", [{"meta": {}}, "text", None, {"data": {"_id": "a1"}}])
async def test_lookup_unexpected_shape_raises_with_shape(body):
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape from GET /p"):
        await require_listed_record(
            _ListClient(body), "/p", "a1", key=None, kind="Thing", list_tool="list_things"
        )


async def test_lookup_empty_list_says_none():
    with pytest.raises(ValueError, match=r"valid: \(none\)"):
        await require_listed_record(
            _ListClient([]), "/p", "a1", key=None, kind="Thing", list_tool="list_things"
        )


# ============================================== purpose pinned by one helper
_PURPOSE = {
    "update_vpn_server": ("fields", "remote-user-vpn"),
    "update_site_to_site_tunnel": ("tunnel", "site-vpn"),
    "update_wan_interface": ("wan", "wan"),
}


@pytest.mark.parametrize("name", sorted(_PURPOSE))
@pytest.mark.parametrize("given", ["absent", None, "same"])
async def test_purpose_is_pinned_in_the_body(monkeypatch, name, given):
    arg, purpose = _PURPOSE[name]
    body: dict[str, Any] = {"name": "probe-renamed"}
    if given == "same":
        body["purpose"] = purpose
    elif given is None:
        body["purpose"] = None
    args = {**tool_args.generated_args(TOOLS[name]), arg: body}
    up = uh.FakeUpstream()
    await cti._call(monkeypatch, name, up, args)
    puts = [s for s in up.writes() if s.method == "PUT"]
    assert len(puts) == 1, up.writes()
    assert puts[0].sent_json == {"name": "probe-renamed", "purpose": purpose}, puts[0].sent_json


def test_one_purpose_helper():
    from pathlib import Path

    src = Path(statistics.__file__).parent
    offenders = [
        p.name
        for p in sorted(src.glob("*.py"))
        if p.name != "_classic_objects.py" and 'get("purpose")' in p.read_text()
    ]
    assert offenders == [], f"purpose handled outside with_purpose: {offenders}"
    assert with_purpose("t", {"purpose": None, "a": 1}, "wan") == {"purpose": "wan", "a": 1}
    # Another purpose is sent as given (the controller judges it).
    assert with_purpose("t", {"purpose": "site-vpn"}, "wan") == {"purpose": "site-vpn"}


# ============================================== every interval and scope the controller takes
_PROBED_INTERVALS = ("minute", "5minutes", "hourly", "daily", "monthly", "archive")
_PROBED_SCOPES = ("site", "ap", "user", "gw", "sw", "device", "speedtest", "isp")


def test_report_sets_are_the_probed_sets():
    assert statistics.REPORT_INTERVALS == _PROBED_INTERVALS
    assert statistics.REPORT_SCOPES == _PROBED_SCOPES


@pytest.mark.parametrize("interval", _PROBED_INTERVALS)
@pytest.mark.parametrize("scope", _PROBED_SCOPES)
async def test_every_probed_pair_reaches_the_controller(monkeypatch, interval, scope):
    up = uh.FakeUpstream()
    args = {
        **tool_args.generated_args(TOOLS["get_historical_stats"]),
        "interval": interval,
        "scope": scope,
    }
    await cti._call(monkeypatch, "get_historical_stats", up, args)
    posts = [s for s in up.served if s.method == "POST"]
    assert [s.path.rsplit("/", 1)[-1] for s in posts] == [f"{interval}.{scope}"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("interval", "weekly"),
        ("interval", "Hourly"),
        ("interval", " hourly"),
        ("scope", "switch"),
        ("scope", "gateway"),
        ("scope", "GW"),
        ("scope", "sw "),
    ],
)
async def test_unknown_report_value_fails_listing_every_valid_value(monkeypatch, field, value):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(TOOLS["get_historical_stats"]), field: value}
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, "get_historical_stats", up, args)
    valid = _PROBED_INTERVALS if field == "interval" else _PROBED_SCOPES
    text = str(exc.value)
    assert repr(value) in text and all(repr(v) in text for v in valid), text
    assert up.served == [], up.served


# --------------------------------------------------------------------------- id case
_UPSTREAM_HEX = "abcdef0123456789abcdef01"


class _ListStub:
    """A client whose Classic list holds one record; records every write it is sent."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str, Any]] = []

    async def get(self, path: str, **_kw: Any) -> Any:
        return {"meta": {"rc": "ok"}, "data": [{"_id": _UPSTREAM_HEX, "name": "SSH"}]}

    async def put(self, path: str, *, json: Any = None, **_kw: Any) -> Any:
        self.writes.append(("PUT", path, json))
        return {"meta": {"rc": "ok"}, "data": []}

    async def delete(self, path: str, **_kw: Any) -> Any:
        self.writes.append(("DELETE", path, None))
        return {"meta": {"rc": "ok"}, "data": []}


class _RegistryStub:
    async def resolve_key_for_host(self, host: str) -> None:
        return None

    async def resolve_host_id(self, host: str, **_kw: Any) -> str:
        return "host-1"

    async def resolve_site_slug(self, site: str, host_id: str, **_kw: Any) -> str:
        return "default"


async def test_delete_port_forward_sends_the_upstream_spelling():
    client = _ListStub()
    await network_services_proxy.delete_port_forward(
        client, _RegistryStub(), "h", "Default", _UPSTREAM_HEX.upper()
    )
    assert [(m, p.rsplit("/", 1)[-1]) for m, p, _b in client.writes] == [("DELETE", _UPSTREAM_HEX)]


async def test_update_port_forward_sends_the_upstream_spelling_in_url_and_body():
    client = _ListStub()
    await network_services_proxy.update_port_forward(
        client,
        _RegistryStub(),
        "h",
        "Default",
        _UPSTREAM_HEX.upper(),
        {"_id": _UPSTREAM_HEX.upper(), "name": "SSH-2"},
    )
    ((method, path, body),) = client.writes
    assert method == "PUT" and path.endswith(f"/portforward/{_UPSTREAM_HEX}")
    assert body == {"_id": _UPSTREAM_HEX, "name": "SSH-2"}


def test_with_upstream_id_respells_only_the_same_record():
    body = {"_id": _UPSTREAM_HEX.upper(), "name": "x"}
    assert with_upstream_id(body, "_id", _UPSTREAM_HEX) == {"_id": _UPSTREAM_HEX, "name": "x"}
    assert body["_id"] == _UPSTREAM_HEX.upper()  # never mutated
    other = {"_id": "0000000000000000000000ff"}
    assert with_upstream_id(other, "_id", _UPSTREAM_HEX) is other
    assert with_upstream_id({"name": "x"}, "_id", _UPSTREAM_HEX) == {"name": "x"}
    # A second id of the same record (a networkconf external_id) keeps its own spelling.
    alias = "00000000-0000-4000-b000-000000fa0040"
    assert with_upstream_id({"_id": alias.upper()}, "_id", _UPSTREAM_HEX, alias) == {"_id": alias}
    # A non-hex id is matched exactly, so another case is a different id.
    assert with_upstream_id({"id": "Rule-1"}, "id", "rule-1") == {"id": "Rule-1"}
