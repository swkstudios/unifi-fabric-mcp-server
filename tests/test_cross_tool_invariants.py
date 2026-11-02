"""Cross-tool invariants, enforced by behaviour across EVERY registered tool.

Each property is parametrized over the live tool registry, so a new tool is covered the
moment it is registered (and a tool the harness cannot drive is a failure, not a skip).
The upstream is a shape-faithful fake (``tests/upstream_harness.py``) seeded from
sanitized real responses recorded from a live console (``tests/fixtures/recorded/``).

Properties:

a. Pass-through: with ``UNIFI_REDACT_SECRETS`` unset, every upstream record a tool
   receives is in its response byte-equal (deep compare). Allowed: documented additive
   ``_``-prefixed keys, the ``{"result": [...]}`` list envelope, and tool-owned wrapper
   objects around the records. Record *selection* (get-one-from-a-list, search/filter)
   must return the selected records verbatim. Derived outputs are an explicit, reasoned
   list (``DERIVED``) and nothing else.
b. No truncation: lists longer than any drain page (``LARGE_LIST_ITEMS``) and >1 MB
   records come back complete.
c. Errors: a 400/403/404/500 upstream body appears verbatim in the tool error (or, for
   fan-out tools that report per-item failures, in the result).
d. Unknown or ambiguous host/site fails fast and lists the valid choices.
e. Write tools are refused at the chokepoint under ``UNIFI_READ_ONLY=1`` (no write
   verb reaches the transport) and reach a write verb with default flags.
f. Description hand-offs name real tools; examples validate against the input schema;
   descriptions carry no markup.
g. Additive ``_`` keys a read adds are never sent back on a get -> update round trip.
h. Multi-page upstream lists (cursor, offset/limit/totalCount, page/links.next; >= 3
   pages) are drained by default: every paged query is read to its FINAL page, in every
   paging family (the harness logs each page it serves); a short page never stops a drain below
   ``totalCount``; an upstream that ignores offset never yields duplicates presented as
   complete; only the opt-in ``UNIFI_PAGINATE_MAX_PAGES`` cap may stop early, and then
   the result says ``incomplete: true`` and keeps what it gathered.
i. Multi-key aggregation tools include every key's data and report per-key failures;
   every key failing is an error, and an unknown ``key_label`` lists the valid labels.
j. Every tool completes when it fans out wider than ``UNIFI_MAX_CONCURRENCY``.
k. An unexpected upstream shape raises (or is passed through verbatim) - never an empty
   result.
l. Every host-scoped tool routes to the API key that owns the console (multi-key).
m. Every paging style has a repeated-page guard: an upstream that keeps answering "more"
   with the same page ends in an error or ``incomplete: true``, never a loop, and the
   repeated page is never appended (no added duplicates, incomplete or not).
n. With ``UNIFI_AUDIT_LOG`` set every write attempt (success or failure) is audited, and
   a transport error is reported with its method and path.
o. ``totalCount`` is never invented: every ``totalCount`` a tool returns is a value the
   upstream reported, or null. An upstream that sends no total, and a drain stopped by
   the opt-in cap, never yield a count computed from the records gathered.
p. Search matches the field names real records use (recorded Network Integration
   ``macAddress`` / ``ipAddress``), and a null field never matches.
h2. With ``UNIFI_CACHE_TTL_SECONDS=0`` exactly as with 900: a console/site NAME given to
   any tool is refused against a capped enumeration list (the incomplete state travels
   with the fetched list), and every tool completes on complete lists (a list is never
   re-read from an expired cache entry).
q. A site whose list stopped at the opt-in cap is incomplete, never failed and never
   succeeded, in every fan-out tool that counts sites.
r. Multi-key: one key's unexpected list shape is that key's error; the other keys' data
   is still returned.
z. A normal multi-page drain never returns a record twice, including when one console is
   visible to two API keys (each console site is read once).
s. Structured output is valid for list-valued upstream bodies (Classic ``{meta, data: [...]}``
   reads and writes, v2 bare arrays): a tool advertising an object result never returns a
   list, and a Classic write answered with list-valued data reaches a real FastMCP client.
t. No Classic REST tool or stat read drops the upstream ``meta`` (envelope pass-through).
u. An unknown selector (id / MAC / network id) fails listing every valid choice.
v. Every write tool of an area with a write opt-out (Protect, Mobility, Carrier Fabric,
   connector relay; derived from readOnlyHint and the family index) is refused before
   any upstream call when the opt-out is set; read-only families have no write tools.
w. Every write whose upstream answers 204/empty, a non-JSON body or a bare JSON value
   that is not an object (true, 7, []) completes and returns that body verbatim (as the
   result, or under ``response``). Classic data shapes use an affirmative meta.rc="ok"
   envelope; a malformed or non-affirmative Classic envelope is refused. Every
   read given the same bodies passes them through or raises an actionable error, never
   a FastMCP result-type or Python attribute/type error. Every JSON GET answering its
   record list as bare scalars or with null entries (the /v1/hosts, /v1/sites and console
   site lists included) is passed through, skipped or an actionable shape error: never a
   bare Python exception, raised or inside a result.
x. A bare JSON value where an object or list is expected raises, or is passed through
   verbatim; it is never wrapped in an invented key such as ``{"data": ...}``.
y. A cursor protocol that cycles (A, B, A, ...) or says "more" without a cursor ends in
   an error or ``incomplete: true``; never a loop or a result presented as complete.
ba. ``UNIFI_READ_ONLY=1`` refuses every write tool before ANY upstream call, including the
   resolution and read-before steps of tools that read first.
bb. A free-form body dict reaches the write verbatim: a body key named like a helper
   parameter (``site``, ``host``, ``client``, ``registry``, the id argument) is sent.
bc. No write drops a field its published request schema accepts (the Integration
   sanitizer's reserved fields included: ACL rule ``index``).
bd. Every query parameter of a published write operation is reachable: a required one
   fails fast naming it, an optional one is a tool argument sent only when given. The
   same holds for the optional query parameters of the published READ operations a tool
   passes through (tools whose documented contract is a derived view or a record
   selection excepted). Paging is consistent across list tools: every ``list_*`` tool
   whose upstream operation publishes ``offset`` / ``limit`` exposes both (drain-all by
   default; given, exactly that one page is fetched).
be. A string argument interpolated into a request path rejects ``?``/``#``/``/`` before
   any upstream call.
bf. A body field the published schema marks required is a required tool argument (no
   default filled in for the caller).
bg. An explicit empty list argument is forwarded as given, never replaced by a default.
bh. "Get it from <tool> (<field>)" hand-offs name the field, and an ``x[].`` path names a
   key the source tool's result really has.
bi. Every tool that drains an offset list returns the upstream ``totalCount``.
bj. A literal body quoted in a description uses a value the published schema accepts,
   unless the same sentence says the controller rejects it.
bk. Filter examples quote string operands; the server instructions attribute RADIUS
   profiles to the Network Integration API.
aa. Opt-in ``UNIFI_DRY_RUN`` reaches every write tool: no write verb is sent upstream
   (the connector relay included, also to a Classic ``cmd/stat`` command), and no tool
   description claims there is no dry-run. No dry-run result claims a completed write
   (``deleted: true``, ``forgotten``, a status other than ``dry_run``, an HTTP status
   included); every delete tool, and the connector relay for every method, says
   ``status: "dry_run"``; every preview carries ``params``, equal to the query the same
   call sends without dry-run.
ab. The read-POST classification is anchored: every POST a tool sends that the write
   classifier calls a read is a Classic site ``stat`` route or the ISP-metrics query; a
   Classic command (``cmd/stat`` ...) is always a write.
ac. A tool taking ``sites[]`` entries on consoles owned by different keys queries each
   owning key and merges every key's recorded real response (records tagged
   ``_keyLabel``, the rest of each key's body kept under ``byKey``).
ad. A multi-key merge keeps the single-key access path: every non-framing top-level key
   a tool returns with one key is present when it merges two keys.
ae. An empty (200, no body) or non-JSON body on a tool's own GET is raised naming the
   request (or passed through verbatim); it never surfaces as an attribute/type error.
af. A description that promises ``_keyLabel`` on merged records is kept: the tool's
   two-key result carries ``_keyLabel``.
ag. The connector relay reaches every Classic route namespace (``set/setting``, ``upd``,
   ``list``, ``group``, ``api/self``, ``api/stat/sites``) and forwards ``params`` on the
   write and on its read-before / read-after.
bm. A write body field holding exactly the redaction mask (a ``UNIFI_REDACT_SECRETS``
   read fed back into a write) never reaches upstream, at any nesting depth, in every
   write tool; its siblings still do, the write is not refused, and the result lists the
   dropped paths under ``_redactedFieldsNotSent``.
bl. A write that resolves its target in a list first (v2 device tags; Classic networkconf
   VPN servers, site-to-site tunnels and WANs, scoped by ``purpose``) sends no write verb
   when the target is unknown, and an id of another networkconf purpose is unknown to it;
   the error lists every record of that purpose.
bn. The connector relay honours every per-area write opt-out (Protect, Mobility, Carrier
   Fabric): a relayed mutation on a route class of an opted-out area is refused naming the
   variable before any upstream call, other areas' routes are unaffected, and a relayed
   mutation is sent once on HTTP 429 (never auto-retried).
bo. Pass-through of result keys: every top-level key of a tool result is a key an
   upstream body the tool read carries (at its top level, or of the records it carries),
   an additive ``_``-prefixed key, or a documented result-envelope key from the fixed set
   ``RESULT_ENVELOPE_KEYS``. A tool never invents a non-underscore key (``wans``,
   ``count``, ``cameras`` ...) around an upstream body. Documented derived outputs
   (``DERIVED``) are tool-owned documents and are exempt. The same holds when the upstream
   records are sparse (no recorded fields): a key the record lacks is never invented as
   ``null``.
bp. An empty-body success (204, or 200 with no body) is never an empty MCP result: every
   tool returns an explicit ``null`` text block plus ``structuredContent`` (``{"result":
   null}``) where its output schema admits it, also through a real FastMCP client.
bq. MAC as id: every tool whose ``device_id`` / ``client_id`` accepts "UUID or MAC" sends
   the same requests (and returns the same result) for the MAC in colon, dash and bare
   form as for the id. A MAC the tool resolves to an id that is not found fails listing
   the valid choices before any write; a write addressed upstream by the MAC itself
   (Classic ``stamgr``) sends an unlisted MAC as is, exactly once. Within a tool family,
   every tool taking that argument accepts the MAC.
bq2. No connected-only precondition on a MAC-addressed write: no write tool given a MAC
   (an offline client's, absent from every list) reads a connected-only list (Integration
   ``/sites/{id}/clients``, Classic ``/stat/sta``); every Classic ``stamgr`` tool sends
   that MAC with exactly one write and no non-resolution read. Only writes addressed
   upstream by the Integration client id are exempt (``_ID_ADDRESSED_CLIENT_WRITES``).
br. Id case: every write tool given a hex id in non-canonical case (upper-case) that names
   an upstream record sends, for an id it matches locally (a list resolved before the
   write: an unknown id is refused with no write), exactly the requests it sends for the
   upstream spelling -- the URL and every body field (a body ``_id`` / ``id`` naming the
   record included) carry the upstream form, never the caller's. An id it forwards
   unmatched (the upstream decides) is sent exactly as the caller spelled it. Holds with
   default flags, under ``UNIFI_DRY_RUN`` (the preview) and with several sites per console.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import functools
import json
import logging
import re
from typing import Any
from urllib.parse import quote

import httpx
import jsonschema
import pytest
from fastmcp.exceptions import ToolError

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import LazyCatalog, lazy_parametrize, tools_by_name
from tests._tool_classes import class_axis, tool_batches
from unifi_fabric import families, read_only, refusals, route_secrets, server
from unifi_fabric.client import is_dry_run_preview
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.redaction import MASKED_FIELDS_KEY, REDACTION_MASK, is_credential_field
from unifi_fabric.secret_scrub import scrub
from unifi_fabric.tools import _pagination
from unifi_fabric.tools import carrier_fabric as _carrier_fabric
from unifi_fabric.tools import connector as _connector
from unifi_fabric.tools import mobility as _mobility
from unifi_fabric.tools import network_mobile_wan as _network_mobile_wan
from unifi_fabric.tools import system_log as _system_log
from unifi_fabric.write_body import IDENTITY_FIELDS

#: Records in a large list (invariant b). Lists are uncapped by rule: only the opt-in
#: UNIFI_PAGINATE_MAX_PAGES stops a drain, so the product has no size threshold to
#: cross. The count only has to exceed the largest page any drain requests, so a list
#: comes back complete even when it is longer than a full page the client asked for.
LARGE_LIST_ITEMS = (
    max(
        _pagination.DRAIN_PAGE_SIZE,
        _system_log.DRAIN_PAGE_SIZE,
        _carrier_fabric._MAX_PAGE_SIZE,
        _mobility._MAX_PAGE_SIZE,
    )
    + 1
)


def _usage_workflows() -> str:
    from pathlib import Path

    return (
        (Path(__file__).resolve().parents[1] / "docs/TOOL-USAGE.md")
        .read_text()
        .split("## create_network")[0]
    )


def _tools() -> dict[str, Any]:
    return tools_by_name()


@functools.cache
def _lz_TOOLS():
    return _tools()


def _is_read(tool: Any) -> bool:
    ann = tool.annotations
    return bool(ann and getattr(ann, "read_only_hint", None))


@functools.cache
def _lz_READ_TOOLS():
    return sorted(n for n, t in _lz_TOOLS().items() if _is_read(t))


@functools.cache
def _lz_WRITE_TOOLS():
    return sorted(n for n, t in _lz_TOOLS().items() if not _is_read(t))


# --------------------------------------------------------------------------- policy
# Tools with no upstream call to compare against.
NO_UPSTREAM = {
    "list_configured_api_keys": "reports the server's own key configuration",
}

# Documented derived outputs: the tool's contract is a computed view, not records.
DERIVED = {
    "get_unifi_placement_snapshot": "documented sanitized placement projection (schema v1)",
    "get_fleet_summary": "documented counts/rollups across the fleet",
    "get_innerspace_summary": "documented counts/rollup of the InnerSpace project",
    "collect_protect_device_changes": "documented add/remove/modify diff of snapshots",
}


# A warning result retains two upstream bodies under documented source keys.
MULTI_SOURCE_COMPOSITE = {"list_site_warnings"}
# Documented record selection: the tool returns the records matching its arguments
# (one by id / MAC / key, or a search/filter); each selected record must be verbatim.
SELECT = {
    "update_device_radio": "selects one AP and exposes its post-write operating radio fields",
    "get_arm_profile": "picks the profile with arm_profile_id out of the arm-profile list",
    "get_vpn_server": "picks the server with server_id out of the drained VPN server list",
    "get_radius_profile": "picks the profile with profile_id out of the drained RADIUS list",
    "get_wlan_group": "picks the group with group_id out of the Classic wlangroup list",
    "get_client_link_diagnostics": "picks the client by MAC out of the active-client stats",
    "search_across_sites": "returns only the device/client records matching the query",
    "search_device_fleet": "returns only the fleet devices matching the query",
    "list_innerspace_devices": "returns the device shapes selected out of the project",
    "update_innerspace_plan": "picks the plan with plan_id out of the project document",
    "list_wan_interfaces": "keeps only the wan subsystem entries of stat/health",
    "get_setting": "picks the setting group with setting_key out of the settings list",
    "get_device_port_state": "picks the device by id out of stat/device (port_table)",
    "get_device_replacement_options": "resolves a device out of stat/device, then reads candidates",
    "get_device_stp_state": "picks the device by id out of stat/device (STP fields)",
    "get_traffic_route": "picks the route with route_id out of the v2 traffic-route list",
    "get_ap_group": "picks the group with group_id out of the v2 apgroups list",
}

# Lookups a tool makes to resolve an argument (not part of its result by contract).
AUXILIARY: dict[str, tuple[str, ...]] = {
    "get_device_replacement_options": ("/stat/device",),
    "block_client": ("/clients/",),
    "unblock_client": ("/clients/",),
    "reconnect_client": ("/clients/",),
    "create_network": ("/rest/portconf",),
    "list_port_profiles": ("/rest/networkconf",),
    "get_port_profile": ("/rest/networkconf",),
    "update_port_profile": ("/rest/networkconf", "/rest/portconf/"),
    "allow_network_on_port_profile": ("/rest/networkconf", "/rest/portconf/"),
    "exclude_network_on_port_profile": ("/rest/networkconf", "/rest/portconf/"),
    "attach_carrier_subscriber_host": ("/carrier/subscribers/",),
    "assign_carrier_subscriber_plan": ("/carrier/subscribers/",),
    "suspend_carrier_subscriber": ("/carrier/subscribers/",),
    "resume_carrier_subscriber": ("/carrier/subscribers/",),
    "update_arm_profile_settings": ("/nvrs",),
    # N07: the VPN server id is resolved in Classic networkconf before the v2 read.
    "get_openvpn_client_config": ("/rest/networkconf",),
    "list_wireguard_users": ("/rest/networkconf",),
}

# Tools whose own upstream is a registry resolution endpoint.
PRIMARY_RESOLUTION = {
    "list_hosts": "/v1/hosts",
    "list_sites": "/v1/sites",
    "list_local_sites": "/integration/v1/sites",
    "list_all_sites_aggregated": "/v1/sites",
}

# The generic connector relays forward exactly one upstream request and return that
# response verbatim (status + body); draining is the caller's choice of path/params.
# Private Protect tools deliberately preserve the connector status/body contract,
# including upstream failures; their docs describe this relay result.
RAW_RELAY = {
    "get_camera_private",
    "update_camera_private",
    "list_ptz_presets",
    "list_ptz_patrols",
    "get_nvr_private",
    "update_nvr",
    "get_sensor_private",
    "update_sensor_private",
    "export_camera_video",
    "reboot_protect_device",
    "adopt_protect_device",
    "unadopt_protect_device",
    "reboot_nvr",
    "clear_sensor_tamper",
    "fabric_connector_get",
    "fabric_connector_post",
    "fabric_connector_put",
    "fabric_connector_patch",
    "fabric_connector_delete",
}

# Site Manager /v1/devices returns per-host wrappers {hostId, hostName, updatedAt,
# devices}; these tools return the devices flat, each carrying every wrapper field
# as an additive ``_<field>``.
UNWRAP_DEVICES = {"list_all_devices", "search_device_fleet"}


# --------------------------------------------------------------------------- helpers
@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


async def _call(
    monkeypatch,
    name: str,
    upstream: uh.FakeUpstream,
    args: dict | None = None,
    env: dict[str, str] | None = None,
    keys: list[APIKeyConfig] | None = None,
):
    for k, v in {**tool_args.TOOL_ENV.get(name, {}), **(env or {})}.items():
        monkeypatch.setenv(k, v)
    uh.install(monkeypatch, upstream, keys=keys)
    # Discovery proxies call a cloned app and bypass install's production-call
    # wrapper. Prepare here too; direct calls receive the same idempotent setup.
    tool_args.prepare_upstream(name, upstream)
    call_args = tool_args.generated_args(_lz_TOOLS()[name]) if args is None else args
    if args is None and name == "fabric_connector_get":
        # Write-class sweeps must exercise this mixed relay's mutating route.
        # Explicit caller arguments still cover ordinary GETs verbatim.
        call_args = {**call_args, "path": f"protect/api/cameras/{uh.ARG_ID}/enable-control"}
    return await server.mcp.call_tool(name, call_args)


def _expected_records(name: str, upstream: uh.FakeUpstream) -> list[tuple[str, Any]]:
    """(path, record) pairs the tool's response must carry verbatim."""
    out: list[tuple[str, Any]] = []
    served = [s for s in upstream.served if 200 <= s.status < 300]
    prim = PRIMARY_RESOLUTION.get(name)
    for s in served:
        if isinstance(s.body, bytes | str):
            continue
        if s.resolution and not (prim and s.path.endswith(prim)):
            continue
        if any(a in s.path for a in AUXILIARY.get(name, ())) and s.method == "GET":
            continue
        if name in _lz_WRITE_TOOLS() and s.method == "GET":
            continue  # write tools: their write responses are the result contract
        for rec in uh.upstream_records(s.body):
            out.append((s.path, rec))
    return out


def _identity(rec: Any) -> tuple[str, Any] | None:
    if not isinstance(rec, dict):
        return None
    for key in ("probe", "id", "_id", "mac", "key", "siteId"):
        if rec.get(key) is not None:
            return key, rec[key]
    return None


def _nested_objects(obj: Any) -> list[dict]:
    out: list[dict] = []
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            out.append(node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


def _fidelity_violations(name: str, payload: Any, upstream: uh.FakeUpstream) -> list[str]:
    problems: list[str] = []
    index = uh.PayloadIndex(payload)
    records = _expected_records(name, upstream)
    if name in UNWRAP_DEVICES:
        flat = []
        for path, wrapper in records:
            if isinstance(wrapper, dict) and isinstance(wrapper.get("devices"), list):
                extra = {f"_{k}": v for k, v in wrapper.items() if k != "devices"}
                flat += [(path, {**d, **extra}) for d in wrapper["devices"]]
            else:
                flat.append((path, wrapper))
        records = flat
    if name in SELECT:
        # Every upstream object (at any depth) the tool returns must come back verbatim.
        # Checked from the returned side: an identity key such as ``mac`` also names
        # reference objects (a parent_device, an uplink, a downlink row) nested in records
        # the tool did NOT select, so a served object sharing an identity with a returned
        # one is not evidence that the returned one was altered.
        served: dict[tuple[str, Any], list[tuple[str, Any]]] = {}
        for path, rec in records:
            for obj in _nested_objects(rec):
                ident = _identity(obj)
                if ident is not None:
                    served.setdefault(ident, []).append((path, obj))
        selected = 0
        for returned in _nested_objects(payload):
            ident = _identity(returned)
            if ident is None or ident not in served:
                continue
            selected += 1
            if not any(uh.strip_additive(returned, obj) == obj for _, obj in served[ident]):
                problems.append(f"selected object altered from {served[ident][0][0]} ({ident})")
        if records and not selected:
            problems.append("no upstream record returned by a selection tool")
        return problems
    for path, rec in records:
        if not index.contains(rec):
            problems.append(f"record from {path} missing or altered: {json.dumps(rec)[:160]}")
    return problems


def _decoded_leaves(payload: Any) -> list[bytes]:
    """Every string leaf of ``payload`` that is valid base64, decoded."""
    out: list[bytes] = []
    for leaf in _string_leaves(payload):
        if len(leaf) < 8:
            continue
        try:
            out.append(base64.b64decode(leaf, validate=True))
        except (binascii.Error, ValueError):
            continue
    return out


def _binary_problems(name: str, payload: Any, upstream: uh.FakeUpstream) -> list[str]:
    """Every binary body the upstream served comes back byte-for-byte (decoded)."""
    bodies = [s for s in upstream.served if 200 <= s.status < 300 and isinstance(s.body, bytes)]
    decoded = _decoded_leaves(payload) if bodies else []
    return [
        f"{s.path}: {len(s.body)} served bytes not returned exactly"
        for s in bodies
        if not any(d == s.body for d in decoded)
    ]


BINARY_TOOLS = (
    "export_camera_video",
    "get_camera_snapshot",
    "get_recognition_group_image",
    "get_thumbnail",
    "get_innerspace_asset",
)


async def _eligible_a_upstream_fields_pass_through(name):
    if name in NO_UPSTREAM or name in DERIVED:
        return False
    return True


# =========================================================================== (a)
@tool_batches(
    "name", lambda: sorted(_lz_TOOLS()), eligible=_eligible_a_upstream_fields_pass_through
)
async def test_a_upstream_fields_pass_through(monkeypatch, name):
    if name in NO_UPSTREAM or name in DERIVED:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream()
    res = await _call(monkeypatch, name, up)
    payload = uh.result_payload(res)
    problems = _fidelity_violations(name, payload, up) + _binary_problems(name, payload, up)
    assert problems == [], f"{name}: " + "; ".join(problems[:5])


async def _eligible_a_single_object_envelope_is_returned_whole(monkeypatch, name):
    """A read answered by ONE single-object envelope (``{data: {...}, httpStatusCode,
    traceId}``) returns that envelope verbatim, never just ``data`` and never re-wrapped
    under a tool-owned key (``{device: ...}``): the envelope fields are upstream data."""
    if name in NO_UPSTREAM or name in DERIVED or name in SELECT:
        return False
    up = uh.FakeUpstream()
    uh.result_payload(await _call(monkeypatch, name, up))
    primary = [
        s
        for s in up.served
        if 200 <= s.status < 300 and (not s.resolution) and isinstance(s.body, dict)
    ]
    if len(primary) != 1 or not isinstance(primary[0].body.get("data"), dict):
        return False
    return True


@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_a_single_object_envelope_is_returned_whole
)
async def test_a_single_object_envelope_is_returned_whole(monkeypatch, name):
    """A read answered by ONE single-object envelope (``{data: {...}, httpStatusCode,
    traceId}``) returns that envelope verbatim, never just ``data`` and never re-wrapped
    under a tool-owned key (``{device: ...}``): the envelope fields are upstream data."""
    if name in NO_UPSTREAM or name in DERIVED or name in SELECT:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    primary = [
        s
        for s in up.served
        if 200 <= s.status < 300 and not s.resolution and isinstance(s.body, dict)
    ]
    if len(primary) != 1 or not isinstance(primary[0].body.get("data"), dict):
        raise AssertionError("inapplicable case was not filtered before batching")
    body = primary[0].body
    assert isinstance(payload, dict), f"{name}: returned {type(payload).__name__}"
    lost = {k: v for k, v in body.items() if uh.strip_additive(payload.get(k), v) != v}
    assert not lost, f"{name}: envelope fields not returned verbatim: {sorted(lost)}"


async def test_a_binary_tools_are_exercised(monkeypatch):
    """The byte-exact binary check is not vacuous: each binary tool is served bytes."""
    assert set(BINARY_TOOLS) <= set(_lz_TOOLS())
    for name in BINARY_TOOLS:
        up = uh.FakeUpstream()
        payload = uh.result_payload(await _call(monkeypatch, name, up))
        served = [s.body for s in up.served if isinstance(s.body, bytes)]
        assert served, f"{name}: no binary body served"
        assert _binary_problems(name, payload, up) == [], name
        # a single altered byte is caught
        tampered = {"image_base64": base64.b64encode(served[0][:-1] + b"\x00").decode()}
        assert _binary_problems(name, tampered, up) != [], name


def test_a_policy_lists_name_real_tools_only():
    listed = (
        set(NO_UPSTREAM)
        | set(DERIVED)
        | set(SELECT)
        | RAW_RELAY
        | set(AUXILIARY)
        | set(PRIMARY_RESOLUTION)
        | UNWRAP_DEVICES
        | set(ENUMERATING)
    )
    assert listed - set(_lz_TOOLS()) == set()
    # every exception carries its own specific reason (no generic keyword match)
    for policy in (NO_UPSTREAM, DERIVED, SELECT, ENUMERATING):
        for name, reason in policy.items():
            assert isinstance(reason, str) and len(reason.split()) >= 4, name
    assert len(set(DERIVED.values())) == len(DERIVED)
    assert len(set(SELECT.values())) == len(SELECT)


# ------------------------------------------------------------- derived outputs
def _served_once(up: uh.FakeUpstream, suffix: str) -> list[Any]:
    """Records served on paths ending with ``suffix``, each distinct page counted once."""
    seen: set[tuple[str, str]] = set()
    out: list[Any] = []
    for s in up.served:
        if not 200 <= s.status < 300 or isinstance(s.body, bytes | str):
            continue
        if not s.path.endswith(suffix) or (s.path, s.query) in seen:
            continue
        seen.add((s.path, s.query))
        out.extend(uh.upstream_records(s.body))
    return out


def _derived_problems(name: str, payload: Any, up: uh.FakeUpstream) -> list[str]:
    """Each documented derived output's counts/rollups match the drained input."""
    p: list[str] = []
    if name == "get_fleet_summary":
        hosts = _served_once(up, "/v1/hosts")
        sites = _served_once(up, "/v1/sites")
        wrappers = _served_once(up, "/v1/devices")
        devices = sum(
            len(w["devices"]) if isinstance(w, dict) and isinstance(w.get("devices"), list) else 1
            for w in wrappers
        )
        if payload.get("hosts") != len(hosts):
            p.append(f"hosts {payload.get('hosts')} != {len(hosts)} drained")
        if payload.get("sites") != len(sites):
            p.append(f"sites {payload.get('sites')} != {len(sites)} drained")
        total = (payload.get("devices") or {}).get("total")
        if total != devices:
            p.append(f"devices.total {total} != {devices} drained")
        by_status = sum(((payload.get("devices") or {}).get("byStatus") or {}).values())
        if by_status != devices:
            p.append(f"byStatus sums to {by_status}, not {devices}")
    elif name == "get_innerspace_summary":
        bodies = [r for r in _served_once(up, "/project") if isinstance(r, dict)]
        project = bodies[0].get("data", bodies[0]) if bodies else {}
        for field, src in (
            ("shape_total", "shapes"),
            ("plan_count", "plans"),
            ("product_count", "products"),
        ):
            want = len(project.get(src) or [])
            if payload.get(field) != want:
                p.append(f"{field} {payload.get(field)} != {want} in the project")
        if payload.get("shape_total") != sum((payload.get("shape_counts") or {}).values()):
            p.append("shape_counts do not sum to shape_total")
    elif name == "collect_protect_device_changes":
        # identical snapshots on every poll: the documented diff is empty and complete
        if payload.get("changes") != [] or payload.get("_truncated") is not False:
            p.append(f"unchanged devices reported as changes: {str(payload)[:160]}")
    elif name == "get_unifi_placement_snapshot":
        topo = payload.get("topology") or []
        withheld = (payload.get("_withheld") or {}).get("topology.display_name") or {}
        for kind, suffix in (("protect_camera", "/cameras"), ("protect_sensor", "/sensors")):
            served = _served_once(up, suffix)
            want = len(served)
            nodes = [t for t in topo if isinstance(t, dict) and t.get("kind") == kind]
            if len(nodes) != want:
                p.append(f"{kind} {len(nodes)} != {want} served")
            # a served name is either projected or counted as withheld: never dropped silently
            named = sum(1 for r in served if isinstance(r, dict) and str(r.get("name") or ""))
            shown = sum(1 for t in nodes if t.get("display_name"))
            if shown + sum(withheld.values()) < named:
                p.append(f"{kind}: {named - shown} names dropped without a _withheld count")
    else:
        p.append("derived tool without a count check")
    return p


def test_every_derived_tool_has_a_count_check():
    assert all(
        _derived_problems(n, {}, uh.FakeUpstream()) != ["derived tool without a count check"]
        for n in DERIVED
    )


# =========================================================================== (b)
# Keep each large-body batch together on one xdist worker. Generated filler records
# stay lean so the memory cost tracks the body and consumer being checked.
def _large_innerspace_project() -> dict[str, Any]:
    """A documented project envelope with a large, verbatim device-shape array."""
    shapes = [
        {
            "type": "device",
            "id": f"device-{i}",
            "planId": "plan-1",
            "productId": "uap-probe",
            "probe": f"innerspace-device-{i}",
        }
        for i in range(LARGE_LIST_ITEMS)
    ]
    shapes[-1]["blob"] = "x" * (1024 * 1024 + 7)
    return {
        "data": {
            "shapes": shapes,
            "plans": [{"id": "plan-1", "title": "Survey floor", "ordering": 0}],
            "products": [{"id": "uap-probe"}],
            "wallTypes": [],
            "attenuationObjectTypes": [],
            "project": {"id": "project-1", "title": "Survey project"},
        }
    }


def _innerspace_large_body_problems(name: str, payload: Any, up: uh.FakeUpstream) -> list[str]:
    """Check complete large InnerSpace shape handling for each consumer contract."""
    consumers = {
        "get_innerspace_project",
        "get_innerspace_summary",
        "get_unifi_placement_snapshot",
        "list_innerspace_devices",
    }
    if name not in consumers:
        return []
    bodies = [
        s.body
        for s in up.served
        if 200 <= s.status < 300
        and s.path.endswith("/innerspace/integration/v1/project")
        and isinstance(s.body, dict)
    ]
    if len(bodies) != 1:
        return [f"expected one InnerSpace project response, got {len(bodies)}"]
    project = bodies[0].get("data", bodies[0])
    if not isinstance(project, dict) or not isinstance(project.get("shapes"), list):
        return ["served InnerSpace project has no shapes array"]
    shapes = project["shapes"]
    devices = [
        shape for shape in shapes if isinstance(shape, dict) and shape.get("type") == "device"
    ]
    if name in {"get_innerspace_project", "list_innerspace_devices"}:
        index = uh.PayloadIndex(payload)
        missing = [
            shape.get("probe", shape.get("id", "<unknown>"))
            for shape in devices
            if not index.contains(shape)
        ]
        return (
            [f"{len(missing)} of {len(devices)} device shapes dropped or altered"]
            if missing
            else []
        )
    if not isinstance(payload, dict):
        return ["InnerSpace derived result is not an object"]
    if name == "get_innerspace_summary":
        counts = payload.get("shape_counts")
        if payload.get("shape_total") != len(shapes):
            return [f"shape_total {payload.get('shape_total')} != {len(shapes)} served shapes"]
        if not isinstance(counts, dict) or counts.get("device") != len(devices):
            return [f"shape_counts.device does not represent all {len(devices)} device shapes"]
        return []
    unprojected = payload.get("_unprojected")
    record_counts = (
        unprojected.get("placed_devices.record") if isinstance(unprojected, dict) else None
    )
    count = record_counts.get("no_position") if isinstance(record_counts, dict) else None
    if count != len(devices):
        return [f"_unprojected placed devices {count} != {len(devices)} served shapes"]
    return []


# One case peaks near 1.9 GB RSS (a 10,000-entry list with a > 1 MB entry). Under
# pytest-xdist (CI: -n 4 --dist loadgroup) every case runs on ONE worker, so two of these
async def _eligible_b_large_bodies_return_complete(name):
    if name in NO_UPSTREAM:
        return False
    return True


# peaks never coincide inside the CI runner's memory limit. No effect without xdist.
@pytest.mark.xdist_group(name="large-bodies")
@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), max_batch=6, eligible=_eligible_b_large_bodies_return_complete
)
async def test_b_large_bodies_return_complete(monkeypatch, name, large_body_cache):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    prim = PRIMARY_RESOLUTION.get(name)
    up = uh.FakeUpstream(mode="big", big_items=LARGE_LIST_ITEMS, big_resolution=prim is not None)
    if name in {
        "get_innerspace_project",
        "get_innerspace_summary",
        "get_unifi_placement_snapshot",
        "list_innerspace_devices",
    }:
        up.project_body = _large_innerspace_project()
    res = await _call(monkeypatch, name, up)
    payload = uh.result_payload(res)
    innerspace_problems = _innerspace_large_body_problems(name, payload, up)
    assert innerspace_problems == [], f"{name}: " + "; ".join(innerspace_problems)
    # binary assets: the complete bytes, decoded exactly, no size cap
    assert _binary_problems(name, payload, up) == [], name
    if name in DERIVED:
        problems = _derived_problems(name, payload, up)
        assert problems == [], f"{name}: " + "; ".join(problems[:4])
        return
    if name in SELECT:
        assert _fidelity_violations(name, payload, up) == []
        return
    big_lists = 0
    for s in up.served:
        if not 200 <= s.status < 300 or isinstance(s.body, bytes | str):
            continue
        if s.resolution and not (prim and s.path.endswith(prim)):
            continue
        if any(a in s.path for a in AUXILIARY.get(name, ())):
            continue
        recs = uh.upstream_records(s.body)
        if len(recs) >= LARGE_LIST_ITEMS:
            if prim and s.resolution:
                wire_bytes = len(json.dumps(s.body, separators=(",", ":")).encode())
                assert wire_bytes <= 16 * 1024 * 1024, (
                    f"{name}: synthetic primary body is {wire_bytes} bytes"
                )
            big_lists += 1
            got = _probes(payload)
            missing = [
                r["probe"]
                for r in recs
                if isinstance(r, dict) and isinstance(r.get("probe"), str) and r["probe"] not in got
            ]
            assert missing == [], f"{name}: {len(missing)} of {len(recs)} items dropped"
        for r in recs:
            if isinstance(r, dict) and "blob" in r:
                assert uh.contains_text(payload, r["blob"]), f"{name}: >1 MB field truncated"
    if prim:
        # the enumeration tools are really served a LARGE_LIST_ITEMS list with a > 1 MB entry
        hit = [
            s
            for s in up.served
            if s.resolution
            and s.path.endswith(prim)
            and len(uh.upstream_records(s.body)) >= LARGE_LIST_ITEMS
            and any(isinstance(r, dict) and "blob" in r for r in uh.upstream_records(s.body))
        ]
        assert hit and big_lists, f"{name}: big enumeration scenario not exercised"


def _probes(obj: Any) -> set[str]:
    out: set[str] = set()
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            p = node.get("probe")
            if isinstance(p, str):
                out.add(p)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


# =========================================================================== (c)
_ERROR_STATUSES = (400, 403, 404, 500)


async def _eligible_c_upstream_error_body_verbatim(name):
    if name in NO_UPSTREAM:
        return False
    return True


@class_axis(
    "name",
    lambda: sorted(_lz_TOOLS()),
    status=lambda: _ERROR_STATUSES,
    eligible=_eligible_c_upstream_error_body_verbatim,
)
async def test_c_upstream_error_body_verbatim(monkeypatch, name, status):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    body = json.dumps(
        {
            "statusCode": status,
            "code": "api.probe-error",
            "message": f"probe reason {name}",
            "requestPath": "/probe/path",
            "detail": {"field": "x", "why": "upstream said so"},
        },
        separators=(",", ":"),
    )
    up = uh.FakeUpstream(
        mode="error",
        error_status=status,
        error_body=body,
        error_resolution=name in PRIMARY_RESOLUTION,
    )
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError as exc:
        assert body in str(exc), f"{name}: upstream {status} body not verbatim in: {exc}"
        return
    # Fan-out / per-item tools report the failure in the result instead of raising.
    payload = uh.result_payload(res)
    text = uh.all_strings(payload)
    leaves = _string_leaves(payload)
    parsed = json.loads(body)
    assert any(body in leaf for leaf in leaves) or uh.contains_record(payload, parsed), (
        f"{name}: upstream {status} was swallowed (no error, body absent): {text[:300]}"
    )


_NON_JSON_ERROR_BODIES = {
    "text": "upstream plain-text failure: request rejected without a JSON envelope",
    "empty": "",
    "huge": "upstream diagnostic: " + "x" * (1024 * 1024),
}


async def _eligible_c_non_json_error_bodies_reach_the_caller_verbatim(name):
    """Text, empty, and >1 MiB non-2xx bodies keep their original bytes for every tool.

    The JSON-only companion above cannot detect a client path that parses, masks, or
    truncates arbitrary error content before the MCP caller receives it.
    """
    if name in NO_UPSTREAM:
        return False
    return True


@class_axis(
    "name",
    lambda: sorted(_lz_TOOLS()),
    body_kind=lambda: sorted(_NON_JSON_ERROR_BODIES),
    eligible=_eligible_c_non_json_error_bodies_reach_the_caller_verbatim,
)
async def test_c_non_json_error_bodies_reach_the_caller_verbatim(monkeypatch, name, body_kind):
    """Text, empty, and >1 MiB non-2xx bodies keep their original bytes for every tool.

    The JSON-only companion above cannot detect a client path that parses, masks, or
    truncates arbitrary error content before the MCP caller receives it.
    """
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    body = _NON_JSON_ERROR_BODIES[body_kind]
    up = uh.FakeUpstream(
        mode="error",
        error_status=500,
        error_body=body,
        error_resolution=name in PRIMARY_RESOLUTION,
    )
    try:
        result = await _call(monkeypatch, name, up)
    except ToolError as exc:
        caller_text = str(exc)
    else:
        caller_text = uh.all_strings(uh.result_payload(result))
    assert up.served, f"{name}: no upstream request was made"
    assert any(s.status == 500 and s.body == body for s in up.served), name
    assert body in caller_text, f"{name}: {body_kind} error body was rewritten or masked"


def _string_leaves(obj: Any) -> list[str]:
    out: list[str] = []
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


# =========================================================================== (d)
@functools.cache
def _lz_HOST_TOOLS():
    return sorted(
        n for n, t in _lz_TOOLS().items() if "host" in (t.parameters.get("properties") or {})
    )


@functools.cache
def _lz_SITE_TOOLS():
    return sorted(
        n for n, t in _lz_TOOLS().items() if "site" in (t.parameters.get("properties") or {})
    )


@tool_batches("name", lambda: _lz_HOST_TOOLS())
async def test_d_unknown_host_lists_valid_choices(monkeypatch, name):
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), "host": "no-such-console"}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert "no-such-console" in str(exc.value), name
    assert uh.HOST in str(exc.value), f"{name}: valid console not listed: {exc.value}"
    assert up.writes() == [], name


@tool_batches("name", lambda: _lz_SITE_TOOLS())
async def test_d_unknown_site_lists_valid_choices(monkeypatch, name):
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), "site": "no-such-site"}
    if "host" in (_lz_TOOLS()[name].parameters.get("properties") or {}):
        args.setdefault("host", uh.HOST)
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    msg = str(exc.value)
    assert "no-such-site" in msg, name
    assert "Default" in msg or "default" in msg, f"{name}: valid sites not listed: {msg}"
    assert up.writes() == [], name


def _twin_hosts() -> list[dict]:
    twin = json.loads(json.dumps(uh.HOST_RECORD))
    twin["id"] = "0" * 54 + "FA0099:0000000099"
    return [uh.HOST_RECORD, twin]


@tool_batches("name", lambda: _lz_HOST_TOOLS())
async def test_d_ambiguous_host_fails_fast_listing_matches(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key={"k-test": _twin_hosts()})
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), "host": uh.HOST}
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    msg = str(exc.value)
    assert uh.HOST_ID in msg and "FA0099:0000000099" in msg, f"{name}: {msg}"
    assert up.writes() == []


# =========================================================================== (e)
@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_e_write_refused_at_chokepoint_when_read_only(monkeypatch, name):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, env={read_only.ENV_VAR: "1"})
    assert read_only.ENV_VAR in str(exc.value), f"{name}: {exc.value}"
    assert up.writes() == [], f"{name}: write reached the transport under read-only"


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_e_write_reaches_a_write_verb_by_default(monkeypatch, name):
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up)
    assert up.writes(), f"{name}: no write verb reached the transport (route not proven)"


# =========================================================================== (f)
_TOOLISH = re.compile(
    r"(?<![\w./{-])((?:list|get|create|update|delete|set|search|collect|query|compare|"
    r"fabric_connector|block|unblock|adopt|unadopt|enable|disable|siren|relay|speaker|"
    r"alarm_hub|ptz|start|patch|allow|exclude|bulk|execute|restart|locate|upgrade|"
    r"approve|reject|reconnect|attach|detach|assign|suspend|resume|pos|trigger|upload)"
    r"_[a-z0-9_]+)(?![\w(-])"
)
# Words in descriptions that look like tool names but name API fields/values.
_NOT_TOOLS = {
    "get_settings",
    # named explicitly as aliases that do NOT exist ("there is no `list_vouchers`")
    "list_vouchers",
    "get_voucher",
}


def _all_descriptions() -> list[tuple[str, str]]:
    out = [("INSTRUCTIONS", server.INSTRUCTIONS)]
    for name, tool in _lz_TOOLS().items():
        out.append((name, tool.description or ""))
        for pname, prop in (tool.parameters.get("properties") or {}).items():
            out.append((f"{name}.{pname}", str(prop.get("description") or "")))
    return out


def test_f_every_tool_reference_is_registered():
    phantom = []
    for where, text in _all_descriptions():
        for m in _TOOLISH.finditer(text):
            ref = m.group(1).rstrip("_")
            if ref in _lz_TOOLS() or ref in _NOT_TOOLS or ref.endswith("_id"):
                continue
            if any(t.startswith(ref + "_") or t == ref for t in _lz_TOOLS()):
                continue
            if (
                f"`{ref}`" in text
                or re.search(rf"\b{ref}\s*\(", text)
                or re.search(rf"(use|call|from|see|via|with|to)\s+`?{ref}\b", text, re.I)
            ):
                phantom.append(f"{where}: {ref}")
    assert phantom == [], f"descriptions reference unregistered tools: {phantom}"


_GET_IT_FROM = re.compile(r"[Gg]et (?:it|them|one|ids?) from `?([a-z_]+)`?")


def test_f_get_it_from_handoffs_name_real_tools():
    bad = [
        f"{where}: {m.group(1)}"
        for where, text in _all_descriptions()
        for m in _GET_IT_FROM.finditer(text)
        if m.group(1) not in _lz_TOOLS()
    ]
    assert bad == []


def test_f_examples_validate_against_the_input_schema():
    from unifi_fabric.argument_errors import _example_from_description

    bad = []
    seen = 0
    for name, tool in _lz_TOOLS().items():
        example = _example_from_description(tool.description or "")
        if example is None:
            continue
        seen += 1
        schema = dict(tool.parameters)
        schema["additionalProperties"] = False
        try:
            jsonschema.validate(json.loads(example), schema)
        except jsonschema.ValidationError as exc:
            bad.append(f"{name}: {exc.message}")
    assert seen >= 50
    assert bad == []


_MARKUP = re.compile(r"\]\(https?://|!\[|&lt;|&gt;|&amp;|</?[a-zA-Z][^>]*>")


def test_f_readme_confirm_count_matches_the_registry():
    """The count in docs/COVERAGE.md of tools that accept the ignored ``confirm`` parameter is the
    number of registered tools whose input schema has it (it said 11 while 43 did)."""
    from pathlib import Path

    readme = (Path(__file__).resolve().parents[1] / "docs" / "COVERAGE.md").read_text()
    stated = re.findall(r"(\d+) write and action tools[^\n]*?accept an optional `confirm`", readme)
    actual = sum("confirm" in (t.parameters.get("properties") or {}) for t in _lz_TOOLS().values())
    assert stated, "docs/COVERAGE.md no longer states how many tools accept confirm"
    assert {int(n) for n in stated} == {actual}, (
        f"docs/COVERAGE.md says {stated}, registry has {actual}"
    )


def test_f_no_markdown_link_or_html_markup_in_tool_descriptions():
    bad = [where for where, text in _all_descriptions()[1:] if _MARKUP.search(text)]
    assert bad == []


# =========================================================================== (g)
#: Name twins (get_X / update_X) whose update takes no record: nothing read is fed back,
#: so there is no round trip to check. Each reason cites the update's signature.
_SCALAR_TWIN_UPDATES = {
    "update_protect_device_password": (
        "takes the password string (device_password) and sends {devicePassword}; "
        "the read record is never its argument"
    ),
}


def _round_trip_pairs() -> list[tuple[str, str]]:
    from tests.test_return_shapes import READ_TO_WRITE

    pairs = dict(READ_TO_WRITE)
    for name in _lz_TOOLS():
        if name.startswith("get_"):
            twin = "update_" + name[4:]
            if twin in _lz_TOOLS() and twin not in _SCALAR_TWIN_UPDATES:
                pairs.setdefault(name, twin)
    return sorted(pairs.items())


def test_g_scalar_twin_updates_take_no_object():
    """An exempt twin really takes no object parameter (an exemption cannot go stale)."""
    assert "update_protect_device_password" in _SCALAR_TWIN_UPDATES
    for name in _SCALAR_TWIN_UPDATES:
        assert _object_param(_lz_TOOLS()[name]) is None, name


def _object_param(tool: Any) -> str | None:
    """The write tool's object-typed parameter that takes the record (required first)."""
    props = tool.parameters.get("properties") or {}
    required = list(tool.parameters.get("required", []))
    for pname in required + [p for p in props if p not in required]:
        spec = props.get(pname, {})
        types = {spec.get("type")} | {s.get("type") for s in spec.get("anyOf", [])}
        if "object" in types:
            return pname
    return None


def _keys(obj: Any) -> set[str]:
    out: set[str] = set()
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            out |= set(node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


# Read scenarios for the round trip. "aux_fail" fails the auxiliary reads a tool adds
# to its result (the WAN health read, the port-profile network-name lookup), so the
# read reports that failure under its own additive ``_`` key.
_ROUND_TRIP_SCENARIOS: dict[str, dict[str, Any]] = {
    "normal": {},
    "aux_fail": {"fail_paths": ("/stat/health", "/rest/networkconf")},
}
_RESULT_FRAMING = uh.FRAMING | {"incomplete", "incompleteReason"}
_RENAMED = "probe-renamed"


def _record_of(payload: Any) -> Any:
    """The object a caller would edit and feed back: the record, out of a list envelope
    (``{"result": [...]}``, ``{data, totalCount}``, or the Classic REST ``{meta, data}``
    whose documented hand-off is "edit data[0]")."""
    obj = payload
    for wrapper in ("result", "data"):
        if isinstance(obj, dict) and wrapper in obj and set(obj) - {wrapper} <= _RESULT_FRAMING:
            obj = obj[wrapper]
    if isinstance(obj, list):
        obj = obj[0] if obj else {}
    return obj


async def _round_trip(monkeypatch, read_tool: str, write_tool: str, scenario: str) -> dict:
    """get -> modify one field -> update; what the read added and what the write sent."""
    read_up = uh.FakeUpstream(**_ROUND_TRIP_SCENARIOS[scenario])
    payload = uh.result_payload(await _call(monkeypatch, read_tool, read_up))
    upstream_keys = set().union(
        *[
            _keys(s.body)
            for s in read_up.served
            if s.body is not None and not isinstance(s.body, bytes | str)
        ]
    )
    added = {k for k in _keys(payload) if k.startswith("_") and k not in upstream_keys}
    obj = _record_of(payload)
    if isinstance(obj, dict):
        obj = {**obj, "name": _RENAMED}
    param = _object_param(_lz_TOOLS()[write_tool])
    args = tool_args.generated_args(_lz_TOOLS()[write_tool])
    if param is not None:
        args[param] = obj
    if write_tool == "update_device_tag" and isinstance(obj, dict) and obj.get("_id"):
        # Membership conversion must edit the tag read, not a generated other target.
        args["tag_id"] = obj["_id"]
    if write_tool == "update_port_profile" and isinstance(obj, dict):
        # The read and the write are served by separate harness controllers, and the write
        # resolves networkconf id fields against its own /rest/networkconf, which holds none
        # of the read's ids (one controller in practice; the resolution has its own tests in
        # test_network_services_proxy). The additive keys under test stay in the record.
        obj = {
            k: v
            for k, v in obj.items()
            if k
            not in ("native_networkconf_id", "voice_networkconf_id", "excluded_networkconf_ids")
        }
        args[param or "payload"] = obj
    write_up = uh.FakeUpstream()
    await _call(monkeypatch, write_tool, write_up, args)
    sent = [w.sent_json for w in write_up.writes() if w.sent_json is not None]
    return {
        "added": added,
        "added_to_record": {k for k in added if isinstance(obj, dict) and k in obj},
        "param": param,
        "writes": write_up.writes(),
        "sent": sent,
        "leaked": sorted(added & set().union(*[_keys(b) for b in sent])) if sent else [],
        "reached": any(_RENAMED in uh.all_strings(b) for b in sent),
    }


@lazy_parametrize("scenario", lambda: sorted(_ROUND_TRIP_SCENARIOS))
@lazy_parametrize("read_tool,write_tool", lambda: _round_trip_pairs())
async def test_g_additive_keys_never_written_back(monkeypatch, read_tool, write_tool, scenario):
    rt = await _round_trip(monkeypatch, read_tool, write_tool, scenario)
    assert rt["param"] is not None, f"{write_tool}: no object parameter takes the read result"
    assert rt["writes"], f"{write_tool}: no write reached the transport"
    assert rt["reached"], f"{read_tool}->{write_tool}: the edited record never reached the write"
    assert rt["leaked"] == [], f"{read_tool}->{write_tool} sent additive keys back: {rt['leaked']}"


#: How each scalar twin writes: (scalar argument, body key, method, path suffix). The read
#: twin's record is never fed back; the write must send the scalar alone.
_SCALAR_TWIN_WRITES = {
    "update_protect_device_password": (
        "device_password",
        "devicePassword",
        "PATCH",
        "/nvr/device-password",
    ),
}
_SCALAR_TWIN_VALUE = "probe-scalar-twin-value"


def _scalar_twin_pairs() -> list[tuple[str, str]]:
    return sorted(("get_" + name.removeprefix("update_"), name) for name in _SCALAR_TWIN_WRITES)


def test_g_every_scalar_twin_has_a_write_contract():
    assert set(_SCALAR_TWIN_WRITES) == set(_SCALAR_TWIN_UPDATES)
    for read_tool, write_tool in _scalar_twin_pairs():
        assert read_tool in _lz_TOOLS() and write_tool in _lz_TOOLS(), (read_tool, write_tool)


@lazy_parametrize("scenario", lambda: sorted(_ROUND_TRIP_SCENARIOS))
@lazy_parametrize("read_tool,write_tool", lambda: _scalar_twin_pairs())
async def test_g_scalar_twin_sends_only_its_scalar(monkeypatch, read_tool, write_tool, scenario):
    """get -> update of a scalar twin: the update sends exactly its one scalar field, so
    nothing the read added (or any other read field) is written back."""
    read_up = uh.FakeUpstream(**_ROUND_TRIP_SCENARIOS[scenario])
    payload = uh.result_payload(await _call(monkeypatch, read_tool, read_up))
    assert [s for s in read_up.served if not s.resolution], f"{read_tool}: no read was sent"
    assert payload is not None, f"{read_tool}: empty read result"
    param, key, method, suffix = _SCALAR_TWIN_WRITES[write_tool]
    args = tool_args.generated_args(_lz_TOOLS()[write_tool])
    args[param] = _SCALAR_TWIN_VALUE
    write_up = uh.FakeUpstream()
    await _call(monkeypatch, write_tool, write_up, args)
    writes = write_up.writes()
    assert [(w.method, w.path.endswith(suffix)) for w in writes] == [(method, True)], [
        (w.method, w.path) for w in writes
    ]
    assert writes[0].sent_json == {key: _SCALAR_TWIN_VALUE}, writes[0].sent_json


async def test_g_round_trips_carry_additive_keys(monkeypatch):
    """Property (g) is not vacuous: real reads add ``_`` keys to the very record that is
    fed into the write (so only the write-side strip keeps them from going upstream)."""
    added: dict[tuple[str, str, str], set[str]] = {}
    for read_tool, write_tool in _round_trip_pairs():
        for scenario in _ROUND_TRIP_SCENARIOS:
            rt = await _round_trip(monkeypatch, read_tool, write_tool, scenario)
            if rt["added_to_record"]:
                added[(read_tool, write_tool, scenario)] = rt["added_to_record"]
    assert added, "no round-trip read added a _ key to the record it hands to the write"
    seen = set().union(*added.values())
    assert {"_resolved_networks", "_resolvedNetworksError", "_wanHealthError"} <= seen, seen


async def _eligible_h_multi_page_lists_fully_drained(name):
    if name in MULTI_SOURCE_COMPOSITE:
        return False
    if name in NO_UPSTREAM:
        return False
    return True


# =========================================================================== (h)
@tool_batches("name", lambda: _lz_READ_TOOLS(), eligible=_eligible_h_multi_page_lists_fully_drained)
async def test_h_multi_page_lists_fully_drained(monkeypatch, name):
    if name in MULTI_SOURCE_COMPOSITE:
        raise AssertionError("inapplicable case was not filtered before batching")
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged")
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    if name in DERIVED:
        problems = _derived_problems(name, payload, up)
    else:
        problems = _fidelity_violations(name, payload, up)
    # every paged query the tool started was read to its FINAL page (every family:
    # Integration offset, Site Manager nextToken, Carrier cursor, Mobility / Protect
    # events offset, Protect recognition page/links.next, the enumeration lists) -
    # not only "the records served came back", which a first-page-only drain passes
    if name not in RAW_RELAY:  # a relay forwards exactly the one request asked for
        problems += up.undrained()
    assert problems == [], f"{name}: " + "; ".join(problems[:4])
    # every mention of "incomplete" is an "incomplete": false flag (one false flag
    # elsewhere in the payload no longer excuses a true one)
    assert "incomplete" not in uh.all_strings(payload).replace('"incomplete": false', ""), (
        f"{name}: incomplete without a cap"
    )


_PAGING_PARAMS = ("offset", "nextToken", "page")


def _drained_paths(up: uh.FakeUpstream) -> set[str]:
    """Paths the tool read as >= 3 distinct pages of one query (re-polling is not paging).

    A cursor protocol's first page carries no cursor (Site Manager ``/v1/devices`` sends
    only ``pageSize``, then ``nextToken=p1``, ``p2``), so the cursorless request counts as
    one page of its query; re-polling the same request is still one page.
    """
    from urllib.parse import parse_qsl

    pages: dict[tuple[str, str], set[str]] = {}
    for s in up.served:
        if s.resolution:
            continue
        params = dict(parse_qsl(s.query))
        cursor = tuple(params.pop(p, "") for p in _PAGING_PARAMS)
        rest = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        pages.setdefault((s.path, rest), set()).add("|".join(cursor))
    return {path for (path, _rest), cur in pages.items() if len(cur) >= 3}


#: A NAME resolved against an incomplete (capped) host/site list is refused with
#: this error (a twin past the cap could exist); only an exact id resolves there.
_UNAMBIGUOUS = "unambiguously"
_EA_SITE_ID: str = uh.recorded("site_manager/v1_sites.json")["body"]["data"][0]["siteId"]


async def _call_capped(monkeypatch, name: str, make_up, env: dict[str, str]):
    """Call ``name`` with a capped list; a name refused as ambiguous-under-cap is retried
    with the exact ids (console id; console-site UUID, else the Site Manager siteId).

    Returns ``(result, upstream)``. The refusal itself must come before any write.
    """
    up = make_up()
    try:
        return await _call(monkeypatch, name, up, env=env), up
    except ToolError as exc:
        if _UNAMBIGUOUS not in str(exc):
            raise
        assert "UNIFI_PAGINATE_MAX_PAGES" in str(exc), f"{name}: {exc}"
        assert not up.writes(), f"{name}: write sent before the ambiguous-name refusal"
        refusal = exc
    args = tool_args.generated_args(_lz_TOOLS()[name])
    if name == "fabric_connector_get":
        args["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
    if "host" in args:
        args["host"] = uh.HOST_ID
    last: Exception = refusal
    for site_id in (uh.SITE_ID, _EA_SITE_ID) if "site" in args else (None,):
        if site_id is not None:
            args["site"] = site_id
        if name == "compare_site_performance":
            args["sites"] = [_EA_SITE_ID]
        up = make_up()
        try:
            return await _call(monkeypatch, name, up, args, env=env), up
        except ToolError as exc:
            last = exc
    raise last


# Reads that fetch one document rather than a paged list: no page cap applies, so the
# property for them is that the read is one request and drains nothing.
SINGLE_DOCUMENT_READS = {
    "get_innerspace_project": "one GET of the InnerSpace project document",
    "get_innerspace_summary": "a summary computed from one GET of the project document",
    "list_innerspace_devices": "devices taken from one GET of the project document",
}


def test_h_single_document_reads_are_read_tools():
    assert set(SINGLE_DOCUMENT_READS) <= set(_lz_READ_TOOLS())


async def _eligible_h_page_cap_is_explicit(monkeypatch, name):
    if name in NO_UPSTREAM:
        return False
    probe = uh.FakeUpstream(mode="paged")
    await _call(monkeypatch, name, probe)
    if name in SINGLE_DOCUMENT_READS:
        reads = [s.path for s in probe.served if not s.resolution]
        assert not _drained_paths(probe), f"{name}: a single-document read drained pages"
        assert len(reads) == 1, f"{name}: expected one document request, sent {reads}"
        return True
    if not _drained_paths(probe):
        return False
    return True


@tool_batches("name", lambda: _lz_READ_TOOLS(), eligible=_eligible_h_page_cap_is_explicit)
async def test_h_page_cap_is_explicit(monkeypatch, name):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    probe = uh.FakeUpstream(mode="paged")
    await _call(monkeypatch, name, probe)
    if name in SINGLE_DOCUMENT_READS:
        reads = [s.path for s in probe.served if not s.resolution]
        assert not _drained_paths(probe), f"{name}: a single-document read drained pages"
        assert len(reads) == 1, f"{name}: expected one document request, sent {reads}"
        return
    if not _drained_paths(probe):
        raise AssertionError("inapplicable case was not filtered before batching")
    try:
        res, up = await _call_capped(
            monkeypatch,
            name,
            lambda: uh.FakeUpstream(mode="paged"),
            {"UNIFI_PAGINATE_MAX_PAGES": "2"},
        )
    except ToolError as exc:
        pytest.fail(f"{name}: capped drain raised instead of returning partial: {exc}")
    if name in SELECT_BY_ID:
        # the target is on the gathered pages: it comes back verbatim, no failure
        problems = _fidelity_violations(name, uh.result_payload(res), up)
        assert problems == [], f"{name}: " + "; ".join(problems[:3])
        return
    text = uh.all_strings(uh.result_payload(res))
    assert '"incomplete": true' in text, f"{name}: capped drain not flagged incomplete"
    first_page = [s for s in up.served if not s.resolution and 200 <= s.status < 300]
    gathered = [r for s in first_page[:1] for r in uh.upstream_records(s.body)]
    assert gathered, f"{name}: the capped drain gathered no records (property vacuous)"
    got = _probes(uh.result_payload(res))
    for rec in gathered:
        if isinstance(rec, dict) and "probe" in rec and name not in set(SELECT) | set(DERIVED):
            assert rec["probe"] in got, f"{name}: gathered items dropped on cap"


# Selection tools that pick ONE record by id out of a drained list (the rest of SELECT
# filter a list and return every match, so a capped drain must flag the result).
SELECT_BY_ID = {
    "get_arm_profile": "arm_profile_id",
    "get_vpn_server": "server_id",
    "get_radius_profile": "profile_id",
    "get_wlan_group": "group_id",
    "get_client_link_diagnostics": "client_id",
    "get_setting": "setting_key",
    "get_device_port_state": "device_id",
    "get_device_stp_state": "device_id",
    "get_traffic_route": "route_id",
    "get_ap_group": "group_id",
}


async def _eligible_capped_lookup(monkeypatch, name):
    probe = uh.FakeUpstream(mode="paged")
    await _call(monkeypatch, name, probe)
    return bool(_drained_paths(probe))


@tool_batches("name", lambda: sorted(SELECT_BY_ID), eligible=_eligible_capped_lookup)
async def test_h_capped_lookup_miss_says_list_incomplete(monkeypatch, name):
    """A by-id selection whose target is NOT on the pages a capped drain gathered fails
    saying the list was incomplete (never a bare "not found" that reads as definitive)."""
    probe = uh.FakeUpstream(mode="paged")
    await _call(monkeypatch, name, probe)
    assert _drained_paths(probe), f"{name}: selected lookup no longer drains a list"
    args = tool_args.generated_args(_lz_TOOLS()[name])
    param = SELECT_BY_ID[name]
    args[param] = {
        uh.ARG_ID: "00000000-0000-4000-8000-00000000ffff",
        uh.ARG_HEX: "ffffffffffffffffffffffff",
        uh.ARG_MAC: "02:00:5e:ff:ff:ff",
    }.get(args[param], "absent-probe-key")
    up = uh.FakeUpstream(mode="paged")
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args, env={"UNIFI_PAGINATE_MAX_PAGES": "2"})
    msg = str(exc.value).lower()
    assert "incomplete" in msg or "unifi_paginate_max_pages" in msg or "cap" in msg, (
        f"{name}: capped-drain miss reads as definitive: {exc.value}"
    )


def test_h_select_by_id_names_real_selection_tools():
    assert set(SELECT_BY_ID) <= set(SELECT)
    for name, param in SELECT_BY_ID.items():
        assert param in (_lz_TOOLS()[name].parameters.get("properties") or {}), name


# Tools whose result enumerates (or resolves a name against) the console or Site Manager
# site list: when only that list is capped, the result must say it is incomplete.
ENUMERATING = {
    "list_hosts": "returns the console list itself",
    "list_sites": "returns the Site Manager site list itself",
    "list_all_sites_aggregated": "returns the Site Manager site list with health",
    "get_fleet_summary": "counts the drained console and site lists",
    "list_all_clients": "fans out over every site in the Site Manager site list",
    "search_across_sites": "searches every site in the Site Manager site list",
}

#: Tools that resolve an exact siteId against the Site Manager site list: an id is
#: unique, so a capped list cannot hide a second match and the result is NOT incomplete
#: (a NAME there is refused instead, see ``_call_capped``).
EXACT_ID_ON_CAPPED_LIST = {
    "get_site_health_summary": "resolves the siteId against the Site Manager site list",
    "get_site_inventory": "resolves the siteId against the Site Manager site list",
    "compare_site_performance": "resolves each siteId against the Site Manager site list",
}


async def _eligible_h_enumeration_cap_is_explicit(name):
    """Only the console / site enumeration lists are paged and capped: no tool - read or
    write - fails when given exact ids (the target is on the pages gathered), a name is
    refused as unresolvable-under-cap before any write, a write tool still
    reaches its write verb, and every enumerating tool flags its result."""
    if name in NO_UPSTREAM:
        return False
    return True


@tool_batches("name", lambda: sorted(_lz_TOOLS()), eligible=_eligible_h_enumeration_cap_is_explicit)
async def test_h_enumeration_cap_is_explicit(monkeypatch, name):
    """Only the console / site enumeration lists are paged and capped: no tool - read or
    write - fails when given exact ids (the target is on the pages gathered), a name is
    refused as unresolvable-under-cap before any write, a write tool still
    reaches its write verb, and every enumerating tool flags its result."""
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    try:
        res, up = await _call_capped(
            monkeypatch,
            name,
            lambda: uh.FakeUpstream(page_resolution=True),
            {"UNIFI_PAGINATE_MAX_PAGES": "2"},
        )
    except ToolError as exc:
        pytest.fail(f"{name}: a capped enumeration list made the tool fail: {exc}")
    if name in _lz_WRITE_TOOLS():
        assert up.writes(), f"{name}: no write verb reached under a capped enumeration list"
    if name in EXACT_ID_ON_CAPPED_LIST:
        text = uh.all_strings(uh.result_payload(res))
        assert '"incomplete": true' not in text and '"_incomplete": true' not in text, (
            f"{name}: an exact siteId on a capped list is a complete resolution"
        )
        assert '"_incompleteReason"' not in text and '"incompleteReason"' not in text
        return
    if name not in ENUMERATING:
        return
    text = uh.all_strings(uh.result_payload(res))
    assert '"incomplete": true' in text or '"_incompleteReason"' in text, (
        f"{name}: capped site/console list not flagged incomplete: {text[:200]}"
    )


#: Tools taking a console or site NAME (generated args), for h2.
@functools.cache
def _lz__NAME_RESOLVING():
    return sorted(
        n for n, t in _lz_TOOLS().items() if {"host", "site"} & set(tool_args.generated_args(t))
    )


@class_axis("name", lambda: _lz__NAME_RESOLVING(), ttl=lambda: ["0", "900"])
async def test_h2_name_refused_under_cap_at_every_cache_ttl(monkeypatch, name, ttl):
    """The incomplete state lives with the fetched list, never in a TTL marker: a
    console/site NAME is refused against a capped enumeration list before any write, with
    UNIFI_CACHE_TTL_SECONDS=0 (no cache) exactly as with 900."""
    up = uh.FakeUpstream(page_resolution=True)
    env = {"UNIFI_PAGINATE_MAX_PAGES": "2", "UNIFI_CACHE_TTL_SECONDS": ttl}
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, env=env)
    assert _UNAMBIGUOUS in str(exc.value), f"{name} (ttl {ttl}): {exc.value}"
    assert not up.writes(), f"{name} (ttl {ttl}): write sent before the refusal"


async def _eligible_h2_no_cache_mode_completes(monkeypatch, name):
    """With UNIFI_CACHE_TTL_SECONDS=0 every tool completes on complete lists: a fetched
    list is used directly, never re-read from a cache entry that has already expired."""
    if name in NO_UPSTREAM:
        return False
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, env={"UNIFI_CACHE_TTL_SECONDS": "0"})
    if name in MULTI_SOURCE_COMPOSITE:
        return False
    return True


@tool_batches("name", lambda: sorted(_lz_TOOLS()), eligible=_eligible_h2_no_cache_mode_completes)
async def test_h2_no_cache_mode_completes(monkeypatch, name):
    """With UNIFI_CACHE_TTL_SECONDS=0 every tool completes on complete lists: a fetched
    list is used directly, never re-read from a cache entry that has already expired."""
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, env={"UNIFI_CACHE_TTL_SECONDS": "0"})

    if name in MULTI_SOURCE_COMPOSITE:
        raise AssertionError("inapplicable case was not filtered before batching")


async def _eligible_h_short_pages_drain_to_total_count(name):
    """An upstream that serves fewer items than requested (clamped page size) while its
    totalCount says more must still be drained to totalCount, or flagged incomplete."""
    if name in NO_UPSTREAM or name in RAW_RELAY:
        return False
    return True


@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_h_short_pages_drain_to_total_count
)
async def test_h_short_pages_drain_to_total_count(monkeypatch, name):
    """An upstream that serves fewer items than requested (clamped page size) while its
    totalCount says more must still be drained to totalCount, or flagged incomplete."""
    if name in NO_UPSTREAM or name in RAW_RELAY:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged", clamp_limit=7)
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    text = uh.all_strings(payload)
    if '"incomplete": true' in text:
        return
    if name in DERIVED:
        # a derived view must be computed from the whole list: every item up to
        # totalCount was read from the upstream, and the rollup matches what was read
        problems = _derived_problems(name, payload, up) + _undrained_totals(up)
    else:
        problems = _fidelity_violations(name, payload, up)
    served_offsets = [s for s in up.served if family_is_integration(s.path) and not s.resolution]
    for s in served_offsets:
        body = s.body if isinstance(s.body, dict) else {}
        total = body.get("totalCount")
        if isinstance(total, int):
            got = _probes(payload)
            want = {f"{s.path}#{i}" for i in range(total)}
            if name not in SELECT and name not in DERIVED and not want <= got:
                problems.append(f"{s.path}: {len(want - got)} of {total} items silently dropped")
            break
    assert problems == [], f"{name}: " + "; ".join(problems[:3])


def _undrained_totals(up: uh.FakeUpstream) -> list[str]:
    """Integration lists whose served pages stopped short of their totalCount."""
    seen: dict[str, set[str]] = {}
    totals: dict[str, int] = {}
    for s in up.served:
        if s.resolution or not family_is_integration(s.path) or not isinstance(s.body, dict):
            continue
        if isinstance(s.body.get("totalCount"), int):
            totals[s.path] = s.body["totalCount"]
            seen.setdefault(s.path, set()).update(_probes(s.body))
    return [
        f"{path}: read {len(seen[path])} of {total} items"
        for path, total in totals.items()
        if len(seen[path]) < total
    ]


def family_is_integration(path: str) -> bool:
    return uh.family(path) == "integration"


async def _eligible_h_ignored_offset_never_silently_duplicates(name):
    """An upstream that ignores offset (always page one) must not loop forever or return
    duplicated pages as if complete: the result is an error or flagged incomplete."""
    if name in NO_UPSTREAM or name in RAW_RELAY:
        return False
    return True


@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_h_ignored_offset_never_silently_duplicates
)
async def test_h_ignored_offset_never_silently_duplicates(monkeypatch, name):
    """An upstream that ignores offset (always page one) must not loop forever or return
    duplicated pages as if complete: the result is an error or flagged incomplete."""
    if name in NO_UPSTREAM or name in RAW_RELAY:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged", ignore_offset=True)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return
    payload = uh.result_payload(res)
    if '"incomplete": true' in uh.all_strings(payload):
        return
    if name in DERIVED:
        # a derived view never counts a repeated page: if the drain read the same page
        # twice it must have said so (error or incomplete), which it did not
        repeated = [
            s.path
            for s in up.served
            if family_is_integration(s.path)
            and not s.resolution
            and "offset=" in s.query
            and not re.search(r"(^|&)offset=0(&|\Z)", s.query)
        ]
        assert repeated == [], f"{name}: derived view built over repeated pages {repeated[:2]}"
        return
    probes: list[str] = []
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if isinstance(node.get("probe"), str) and "/integration/" in node["probe"]:
                probes.append(node["probe"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    dupes = len(probes) - len(set(probes))
    assert dupes == 0, f"{name}: {dupes} duplicated items returned as a complete result"


async def _eligible_j_fan_out_completes_beyond_concurrency(name):
    """Every tool completes when it fans out to more consoles/sites (14) than
    UNIFI_MAX_CONCURRENCY (10): no nested gather/semaphore deadlock."""
    if name in NO_UPSTREAM:
        return False
    return True


# =========================================================================== (j)
@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_j_fan_out_completes_beyond_concurrency
)
async def test_j_fan_out_completes_beyond_concurrency(monkeypatch, name):
    """Every tool completes when it fans out to more consoles/sites (14) than
    UNIFI_MAX_CONCURRENCY (10): no nested gather/semaphore deadlock."""
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(site_count=14)
    args = tool_args.generated_args(_lz_TOOLS()[name])
    if name == "compare_site_performance":
        args["sites"] = [uh.SITE] + [f"fanout{i}" for i in range(1, 14)]
    await _call(monkeypatch, name, up, args, env={"UNIFI_MAX_CONCURRENCY": "10"})


# =========================================================================== (i)
def _two_key_hosts() -> dict[str, list[dict]]:
    beta = json.loads(json.dumps(uh.HOST_RECORD))
    beta["id"] = "0" * 54 + "FB0002:0000000002"
    beta["reportedState"] = dict(beta["reportedState"], hostname="beta-console", name="beta")
    return {"k-alpha": [uh.HOST_RECORD], "k-beta": [beta]}


_KEYS = [
    APIKeyConfig(key="k-alpha", label="alpha"),
    APIKeyConfig(key="k-beta", label="beta", is_org_key=True),
]
_KEY_IDS = ("k-alpha", "k-beta")


def _keys_used(name: str, up: uh.FakeUpstream) -> set[str]:
    """API keys the tool's own requests rode (registry resolution excluded, except for
    the tools whose result IS the resolution list)."""
    prim = PRIMARY_RESOLUTION.get(name)
    return {s.api_key for s in up.served if not s.resolution or (prim and s.path.endswith(prim))}


# Observed behaviour, not a hand-picked list: a tool is multi-key when, run under two API
# keys, its own requests use both. Membership is derived before batching; a baseline
# error fails selection rather than silently removing the tool from coverage.
_MULTI_KEY_SEEN: dict[str, bool] = {}


async def _is_multi_key(name: str) -> bool:
    if name in NO_UPSTREAM:
        return False
    if name not in _MULTI_KEY_SEEN:
        from unifi_fabric import server as production_server  # never the discovery proxy

        up = uh.FakeUpstream(hosts_by_key=_two_key_hosts())
        mp = pytest.MonkeyPatch()
        previous = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        try:
            for k, v in tool_args.TOOL_ENV.get(name, {}).items():
                mp.setenv(k, v)
            uh.install(mp, up, keys=_KEYS)
            tool_args.prepare_upstream(name, up)
            args = sc.conformance_args(name)
            # Site names repeat under two keys. A canonical site ID selects
            # one owner without swallowing the ambiguous-name baseline error.
            if name in {
                "compare_site_performance",
                "get_site_health_summary",
                "get_site_inventory",
            }:
                host_id = uh.HOST_RECORD["id"]
                site_id = "aa" + host_id[-22:].replace(":", "0").lower().rjust(22, "0")
                args["sites" if name == "compare_site_performance" else "site"] = (
                    [site_id] if name == "compare_site_performance" else site_id
                )
            if name == "create_carrier_subscriber":
                args["key_label"] = "alpha"
            await production_server.mcp.call_tool(name, args)
        finally:
            mp.undo()
            logging.disable(previous)
        _MULTI_KEY_SEEN[name] = set(_KEY_IDS) <= _keys_used(name, up)
    return _MULTI_KEY_SEEN[name]


async def _is_aggregation(name: str) -> bool:
    return not _takes_object_id(name) and await _is_multi_key(name)


async def _is_owner_lookup(name: str) -> bool:
    return _takes_object_id(name) and await _is_multi_key(name)


def _multi_key_candidates() -> list[str]:
    return sorted(n for n in _lz_TOOLS() if n not in NO_UPSTREAM)


def _derive_multi_key_tools() -> list[str]:
    """The whole multi-key set (for the coverage assertions; built at execution)."""

    async def run_all() -> list[str]:
        return [n for n in _multi_key_candidates() if await _is_multi_key(n)]

    return _run_coroutine(run_all())


def _run_coroutine(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        return pool.submit(asyncio.run, coro).result()


@functools.cache
def _lz_MULTI_KEY_TOOLS():
    return _derive_multi_key_tools()


def _takes_object_id(name: str) -> bool:
    return any(p.endswith("_id") for p in _lz_TOOLS()[name].parameters.get("required", []))


# Merging tools (lists, searches, aggregates) vs lookups that find the key owning one object.
@functools.cache
def _lz_AGGREGATION_TOOLS():
    return sorted(n for n in _lz_MULTI_KEY_TOOLS() if not _takes_object_id(n))


@functools.cache
def _lz_OWNER_LOOKUP_TOOLS():
    return sorted(n for n in _lz_MULTI_KEY_TOOLS() if _takes_object_id(n))


def test_i_multi_key_coverage_is_derived_and_complete():
    """The derived set covers every org-scoped family that must aggregate across keys."""
    must = {
        n
        for n in _lz_TOOLS()
        if n == "get_isp_metrics" or "sdwan" in n or re.match(r"(list|get)_(mobility|carrier)_", n)
    }
    must |= {"list_hosts", "list_sites", "list_all_devices", "list_devices", "get_fleet_summary"}
    assert must - set(_lz_MULTI_KEY_TOOLS()) == set(), sorted(must - set(_lz_MULTI_KEY_TOOLS()))
    assert set(_lz_AGGREGATION_TOOLS()) & set(_lz_READ_TOOLS()) == set(_lz_AGGREGATION_TOOLS())


def _key_contributed(name: str, key: str, payload: Any, up: uh.FakeUpstream) -> bool:
    """True if ``key``'s upstream data reaches the result."""
    if any(p.endswith(f"@{uh.key_probe_tag(key)}") for p in _probes(payload)):
        return True
    text = uh.all_strings(payload)
    prim = PRIMARY_RESOLUTION.get(name)
    for s in up.served:
        if s.api_key != key or not 200 <= s.status < 300 or isinstance(s.body, bytes | str):
            continue
        if s.resolution and not (prim and s.path.endswith(prim)):
            continue
        for rec in uh.upstream_records(s.body):
            for field in ("id", "siteId"):
                if isinstance(rec, dict) and isinstance(rec.get(field), str):
                    if f'"{rec[field]}"' in text:
                        return True
    if name == "get_fleet_summary":
        # A count rollup: the key answered its console list, and the rolled-up host count
        # is every distinct console every key served (a key whose consoles were dropped
        # would leave its own consoles uncounted; consoles shared by id count once).
        hosts = [
            s
            for s in up.served
            if s.path.endswith("/v1/hosts")
            and 200 <= s.status < 300
            and not isinstance(s.body, bytes | str)
        ]
        ids = {
            rec["id"]
            for s in hosts
            for rec in uh.upstream_records(s.body)
            if isinstance(rec, dict) and isinstance(rec.get("id"), str)
        }
        return (
            any(s.api_key == key for s in hosts)
            and isinstance(payload, dict)
            and payload.get("hosts") == len(ids)
        )
    return False


@tool_batches("name", _multi_key_candidates, member=_is_aggregation)
async def test_i_every_key_contributes(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts(), tag_keys=True)
    payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    missing = [k for k in _KEY_IDS if not _key_contributed(name, k, payload, up)]
    assert missing == [], f"{name}: data of {missing} missing from the merged result"


@tool_batches("name", _multi_key_candidates, member=_is_multi_key)
async def test_i_every_key_failing_is_an_error(monkeypatch, name):
    up = uh.FakeUpstream(
        hosts_by_key=_two_key_hosts(), failing_keys=frozenset({"k-alpha", "k-beta"})
    )
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, keys=_KEYS)
    assert "lacks scope" in str(exc.value), f"{name}: {exc.value}"


@tool_batches("name", _multi_key_candidates, member=_is_owner_lookup)
@lazy_parametrize("absent", lambda: ["missing", "failing"])
async def test_i_lookup_finds_the_owning_key(monkeypatch, name, absent):
    """A lookup by id finds the object on whichever key holds it: the first key not
    holding it (404) or lacking scope (403) never fails the call or hides the owner."""
    kw = {"missing_keys" if absent == "missing" else "failing_keys": frozenset({"k-alpha"})}
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts(), tag_keys=True, **kw)
    payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    if name in _lz_WRITE_TOOLS():
        wrote = {w.api_key for w in up.writes() if 200 <= w.status < 300}
        assert wrote == {"k-beta"}, f"{name}: write rode {wrote}, not the owning key"
    else:
        assert _key_contributed(name, "k-beta", payload, up), f"{name}: owner's object missing"


@functools.cache
def _lz_KEY_LABEL_TOOLS():
    return sorted(
        n for n, t in _lz_TOOLS().items() if "key_label" in (t.parameters.get("properties") or {})
    )


@lazy_parametrize("name", lambda: _lz_KEY_LABEL_TOOLS())
async def test_i_unknown_key_label_lists_valid_labels(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts())
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), "key_label": "no-such-key"}
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args, keys=_KEYS)
    msg = str(exc.value)
    assert "no-such-key" in msg and "alpha" in msg and "beta" in msg, f"{name}: {msg}"
    assert up.writes() == [], name


async def _eligible_i_capped_key_keeps_items_and_says_incomplete(monkeypatch, name):
    """Multi-key: a key whose drain stops at the opt-in cap keeps what it gathered and the
    result says incomplete (never an error, never dropped items)."""
    probe = uh.FakeUpstream(mode="paged", hosts_by_key=_two_key_hosts())
    await _call(monkeypatch, name, probe, keys=_KEYS)
    prim = PRIMARY_RESOLUTION.get(name)
    if not _drained_paths(probe) and (not prim):
        return False
    return True


@tool_batches(
    "name",
    _multi_key_candidates,
    member=_is_aggregation,
    eligible=_eligible_i_capped_key_keeps_items_and_says_incomplete,
)
async def test_i_capped_key_keeps_items_and_says_incomplete(monkeypatch, name):
    """Multi-key: a key whose drain stops at the opt-in cap keeps what it gathered and the
    result says incomplete (never an error, never dropped items)."""
    probe = uh.FakeUpstream(mode="paged", hosts_by_key=_two_key_hosts())
    await _call(monkeypatch, name, probe, keys=_KEYS)
    prim = PRIMARY_RESOLUTION.get(name)
    if not _drained_paths(probe) and not prim:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged", hosts_by_key=_two_key_hosts(), tag_keys=True)
    try:
        res = await _call(monkeypatch, name, up, keys=_KEYS, env={"UNIFI_PAGINATE_MAX_PAGES": "2"})
    except ToolError as exc:
        pytest.fail(f"{name}: capped multi-key drain raised: {exc}")
    payload = uh.result_payload(res)
    text = uh.all_strings(payload)
    assert '"incomplete": true' in text, f"{name}: capped multi-key drain not flagged"
    dropped = [k for k in _KEY_IDS if not _key_contributed(name, k, payload, up)]
    assert dropped == [], f"{name}: capped key(s) {dropped} had their items dropped"


@tool_batches("name", _multi_key_candidates, member=_is_aggregation)
async def test_i_failing_key_reported_not_hidden(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts(), failing_keys=frozenset({"k-beta"}))
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    except ToolError as exc:
        assert "lacks scope" in str(exc), f"{name}: {exc}"
        return
    text = uh.all_strings(payload)
    assert "lacks scope" in text, f"{name}: beta failure not reported: {text[:300]}"
    assert "beta" in text, f"{name}: failing key not named"


def _assert_by_key_is_answering(name: str, payload: Any) -> None:
    """byKey carries exactly the answering keys' upstream envelopes: its keys are
    ``_key_labels`` (never a key that failed, a bad shape included)."""
    by_key = payload.get("byKey") if isinstance(payload, dict) else None
    if isinstance(by_key, dict):
        labels = payload.get("_key_labels")
        assert sorted(by_key) == sorted(labels or []), (
            f"{name}: byKey keys {sorted(by_key)} != _key_labels {labels}"
        )


def _key_error_text(entry: Any) -> str:
    """An ``errors`` entry as text: a string, or ``"<key>: <reason>"`` for a structured
    entry (search_across_sites: {key, siteId, scope, reason})."""
    if isinstance(entry, dict):
        return f"{entry.get('key')}: {entry.get('reason', '')}"
    return str(entry)


@tool_batches("name", _multi_key_candidates, member=_is_aggregation)
@lazy_parametrize("failing", lambda: [None, "k-alpha", "k-beta"])
async def test_i_key_labels_are_the_answering_keys(monkeypatch, name, failing):
    """One multi-key coverage report for every multi-key tool: ``_key_labels`` is exactly
    the keys whose results are included (configuration order), and each failed key is
    under ``errors`` as ``"<label>: <reason>"``."""
    up = uh.FakeUpstream(
        hosts_by_key=_two_key_hosts(),
        failing_keys=frozenset({failing}) if failing else frozenset(),
    )
    payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    assert isinstance(payload, dict), name
    assert not {"key_label", "key_labels"} & set(payload), f"{name}: unprefixed key fields"
    answering = [k.label for k in _KEYS if k.key != failing]
    assert payload.get("_key_labels") == answering, (
        f"{name} (failing={failing}): _key_labels={payload.get('_key_labels')!r}, "
        f"answering keys {answering}"
    )
    _assert_by_key_is_answering(name, payload)
    key_errors = [
        e
        for e in payload.get("errors") or []
        if _key_error_text(e).startswith(tuple(f"{k.label}: " for k in _KEYS))
    ]
    if failing is None:
        assert key_errors == [], f"{name}: key errors without a failing key: {key_errors}"
    else:
        label = next(k.label for k in _KEYS if k.key == failing)
        texts = [_key_error_text(e) for e in key_errors]
        assert len(texts) == 1, f"{name}: failed key {label!r} not reported once: {texts}"
        assert texts[0].startswith(f"{label}: ") and "lacks scope" in texts[0], texts


async def _eligible_i_by_key_kept_for_envelope_less_keys(monkeypatch, name):
    """``byKey == _key_labels`` also when a key's body carries nothing beside its
    records (no traceId / httpStatusCode): every answering key has a byKey entry (``{}``),
    in every tool that reports byKey at all."""
    normal = uh.result_payload(
        await _call(monkeypatch, name, uh.FakeUpstream(hosts_by_key=_two_key_hosts()), keys=_KEYS)
    )
    if not (isinstance(normal, dict) and "byKey" in normal):
        return False
    return True


@tool_batches(
    "name",
    _multi_key_candidates,
    member=_is_aggregation,
    eligible=_eligible_i_by_key_kept_for_envelope_less_keys,
)
async def test_i_by_key_kept_for_envelope_less_keys(monkeypatch, name):
    """``byKey == _key_labels`` also when a key's body carries nothing beside its
    records (no traceId / httpStatusCode): every answering key has a byKey entry (``{}``),
    in every tool that reports byKey at all."""
    normal = uh.result_payload(
        await _call(monkeypatch, name, uh.FakeUpstream(hosts_by_key=_two_key_hosts()), keys=_KEYS)
    )
    if not (isinstance(normal, dict) and "byKey" in normal):
        raise AssertionError("inapplicable case was not filtered before batching")
    for failing in (None, "k-beta"):
        up = uh.FakeUpstream(
            hosts_by_key=_two_key_hosts(),
            bare_envelope=True,
            failing_keys=frozenset({failing}) if failing else frozenset(),
        )
        payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
        assert isinstance(payload, dict) and isinstance(payload.get("byKey"), dict), (
            f"{name} (failing={failing}): byKey missing for envelope-less keys: "
            f"{sorted(payload) if isinstance(payload, dict) else payload!r}"
        )
        _assert_by_key_is_answering(name, payload)


async def _eligible_k_unexpected_shape_is_never_an_empty_result(name):
    if name in NO_UPSTREAM:
        return False
    return True


# =========================================================================== (k)
@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_k_unexpected_shape_is_never_an_empty_result
)
async def test_k_unexpected_shape_is_never_an_empty_result(monkeypatch, name):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="shape", error_resolution=name in PRIMARY_RESOLUTION)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return
    if not any(s.body == {"unexpectedShape": "probe-shape"} for s in up.served):
        return  # binary endpoints keep answering bytes; nothing JSON-shaped to check
    text = uh.all_strings(uh.result_payload(res))
    assert "probe-shape" in text, (
        f"{name}: an unexpected upstream shape vanished into a result: {text[:200]}"
    )


# =========================================================================== (l)
def _beta_owns_target() -> dict[str, list[dict]]:
    alpha_only = json.loads(json.dumps(uh.HOST_RECORD))
    alpha_only["id"] = "0" * 54 + "FA0077:0000000077"
    alpha_only["reportedState"] = dict(
        alpha_only["reportedState"], hostname="alpha-only", name="alpha-only"
    )
    return {"k-alpha": [alpha_only], "k-beta": [uh.HOST_RECORD]}


@tool_batches("name", lambda: _lz_HOST_TOOLS())
async def test_l_host_scoped_tool_uses_the_owning_key(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_beta_owns_target())
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), "host": uh.HOST}
    await _call(monkeypatch, name, up, args, keys=_KEYS)
    prim = PRIMARY_RESOLUTION.get(name)
    mine = [
        s
        for s in up.served
        if not s.resolution or (prim and "/proxy/" in s.path and s.path.endswith(prim))
    ]
    wrong = sorted({f"{s.method} {s.path}" for s in mine if s.api_key != "k-beta"})
    assert wrong == [], f"{name}: requests for a beta-owned console rode another key: {wrong}"
    assert mine, f"{name}: no upstream call made"


async def _eligible_m_repeated_page_guard(name):
    if name in NO_UPSTREAM or name in RAW_RELAY:
        return False
    return True


# =========================================================================== (m)
@tool_batches("name", lambda: _lz_READ_TOOLS(), eligible=_eligible_m_repeated_page_guard)
async def test_m_repeated_page_guard(monkeypatch, name):
    if name in NO_UPSTREAM or name in RAW_RELAY:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged", repeat_pages=True)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return
    payload = uh.result_payload(res)
    if '"incomplete": true' not in uh.all_strings(payload):
        counts = _probe_counts(payload)
        dupes = sum(n - 1 for n in counts.values())
        assert dupes == 0, f"{name}: repeated pages returned as a complete result ({dupes} dupes)"
    # Incomplete or not, the repeated page itself is never appended: no list carries a
    # record more often than the same tool's list does on a normal multi-page upstream
    # (a tool may legitimately present one record several times, e.g. one match per field).
    baseline_up = uh.FakeUpstream(mode="paged")
    try:
        baseline = uh.result_payload(await _call(monkeypatch, name, baseline_up))
    except ToolError:
        baseline = None
    allowed = max(_max_multiplicity(baseline), 1)
    got = _max_multiplicity(payload)
    assert got <= allowed, (
        f"{name}: a repeated page was appended (a record appears {got}x in one list; "
        f"{allowed}x on a normal multi-page upstream)"
    )


def _max_multiplicity(payload: Any) -> int:
    """The most times any one probe record appears within a single list of the payload."""
    worst = 0
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(value for key, value in node.items() if not key.startswith("_"))
        elif isinstance(node, list):
            counts: dict[str, int] = {}
            for item in node:
                if isinstance(item, dict) and isinstance(item.get("probe"), str):
                    counts[item["probe"]] = counts.get(item["probe"], 0) + 1
            worst = max([worst, *counts.values()])
            stack.extend(node)
    return worst


# =========================================================================== (n)
def _audit_lines(path) -> list[str]:
    return path.read_text().splitlines() if path.exists() else []


def _audits_path(line: str, path: str) -> bool:
    """``line`` audits ``path``: segment for segment, a segment holding a registered secret
    (a credential id, a share id the call bound) is written as the scrub mask ``***``."""
    m = re.search(r"\bpath=(\S+)", line)
    if m is None:
        return False
    audited, sent = m.group(1).split("/"), path.split("/")
    return len(audited) == len(sent) and all(
        a == b or a == "***" for a, b in zip(audited, sent, strict=True)
    )


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_n_every_write_attempt_is_audited(monkeypatch, tmp_path, name):
    log = tmp_path / "audit.log"
    env = {"UNIFI_AUDIT_LOG": str(log)}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, env=env)
    lines = _audit_lines(log)
    assert up.writes(), f"{name}: no write reached the upstream (property vacuous)"
    for w in up.writes():
        assert any(f"method={w.method}" in ln and _audits_path(ln, w.path) for ln in lines), (
            f"{name}: successful {w.method} {w.path} not audited"
        )
    # a failed write is audited too: only the write verb fails (reads succeed), so every
    # write tool, a read-before one included, really sends its write
    log.unlink(missing_ok=True)
    failing = uh.FakeUpstream(write_status=500, error_body='{"code":"boom"}')
    if name in RAW_RELAY:  # the relay reports an upstream 4xx/5xx as status, by design
        await _call(monkeypatch, name, failing, env=env)
    else:
        with pytest.raises(ToolError):
            await _call(monkeypatch, name, failing, env=env)
    lines = _audit_lines(log)
    assert failing.writes(), f"{name}: no failing write was sent (property vacuous)"
    for w in failing.writes():
        assert any(_audits_path(ln, w.path) and "http_500" in ln for ln in lines), (
            f"{name}: failed {w.method} {w.path} not audited"
        )


async def _eligible_n_transport_error_names_method_and_path(name):

    if name in NO_UPSTREAM:
        return False
    return True


@tool_batches(
    "name", lambda: sorted(_lz_TOOLS()), eligible=_eligible_n_transport_error_names_method_and_path
)
async def test_n_transport_error_names_method_and_path(monkeypatch, tmp_path, name):
    from unifi_fabric.client import is_write_request

    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    log = tmp_path / "audit.log"
    up = uh.FakeUpstream(transport_error=True, error_resolution=name in PRIMARY_RESOLUTION)
    try:
        res = await _call(monkeypatch, name, up, env={"UNIFI_AUDIT_LOG": str(log)})
    except ToolError as exc:
        msg = str(exc)
        args = tool_args.generated_args(_lz_TOOLS()[name])
        secrets = route_secrets.tool_call_secrets(name, args)
        failed = [s for s in up.served if s.status == 0]
        assert failed, name
        # Transport errors preserve caller-supplied path values unless opt-in redaction is
        # enabled; audit records below remain independently scrubbed.
        assert any(f.method in msg and f.path in msg for f in failed), (
            f"{name}: transport error lacks method/path: {msg[:300]}"
        )
        for f in failed:
            if is_write_request(f.method, f.path, f.sent_json):
                audited = scrub(f.path, secrets)
                assert any(f"path={audited}" in ln for ln in _audit_lines(log)), (
                    f"{name}: write that failed at the transport was not audited"
                )
        return
    text = uh.all_strings(uh.result_payload(res))
    args = tool_args.generated_args(_lz_TOOLS()[name])
    secrets = route_secrets.tool_call_secrets(name, args)
    failed = [s for s in up.served if s.status == 0]
    assert any(s.path in text for s in failed), (
        f"{name}: transport failure swallowed without method/path: {text[:300]}"
    )
    if secrets:
        assert not any(s in text for s in secrets), f"{name}: transport result leaks a secret"


# =========================================================================== (o)
def _total_counts(obj: Any) -> list[Any]:
    out: list[Any] = []
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "totalCount" in node:
                out.append(node["totalCount"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


async def _eligible_o_total_count_never_invented(name):
    if name in NO_UPSTREAM:
        return False
    return True


@class_axis(
    "name",
    lambda: _lz_READ_TOOLS(),
    variant=lambda: ["upstream_sends_no_total", "capped_drain"],
    eligible=_eligible_o_total_count_never_invented,
)
async def test_o_total_count_never_invented(monkeypatch, name, variant):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged", omit_total=variant == "upstream_sends_no_total")
    env = {"UNIFI_PAGINATE_MAX_PAGES": "2"} if variant == "capped_drain" else None
    try:
        res = await _call(monkeypatch, name, up, env=env)
    except ToolError:
        return  # error reporting is covered by (c)/(h)
    reported = {
        s.body.get("totalCount")
        for s in up.served
        if isinstance(s.body, dict) and isinstance(s.body.get("totalCount"), int)
    }
    for value in _total_counts(uh.result_payload(res)):
        assert value is None or value in reported, (
            f"{name}: totalCount {value!r} is not a total the upstream reported "
            f"({sorted(reported) or 'none reported'})"
        )


# =========================================================================== (p)
_REC_DEVICES = uh.recorded("network_integration/network_integration_v1_sites_ID_devices.json")
_REC_CLIENTS = uh.recorded("network_integration/network_integration_v1_sites_ID_clients.json")


@pytest.mark.parametrize(
    ("fixture", "field"),
    [
        (_REC_DEVICES, "macAddress"),
        (_REC_DEVICES, "ipAddress"),
        (_REC_CLIENTS, "macAddress"),
        (_REC_CLIENTS, "ipAddress"),
    ],
)
async def test_p_search_matches_recorded_integration_fields(monkeypatch, fixture, field):
    record = fixture["body"]["data"][0]
    query = str(record[field]).upper()  # matching is case-insensitive
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(monkeypatch, "search_across_sites", up, {"query": query})
    )
    assert any(uh.strip_additive(m, record) == record for m in payload["data"]), (
        f"search on recorded {field} {query!r} did not return the record verbatim"
    )


async def test_p_search_null_field_never_matches_none(monkeypatch):
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(monkeypatch, "search_across_sites", up, {"query": "none"})
    )
    searched = ("name", "macAddress", "ipAddress", "mac", "ip", "model", "hostname")
    candidates = [
        r
        for s in up.served
        if not s.resolution and s.method == "GET"
        for r in uh.upstream_records(s.body)
        if isinstance(r, dict) and any(r.get(f) is None for f in searched)
    ]
    assert candidates, "no searched record has a null field (property vacuous)"
    for match in payload["data"]:
        values = [str(match.get(f)) for f in searched if match.get(f) is not None]
        assert any("none" in v.lower() for v in values), f"spurious match: {match}"


# =========================================================================== (q)
SITE_COUNTING_TOOLS = ["search_across_sites", "list_all_clients"]


@pytest.mark.parametrize("name", SITE_COUNTING_TOOLS)
async def test_q_capped_site_is_incomplete_not_failed(monkeypatch, name):
    up = uh.FakeUpstream(mode="paged")
    payload = uh.result_payload(
        await _call(monkeypatch, name, up, env={"UNIFI_PAGINATE_MAX_PAGES": "2"})
    )
    assert payload.get("incomplete") is True, f"{name}: capped site list not flagged"
    assert payload["_sitesFailed"] == 0, f"{name}: a capped site was counted as failed"
    assert payload["_sitesIncomplete"] >= 1, f"{name}: capped site not counted incomplete"
    total = payload.get("_sitesSearched", payload.get("_sitesQueried"))
    assert (
        payload["_sitesSucceeded"] + payload["_sitesFailed"] + payload["_sitesIncomplete"] == total
    ), f"{name}: site counts do not add up: {payload}"
    assert "errors" not in payload or not any("incomplete" in str(e) for e in payload["errors"]), (
        f"{name}: a capped site was reported as an error"
    )


async def _eligible_r_one_keys_bad_shape_is_that_keys_error(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts(), junk_keys=frozenset({"k-beta"}))
    try:
        uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    except ToolError as exc:
        pytest.fail(f"{name}: one key's bad shape failed the whole call: {exc}")
    if not any(s.api_key == "k-beta" and s.path in uh.JUNK_PATHS for s in up.served):
        return False
    return True


# =========================================================================== (r)
@tool_batches(
    "name",
    _multi_key_candidates,
    member=_is_aggregation,
    eligible=_eligible_r_one_keys_bad_shape_is_that_keys_error,
)
async def test_r_one_keys_bad_shape_is_that_keys_error(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts(), junk_keys=frozenset({"k-beta"}))
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    except ToolError as exc:
        pytest.fail(f"{name}: one key's bad shape failed the whole call: {exc}")
    if not any(s.api_key == "k-beta" and s.path in uh.JUNK_PATHS for s in up.served):
        raise AssertionError("inapplicable case was not filtered before batching")
    text = uh.all_strings(payload)
    assert "beta" in text and "str" in text, f"{name}: beta's bad shape not reported: {text[:300]}"
    assert payload.get("_key_labels") == ["alpha"], f"{name}: {payload.get('_key_labels')}"
    _assert_by_key_is_answering(name, payload)
    # The records alpha's own (non-resolution) reads were served, by their probe: a
    # generated device record names no console (its hostId is ARG_ID), so the console id
    # alone cannot show that alpha's devices came back.
    alpha_probes = {
        rec["probe"]
        for s in up.served
        if s.api_key == "k-alpha" and not s.resolution
        for rec in uh.upstream_records(s.body)
        if isinstance(rec, dict) and isinstance(rec.get("probe"), str)
    }
    assert (
        uh.HOST_ID in text
        or name in {"search_device_fleet", "search_across_sites", "get_fleet_summary"}
        or any(uh.HOST_ID in s.path for s in up.served)
        or any(probe in text for probe in alpha_probes)
    ), f"{name}: alpha key data missing"


# =========================================================================== (s)
def _advertises_object(tool: Any) -> bool:
    schema = tool.output_schema
    return (
        isinstance(schema, dict)
        and schema.get("type") == "object"
        and not schema.get("x-fastmcp-wrap-result")
    )


async def _eligible_s_structured_output_valid_for_list_valued_upstream_bodies(name):
    """The harness serves the real list-valued shapes: Classic ``{meta, data: [...]}`` for
    reads AND writes, v2 bare arrays. A tool that advertises an object output schema must
    return an object (its structured content validates against that schema); it must
    never hand a list to FastMCP under a ``dict`` return type, which only surfaces AFTER
    a write has been applied (FastMCP: "structured_content must be a dict")."""
    if name in NO_UPSTREAM:
        return False
    return True


@tool_batches(
    "name",
    lambda: sorted(_lz_TOOLS()),
    eligible=_eligible_s_structured_output_valid_for_list_valued_upstream_bodies,
)
async def test_s_structured_output_valid_for_list_valued_upstream_bodies(monkeypatch, name):
    """The harness serves the real list-valued shapes: Classic ``{meta, data: [...]}`` for
    reads AND writes, v2 bare arrays. A tool that advertises an object output schema must
    return an object (its structured content validates against that schema); it must
    never hand a list to FastMCP under a ``dict`` return type, which only surfaces AFTER
    a write has been applied (FastMCP: "structured_content must be a dict")."""
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream()
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return  # an error is a failure mode tested elsewhere, never a shape violation
    meta = getattr(res, "meta", None) or {}
    tool = _lz_TOOLS()[name]
    if _advertises_object(tool):
        assert not (meta.get("fastmcp") or {}).get("wrap_result"), (
            f"{name}: advertises an object result but returned a list "
            f"({str(res.structured_content)[:160]})"
        )
    if tool.output_schema is not None and res.structured_content is not None:
        jsonschema.validate(res.structured_content, tool.output_schema)


_LIST_DATA_WRITES = ("create_hotspot_operator", "update_hotspot_operator")


@pytest.mark.parametrize("name", _LIST_DATA_WRITES)
async def test_s_list_valued_write_response_through_a_real_fastmcp_client(monkeypatch, name):
    """Regression on the wire: a Classic write answered with ``{meta, data: [...]}`` is
    delivered to a real FastMCP client as that object (meta kept), not as an error raised
    after the write was applied."""
    from fastmcp import Client

    up = uh.FakeUpstream()
    for k, v in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(k, v)
    uh.install(monkeypatch, up, tool_mode="full")
    async with Client(server.mcp) as mcp_client:
        res = await mcp_client.call_tool(name, tool_args.generated_args(_lz_TOOLS()[name]))
    assert not res.is_error
    write = [s for s in up.served if s.method in ("POST", "PUT")]
    assert len(write) == 1 and isinstance(write[0].body["data"], list)
    assert res.structured_content == write[0].body


# =========================================================================== (t)
class _MetaProbeUpstream(uh.FakeUpstream):
    """Every Classic REST/stat answer carries a distinctive ``meta`` naming its path."""

    def _generic(self, req: Any) -> Any:
        body = super()._generic(req)
        if uh.family(req.url.path) == "classic" and isinstance(body, dict) and "meta" in body:
            body = {**body, "meta": {"rc": "ok", "msg": f"probe-meta {req.url.path}"}}
        return body


def _contains_value(node: Any, key: str, value: Any) -> bool:
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if cur.get(key) == value:
                return True
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return False


async def _eligible_t_no_classic_tool_drops_meta(name):
    """Envelope pass-through: every Classic REST tool and every
    stat read returns the controller's ``{"meta", "data"}`` body verbatim — selections narrow
    ``data``, projections carry ``meta`` — so the upstream ``meta`` of every Classic answer
    that is part of the result contract appears in the result unchanged."""
    if name in NO_UPSTREAM or name in DERIVED:
        return False
    return True


@tool_batches("name", lambda: sorted(_lz_TOOLS()), eligible=_eligible_t_no_classic_tool_drops_meta)
async def test_t_no_classic_tool_drops_meta(monkeypatch, name):
    """Envelope pass-through: every Classic REST tool and every
    stat read returns the controller's ``{"meta", "data"}`` body verbatim — selections narrow
    ``data``, projections carry ``meta`` — so the upstream ``meta`` of every Classic answer
    that is part of the result contract appears in the result unchanged."""
    if name in NO_UPSTREAM or name in DERIVED:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = _MetaProbeUpstream()
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return
    payload = uh.result_payload(res)
    contract = [
        s
        for s in up.served
        if 200 <= s.status < 300
        and not s.resolution
        and uh.family(s.path) == "classic"
        and isinstance(s.body, dict)
        and "meta" in s.body
        and not (s.method == "GET" and any(a in s.path for a in AUXILIARY.get(name, ())))
        and not (name in _lz_WRITE_TOOLS() and s.method == "GET")
    ]
    for s in contract:
        assert _contains_value(payload, "meta", s.body["meta"]), (
            f"{name}: dropped the Classic meta of {s.method} {s.path}"
        )


# =========================================================================== (u)
# Tools that pick one record out of an upstream list (or resolve an id against one): the
# argument that selects, and an identity key of the listed records the error must name.
_SELECTORS: dict[str, tuple[str, str]] = {
    "get_vpn_server": ("server_id", "id"),
    "get_radius_profile": ("profile_id", "id"),
    "get_wlan_group": ("group_id", "_id"),
    "get_traffic_route": ("route_id", "_id"),
    "get_ap_group": ("group_id", "_id"),
    "get_client_link_diagnostics": ("client_id", "_id"),
    "get_device_port_state": ("device_id", "_id"),
    "get_device_stp_state": ("device_id", "_id"),
    "get_device": ("device_id", "id"),
    "allow_network_on_port_profile": ("network_id", "_id"),
    "exclude_network_on_port_profile": ("network_id", "_id"),
    # v2 device tags are resolved in the site's tag list before the write
    "update_device_tag": ("tag_id", "_id"),
    "delete_device_tag": ("tag_id", "_id"),
}
_UNKNOWN = {
    "id": "00000000-0000-4000-8000-0000000000ee",
    "hex": "0000000000000000000000ee",
    "mac": "02:00:5e:00:00:ee",
}


def _unknown_for(name: str, arg: str) -> str:
    if name in ("get_device", "get_client_link_diagnostics") or name.startswith("get_device_"):
        return _UNKNOWN["mac"]
    if name in ("get_wlan_group", "get_traffic_route", "get_ap_group"):
        return _UNKNOWN["hex"]
    return _UNKNOWN["id"]


@pytest.mark.parametrize("name", sorted(_SELECTORS))
async def test_u_unknown_selector_fails_listing_the_valid_choices(monkeypatch, name):
    """An id that matches nothing fails fast naming every valid choice from the list it was
    matched against — never a bare "not found", never a silent first match."""
    arg, ident = _SELECTORS[name]
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), arg: _unknown_for(name, arg)}
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    msg = str(exc.value)
    listed = [
        rec.get(ident)
        for s in up.served
        if 200 <= s.status < 300 and not s.resolution and s.method == "GET"
        for rec in uh.upstream_records(s.body)
        if isinstance(rec, dict) and rec.get(ident)
    ]
    assert listed, f"{name}: harness served no records to choose from"
    missing = [v for v in listed if str(v) not in msg]
    assert missing == [], f"{name}: error does not list valid choices {missing[:3]}: {msg[:300]}"


def test_u_selector_policy_names_real_tools():
    assert set(_SELECTORS) <= set(_lz_TOOLS())


# =========================================================================== (v)
# Every write tool of an area with a write opt-out is refused before ANY upstream call
# when the opt-out is set. The tool set is derived from the read/write classification
# (readOnlyHint) and the family index, so a new write tool is covered on registration.
_AREA_WRITE_OPT_OUTS = {
    family: switch.env
    for switch in _connector.switches.AREA_WRITE_SWITCHES
    for family in (switch.family, *switch.related_families)
}
_AREA_WRITE_OPT_OUTS["connector"] = "UNIFI_ENABLE_CONNECTOR_WRITE"
FAMILY = families.build_family_index()


@functools.cache
def _lz_OPT_OUT_WRITE_TOOLS():
    return sorted(n for n in _lz_WRITE_TOOLS() if FAMILY.get(n) in _AREA_WRITE_OPT_OUTS)


def test_v_opt_out_areas_have_write_tools_and_read_only_areas_have_none():
    covered = {FAMILY[n] for n in _lz_OPT_OUT_WRITE_TOOLS()}
    assert covered <= set(_AREA_WRITE_OPT_OUTS), covered
    for switch in _connector.switches.AREA_WRITE_SWITCHES:
        assert any(switch.governs(family) for family in covered), switch.env
    # Every write tool's family is governed by an area switch or is one of the families
    # without an area opt-out. InnerSpace has write tools, governed by
    # UNIFI_ENABLE_INNERSPACE_WRITE (it is in the table above).
    ungoverned = {"site_manager", "connector"}
    stray = [
        n
        for n in _lz_WRITE_TOOLS()
        if FAMILY.get(n) not in ungoverned
        and not any(s.governs(FAMILY.get(n)) for s in _connector.switches.AREA_WRITE_SWITCHES)
    ]
    assert any(FAMILY.get(n) == "innerspace" for n in _lz_WRITE_TOOLS())
    assert stray == [], stray


@tool_batches("name", lambda: _lz_OPT_OUT_WRITE_TOOLS())
async def test_v_area_opt_out_refuses_before_any_upstream_call(monkeypatch, name):
    env_var = _AREA_WRITE_OPT_OUTS[FAMILY[name]]
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, env={env_var: "0"})
    assert env_var in str(exc.value), f"{name}: {exc.value}"
    assert up.served == [], f"{name}: upstream called before the opt-out refused: {up.served}"


# =========================================================================== (w)
# A write that has already happened is never reported as a failure because of its
# response body: an empty (204) body, a non-JSON body, or a bare JSON value that is not
# an object (true, 7, []) comes back verbatim - as the result itself (tools declaring a
# pass-through return type) or under ``response`` (tools that return an envelope; the
# connector relay reports it under its documented ``body``). Every read tool given the
# same bodies on its GETs either passes them through or raises an actionable error: it
# never fails inside FastMCP's output conversion ("structured_content must be a dict")
# or with a Python attribute/type error.
W_BODIES = ("empty", "text", "true", "int", "list")


@functools.cache
def _lz_W_WRITE_TOOLS():
    return sorted(n for n in _lz_WRITE_TOOLS() if n not in NO_UPSTREAM)


@functools.cache
def _lz_W_READ_TOOLS():
    return sorted(n for n in _lz_READ_TOOLS() if n not in NO_UPSTREAM)


_INTERNAL_FAILURES = (AttributeError, TypeError, KeyError, IndexError)


def _internal_failure(exc: BaseException) -> str | None:
    """Why a ToolError is an internal failure rather than an actionable error, or None."""
    msg = str(exc)
    if "structured_content must be" in msg:
        return "FastMCP rejected the result type"
    # FastMCP chains the exception the tool raised as the ToolError's cause; an
    # actionable error the tool raised (even one translating a TypeError) is not it.
    cause = exc.__cause__
    if isinstance(cause, _INTERNAL_FAILURES):
        return f"{type(cause).__name__}: {cause}"
    for sig in ("object has no attribute", "is not subscriptable", "not iterable"):
        if sig in msg:
            return sig
    return None


def _body_returned(payload: Any, expected: Any) -> bool:
    # A None (empty-body) result of a pass-through tool is served as an explicit null
    # (``{"result": null}``), a list result in the {"result": [...]} envelope; an empty
    # MCP result (read back as []) is never accepted for an empty body.
    if payload == expected and expected is not None:
        return True
    if (
        isinstance(payload, dict)
        and "result" in payload
        and type(payload["result"]) is type(expected)
        and payload["result"] == expected
        and all(key == "result" or key.startswith("_") for key in payload)
    ):
        return True
    return isinstance(payload, dict) and any(
        k in payload and payload[k] == expected for k in ("response", "body")
    )


#: Writes that require affirmative Classic success (meta.rc == "ok", tools/_classic_cmd.py):
#: their bare body is served inside a Classic envelope (a bare body is not success).
AFFIRMATIVE_CLASSIC_WRITES = frozenset(
    {
        "ok",
        "update_device_radio",
        "create_site_vpn",
        "delete_site_vpn",
        "control_site_vpn",
        "cancel_controller_backup",
        "delete_controller_backup",
        "restore_controller_backup",
        "import_site_configuration",
        "send_test_email",
        "get_remote_access_turn_credentials",
        "set_cloud_access_registration",
        "refresh_sso_session",
        "link_ubiquiti_sso_account",
        "set_controller_system_parameter",
        "check_controller_firmware_update",
        "manage_firmware_cache",
    }
)


class _ProtocolWriteBodyUpstream(uh.FakeUpstream):
    """Supply affirmative envelopes only for writes whose protocol requires one."""

    affirmative_classic = True

    def __call__(self, req):
        response = super().__call__(req)
        if (
            self.affirmative_classic
            and uh.is_write_request(req.method, req.url.path, uh.request_json(req))
            and uh.family(req.url.path) == "classic"
        ):
            body = {"meta": {"rc": "ok"}, "data": self.served[-1].body}
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        return response


#: Writes whose Classic route requires affirmative success (HTTP 2xx AND meta.rc "ok",
#: tools._classic_cmd): the AP configuration writer and the N04 LTE / MBB commands.
AFFIRMATIVE_CLASSIC_WRITERS = frozenset(
    {"update_device_radio"}
    | {
        n
        for n, (source, _r, _w) in _network_mobile_wan.ROUTE_CHOICES.items()
        if source == "classic"
    }
)

# Classic writers that require meta.rc "ok" before they report success.
_AFFIRMATIVE_CLASSIC_WRITERS = frozenset(
    {
        "bulk_update_objects",
        "clear_switch_counters",
        "clone_device_config",
        "disconnect_remote_vpn_user",
        "locate_switch_port",
        "manage_device_ssh_session",
        "recover_switch_port",
        "run_device_self_test",
        "set_device_alignment_mode",
        "set_device_rearrange_mode",
        "set_outlet_power",
        "set_priority_uplink",
        "unpair_building_bridge",
    }
)


@class_axis("name", lambda: _lz_W_WRITE_TOOLS(), body=lambda: W_BODIES)
async def test_w_write_body_returned_verbatim_never_raised(monkeypatch, name, body):
    up = _ProtocolWriteBodyUpstream(write_body=body)
    # The AP configuration writer requires affirmative Classic success. Existing
    # pass-through Classic writers still exercise the original bare-body contract.
    up.affirmative_classic = name in (
        {"start_spectrum_scan"}
        | AFFIRMATIVE_CLASSIC_WRITES
        | AFFIRMATIVE_CLASSIC_WRITERS
        | _AFFIRMATIVE_CLASSIC_WRITERS
    )
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError as exc:
        if up.writes():
            pytest.fail(f"{name}: an applied write was reported as failed: {exc}")
        raise
    assert up.writes(), f"{name}: no write reached the transport"
    payload = uh.result_payload(res)
    expected = uh.DECODED_BODIES[body]
    if up.affirmative_classic and uh.family(up.writes()[0].path) == "classic":
        expected = {"meta": {"rc": "ok"}, "data": expected}
        if name in AFFIRMATIVE_CLASSIC_WRITES:
            # additive ``_`` keys only (a verifying writer's _verified / _readAfterError)
            payload = uh.strip_additive(payload, expected)
    assert _body_returned(payload, expected), f"{name}: body {expected!r} not returned: {payload!r}"


@class_axis("name", lambda: _lz_W_READ_TOOLS(), body=lambda: W_BODIES)
async def test_w_read_non_object_body_never_an_internal_failure(monkeypatch, name, body):
    up = uh.FakeUpstream(get_body=body)
    try:
        await _call(monkeypatch, name, up)
    except ToolError as exc:
        why = _internal_failure(exc)
        assert why is None, f"{name}: {why}: {str(exc)[:300]}"


@class_axis("name", lambda: _lz_W_WRITE_TOOLS(), body=lambda: W_BODIES)
async def test_w_write_read_before_non_object_body_is_actionable(monkeypatch, name, body):
    """The GETs a write makes (resolution, read-before, read-after) answered with a
    non-object body: the write fails before sending anything with an actionable shape
    error, or completes; never a Python attribute/type error."""
    up = uh.FakeUpstream(get_body=body)
    try:
        await _call(monkeypatch, name, up)
    except ToolError as exc:
        why = _internal_failure(exc)
        assert why is None, f"{name}: {why}: {str(exc)[:300]}"
        assert not up.writes(), f"{name}: an applied write was reported as failed: {exc}"


def test_w_covers_every_tool():
    assert set(_lz_W_WRITE_TOOLS()) | set(_lz_W_READ_TOOLS()) | set(NO_UPSTREAM) == set(_lz_TOOLS())


@class_axis(
    "name",
    lambda: sorted(n for n in _lz_TOOLS() if n not in NO_UPSTREAM),
    shape=lambda: uh.ITEM_SHAPES,
)
async def test_w_list_of_scalars_or_nulls_never_a_bare_python_exception(monkeypatch, name, shape):
    """Every JSON GET a tool makes (the /v1/hosts, /v1/sites and console site lists
    included) answers its record list as bare scalars, or with null entries among the
    records: the tool passes it through, skips what it cannot use, or raises an actionable
    shape error; never a Python attribute/type/key/index error, and a write it already
    applied is never reported as failed."""
    up = uh.FakeUpstream(item_shape=shape)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError as exc:
        why = _internal_failure(exc)
        assert why is None, f"{name}: {why}: {str(exc)[:300]}"
        assert not up.writes(), f"{name}: an applied write was reported as failed: {exc}"
        return
    # A per-item / per-site / per-key error reported inside a result is never a bare
    # Python exception text either.
    text = uh.all_strings(uh.result_payload(res))
    leaked = [sig for sig in _PYTHON_ERROR_SIGNATURES if sig in text]
    assert leaked == [], f"{name}: a Python exception surfaced in the result: {leaked}"


@class_axis(
    "name",
    lambda: sorted(n for n in _lz_TOOLS() if n not in NO_UPSTREAM),
    shape=lambda: uh.FIELD_SHAPES,
)
async def test_w_wrong_typed_record_fields_never_a_bare_python_exception(monkeypatch, name, shape):
    """Every record of every JSON GET carries wrong-typed fields (an int or a list
    where a string is expected, a string where an object is expected: meta=123, a numeric
    hostId, status=["a"], ...). The tool passes them through or raises an actionable
    shape error; never a bare Python exception, and an applied write is never reported
    as failed."""
    up = uh.FakeUpstream(item_shape=shape)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError as exc:
        why = _internal_failure(exc)
        assert why is None, f"{name}: {why}: {str(exc)[:300]}"
        assert not up.writes(), f"{name}: an applied write was reported as failed: {exc}"
        return
    text = uh.all_strings(uh.result_payload(res))
    leaked = [sig for sig in _PYTHON_ERROR_SIGNATURES if sig in text]
    assert leaked == [], f"{name}: a Python exception surfaced in the result: {leaked}"


@class_axis(
    "name",
    lambda: sorted(n for n in _lz_TOOLS() if n not in NO_UPSTREAM),
    scope=lambda: ["every-read", "own-reads"],
    shape=lambda: uh.PAGING_SHAPES,
)
async def test_w_wrong_typed_paging_controls_are_shape_errors(monkeypatch, name, shape, scope):
    """Every JSON GET (every list and drain path: the enumeration lists, the
    cursor / offset / links / Carrier-cursor drains, collectors, and the read-before /
    read-after of write tools) answers its pagination controls wrong-typed (an int or
    list ``nextToken``, a string or list ``totalCount`` / ``total``, a ``links`` that is
    not an object or a non-string ``links.next``, a non-string ``meta.nextCursor``, a
    non-boolean ``meta.hasMore``; ``offset`` / ``limit`` / ``count`` too). A consumed
    control is a ResponseShapeError naming it - raised, or reported in the result for
    the key / site / item it belongs to; never a bare Python exception, never a drain
    that ignores it and reports success, and an applied write is never reported failed.
    ``own-reads`` keeps the enumeration lists well-typed so each tool's own drains (and
    a write tool's read-before / read-after) are the ones poisoned.
    """
    up = uh.FakeUpstream(mode="paged", paging_shape=shape, paging_resolution=scope == "every-read")
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError as exc:
        why = _internal_failure(exc)
        assert why is None, f"{name}: {why}: {str(exc)[:300]}"
        assert not up.writes(), f"{name}: an applied write was reported as failed: {exc}"
        msg = str(exc)
        if "Unexpected response shape" in msg:
            assert any(f"{f} of GET" in msg for f in _POISON_LABELS), f"{name}: {msg[:300]}"
        return
    text = uh.all_strings(uh.result_payload(res))
    leaked = [sig for sig in _PYTHON_ERROR_SIGNATURES if sig in text]
    assert leaked == [], f"{name}: a Python exception surfaced in the result: {leaked}"
    consumed = up.poisoned & set(uh.CONSUMED_PAGING_FIELDS)
    # A tool returning one upstream body verbatim (a non-list read such as the
    # recognition counts, or a relay) consumes no control: pass-through is allowed.
    payload = uh.result_payload(res)
    verbatim = any(payload == x.body for x in up.served if 200 <= x.status < 300)
    if consumed and name not in RAW_RELAY and not verbatim:
        assert any(f"{f} of GET" in text for f in _POISON_LABELS), (
            f"{name}: wrong-typed {sorted(consumed)} served, yet the tool succeeded without "
            f"a shape error naming it: {text[:300]}"
        )


_POISON_LABELS = (
    "nextToken",
    "totalCount",
    "total",
    "links",
    "links.next",
    "meta.nextCursor",
    "meta.hasMore",
)


_PYTHON_ERROR_SIGNATURES = (
    "object has no attribute",
    "is not subscriptable",
    "object is not iterable",
    "AttributeError",
    "TypeError",
    "KeyError",
    "IndexError",
)


# =========================================================================== (x)
# A non-object body where an object (or list) is expected raises naming the shape, or is
# passed through verbatim; it is never wrapped in an invented key such as {"data": ...}.
def _invented_wraps(payload: Any, scalar: str) -> list[str]:
    hits: list[str] = []
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            hits.extend(k for k, v in node.items() if v == scalar and k not in {"body", "result"})
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return hits


async def _eligible_x_non_object_body_is_never_wrapped(name):
    if name in MULTI_SOURCE_COMPOSITE:
        return False
    if name in NO_UPSTREAM:
        return False
    return True


@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_x_non_object_body_is_never_wrapped
)
async def test_x_non_object_body_is_never_wrapped(monkeypatch, name):
    if name in MULTI_SOURCE_COMPOSITE:
        raise AssertionError("inapplicable case was not filtered before batching")
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(scalar_body=True)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return
    if not any(s.body == "probe-scalar" for s in up.served):
        return  # binary endpoints keep answering bytes
    hits = _invented_wraps(uh.result_payload(res), "probe-scalar")
    assert hits == [], f"{name}: a bare upstream value was wrapped under {hits}"


# =========================================================================== (y)
# Cursor protocols: a cursor cycle (A, B, A, ...) and "more" without a cursor both end in
async def _eligible_y_cursor_cycle_and_missing_cursor_never_complete(name):
    if name in NO_UPSTREAM or name in RAW_RELAY:
        return False
    return True


# an error or ``incomplete: true`` with the pages gathered; never a loop or "complete".
@class_axis(
    "name",
    lambda: _lz_READ_TOOLS(),
    mode=lambda: ["cursor_cycle", "missing_cursor"],
    eligible=_eligible_y_cursor_cycle_and_missing_cursor_never_complete,
)
async def test_y_cursor_cycle_and_missing_cursor_never_complete(monkeypatch, name, mode):
    if name in NO_UPSTREAM or name in RAW_RELAY:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged", **{mode: True})
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return
    uses_cursor = any(
        not s.resolution
        and isinstance(s.body, dict)
        and isinstance(s.body.get("meta"), dict)
        and "hasMore" in s.body["meta"]
        for s in up.served
    ) or (
        # A cycling Site Manager nextToken list the tool returns or enumerates (a tool
        # that only resolves a name against it may stop at the first page).
        mode == "cursor_cycle"
        and any(
            s.path in uh.NEXT_TOKEN_PATHS
            and "nextToken=pA" in s.query
            and (
                not s.resolution
                or name in ENUMERATING
                or s.path.endswith(PRIMARY_RESOLUTION.get(name, "\0"))
            )
            for s in up.served
        )
    )
    if not uses_cursor:
        return  # the tool's upstream does not use a cursor protocol
    # a verbatim upstream envelope carries the underscore marker instead (no key is
    # added to an upstream body except a ``_``-prefixed one)
    text = uh.all_strings(uh.result_payload(res))
    assert '"incomplete": true' in text or '"_incomplete": true' in text, (
        f"{name}: a {mode} drain was presented as complete"
    )


# =========================================================================== (z)
def _probe_counts(payload: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            probe = node.get("probe")
            if isinstance(probe, str):
                counts[probe] = counts.get(probe, 0) + 1
            stack.extend(value for key, value in node.items() if not key.startswith("_"))
        elif isinstance(node, list):
            stack.extend(node)
    return counts


async def _eligible_z_multi_page_drain_returns_each_record_once(name):
    if name in NO_UPSTREAM or name in DERIVED:
        return False
    return True


@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_z_multi_page_drain_returns_each_record_once
)
async def test_z_multi_page_drain_returns_each_record_once(monkeypatch, name):
    if name in NO_UPSTREAM or name in DERIVED:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged")
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    dupes = {p: n for p, n in _probe_counts(payload).items() if n > 1}
    assert not dupes, f"{name}: records returned more than once: {sorted(dupes)[:5]}"


@pytest.mark.parametrize("name", ["search_across_sites", "list_all_clients"])
async def test_z_console_visible_to_two_keys_is_read_once(monkeypatch, name):
    shared = {"k-alpha": [uh.HOST_RECORD], "k-beta": [uh.HOST_RECORD]}
    up = uh.FakeUpstream(mode="paged", hosts_by_key=shared)
    payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    dupes = {p: n for p, n in _probe_counts(payload).items() if n > 1}
    assert not dupes, f"{name}: a console seen by two keys returned records twice"
    assert payload["_count"] > 0, f"{name}: the shared console's records were dropped"


# ======================================================================= (area C)
# Protect / Mobility / Carrier Fabric write contracts, enforced across every write tool
# of those families (derived from readOnlyHint and the family index, so a new tool is
# covered on registration):
#   C1. Path-enum values a description names (prose and example) are in the pinned spec.
#   C2. Every status a write returns is advertised in its description, and every no-op
#       status a description advertises is actually returned when the change is already
#       applied (a description never promises an unreachable result).
#   C3. Within a family, every update_* tool returns ONE result shape (updated and no-op).
#   C4. A different value for a sent field is never answered with a no-op: the write is
#       sent and the upstream decides.
#   C5. Descriptions put the area write opt-out first in the guarded order (it refuses
#       before validation or any upstream read, as property v proves).

# Path parameters whose values are a closed enum in the pinned published spec. Source:
# Protect 7.3.70 components.schemas.assetFileType (GET/POST /v1/files/{fileType}).
_PINNED_PATH_ENUMS: dict[str, set[str]] = {"file_type": {"animations"}}
_AREA_C_FAMILIES = {"protect", "mobility", "carrier"}


@functools.cache
def _lz_AREA_C_WRITE_TOOLS():
    return sorted(n for n in _lz_WRITE_TOOLS() if FAMILY.get(n) in _AREA_C_FAMILIES)


_NO_OP_STATUSES = {"no_op", "noop"}
_STATUS_RE = re.compile(r'status:\s*"([a-z_]+)"')
# Optional sent fields a tool's no-op decision depends on (generated args carry only the
# required ones).
_SENT_OPTIONALS: dict[str, dict[str, Any]] = {
    "suspend_carrier_subscriber": {"reason": "probe-reason"},
}


def test_c1_path_enum_values_named_in_descriptions_are_in_the_spec():
    from unifi_fabric.argument_errors import _example_from_description

    bad: list[str] = []
    checked = 0
    for name, tool in _lz_TOOLS().items():
        props = tool.parameters.get("properties") or {}
        for pname, allowed in _PINNED_PATH_ENUMS.items():
            if pname not in props:
                continue
            checked += 1
            text = str(props[pname].get("description") or "") + "\n" + (tool.description or "")
            named = set(re.findall(r"'([A-Za-z0-9][A-Za-z0-9_-]*)'", text))
            bad += [f"{name}.{pname}: '{v}' not in {sorted(allowed)}" for v in named - allowed]
            example = _example_from_description(tool.description or "")
            if example is not None and pname in json.loads(example):
                value = json.loads(example)[pname]
                if value not in allowed:
                    bad.append(f"{name}: example {pname}={value!r} not in {sorted(allowed)}")
    assert checked >= 2, "no tool takes a pinned path-enum parameter"
    assert bad == [], bad


class _StatefulWriteUpstream(uh.FakeUpstream):
    """The fake upstream, plus the state changes the action endpoints document (the base
    harness reflects only request-body fields): suspend/resume set ``suspended`` (and
    ``suspendReason``), a host DELETE clears ``hostId``, and selecting an arm profile sets
    the NVR ``armMode``. The arm-profile list also carries the profile a changed
    ``arm_profile_id`` names (``_bump(ARG_ID)``), so selecting a different, existing
    profile is a real write and not an unknown-id refusal."""

    def __call__(self, req: Any) -> Any:
        resp = super().__call__(req)
        if not 200 <= resp.status_code < 300:
            return resp
        path = req.url.path
        if req.method == "GET" and path.endswith("/arm-profiles"):
            profiles = resp.json()
            if isinstance(profiles, list) and profiles and isinstance(profiles[0], dict):
                other = {**profiles[0], "id": _bump(uh.ARG_ID), "probe": "arm-profile-other"}
                return httpx.Response(200, json=[*profiles, other])
        if req.method == "GET" and path.endswith("/nvrs") and "armMode" in self.overlay:
            nvr = resp.json()
            if isinstance(nvr, dict):  # the NVR is one object, not a record list
                return httpx.Response(200, json={**nvr, "armMode": self.overlay["armMode"]})
        try:
            body = json.loads(req.content) if req.content else None
        except ValueError:
            body = None
        if req.method == "POST" and path.endswith("/suspend"):
            self.overlay["suspended"] = True
            if isinstance(body, dict) and "reason" in body:
                self.overlay["suspendReason"] = body["reason"]
        elif req.method == "POST" and path.endswith("/resume"):
            self.overlay["suspended"] = False
        elif req.method == "DELETE" and path.endswith("/host"):
            self.overlay["hostId"] = None
        elif req.method == "PATCH" and path.endswith("/arm-profiles/settings"):
            if isinstance(body, dict):
                self.overlay["armMode"] = {"armProfileId": body.get("armProfileId")}
        return resp


def _bump(value: Any) -> Any:
    if isinstance(value, str):
        if value == uh.ARG_ID:  # keep a valid id: another UUID
            return value[:-2] + "ab"
        return value + "2"
    if isinstance(value, bool):
        return not value
    if isinstance(value, int | float):
        return value + 1
    if isinstance(value, dict):
        # Identity keys address the object; they are no value to change (IDENTITY_FIELDS).
        return {k: v if k in IDENTITY_FIELDS else _bump(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_bump(v) for v in value]
    return value


def _sent_leaves(sent: Any) -> list[Any]:
    out: list[Any] = []
    stack = [sent]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        else:
            out.append(node)
    return out


def _changed_args(args: dict[str, Any], write: Any) -> dict[str, Any]:
    """``args`` with every argument whose value the write sent in its BODY bumped."""
    leaves = _sent_leaves(write.sent_json)
    out = dict(args)
    for pname, value in args.items():
        if pname in {"host", "site", "key_label", "confirm"}:
            continue
        values = _sent_leaves(value) if isinstance(value, dict | list) else [value]
        if values and all(v in leaves for v in values):
            out[pname] = _bump(value)
    return out


async def _write_sequence(monkeypatch, name: str) -> dict[str, Any]:
    """Call 1 applies the write; call 2 repeats it (the change is now applied); call 3
    sends a different value for every sent body field.

    The sequence needs an upstream whose reads reflect the writes: a replayed capture is
    the same body on every read, so the change is never seen as applied. The records are
    therefore generated (the harness overlays each written field on them)."""
    up = _StatefulWriteUpstream(replay_recordings=False)
    for k, v in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(k, v)
    uh.install(monkeypatch, up)
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), **_SENT_OPTIONALS.get(name, {})}

    async def run(call_args: dict[str, Any]) -> tuple[Any, int]:
        before = len(up.writes())
        payload = uh.result_payload(await server.mcp.call_tool(name, call_args))
        return payload, len(up.writes()) - before

    first, first_writes = await run(args)
    try:
        second, second_writes = await run(args)
    except ToolError as exc:
        # Repeating an applied delete whose record the upstream no longer lists (the
        # harness models delete_protect_backup's read-back: the backup is gone) is a
        # registered lookup miss before any write, never a status to compare.
        refusal = refusals.classify(str(exc).split(": ", 1)[-1])
        if not (_is_delete_tool(name) and refusal and refusal.id == "lookup-miss"):
            raise
        second, second_writes = {"error": str(exc)}, 0
    first_write = up.writes()[0] if first_writes else None
    changed = _changed_args(args, first_write) if first_write is not None else args
    third: Any = None
    third_writes = 0
    if changed != args:
        try:
            third, third_writes = await run(changed)
        except ToolError as exc:  # a changed value the tool rejects is not a no-op
            third = {"error": str(exc)}
    return {
        "results": [first, second, third],
        "writes": [first_writes, second_writes, third_writes],
        "changed": changed != args,
        # A ``status`` field of an upstream body: returned verbatim it is upstream data,
        # not a tool-owned status label (accept_ironclad_terms sends and echoes one).
        "upstream_statuses": {
            served.body["status"]
            for served in up.served
            if isinstance(served.body, dict) and isinstance(served.body.get("status"), str)
        },
    }


def _status(payload: Any) -> Any:
    return payload.get("status") if isinstance(payload, dict) else None


@tool_batches("name", lambda: _lz_AREA_C_WRITE_TOOLS())
async def test_c2_statuses_returned_are_advertised_and_advertised_no_ops_reachable(
    monkeypatch, name
):
    seq = await _write_sequence(monkeypatch, name)
    advertised = set(_STATUS_RE.findall(_lz_TOOLS()[name].description or ""))
    observed = {
        _status(r)
        for r in seq["results"]
        if _status(r) is not None and _status(r) not in seq["upstream_statuses"]
    }
    if name in RAW_RELAY:
        # Private relay wrappers preserve numeric HTTP status rather than inventing
        # tool-owned string status labels. The upstream status contract is explicit.
        assert observed and all(type(status) is int for status in observed), (
            f"{name}: connector status must remain a numeric HTTP status: {observed}"
        )
        assert "status" in (_lz_TOOLS()[name].description or "").lower(), (
            f"{name}: the numeric upstream status contract is undocumented"
        )
        return
    assert observed <= advertised, f"{name}: returns {observed - advertised} undocumented"
    promised = advertised & _NO_OP_STATUSES
    if promised:
        assert _status(seq["results"][1]) in promised, (
            f"{name}: advertises {promised} but repeating an applied write returned "
            f"{_status(seq['results'][1])!r}"
        )
        assert seq["writes"][1] == 0, f"{name}: a no-op still sent a write"


async def test_c3_update_tools_share_one_result_shape_per_family(monkeypatch):
    by_family: dict[str, dict[str, set[frozenset[str]]]] = {}
    for name in _lz_AREA_C_WRITE_TOOLS():
        if not name.startswith("update_"):
            continue
        seq = await _write_sequence(monkeypatch, name)
        fam = by_family.setdefault(FAMILY[name], {"updated": set(), "no_op": set()})
        for payload in seq["results"][:2]:
            st = _status(payload)
            # The shape is the tool-owned keys; ``_``-prefixed keys are per-tool additive
            # context (update_protect_device_settings' documented _route), never shape.
            keys = frozenset(k for k in payload if not k.startswith("_")) if st else frozenset()
            if st == "updated":
                fam["updated"].add(keys)
            elif st in _NO_OP_STATUSES:
                fam["no_op"].add(keys | {f"status={st}"})
    assert set(by_family) >= {"protect", "mobility"}, by_family
    bad = {
        f"{fam}.{kind}": sorted(sorted(s) for s in variants)
        for fam, kinds in by_family.items()
        for kind, variants in kinds.items()
        if len(variants) > 1
    }
    assert bad == {}, f"update tools of one family return different shapes: {bad}"


@functools.cache
def _lz_NO_OP_CAPABLE_TOOLS():
    return sorted(
        n
        for n in _lz_AREA_C_WRITE_TOOLS()
        if set(_STATUS_RE.findall(_lz_TOOLS()[n].description or "")) & _NO_OP_STATUSES
    )


# Body-less actions: the request carries no value that could differ.
_BODYLESS_NO_OP = {
    "detach_carrier_subscriber_host": "DELETE .../host carries no body",
    "resume_carrier_subscriber": "POST .../resume carries no body",
}


@tool_batches("name", lambda: _lz_NO_OP_CAPABLE_TOOLS())
async def test_c4_a_different_sent_value_is_never_a_no_op(monkeypatch, name):
    seq = await _write_sequence(monkeypatch, name)
    if not seq["changed"]:
        assert name in _BODYLESS_NO_OP, f"{name}: no sent value to change"
        return
    third = seq["results"][2]
    assert _status(third) not in _NO_OP_STATUSES and seq["writes"][2] >= 1, (
        f"{name}: a changed sent value was answered with {third!r} and no write"
    )


def test_c4_covers_the_no_op_capable_tools():
    assert "suspend_carrier_subscriber" in _lz_NO_OP_CAPABLE_TOOLS()
    assert set(_BODYLESS_NO_OP) <= set(_lz_NO_OP_CAPABLE_TOOLS())
    assert len(_lz_NO_OP_CAPABLE_TOOLS()) >= 15, _lz_NO_OP_CAPABLE_TOOLS()


@tool_batches("name", lambda: _lz_OPT_OUT_WRITE_TOOLS())
def test_c5_descriptions_put_the_opt_out_first(name):
    text = " ".join((_lz_TOOLS()[name].description or "").split())
    assert "kill-switch" not in text.lower(), f"{name}: says kill-switch, not the opt-out"
    env_var = _AREA_WRITE_OPT_OUTS[FAMILY[name]]
    read_before = text.lower().find("read-before")
    if read_before == -1 or "Guarded" not in text:
        return
    opt_out = min((i for i in (text.find(env_var), text.find("opt-out")) if i != -1), default=-1)
    assert opt_out != -1 and opt_out < read_before, (
        f"{name}: the guarded order lists read-before before the {env_var} opt-out"
    )


#   C6. A drained list whose upstream reports a total keeps that total in the result,
#       complete or stopped by the opt-in cap (o proves it is never invented).
#   C7. A collector never silently skips an upstream record it cannot key by id.
_AREA_C_READ_FAMILIES = _AREA_C_FAMILIES | {"innerspace"}


@functools.cache
def _lz_AREA_C_READ_TOOLS():
    return sorted(n for n in _lz_READ_TOOLS() if FAMILY.get(n) in _AREA_C_READ_FAMILIES)


def _reported_totals(up: uh.FakeUpstream) -> set[int]:
    totals: set[int] = set()
    for s in up.served:
        if s.resolution or not 200 <= s.status < 300 or not isinstance(s.body, dict):
            continue
        for k in ("total", "totalCount"):
            v = s.body.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                totals.add(v)
    return totals


def _result_totals(payload: Any) -> set[Any]:
    found: set[Any] = set()
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            found.update(node[k] for k in ("total", "totalCount") if k in node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return found


async def _eligible_c6_upstream_total_survives_a_drain(name):
    if name in DERIVED or name in SELECT:
        return False
    return True


@class_axis(
    "name",
    lambda: _lz_AREA_C_READ_TOOLS(),
    capped=lambda: [False, True],
    eligible=_eligible_c6_upstream_total_survives_a_drain,
)
async def test_c6_upstream_total_survives_a_drain(monkeypatch, name, capped):
    if name in DERIVED or name in SELECT:
        raise AssertionError("inapplicable case was not filtered before batching")
    if capped:
        res, up = await _call_capped(
            monkeypatch,
            name,
            lambda: uh.FakeUpstream(mode="paged"),
            {"UNIFI_PAGINATE_MAX_PAGES": "1"},
        )
    else:
        up = uh.FakeUpstream(mode="paged")
        res = await _call(monkeypatch, name, up)
    payload = uh.result_payload(res)
    reported = _reported_totals(up)
    if not reported:
        return  # this upstream reports no total
    assert reported & _result_totals(payload), (
        f"{name}: upstream reported total {sorted(reported)} but the result carries none"
        + (" (capped drain)" if capped else "")
    )


class _IdlessRecordUpstream(uh.FakeUpstream):
    """Every Protect list answer carries one extra record with no ``id``."""

    def _generic(self, req: Any) -> Any:
        body = super()._generic(req)
        if req.method == "GET" and isinstance(body, list) and "/proxy/protect/" in req.url.path:
            body = [*body, {"name": f"idless-probe {req.url.path}"}]
        return body


@functools.cache
def _lz_PROTECT_COLLECTORS():
    return sorted(
        n for n in _lz_READ_TOOLS() if FAMILY.get(n) == "protect" and n.startswith("collect_")
    )


@lazy_parametrize("name", lambda: _lz_PROTECT_COLLECTORS())
async def test_c7_collector_never_silently_skips_an_idless_record(monkeypatch, name):
    import unifi_fabric.tools.protect as protect_mod

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(protect_mod, "_sleep", _no_sleep)
    # Generated data: the id-less record is added to generated list answers, and a
    # replayed capture never passes through _generic.
    up = _IdlessRecordUpstream(replay_recordings=False)
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    served = [
        rec["name"]
        for s in up.served
        if s.method == "GET" and isinstance(s.body, list)
        for rec in s.body
        if isinstance(rec, dict) and str(rec.get("name", "")).startswith("idless-probe")
    ]
    assert served, f"{name}: harness served no id-less record"
    text = uh.all_strings(payload)
    missing = [n for n in served if n not in text]
    assert missing == [], f"{name}: id-less records silently skipped: {missing[:3]}"


def test_c7_collectors_are_covered():
    assert set(_lz_PROTECT_COLLECTORS()) >= {
        "collect_protect_events",
        "collect_protect_device_changes",
    }


#   C8. A multi-key write with no key_label never silently lands on the first configured
#       key: it routes to the key that owns its target, or fails fast naming every label
#       before any write is attempted.
@functools.cache
def _lz_KEY_ROUTED_WRITE_TOOLS():
    return sorted(set(_lz_AREA_C_WRITE_TOOLS()) & set(_lz_KEY_LABEL_TOOLS()))


def test_c8_key_routed_writes_are_covered():
    assert "create_carrier_subscriber" in _lz_KEY_ROUTED_WRITE_TOOLS()
    assert len(_lz_KEY_ROUTED_WRITE_TOOLS()) >= 10, _lz_KEY_ROUTED_WRITE_TOOLS()


@lazy_parametrize("name", lambda: _lz_KEY_ROUTED_WRITE_TOOLS())
async def test_c8_multi_key_write_never_defaults_to_the_first_key(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts(), missing_keys=frozenset({"k-alpha"}))
    try:
        await _call(monkeypatch, name, up, keys=_KEYS)
    except ToolError as exc:
        assert up.writes() == [], f"{name}: failed after attempting a write: {exc}"
        msg = str(exc)
        assert "alpha" in msg and "beta" in msg, f"{name}: error lists no labels: {msg}"
        return
    wrote = {w.api_key for w in up.writes()}
    assert wrote == {"k-beta"}, f"{name}: write rode {wrote}, not the owning key"


# =========================================================================== (network)
# Network properties. Each one is swept across the whole registry (or every tool reaching
# a published operation), not only the tool where the behaviour was first observed.
from tests import test_spec_conformance as sc  # noqa: E402

_PROBE_QS = "zzq?x=1"


def _spec_operation(method: str, path: str) -> tuple[Any, str, dict[str, Any]] | None:
    """(spec, template, operation) of the published operation a request targets."""
    fam, inner = sc.route(path)
    if fam.startswith("unspecced:") or fam == "unknown":
        return None
    candidates = [sc.specs()[s] for s in sc.DIRECT_SPECS] if fam == "direct" else [sc.specs()[fam]]
    for spec in candidates:
        hit = sc._match(spec, inner)
        if hit:
            op = spec.doc["paths"][hit[0]].get(method.lower())
            if op is not None:
                return spec, hit[0], op
    return None


def _schema_props(spec: Any, node: Any, seen: set[str] | None = None) -> set[str]:
    """Top-level property names a request schema accepts (every allOf/oneOf/anyOf branch
    and every discriminator variant)."""
    seen = set() if seen is None else seen
    out: set[str] = set()
    if not isinstance(node, dict):
        return out
    ref = node.get("$ref")
    if ref:
        if ref in seen:
            return out
        seen.add(ref)
        target, _ = sc._resolve(spec, node)
        return _schema_props(spec, target, seen)
    out |= set(node.get("properties") or {})
    for key in ("allOf", "oneOf", "anyOf"):
        for branch in node.get(key) or []:
            out |= _schema_props(spec, branch, seen)
    mapping = (node.get("discriminator") or {}).get("mapping") or {}
    for target in mapping.values():
        out |= _schema_props(spec, {"$ref": target}, seen)
    return out


def _request_body_props(spec: Any, op: dict[str, Any]) -> set[str]:
    body = op.get("requestBody")
    if not body:
        return set()
    body, _ = sc._resolve(spec, body)
    schema = ((body.get("content") or {}).get("application/json") or {}).get("schema")
    return _schema_props(spec, schema)


def _query_params(spec: Any, template: str, op: dict[str, Any]) -> dict[str, bool]:
    """{name: required} of an operation's query parameters."""
    item = spec.doc["paths"][template]
    out: dict[str, bool] = {}
    for raw in [*item.get("parameters", []), *op.get("parameters", [])]:
        p, _ = sc._resolve(spec, raw)
        if p.get("in") == "query":
            out[p["name"]] = bool(p.get("required"))
    return out


def _object_params(name: str) -> list[str]:
    props = (_lz_TOOLS()[name].parameters or {}).get("properties") or {}
    return [p for p, s in props.items() if sc._is_object_param(s)]


def _write_bodies(up: uh.FakeUpstream) -> list[Any]:
    return [s.sent_json for s in up.writes() if s.sent_json is not None]


def _all_keys(node: Any) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for obj in _nested_objects(node):
        for k, v in obj.items():
            out.setdefault(k, []).append(v)
    return out


# =========================================================================== (ba)
# Read-only mode refuses every write tool before ANY upstream call - including the
# read-before steps (resolution, lookups, current-state GETs) of tools that read first.
@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_ba_read_only_refuses_write_tools_before_any_upstream_call(monkeypatch, name):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, env={read_only.ENV_VAR: "1"})
    assert read_only.ENV_VAR in str(exc.value), f"{name}: {exc.value}"
    served = [(s.method, s.path) for s in up.served]
    assert served == [], f"{name}: upstream called before the read-only refusal: {served}"


@tool_batches("name", lambda: _lz_READ_TOOLS())
async def test_ba_read_tools_still_run_in_read_only_mode(monkeypatch, name):
    up = uh.FakeUpstream()
    try:
        await _call(monkeypatch, name, up, env={read_only.ENV_VAR: "1"})
    except ToolError as exc:
        assert read_only.ENV_VAR not in str(exc), f"{name}: read tool refused: {exc}"


@pytest.mark.parametrize("field", ["readOnlyHint", "read_only_hint"])
def test_ba_middleware_reads_either_sdk_hint_name(field):
    from types import SimpleNamespace

    from unifi_fabric.read_only_tools import _is_read_tool

    assert _is_read_tool(SimpleNamespace(annotations=SimpleNamespace(**{field: True})))
    assert not _is_read_tool(SimpleNamespace(annotations=SimpleNamespace(**{field: False})))
    assert not _is_read_tool(SimpleNamespace(annotations=None))


# =========================================================================== (bb)
# A free-form body dict reaches the write verbatim: a body key named like a Python
# parameter of the helper (site, host, client, registry, the id argument) is sent, never
# bound to that parameter (no ``got multiple values for argument`` TypeError).
_COLLIDING = ("site", "host", "client", "registry", "key")
# Tools whose object argument is not a free-form request body (a filter/query dict, an
# action selector, or a body the tool documents it builds itself).
_NOT_FREE_FORM_BODY = {
    "update_device_radio": "radios is an enum-band-keyed RadioChanges map, not free-form body",
    "bulk_delete_hotspot_vouchers": "filter_params is the DELETE query string, not a body",
    "get_unifi_placement_snapshot": "a read; its object argument selects snapshot sources",
}


@functools.cache
def _lz_FREE_FORM_WRITE_TOOLS():
    return sorted(
        n for n in _lz_WRITE_TOOLS() if _object_params(n) and n not in _NOT_FREE_FORM_BODY
    )


async def _eligible_bb_body_keys_named_like_parameters_are_sent(name):
    args = sc.conformance_args(name)
    injected = [p for p in _object_params(name) if isinstance(args.get(p), dict)]
    if not injected:
        return False
    return True


@tool_batches(
    "name",
    lambda: _lz_FREE_FORM_WRITE_TOOLS(),
    eligible=_eligible_bb_body_keys_named_like_parameters_are_sent,
)
async def test_bb_body_keys_named_like_parameters_are_sent(monkeypatch, name):
    tool = _lz_TOOLS()[name]
    args = sc.conformance_args(name)
    id_args = [p for p in (tool.parameters.get("properties") or {}) if p.endswith("_id")]
    colliding = {k: f"probe-{k}-value" for k in (*_COLLIDING, *id_args)}
    injected = [p for p in _object_params(name) if isinstance(args.get(p), dict)]
    if not injected:
        raise AssertionError("inapplicable case was not filtered before batching")
    for param in injected:
        args[param] = {**args[param], **colliding}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args=args)
    sent = _all_keys(_write_bodies(up))
    missing = [k for k, v in colliding.items() if v not in sent.get(k, [])]
    assert missing == [], f"{name}: body keys not sent verbatim: {missing}"


# =========================================================================== (bc)
# No write drops a field its published request schema accepts. The Integration
# read-modify-write sanitizer strips server-managed fields (id, metadata, default, index);
# a field the target operation's schema lists (ACL rule ``index``) must still be sent.
def _specced_body_writes() -> list[str]:
    out = []
    for name in _lz_WRITE_TOOLS():
        if not _object_params(name) or name in _NOT_FREE_FORM_BODY:
            continue
        out.append(name)
    return sorted(out)


# Writes whose object argument is not forwarded as a pass-through body, so the probe of
# the no-published-schema branch below does not apply to them.
_NOT_PASS_THROUGH_BODY = {
    "delete_qos_rule": "the object argument is a list of rule ids, not a body object",
    "reorder_qos_rules": "the object argument is an ordered list of rule ids, not a body object",
    "enroll_doorbell_credential": "fields applies only to step assign and is refused for enroll",
    "get_multicast_insights": "query_params is the query string of a POST with no body",
}


def test_bc_pass_through_exemptions_are_body_writes():
    assert set(_NOT_PASS_THROUGH_BODY) <= set(_specced_body_writes())


async def _eligible_bc_write_forwards_every_field_its_spec_schema_accepts(monkeypatch, name):
    tool = _lz_TOOLS()[name]
    args = sc.conformance_args(name)
    if name == "fabric_connector_get":
        args["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args=args)
    targets = [_spec_operation(s.method, s.path) for s in up.writes()]
    targets = [t for t in targets if t is not None]
    accepted: set[str] = set()
    for spec, _template, op in targets:
        accepted |= _request_body_props(spec, op)
    if not accepted:
        if name in _NOT_PASS_THROUGH_BODY:
            return False
        probes = {"probeField": "probe-probeField"}
        for param in _object_params(name):
            args[param] = {**(args.get(param) or {}), **probes}
    else:
        from unifi_fabric.tools import _payload

        probes = {f: f"probe-{f}" for f in accepted & _payload._INTEGRATION_READONLY_FIELDS}
        props = (tool.parameters or {}).get("properties") or {}
        if "name" in accepted and "name" not in props:
            probes["name"] = "probe-name-field"
        injected = [p for p in _object_params(name) if isinstance(args.get(p), dict)]
        if not probes or not injected:
            return False
        for param in injected:
            args[param] = {**args[param], **probes}
    return True


@tool_batches(
    "name",
    lambda: _specced_body_writes(),
    eligible=_eligible_bc_write_forwards_every_field_its_spec_schema_accepts,
)
async def test_bc_write_forwards_every_field_its_spec_schema_accepts(monkeypatch, name):
    tool = _lz_TOOLS()[name]
    args = sc.conformance_args(name)
    if name == "fabric_connector_get":
        args["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args=args)
    targets = [_spec_operation(s.method, s.path) for s in up.writes()]
    targets = [t for t in targets if t is not None]
    accepted: set[str] = set()
    for spec, _template, op in targets:
        accepted |= _request_body_props(spec, op)
    if not accepted:
        if name in _NOT_PASS_THROUGH_BODY:
            raise AssertionError("inapplicable case was not filtered before batching")
        # No published request schema (Classic and private controller routes): the object
        # argument is forwarded as given, so a non-reserved key put into every object
        # argument (optional ones included) must reach the write verbatim.
        probes = {"probeField": "probe-probeField"}
        for param in _object_params(name):
            args[param] = {**(args.get(param) or {}), **probes}
    else:
        from unifi_fabric.tools import _payload

        probes = {f: f"probe-{f}" for f in accepted & _payload._INTEGRATION_READONLY_FIELDS}
        props = (tool.parameters or {}).get("properties") or {}
        if "name" in accepted and "name" not in props:
            probes["name"] = "probe-name-field"
        injected = [p for p in _object_params(name) if isinstance(args.get(p), dict)]
        if not probes or not injected:
            raise AssertionError("inapplicable case was not filtered before batching")
        for param in injected:
            args[param] = {**args[param], **probes}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args=args)
    sent = _all_keys(
        [dict(httpx.QueryParams(request.query)) for request in up.writes()]
        if name == "fabric_connector_get"
        else _write_bodies(up)
    )
    dropped = [k for k, v in probes.items() if v not in sent.get(k, [])]
    assert dropped == [], f"{name}: spec-accepted body fields dropped: {dropped}"


# =========================================================================== (bd)
# Every query parameter a published write operation defines is reachable: a required one
# is validated before the call (fail fast naming it), an optional one is a tool argument
# that is sent only when given.
def _write_query_targets_of(name: str, requests: list) -> list[tuple[str, dict[str, bool]]]:
    out: list[tuple[str, dict[str, bool]]] = []
    if name in RAW_RELAY:
        return out
    for req in requests:
        if not read_only.is_write_request(req.method, req.path, uh.request_json(req)):
            continue
        hit = _spec_operation(req.method, req.path)
        if hit is None:
            continue
        spec, template, op = hit
        qp = _query_params(spec, template, op)
        if qp:
            out.append((template, qp))
    return out


def _write_query_targets() -> dict[str, list[tuple[str, dict[str, bool]]]]:
    out: dict[str, list[tuple[str, dict[str, bool]]]] = {}
    for name, requests in sc.captured_all().items():
        targets = _write_query_targets_of(name, requests)
        if targets:
            out[name] = targets
    return out


async def _captured(name: str) -> list:
    """The requests ``name`` sends with valid arguments (``sc.captured``), at EXECUTION.

    ``sc.capture`` runs its own event loop, so an async test reaches it via a thread."""
    return await asyncio.to_thread(sc.captured, name)


async def _write_query_targets_for(name: str) -> list[tuple[str, dict[str, bool]]]:
    """One tool's write query targets, captured at execution (never at collection)."""
    return _write_query_targets_of(name, await _captured(name))


@functools.cache
def _lz_WRITE_QUERY_TARGETS():
    return _write_query_targets()


def test_bd_write_query_parameters_are_swept():
    # the sweep is not vacuous: the four Network write operations with query parameters
    assert {
        "delete_network",
        "delete_wifi_broadcast",
        "bulk_delete_hotspot_vouchers",
        "set_firewall_policy_ordering",
    } <= set(_lz_WRITE_QUERY_TARGETS())


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


@tool_batches(
    "name",
    lambda: sorted(n for n in _lz_TOOLS() if n not in RAW_RELAY),
    member=_write_query_targets_for,
)
async def test_bd_spec_query_parameters_reachable(monkeypatch, name):
    props = (_lz_TOOLS()[name].parameters or {}).get("properties") or {}
    base = sc.conformance_args(name)
    for _template, qp in await _write_query_targets_for(name):
        for qname, required in qp.items():
            if required:
                continue  # sent on every call: test_spec_conformance proves it
            arg = qname if qname in props else _snake(qname)
            assert arg in props, f"{name}: optional spec query {qname!r} has no tool argument"
            up = uh.FakeUpstream()
            await _call(monkeypatch, name, up, args=dict(base))
            sent = [s.query for s in up.writes()]
            assert all(f"{qname}=" not in q for q in sent), f"{name}: {qname} sent unasked"
            up = uh.FakeUpstream()
            await _call(monkeypatch, name, up, args={**base, arg: True})
            sent = [s.query for s in up.writes()]
            assert any(f"{qname}=true" in q for q in sent), f"{name}: {qname} not sent: {sent}"


# ---- (bd) READ operations: the optional query parameters of every published read a
# tool passes through are tool arguments too, sent verbatim and only when given.
# Paging parameters are driven by the tool's own drain (every page is fetched), so they
# are not caller arguments; DERIVED / SELECT tools document a computed view or a record
# selection whose upstream query is the tool's own implementation, not a pass-through.
_DRAINED_PAGING = {"offset", "limit", "nextToken", "pageSize", "cursor"}
# (tool, spec query name) -> tool argument, where the argument is not the camel/snake
# form of the query name.
_QUERY_ARG_ALIASES = {
    ("list_devices", "hostIds[]"): "host",  # a console name/id, resolved to hostIds[]
    ("get_latest_firmware_versions", "hostIds[]"): "host",  # resolved like list_devices
    ("get_site_inventory", "/v1/sites/{siteId}/devices", "filter"): "device_filter",
    ("get_site_inventory", "/v1/sites/{siteId}/clients", "filter"): "client_filter",
}
# Aliased arguments that are resolved (not forwarded verbatim): reachability is the
# argument's existence; its resolution is covered by the tool's own tests.
_RESOLVED_ALIASES = {
    ("list_devices", "hostIds[]"),
    ("get_latest_firmware_versions", "hostIds[]"),
}


def _query_enums(spec: Any, template: str, op: dict[str, Any]) -> dict[str, list[Any]]:
    """{name: enum} of an operation's enum-constrained query parameters."""
    item = spec.doc["paths"][template]
    out: dict[str, list[Any]] = {}
    for raw in [*item.get("parameters", []), *op.get("parameters", [])]:
        p, _ = sc._resolve(spec, raw)
        schema, _ = sc._resolve(spec, p.get("schema") or {})
        if p.get("in") == "query" and schema.get("enum"):
            out[p["name"]] = list(schema["enum"])
    return out


def _read_query_targets_of(name: str, requests: list) -> list[tuple[str, dict[str, bool]]]:
    out: list[tuple[str, dict[str, bool]]] = []
    if name in RAW_RELAY or name in DERIVED or name in SELECT:
        return out
    for req in requests:
        if req.resolution or read_only.is_write_request(req.method, req.path, uh.request_json(req)):
            continue
        # A write tool may enumerate connected clients, or read the InnerSpace project
        # (its plans), solely to resolve its target (d3d68be0: plan writes resolve the
        # plan in the project first); that internal selection is not an exposed optional
        # query surface (the project read's mode only shapes device heights).
        if name in _lz_WRITE_TOOLS() and (
            req.path.endswith("/clients")
            or ("/innerspace/" in req.path and req.path.endswith("/project"))
        ):
            continue
        hit = _spec_operation(req.method, req.path)
        if hit is None:
            continue
        spec, template, op = hit
        qp = {
            q: r for q, r in _query_params(spec, template, op).items() if q not in _DRAINED_PAGING
        }
        if qp and (template, qp) not in out:
            out.append((template, qp))
            READ_QUERY_ENUMS[(name, template)] = _query_enums(spec, template, op)
    return out


def _read_query_targets() -> dict[str, list[tuple[str, dict[str, bool]]]]:
    out: dict[str, list[tuple[str, dict[str, bool]]]] = {}
    for name, requests in sc.captured_all().items():
        targets = _read_query_targets_of(name, requests)
        if targets:
            out[name] = targets
    return out


async def _read_query_targets_for(name: str) -> list[tuple[str, dict[str, bool]]]:
    return _read_query_targets_of(name, await _captured(name))


READ_QUERY_ENUMS: dict[tuple[str, str], dict[str, list[Any]]] = {}


@functools.cache
def _lz_READ_QUERY_TARGETS():
    return _read_query_targets()


def _query_arg(name: str, template: str, qname: str, props: dict[str, Any]) -> str:
    alias = _QUERY_ARG_ALIASES.get((name, template, qname)) or _QUERY_ARG_ALIASES.get((name, qname))
    if alias:
        return alias
    bare = qname.removesuffix("[]")
    return bare if bare in props else _snake(bare)


#: The value sent for an id-named query argument: a UUID satisfies both a ``format: uuid`` spec
#: rule (Carrier planId, firewall zone ids) and any plain-string id rule.
_ID_PROBE = "3fa85f64-5717-4562-b3fc-0000000b0d01"


def _probe(schema: dict[str, Any], arg: str = "") -> tuple[Any, str]:
    """(argument value, the query value it must arrive as) for a tool argument schema."""
    types = {schema.get("type")} | {a.get("type") for a in schema.get("anyOf") or []}
    if arg.endswith(("_id", "_ids")) and types & {"string", "array"}:
        return ([_ID_PROBE], _ID_PROBE) if "array" in types else (_ID_PROBE, _ID_PROBE)
    if "boolean" in types:
        return True, "true"
    if "array" in types:
        return ["probe-query-value"], "probe-query-value"
    if "integer" in types:
        return 7, "7"
    return "probe-query-value", "probe-query-value"


def _sent_values(up: uh.FakeUpstream, template: str, qname: str) -> list[str]:
    from urllib.parse import parse_qs

    out: list[str] = []
    for served in up.served:
        if served.resolution:
            continue
        hit = _spec_operation(served.method, served.path)
        if hit is None or hit[1] != template:
            continue
        out.extend(parse_qs(served.query, keep_blank_values=True).get(qname, []))
    return out


def test_bd_read_query_parameters_are_swept():
    # the sweep is not vacuous: the read tools whose optional spec query parameters are
    # pass-through arguments
    assert {
        "get_camera_snapshot",
        "get_isp_metrics",
        "list_devices",
        "list_all_devices",
        "list_all_clients",
        "get_site_inventory",
    } <= set(_lz_READ_QUERY_TARGETS())


@tool_batches("name", lambda: sorted(_lz_TOOLS()), member=_read_query_targets_for)
async def test_bd_read_spec_query_parameters_reachable(monkeypatch, name):
    props = (_lz_TOOLS()[name].parameters or {}).get("properties") or {}
    base = sc.conformance_args(name)
    for template, qp in await _read_query_targets_for(name):
        for qname, required in qp.items():
            if required:
                continue  # sent on every call: test_spec_conformance proves it
            arg = _query_arg(name, template, qname, props)
            assert arg in props, f"{name}: optional spec query {qname!r} has no tool argument"
            if (name, qname) in _RESOLVED_ALIASES or arg in base:
                continue
            up = uh.FakeUpstream(replay_recordings=False)
            await _call(monkeypatch, name, up, args=dict(base))
            if props[arg].get("default") is None:
                # an argument with a documented non-null default sends that default
                assert _sent_values(up, template, qname) == [], f"{name}: {qname} sent unasked"
            value, wire = _probe(props[arg], arg)
            enum = READ_QUERY_ENUMS.get((name, template), {}).get(qname)
            if enum and isinstance(value, str):
                value = wire = str(enum[-1])  # an accepted value, not the default
            up = uh.FakeUpstream(replay_recordings=False)
            await _call(monkeypatch, name, up, args={**base, arg: value})
            sent = _sent_values(up, template, qname)
            assert wire in sent, f"{name}: {qname} not sent verbatim from {arg}: {sent}"


# ---- (bd) paging consistency: every list tool whose own upstream operation publishes a
# paging family exposes that family's manual-paging entry point (every family, not only
# offset/limit). Each entry argument defaults to null (drain-all); explicit continuation
# controls fetch one page. Mobility's size-only limit is a logical gathered total.
#: spec paging query parameters -> {tool argument: (value, spec query name, wire value)};
#: the first argument is the first-page entry (usable without a cursor).
PAGING_FAMILIES: dict[frozenset[str], dict[str, tuple[Any, str, str]]] = {
    frozenset({"offset", "limit"}): {"limit": (3, "limit", "3"), "offset": (7, "offset", "7")},
    frozenset({"limit", "cursor"}): {
        "limit": (3, "limit", "3"),
        "cursor": ("probe-cursor", "cursor", "probe-cursor"),
    },
    frozenset({"pageSize", "nextToken"}): {
        "page_size": (3, "pageSize", "3"),
        "page_token": ("probe-token", "nextToken", "probe-token"),
    },
}
_PAGING_EXEMPT = {
    "list_all_clients": "fans out over every site of every console; a caller page of one "
    "site's list is not a page of the merged result",
    "list_all_devices": "a fleet view flattened across every key and console; one page of one "
    "key's /v1/devices is list_devices (page_token / page_size)",
}


#: List tools whose own read is a route the harness also serves as a name resolution.
_OWN_RESOLUTION_LIST = {"list_hosts": "/v1/hosts", "list_sites": "/v1/sites"}


def _paging_target_of(name: str, requests: list) -> tuple[str, frozenset[str]] | None:
    if not name.startswith("list_") or name in RAW_RELAY or name in DERIVED:
        return None
    for req in requests:
        own = _OWN_RESOLUTION_LIST.get(name) == req.path
        if (req.resolution and not own) or read_only.is_write_request(
            req.method, req.path, uh.request_json(req)
        ):
            continue
        hit = _spec_operation(req.method, req.path)
        if hit is None:
            continue
        spec, template, op = hit
        published = set(_query_params(spec, template, op))
        for family in PAGING_FAMILIES:
            if family <= published:
                return (template, family)
    return None


def _paging_targets() -> dict[str, tuple[str, frozenset[str]]]:
    out: dict[str, tuple[str, frozenset[str]]] = {}
    for name, requests in sc.captured_all().items():
        target = _paging_target_of(name, requests)
        if target is not None:
            out[name] = target
    return out


async def _paging_target_for(name: str) -> tuple[str, frozenset[str]] | None:
    return _paging_target_of(name, await _captured(name))


@functools.cache
def _lz_PAGING_TARGETS():
    return _paging_targets()


def test_bd_paging_targets_are_swept():
    assert {
        "list_wifi_broadcasts",
        "list_acl_rules",
        "list_traffic_matching_lists",
        "list_site_to_site_tunnels",
        "list_wan_interfaces",
        "list_pending_devices",
        "list_countries",
        "list_networks",
        "list_clients",
        "list_mobility_devices",
        "list_mobility_clients",
        "list_carrier_subscribers",
        "list_hosts",
        "list_sites",
        "list_devices",
    } <= set(_lz_PAGING_TARGETS())
    assert set(_PAGING_EXEMPT) <= set(_lz_PAGING_TARGETS())
    assert {fam for _t, fam in _lz_PAGING_TARGETS().values()} == set(PAGING_FAMILIES)


def _pages(up: uh.FakeUpstream, template: str) -> list[Any]:
    """The requests to ``template`` (a list route is never another tool's resolution)."""
    return [
        s for s in up.served if (hit := _spec_operation(s.method, s.path)) and hit[1] == template
    ]


def _page_values(up: uh.FakeUpstream, template: str, qname: str) -> list[str]:
    from urllib.parse import parse_qs

    return [
        v
        for s in _pages(up, template)
        for v in parse_qs(s.query, keep_blank_values=True).get(qname, [])
    ]


@tool_batches(
    "name",
    lambda: sorted(n for n in _lz_TOOLS() if n.startswith("list_") and n not in _PAGING_EXEMPT),
    member=_paging_target_for,
)
async def test_bd_list_tools_expose_spec_paging_and_fetch_one_page(monkeypatch, name):
    props = (_lz_TOOLS()[name].parameters or {}).get("properties") or {}
    template, family = await _paging_target_for(name)
    entry = PAGING_FAMILIES[family]
    for arg in entry:
        assert arg in props, f"{name}: the spec pages with {family} but the tool has no {arg}"
        assert props[arg].get("default") is None, f"{name}: {arg} must default to drain-all"
    base = sc.conformance_args(name)
    # Mobility's fixture supplies a terminal total for offset 7 and limit 3.
    up = uh.FakeUpstream(
        mode="paged" if name in {"list_mobility_clients", "list_mobility_devices"} else "normal",
        replay_recordings=False,
    )
    await _call(monkeypatch, name, up, args={**base, **{a: v for a, (v, _q, _w) in entry.items()}})
    pages = _pages(up, template)
    assert len(pages) == 1, f"{name}: manual paging must fetch one page, fetched {len(pages)}"
    for _value, qname, wire in entry.values():
        assert _page_values(up, template, qname) == [wire], (name, qname)
    first_arg, (value, qname, wire) = next(iter(entry.items()))
    # Mobility's first response has nine rows without a total; the next request
    # distinguishes a logical boundary from an unpaged or short-page response.
    up = uh.FakeUpstream(
        mode="paged" if name in {"list_mobility_clients", "list_mobility_devices"} else "normal",
        replay_recordings=False,
    )
    payload = uh.result_payload(await _call(monkeypatch, name, up, args={**base, first_arg: value}))
    if name in {"list_mobility_clients", "list_mobility_devices"}:
        pages = _pages(up, template)
        from urllib.parse import parse_qs

        assert len(pages) == 2
        assert [parse_qs(page.query) for page in pages] == [
            {"limit": ["3"]},
            {"offset": ["3"], "limit": ["1"]},
        ]
        assert _page_values(up, template, "limit") == ["3", "1"]
        assert _page_values(up, template, "offset") == ["3"]
        assert payload["data"] == up._items(pages[0].path, 9)[:3]
        assert payload["_pageSize"] == {
            "requested": 3,
            "sent": [3, 1],
            "effective": 3,
            "returned": 3,
        }
        assert payload["_nextOffset"] == 3
        up = uh.FakeUpstream(mode="paged", replay_recordings=False)
        await _call(monkeypatch, name, up, args={**base, "offset": 7})
        assert len(_pages(up, template)) == 1
        assert _page_values(up, template, "offset") == ["7"]
        assert _page_values(up, template, "limit") == []
    else:
        assert len(_pages(up, template)) == 1, f"{name}: {first_arg} alone must fetch one page"
        assert _page_values(up, template, qname) == [wire], (name, qname)


def test_bd_query_arg_aliases_name_real_arguments():
    assert ("list_devices", "hostIds[]") in _QUERY_ARG_ALIASES
    for alias_key, arg in _QUERY_ARG_ALIASES.items():
        props = (_lz_TOOLS()[alias_key[0]].parameters or {}).get("properties") or {}
        assert arg in props, f"{alias_key}: alias {arg!r} is not a tool argument"


async def test_bd_required_query_dict_fails_fast_naming_the_field(monkeypatch):
    up = uh.FakeUpstream()
    args = {**sc.conformance_args("bulk_delete_hotspot_vouchers"), "filter_params": {}}
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, "bulk_delete_hotspot_vouchers", up, args=args)
    assert "filter" in str(exc.value)
    assert up.served == [], "upstream called without the spec-required filter"


# =========================================================================== (be)
# A string argument interpolated into a request path never rewrites the request's path or
# query string: ``?``, ``#`` or ``/`` in it either fails fast before any upstream call, or
# (a spec ``type: string`` path id) arrives percent-encoded as exactly ONE segment.
def _path_string_args(name: str, up: uh.FakeUpstream, args: dict[str, Any]) -> list[str]:
    props = (_lz_TOOLS()[name].parameters or {}).get("properties") or {}
    paths = [s.path for s in up.served if not s.resolution]
    out = []
    for arg, value in args.items():
        if arg in ("host", "site") or not isinstance(value, str) or len(value) < 6:
            continue
        if (props.get(arg) or {}).get("type") != "string":
            continue
        if any(value in p for p in paths):
            out.append(arg)
    return out


async def _eligible_be_path_arguments_reject_query_and_path_characters(name):
    if name in NO_UPSTREAM:
        return False
    return True


@tool_batches(
    "name",
    lambda: sorted(n for n in _lz_TOOLS() if n not in RAW_RELAY),
    eligible=_eligible_be_path_arguments_reject_query_and_path_characters,
)
async def test_be_path_arguments_reject_query_and_path_characters(monkeypatch, name):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    args = sc.conformance_args(name)
    up = uh.FakeUpstream()
    try:
        await _call(monkeypatch, name, up, args=dict(args))
    except ToolError:
        raise AssertionError("unexpected baseline call error") from None
    for arg in _path_string_args(name, up, args):
        for probe in (_PROBE_QS, "zzq/x#y"):
            up = uh.FakeUpstream()
            try:
                await _call(monkeypatch, name, up, args={**args, arg: probe})
            except ToolError:
                pass
            primary = [s for s in up.served if not s.resolution]
            leaked = [
                (s.method, s.raw_path, s.query)
                for s in primary
                if "x=1" in s.query
                or ("zzq" in s.raw_path and quote(probe, safe="") not in s.raw_path.split("/"))
            ]
            assert leaked == [], f"{name}.{arg}: path argument rewrote the request {leaked}"


# =========================================================================== (bf)
# A field the published schema marks required is the caller's choice: a tool never fills
# a default in for it. Every scalar argument that becomes a spec-required body field is a
# required tool argument.
@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_bf_spec_required_body_fields_are_never_defaulted(monkeypatch, name):
    tool = _lz_TOOLS()[name]
    props = (tool.parameters or {}).get("properties") or {}
    required_args = set(tool.parameters.get("required") or [])
    args = sc.conformance_args(name)
    # This tool contract intentionally names the generated AP.
    up = uh.FakeUpstream(replay_recordings=name != "update_device_radio")
    await _call(monkeypatch, name, up, args=args)
    problems = []
    for s in up.writes():
        hit = _spec_operation(s.method, s.path)
        if hit is None or not isinstance(s.sent_json, dict):
            continue
        spec, _template, op = hit
        body = op.get("requestBody")
        if not body:
            continue
        body, _ = sc._resolve(spec, body)
        schema, _ = sc._resolve(
            spec, ((body.get("content") or {}).get("application/json") or {}).get("schema") or {}
        )
        for field_name in schema.get("required") or []:
            arg = _snake(field_name)
            if arg in props and arg not in required_args:
                problems.append(f"{field_name} (argument {arg} has a default)")
    assert problems == [], f"{name}: spec-required body fields filled in by default: {problems}"


# =========================================================================== (bg)
# An array argument is forwarded exactly as given: an explicit empty list is never
# replaced with a default list.
def _optional_array_args(name: str) -> list[str]:
    schema = _lz_TOOLS()[name].parameters or {}
    required = set(schema.get("required") or [])
    out = []
    for arg, spec in (schema.get("properties") or {}).items():
        types = {spec.get("type")} | {s.get("type") for s in spec.get("anyOf", [])}
        if "array" in types and arg not in required:
            out.append(arg)
    return out


# Tools whose list argument is merged with entries built from other arguments the caller
# gave (not a default substituted for it).
_ARRAY_UNION = {
    "query_isp_metrics": "the body sites list is `sites` plus the host+site entry the caller "
    "also passed (documented: scope by sites, or host+site)",
}


@functools.cache
def _lz_ARRAY_ARG_TOOLS():
    return sorted(n for n in _lz_TOOLS() if _optional_array_args(n) and n not in _ARRAY_UNION)


_BG_PROBE = "probe-bg-item"


def test_bg_union_policy_names_real_tools():
    assert set(_ARRAY_UNION) <= set(_lz_TOOLS())


@lazy_parametrize("name", lambda: _lz_ARRAY_ARG_TOOLS())
async def test_bg_explicit_empty_list_is_never_replaced(monkeypatch, name):
    for arg in _optional_array_args(name):
        keys = {arg, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), arg)}
        # Where a given list travels in a JSON body, the empty list must arrive there as
        # []: a key dropped from the body would otherwise pass unnoticed.
        probe = uh.FakeUpstream()
        try:
            await _call(
                monkeypatch,
                name,
                probe,
                args={**tool_args.generated_args(_lz_TOOLS()[name]), arg: [_BG_PROBE]},
            )
        except ToolError:
            pass
        in_body = any(
            isinstance(s.sent_json, dict) and s.sent_json.get(key) == [_BG_PROBE]
            for s in probe.served
            for key in keys
        )
        up = uh.FakeUpstream()
        args = {**tool_args.generated_args(_lz_TOOLS()[name]), arg: []}
        try:
            await _call(monkeypatch, name, up, args=args)
        except ToolError:
            continue  # rejecting an empty list is the caller's error, not a substitution
        seen = []
        for s in up.served:
            body = s.sent_json if isinstance(s.sent_json, dict) else {}
            for key in keys:
                if key in body:
                    seen.append(body[key])
                    assert body[key] == [], f"{name}: {arg}=[] sent as {body[key]!r}"
        if in_body:
            assert seen, f"{name}: {arg}=[] was dropped from the body it travels in"


# =========================================================================== (bh)
# "Get it from <tool> (<path>[].<field>)" hand-offs name a path the read tool's result
# really has (update_wan_interface once pointed at data[].id; the result is wans[]).
# ``([]._id)`` (empty key) names a tool whose result is a bare JSON array.
_HANDOFF = re.compile(r"[Gg]et (?:it|them|one|ids?) from `?([a-z_]+)`? \(([A-Za-z_]*)\[\]\.")


def _handoffs() -> list[tuple[str, str, str]]:
    out = []
    for where, text in _all_descriptions():
        for m in _HANDOFF.finditer(text):
            if m.group(1) in _lz_TOOLS() and _is_read(_lz_TOOLS()[m.group(1)]):
                out.append((where, m.group(1), m.group(2)))
    return sorted(set(out))


@functools.cache
def _lz_HANDOFFS():
    return _handoffs()


def test_bh_handoffs_are_swept():
    assert len(_lz_HANDOFFS()) >= 50


_ANY_HANDOFF = re.compile(r"[Gg]et (?:it|them|one|ids?) from `?([a-z_]+)`?(\s*\()?")


def test_bh_every_handoff_names_the_field_to_read():
    # "Get it from list_x" alone leaves the caller guessing which field holds the value
    # (reject_pending_device once said "Pending device id. Get it from
    # list_pending_devices." where pending devices have no id field at all).
    bare = [
        f"{where}: {m.group(0)}"
        for where, text in _all_descriptions()
        for m in _ANY_HANDOFF.finditer(text)
        if not m.group(2)
    ]
    assert bare == [], bare


@lazy_parametrize(("where", "source", "key"), lambda: _lz_HANDOFFS())
async def test_bh_handoff_paths_exist_in_the_source_result(monkeypatch, where, source, key):
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, source, up))
    if isinstance(payload, dict) and "result" in payload and len(payload) == 1:
        payload = payload["result"]
    if key == "":
        assert isinstance(payload, list), f"{where}: hand-off says {source} returns an array"
        return
    keys = set(payload) if isinstance(payload, dict) else set()
    assert key in keys, f"{where}: hand-off names {source} ({key}[]) but its result has {keys}"


# =========================================================================== (bi)
# Every tool that drains an offset list returns the upstream ``totalCount`` with it, so a
# caller can tell a complete list from a partial one.
def _drained_totals(up: uh.FakeUpstream) -> set[Any]:
    out = set()
    for s in up.served:
        if s.resolution or not isinstance(s.body, dict):
            continue
        if "totalCount" in s.body and isinstance(s.body.get("data"), list):
            out.add(s.body["totalCount"])
    return out


async def _eligible_bi_offset_drains_return_the_upstream_total(monkeypatch, name):
    if name in NO_UPSTREAM or name in DERIVED or (name in SELECT and name != "list_wan_interfaces"):
        return False
    if name in RAW_RELAY or name in ENUMERATING:
        return False
    up = uh.FakeUpstream(mode="paged")
    try:
        uh.result_payload(await _call(monkeypatch, name, up))
    except ToolError:
        raise AssertionError("unexpected baseline call error") from None
    totals = _drained_totals(up)
    if not totals:
        return False
    return True


@tool_batches(
    "name", lambda: _lz_READ_TOOLS(), eligible=_eligible_bi_offset_drains_return_the_upstream_total
)
async def test_bi_offset_drains_return_the_upstream_total(monkeypatch, name):
    if name in NO_UPSTREAM or name in DERIVED or name in SELECT and name != "list_wan_interfaces":
        raise AssertionError("inapplicable case was not filtered before batching")
    if name in RAW_RELAY or name in ENUMERATING:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(mode="paged")
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up))
    except ToolError:
        raise AssertionError("unexpected baseline call error") from None
    totals = _drained_totals(up)
    if not totals:
        raise AssertionError("inapplicable case was not filtered before batching")
    # Network Integration names it totalCount; the Mobility spec names it total
    totals_keys = ("totalCount", "total")
    returned = {v for k, vals in _all_keys(payload).items() if k in totals_keys for v in vals}
    assert totals & returned, f"{name}: upstream totalCount {totals} not returned"


# =========================================================================== (bj)
# A literal request body quoted in a description (``{'action': 'X'}``) uses a value the
# published schema accepts, unless the same sentence says the controller rejects it.
_LITERAL = re.compile(r"\{['\"](\w+)['\"]:\s*['\"]([\w-]+)['\"]")


def _enum_values(spec: Any, node: Any, prop: str, seen: set[str] | None = None) -> set[str]:
    seen = set() if seen is None else seen
    out: set[str] = set()
    if not isinstance(node, dict):
        return out
    if node.get("$ref"):
        if node["$ref"] in seen:
            return out
        seen.add(node["$ref"])
        return _enum_values(spec, sc._resolve(spec, node)[0], prop, seen)
    disc = node.get("discriminator") or {}
    if disc.get("propertyName") == prop:
        out |= set(disc.get("mapping") or {})
    p = (node.get("properties") or {}).get(prop)
    if isinstance(p, dict):
        p = sc._resolve(spec, p)[0]
        out |= set(p.get("enum") or [])
    for key in ("allOf", "oneOf", "anyOf"):
        for branch in node.get(key) or []:
            out |= _enum_values(spec, branch, prop, seen)
    return out


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
def test_bj_quoted_body_values_match_the_spec_enum(name):
    text = _lz_TOOLS()[name].description or ""
    literals = list(_LITERAL.finditer(text))
    if not literals:
        return
    ops = [_spec_operation(r.method, r.path) for r in sc.captured(name)]
    ops = [o for o in ops if o is not None and o[2].get("requestBody")]
    bad = []
    for m in literals:
        prop, value = m.group(1), m.group(2)
        if re.search(r"[:\[]\s*\Z", text[: m.start()]):
            continue  # a nested object (the value of another key or a list item)
        allowed: set[str] = set()
        for spec, _t, op in ops:
            body, _ = sc._resolve(spec, op["requestBody"])
            schema = ((body.get("content") or {}).get("application/json") or {}).get("schema")
            allowed |= _enum_values(spec, schema, prop)
        if not allowed or value in allowed:
            continue
        start = max(text.rfind(". ", 0, m.start()), text.rfind("\n\n", 0, m.start()), 0)
        stops = [i for i in (text.find(". ", m.end()), text.find("\n\n", m.end())) if i >= 0]
        sentence = text[start : min(stops) if stops else len(text)]
        if re.search(r"reject|HTTP 400|unknown-type-id|invalid", sentence, re.I):
            continue
        bad.append(f"{prop}={value!r} (spec allows {sorted(allowed)})")
    assert bad == [], f"{name}: {bad}"


# =========================================================================== (bk)
# Filter-expression examples in descriptions quote string operands (``model.eq('U6
# Pro')``); an unquoted multi-word operand is not valid filter syntax.
_FILTER_EXAMPLE = re.compile(r"\b[\w.]+\.(?:eq|ne|like|in|notIn)\(([^)]*)\)")


def test_bk_filter_examples_quote_string_operands():
    bad = []
    for where, text in _all_descriptions():
        for m in _FILTER_EXAMPLE.finditer(text):
            operand = m.group(1).strip()
            if (
                not operand
                or operand[0] in "'\""
                or re.fullmatch(r"[\d.,\s-]+|true|false|null", operand)
            ):
                continue
            bad.append(f"{where}: {m.group(0)}")
    assert bad == [], bad


def test_bk_instructions_attribute_radius_profiles_to_network_integration():
    radius = [ln for ln in _usage_workflows().splitlines() if "RADIUS" in ln]
    block = _usage_workflows()[_usage_workflows().index("RADIUS profiles (list") :][:400]
    assert radius
    assert "Site Manager" not in block, block
    assert "Network Integration" in block, block


# =========================================================================== (aa)
_NO_DRY_RUN_CLAIM = re.compile(r"no\s+dry-run", re.IGNORECASE)


def _dry_run_previews(obj: Any) -> list[dict]:
    return [n for n in _nested_objects(obj) if is_dry_run_preview(n)]


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_aa_dry_run_sends_no_write_upstream(monkeypatch, name):
    """Under UNIFI_DRY_RUN no write is sent AND the tool returns the preview.

    A tool that verifies its write (read-before / write / read-after) must return the
    preview rather than verify a write that never happened: raising "silent no-op" or
    reporting the write as unverified is the defect this guards against.
    """
    up = uh.FakeUpstream()
    res = await _call(monkeypatch, name, up, env={"UNIFI_DRY_RUN": "1"})
    assert up.writes() == [], f"{name}: a write reached the transport under UNIFI_DRY_RUN=1"
    payload = uh.result_payload(res)
    previews = _dry_run_previews(payload)
    assert previews, f"{name}: no dry-run preview in the result: {str(payload)[:300]}"
    for key in ("verified", "after", "readAfter", "noOp", "changed"):
        if isinstance(payload, dict) and key in payload:
            assert payload[key] in (None, {}), (
                f"{name}: dry-run result reports {key}={payload[key]}"
            )


def _preview_param_sets(payload: Any) -> list[tuple[tuple[str, str], ...]]:
    """Each dry-run preview's ``params`` as a sorted tuple of encoded query pairs."""
    out = []
    for node in _dry_run_previews(payload):
        params = node["preview"].get("params")
        out.append(tuple(sorted(httpx.QueryParams(params or {}).multi_items())))
    return out


def _completed_write_claims(payload: Any) -> list[str]:
    """Keys in a dry-run result that claim a write happened (none may appear)."""
    claims = [f"deleted={n['deleted']!r}" for n in _nested_objects(payload) if n.get("deleted")]
    if isinstance(payload, dict):
        if "forgotten" in payload:
            claims.append(f"forgotten={payload['forgotten']!r}")
        # Any status but "dry_run" (an HTTP code such as 200 included) claims an outcome
        # the upstream never returned: nothing was sent.
        status = payload.get("status")
        if status is not None and status != "dry_run":
            claims.append(f"status={status!r}")
    return claims


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_aa_dry_run_result_never_reports_a_completed_write(monkeypatch, name):
    """Under UNIFI_DRY_RUN no result says the write happened: no ``deleted: true``, no
    ``forgotten`` list, and a ``status`` string (when present) is ``"dry_run"``. A delete
    tool (one whose preview is a DELETE) says ``status: "dry_run"`` explicitly."""
    up = uh.FakeUpstream()
    res = await _call(monkeypatch, name, up, env={"UNIFI_DRY_RUN": "1"})
    payload = uh.result_payload(res)
    claims = _completed_write_claims(payload)
    assert claims == [], f"{name}: dry-run result claims a completed write: {claims}"
    previews = _dry_run_previews(payload)
    # A delete tool, and the connector relay for every method (no exemption), says
    # status "dry_run" explicitly.
    if any(p["preview"]["method"] == "DELETE" for p in previews) or name in RAW_RELAY:
        assert isinstance(payload, dict) and payload.get("status") == "dry_run", (
            f"{name}: a dry-run result must report status 'dry_run': {str(payload)[:300]}"
        )


@functools.cache
def _lz_DELETE_TOOLS():
    return sorted(
        n
        for n in _lz_WRITE_TOOLS()
        if n.startswith(("delete_", "bulk_delete_")) and n not in RAW_RELAY
    )


def test_aa_delete_tool_set_is_non_empty():
    assert len(_lz_DELETE_TOOLS()) >= 15, _lz_DELETE_TOOLS()


def _is_delete_preview(
    preview: dict[str, Any], name: str = "delete_radius_account", up: uh.FakeUpstream | None = None
) -> bool:
    """Resolving deletes are checked against their own method, collection and body."""
    if name in _RESOLVING_WRITES:
        write = uh.Served(
            preview["method"],
            str(preview.get("path") or ""),
            200,
            None,
            False,
            sent_json=preview.get("body"),
        )
        addressed = _bl_addressed_ids(write, name)
        if up is None:
            return bool(addressed)
        arg, purpose, _foreign = _RESOLVING_WRITES[name]
        wanted = tool_args.generated_args(_lz_TOOLS()[name])[arg]
        matches = [
            record
            for record in _bl_records(up, name, purpose)
            if any(
                str(record.get(field, "")).casefold() == str(wanted).casefold()
                for field in ("_id", "id", "external_id", "name")
            )
        ]
        return len(matches) == 1 and addressed == [matches[0]["_id"]]

    contract = _aa_extra_contracts()[name]
    path, arg, listed, id_field = contract
    shape = _AA_DELETE_SHAPES.get(name, {})
    args = tool_args.generated_args(_lz_TOOLS()[name])
    wanted: Any = None
    if arg is not None:
        wanted = args[arg]
        if up is not None and listed is not None:
            listed_path = _aa_fill(listed, args)
            records = [
                record
                for served in up.served
                if served.method == "GET"
                and served.path == listed_path
                and 200 <= served.status < 300
                for record in uh.upstream_records(served.body)
                if isinstance(record, dict)
                and any(
                    str(record.get(field, "")).casefold() == str(wanted).casefold()
                    for field in (id_field, "id", "external_id", "name")
                )
            ]
            if len(records) != 1:
                return False
            wanted = records[0][id_field]
        path = path.replace("{id}", str(wanted))
        if name == "delete_bgp_config" and up is not None:
            singleton = _aa_fill(listed.removesuffix("/all"), args)
            singleton_rows = [
                row
                for served in up.served
                if served.method == "GET"
                and served.path == singleton
                and 200 <= served.status < 300
                for row in uh.upstream_records(served.body)
                if isinstance(row, dict)
                and any(
                    str(row.get(field, "")).casefold() == str(wanted).casefold()
                    for field in ("_id", "id")
                )
            ]
            if singleton_rows:
                path = singleton
    path = _aa_fill(path, args)
    params = None
    if name == "bulk_delete_hotspot_vouchers":
        params = args.get("filter_params")
    elif name == "delete_rtsps_stream":
        params = {"qualities": args["qualities"]}
    elif name in {"delete_network", "delete_wifi_broadcast"} and args.get("force") is not None:
        params = {"force": str(args["force"]).lower()}
    elif "params" in shape:
        params = shape["params"](args)
    expected_body = shape["body"](args, wanted) if "body" in shape else None
    return (
        preview["method"] == shape.get("method", "DELETE")
        and preview.get("path") == path
        and preview.get("body") == expected_body
        and sorted(httpx.QueryParams(preview.get("params") or {}).multi_items())
        == sorted(httpx.QueryParams(params or {}).multi_items())
    )


def _aa_fill(template: str, args: dict[str, Any]) -> str:
    """``template`` with each ``{argument}`` replaced by the generated argument's value."""
    for key, value in args.items():
        if isinstance(value, str | int) and not isinstance(value, bool):
            template = template.replace("{" + key + "}", str(value))
    return template


#: Deletes that do not simply DELETE a path: the HTTP method, the request body and the
#: query each derives from the tool's own code (cited per entry), never from a guess.
_AA_DELETE_SHAPES: dict[str, dict[str, Any]] = {
    # protect_camera_recording.delete_recordings: DELETE /video?camera&start&end, the
    # epoch SECONDS arguments sent as milliseconds (_epoch_ms).
    "delete_recordings": {
        "params": lambda a: {
            "camera": a["camera_id"],
            "start": int(a["start"]) * 1000,
            "end": int(a["end"]) * 1000,
        }
    },
    # protect_ptz_doorbell.delete_camera_shortcut: DELETE .../shortcuts?shortcutIds=...
    "delete_camera_shortcut": {"params": lambda a: {"shortcutIds": a["shortcut_ids"]}},
    # protect_users_assets.delete_protect_file: always sends ignoreFileExtension.
    "delete_protect_file": {
        "params": lambda a: {"ignoreFileExtension": a.get("ignore_file_extension", False)}
    },
    # Classic POST commands (no HTTP DELETE exists for them in the Network inventory).
    "delete_controller_backup": {
        "method": "POST",
        "body": lambda a, w: {"cmd": "delete-backup", "filename": a["filename"]},
    },
    "delete_site": {
        "method": "POST",
        "body": lambda a, w: {"cmd": "delete-site", "site": w},
    },
    "delete_site_vpn": {
        "method": "POST",
        "body": lambda a, w: {"cmd": "delete-site-vpn", "name": a["name"], "site": a["vpn_site"]},
    },
    # v2 batch routes: the web app deletes with POST and a body of ids.
    "delete_qos_rule": {"method": "POST", "body": lambda a, w: a["body"]},
    "delete_wireguard_users": {"method": "POST", "body": lambda a, w: a["users"]},
}


def _aa_extra_contracts() -> dict[str, tuple[str, str | None, str | None, str]]:
    prefix = f"/v1/connector/consoles/{uh.HOST_ID}/proxy/network"
    integration = prefix + f"/integration/v1/sites/{uh.SITE_ID}"
    classic = prefix + "/api/s/default/rest"
    v2 = prefix + "/v2/api/site/default"
    protect = f"/v1/connector/consoles/{uh.HOST_ID}/proxy/protect/integration/v1"
    root = f"/v1/connector/consoles/{uh.HOST_ID}/proxy"
    protect_api = root + "/protect/api"
    innerspace_api = root + "/innerspace/api"
    classic_api = prefix + "/api/s/default"
    return {
        "bulk_delete_hotspot_vouchers": (integration + "/hotspot/vouchers", None, None, "id"),
        "delete_acl_rule": (integration + "/acl-rules/{id}", "rule_id", None, "id"),
        "delete_arm_profile": (
            protect + "/arm-profiles/{id}",
            "arm_profile_id",
            protect + "/arm-profiles",
            "id",
        ),
        "delete_dns_policy": (integration + "/dns/policies/{id}", "policy_id", None, "id"),
        "delete_firewall_policy": (
            integration + "/firewall/policies/{id}",
            "policy_id",
            None,
            "id",
        ),
        "delete_firewall_zone_proxy": (integration + "/firewall/zones/{id}", "zone_id", None, "id"),
        "delete_hotspot_operator": (
            classic + "/hotspotop/{id}",
            "operator_id",
            classic + "/hotspotop",
            "_id",
        ),
        "delete_hotspot_voucher": (
            integration + "/hotspot/vouchers/{id}",
            "voucher_id",
            None,
            "id",
        ),
        "delete_network": (integration + "/networks/{id}", "network_id", None, "id"),
        "delete_port_forward": (
            classic + "/portforward/{id}",
            "forward_id",
            classic + "/portforward",
            "_id",
        ),
        "delete_rtsps_stream": (protect + "/cameras/{id}/rtsps-stream", "camera_id", None, "id"),
        "delete_scheduled_task": (
            classic + "/scheduletask/{id}",
            "task_id",
            classic + "/scheduletask",
            "_id",
        ),
        "delete_traffic_matching_list": (
            integration + "/traffic-matching-lists/{id}",
            "list_id",
            None,
            "id",
        ),
        "delete_traffic_route": (
            v2 + "/trafficroutes/{id}",
            "route_id",
            v2 + "/trafficroutes",
            "_id",
        ),
        "delete_traffic_rule": (v2 + "/trafficrules/{id}/", "rule_id", v2 + "/trafficrules", "_id"),
        "delete_wifi_broadcast": (
            integration + "/wifi/broadcasts/{id}",
            "broadcast_id",
            None,
            "id",
        ),
        "unadopt_device": (integration + "/devices/{id}", "device_id", None, "id"),
        # Lane tools: Network v2 / Classic / Protect private / InnerSpace private routes.
        # Each path, resolution list and id field is the one the tool's code uses; the
        # private routes are inventoried (tests/fixtures/private_api/tool_map.json).
        "delete_bgp_config": (v2 + "/bgp/config/{id}", "config_id", v2 + "/bgp/config/all", "_id"),
        "delete_camera_shortcut": (
            protect_api + "/cameras/{camera_id}/shortcuts",
            None,
            None,
            "id",
        ),
        "delete_content_filter": (
            v2 + "/content-filtering/{id}",
            "filter_id",
            v2 + "/content-filtering",
            "_id",
        ),
        "delete_controller_backup": (classic_api + "/cmd/backup", None, None, "id"),
        "delete_dhcp_option": (
            classic + "/dhcpoption/{id}",
            "option_id",
            classic + "/dhcpoption",
            "_id",
        ),
        "delete_digital_twin_layout": (v2 + "/digital-twin/layout", None, None, "id"),
        "delete_doorbell_credential": (
            protect_api + "/cameras/{camera_id}/{credential_type}/{credential_id}",
            None,
            None,
            "id",
        ),
        "delete_energy_saving_policy": (
            v2 + "/energy-saving-policies/{id}",
            "policy_id",
            v2 + "/energy-saving-policies",
            "id",
        ),
        "delete_guest_portal_file": (
            classic + "/portalfile/{id}",
            "file_id",
            classic + "/portalfile",
            "_id",
        ),
        "delete_hotspot_package": (
            classic + "/hotspotpackage/{id}",
            "package_id",
            classic + "/hotspotpackage",
            "_id",
        ),
        "delete_innerspace_plan": (innerspace_api + "/project/plan/{plan_id}", None, None, "id"),
        "delete_liveview": (protect_api + "/liveviews/{liveview_id}", None, None, "id"),
        "delete_nat_rule": (v2 + "/nat/{id}", "rule_id", v2 + "/nat", "_id"),
        "delete_network_members_group": (
            v2 + "/network-members-group/{group_id}",
            None,
            None,
            "id",
        ),
        "delete_ospf_router": (v2 + "/ospf/router/{id}", "router_id", v2 + "/ospf/router", "_id"),
        "delete_policy_engine_rule": (
            v2 + "/object-oriented-network-config/{rule_id}",
            None,
            None,
            "id",
        ),
        "delete_power_supervisor": (
            v2 + "/power-supervisors/{id}",
            "supervisor_id",
            v2 + "/power-supervisors",
            "id",
        ),
        "delete_power_supervisor_link": (
            v2 + "/power-supervisors/links/{id}",
            "link_id",
            v2 + "/power-supervisors/links",
            "id",
        ),
        "delete_proav_group": (v2 + "/proav/{kind}/group/{group_id}", None, None, "id"),
        "delete_protect_automation": (
            protect_api + "/automations/{id}",
            "automation_id",
            protect_api + "/automations",
            "id",
        ),
        "delete_protect_backup": (
            protect_api + "/backup/{id}",
            "backup_id",
            protect_api + "/backups",
            "id",
        ),
        "delete_protect_case": (protect_api + "/cases/{case_id}", None, None, "id"),
        "delete_protect_device_tag": (
            protect_api + "/device-tags/{id}",
            "tag_id",
            protect_api + "/device-tags",
            "id",
        ),
        "delete_protect_file": (protect_api + "/files/{file_id}/{asset_id}", None, None, "id"),
        "delete_protect_user_group": (protect_api + "/groups/{group_id}", None, None, "id"),
        "delete_ptz_patrol": (
            protect_api + "/cameras/{camera_id}/ptz/patrol/{slot}",
            None,
            None,
            "id",
        ),
        "delete_ptz_preset": (
            protect_api + "/cameras/{camera_id}/ptz/preset/{slot}",
            None,
            None,
            "id",
        ),
        "delete_qos_rule": (v2 + "/qos-rules/batch-delete", None, None, "id"),
        "delete_recognition_group": (
            protect_api + "/recognition/{type}/groups/{id}",
            "group_id",
            protect_api + "/recognition/{type}/groups",
            "id",
        ),
        "delete_recordings": (protect_api + "/video", None, None, "id"),
        "delete_ringtone": (protect_api + "/ringtones/{ringtone_id}", None, None, "id"),
        "delete_site": (
            classic_api + "/cmd/sitemgr",
            "site_to_delete",
            prefix + "/api/self/sites",
            "_id",
        ),
        "delete_site_vpn": (classic_api + "/cmd/sitemgr", None, None, "id"),
        "delete_ssl_inspection_certificate": (
            v2 + "/ssl-inspection/certificates/{id}",
            "certificate_id",
            v2 + "/ssl-inspection/certificates",
            "_id",
        ),
        "delete_ssl_inspection_profile": (
            v2 + "/ssl-inspection/profiles/{id}",
            "profile_id",
            v2 + "/ssl-inspection/profiles",
            "_id",
        ),
        "delete_static_dns_record": (
            v2 + "/static-dns/{id}",
            "record_id",
            v2 + "/static-dns",
            "_id",
        ),
        "delete_test_config": (
            v2 + "/test-configs/{id}",
            "test_config_id",
            v2 + "/test-configs",
            "_id",
        ),
        "delete_vpn_client": (
            classic + "/networkconf/{id}",
            "vpn_client_id",
            classic + "/networkconf",
            "_id",
        ),
        "delete_wan_sla": (v2 + "/wan-slas/{id}", "sla_id", v2 + "/wan-slas", "_id"),
        "delete_wireguard_users": (
            v2 + "/wireguard/{id}/users/batch_delete",
            "server_id",
            classic + "/networkconf",
            "_id",
        ),
    }


def test_aa_delete_contracts_cover_every_delete_tool():
    resolving = {name for name in _RESOLVING_WRITES if name.startswith("delete_")}
    assert resolving | set(_aa_extra_contracts()) == {*_lz_DELETE_TOOLS(), "unadopt_device"}


@tool_batches("name", lambda: [*_lz_DELETE_TOOLS(), "unadopt_device"])
async def test_aa_every_delete_tool_previews_a_delete_under_dry_run(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, name, up, env={"UNIFI_DRY_RUN": "1"}))
    previews = [p["preview"] for p in _dry_run_previews(payload)]
    assert any(_is_delete_preview(p, name, up) for p in previews), (
        f"{name}: no DELETE (or v2 batch_delete POST) preview: {str(payload)[:300]}"
    )
    assert payload.get("status") == "dry_run" and payload.get("deleted") is not True, payload


@pytest.mark.parametrize("kind", ["bgp", "ospf"])
def test_aa_routing_fake_reflects_only_successful_target_deletes(kind):
    base = (
        f"https://example.test/v1/connector/consoles/{uh.HOST_ID}/proxy/network/v2/api/site/default"
    )
    other = base.replace("/site/default", "/site/other")
    collection = "/bgp/config/all" if kind == "bgp" else "/ospf/router"
    delete = "/bgp/config" if kind == "bgp" else f"/ospf/router/{uh.ARG_ID}"
    up = uh.FakeUpstream(replay_recordings=False)

    def get(url):
        return up(httpx.Request("GET", url)).json()

    assert uh.upstream_records(get(base + collection))
    if kind == "bgp":
        assert uh.upstream_records(get(base + "/bgp/config"))
    up.write_status = 403
    assert up(httpx.Request("DELETE", base + delete)).status_code == 403
    assert uh.upstream_records(get(base + collection))
    up.write_status = None
    assert up(httpx.Request("DELETE", base + delete)).is_success
    assert uh.upstream_records(get(base + collection)) == []
    assert uh.upstream_records(get(other + collection))


def test_aa_batch_delete_preview_rule_is_tool_route_and_body_defined():
    prefix = f"/v1/connector/consoles/{uh.HOST_ID}/proxy/network"
    path = prefix + "/v2/api/site/default/radius/users/batch_delete"
    assert _is_delete_preview({"method": "POST", "path": path, "body": ["record-a"]})
    assert not _is_delete_preview(
        {"method": "POST", "path": path.replace("delete", "update"), "body": ["record-a"]}
    )
    assert not _is_delete_preview(
        {"method": "POST", "path": prefix + "/api/s/default/rest/account", "body": ["record-a"]}
    )
    assert _is_delete_preview(
        {"method": "DELETE", "path": prefix + "/api/s/default/rest/routing/record-a"},
        "delete_static_route",
    )


def test_aa_delete_contracts_reject_a_wrong_method_body_or_query():
    """The lane delete contracts bind method, body and query, not only the path."""
    root = f"/v1/connector/consoles/{uh.HOST_ID}/proxy"
    backup = root + "/network/api/s/default/cmd/backup"
    good = {
        "method": "POST",
        "path": backup,
        "body": {"cmd": "delete-backup", "filename": "probe.png"},
    }
    assert _is_delete_preview(good, "delete_controller_backup")
    assert not _is_delete_preview({**good, "method": "DELETE"}, "delete_controller_backup")
    assert not _is_delete_preview(
        {**good, "body": {"cmd": "delete-backup", "filename": "other.png"}},
        "delete_controller_backup",
    )
    assert not _is_delete_preview({**good, "body": None}, "delete_controller_backup")
    args = tool_args.generated_args(_lz_TOOLS()["delete_recordings"])
    window = {"camera": args["camera_id"], "start": args["start"] * 1000, "end": args["end"] * 1000}
    video = {"method": "DELETE", "path": root + "/protect/api/video", "body": None}
    assert _is_delete_preview({**video, "params": window}, "delete_recordings")
    assert not _is_delete_preview(
        {**video, "params": {**window, "start": args["start"]}}, "delete_recordings"
    )
    assert not _is_delete_preview({**video, "params": None}, "delete_recordings")
    qos = root + "/network/v2/api/site/default/qos-rules/batch-delete"
    ids = tool_args.generated_args(_lz_TOOLS()["delete_qos_rule"])["body"]
    assert _is_delete_preview({"method": "POST", "path": qos, "body": ids}, "delete_qos_rule")
    assert not _is_delete_preview({"method": "POST", "path": qos, "body": []}, "delete_qos_rule")
    assert not _is_delete_preview({"method": "DELETE", "path": qos, "body": ids}, "delete_qos_rule")


_DELETE_VERBS = ("delete_", "bulk_delete_", "remove_", "revoke_", "unadopt_")


def _is_delete_tool(name: str) -> bool:
    return name.startswith(_DELETE_VERBS) and name not in RAW_RELAY


@functools.cache
def _lz_DELETION_TOOLS():
    return sorted(name for name in _lz_WRITE_TOOLS() if _is_delete_tool(name))


def test_aa_every_delete_family_description_states_the_canonical_result_shape():
    """Every delete/remove/revoke result description names its exact public shape."""
    assert len(_lz_DELETION_TOOLS()) == 73
    missing = [
        name
        for name in _lz_DELETION_TOOLS()
        if "Returns {deleted, message, response}" not in (_lz_TOOLS()[name].description or "")
    ]
    assert missing == []


@tool_batches("name", _lz_DELETION_TOOLS)
async def test_aa_every_delete_tool_returns_canonical_real_deletion_result(monkeypatch, name):
    """Every real delete/remove/revoke call returns ``deletion_result`` unchanged.

    The response member is the exact upstream body, including ``None`` for an empty
    successful Classic command. Additional warning metadata is permitted only under
    underscore-prefixed keys, never instead of the canonical result members.
    """
    upstream = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(monkeypatch, name, upstream, env={"UNIFI_DRY_RUN": "0"})
    )
    assert isinstance(payload, dict), f"{name}: real delete result is not an object: {payload!r}"
    assert {"deleted", "message", "response"} <= set(payload), f"{name}: {payload!r}"
    assert {key for key in payload if not key.startswith("_")} == {"deleted", "message", "response"}
    assert payload["deleted"] is True, f"{name}: {payload!r}"
    assert isinstance(payload["message"], str) and payload["message"], f"{name}: {payload!r}"
    writes = upstream.writes()
    assert writes, f"{name}: expected a write request"
    assert payload["response"] in [write.body for write in writes], (
        f"{name}: response was rewritten instead of passing through an upstream body: {payload!r}"
    )


async def test_aa_delete_controller_backup_empty_classic_success_is_canonical(monkeypatch):
    upstream = uh.FakeUpstream(write_body="empty")
    payload = uh.result_payload(
        await _call(monkeypatch, "delete_controller_backup", upstream, env={"UNIFI_DRY_RUN": "0"})
    )
    assert payload["deleted"] is True
    assert payload["response"] is None


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_aa_every_delete_tool_returns_the_full_deletion_result_dry_run_shape(
    monkeypatch, name
):
    """A delete/remove/revoke tool's dry-run result is EXACTLY the ``deletion_result`` shape:
    ``{status: "dry_run", deleted: false, message, response}`` with the client preview under
    ``response``. Returning the bare client preview (``if is_dry_run_preview(r): return r``)
    has ``status`` but no ``deleted`` / ``message`` / ``response`` and is the defect this
    guards against. A tool qualifies by its name (delete_/bulk_delete_/remove_/revoke_/
    unadopt_).
    """
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, name, up, env={"UNIFI_DRY_RUN": "1"}))
    if not _is_delete_tool(name):
        return
    assert isinstance(payload, dict), f"{name}: dry-run result is not an object: {payload!r}"
    assert payload.get("status") == "dry_run", f"{name}: status != 'dry_run': {str(payload)[:300]}"
    assert payload.get("deleted") is False, f"{name}: 'deleted' must be False: {str(payload)[:300]}"
    message = payload.get("message")
    assert isinstance(message, str) and message, f"{name}: missing dry-run message: {payload}"
    assert "response" in payload, f"{name}: missing 'response' (the client preview): {payload}"
    assert is_dry_run_preview(payload["response"]), (
        f"{name}: 'response' is not the client dry-run preview: {str(payload)[:300]}"
    )


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_aa_every_preview_carries_the_query_params_sent_without_dry_run(monkeypatch, name):
    """Every dry-run preview has a ``params`` key, and its value is the query string the
    same call sends upstream without dry-run (a filter, ``force``, zone ids...)."""
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, name, up, env={"UNIFI_DRY_RUN": "1"}))
    previews = _dry_run_previews(payload)
    missing = [p["preview"] for p in previews if "params" not in p["preview"]]
    assert missing == [], f"{name}: preview without params: {missing}"
    live = uh.FakeUpstream()
    await _call(monkeypatch, name, live, env={"UNIFI_DRY_RUN": "0"})
    # Distinct query strings: a paged query POST (the system log, the event lists) sends
    # one POST per page with the same query, while its dry-run previews only the first.
    sent = sorted({tuple(sorted(httpx.QueryParams(w.query).multi_items())) for w in live.writes()})
    assert sorted(set(_preview_param_sets(payload))) == sent, (
        f"{name}: preview params {_preview_param_sets(payload)} != sent query {sent}"
    )


def test_aa_no_description_denies_dry_run():
    claims = sorted(
        n for n, t in _lz_TOOLS().items() if _NO_DRY_RUN_CLAIM.search(_all_description_text(t))
    )
    assert claims == [], f"descriptions claim there is no dry-run (UNIFI_DRY_RUN applies): {claims}"


async def test_aa_dry_run_holds_back_a_relayed_classic_cmd_stat(monkeypatch):
    """POST .../cmd/stat ({"cmd": "reset-dpi"}) is a command: dry-run never sends it."""
    up = uh.FakeUpstream()
    args = {
        "host": uh.HOST,
        "site": uh.SITE,
        "path": "network/api/s/{site}/cmd/stat",
        "body": {"cmd": "reset-dpi"},
    }
    await _call(monkeypatch, "fabric_connector_post", up, args, env={"UNIFI_DRY_RUN": "1"})
    sent = [s for s in up.served if s.method == "POST"]
    assert sent == [], f"cmd/stat reached the transport under UNIFI_DRY_RUN=1: {sent}"


# =========================================================================== (ab)
from unifi_fabric import read_post_routes as _read_post_routes  # noqa: E402


async def _eligible_ab_every_read_post_is_a_known_read_route(name):
    if name in NO_UPSTREAM:
        return False
    return True


@tool_batches(
    "name", lambda: sorted(_lz_TOOLS()), eligible=_eligible_ab_every_read_post_is_a_known_read_route
)
async def test_ab_every_read_post_is_a_known_read_route(monkeypatch, name):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream()
    try:
        await _call(monkeypatch, name, up)
    except ToolError:
        pass
    for s in up.served:
        if s.method == "POST" and not read_only.is_write_request("POST", s.path, s.sent_json):
            assert _read_post_routes.is_read_post("POST", s.path, s.sent_json), (
                f"{name}: POST {s.path} classified as a read"
            )


@pytest.mark.parametrize("cmd", ["stat", "devmgr", "stamgr", "evtmgr", "sitemgr"])
def test_ab_classic_commands_are_writes(cmd):
    path = f"/v1/connector/consoles/H/proxy/network/api/s/default/cmd/{cmd}"
    assert read_only.is_write_request("POST", path), path


# =========================================================================== (ac)
def _sites_schema(t: Any) -> str:
    return json.dumps((t.parameters.get("properties") or {}).get("sites") or {})


# tools whose ``sites`` argument is a list of objects (host-scoped entries), from the schema
@functools.cache
def _lz_SITES_LIST_TOOLS():
    return sorted(
        n
        for n, t in _lz_TOOLS().items()
        if '"type": "array"' in _sites_schema(t) and '"type": "object"' in _sites_schema(t)
    )


def _harness_site_id(host: dict) -> str:
    return "aa" + host["id"][-22:].replace(":", "0").lower().rjust(22, "0")


def test_ac_sites_list_tools_are_derived():
    assert "query_isp_metrics" in _lz_SITES_LIST_TOOLS()


@lazy_parametrize("name", lambda: _lz_SITES_LIST_TOOLS())
async def test_ac_sites_on_two_keys_merge_every_keys_real_response(monkeypatch, name):
    hosts = _two_key_hosts()
    sites = [
        {"hostId": hosts[k][0]["id"], "siteId": _harness_site_id(hosts[k][0])} for k in _KEY_IDS
    ]
    up = uh.FakeUpstream(hosts_by_key=hosts)
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), "sites": sites}
    args.pop("host", None)
    args.pop("site", None)
    payload = uh.result_payload(await _call(monkeypatch, name, up, args, keys=_KEYS))
    own = [s for s in up.served if s.method == "POST" and not s.resolution]
    assert {s.api_key for s in own} == set(_KEY_IDS), f"{name}: not queried on both owners"
    metrics = payload["data"]["metrics"]
    assert sorted(m.get("_keyLabel") for m in metrics) == ["alpha", "beta"], metrics
    for s in own:
        for rec in s.body["data"]["metrics"]:
            assert any(uh.strip_additive(m, rec) == rec for m in metrics), f"{name}: altered"
    assert set(payload["byKey"]) == {"alpha", "beta"}
    assert all("traceId" in v for v in payload["byKey"].values()), payload["byKey"]


# =========================================================================== (ad)
_SHAPE_EXEMPT = {"key_labels", "errors", "byKey", "incomplete", "incompleteReason", "key_label"}


def _top_keys(payload: Any) -> set[str]:
    if not isinstance(payload, dict):
        return set()
    return {
        k
        for k in payload
        if k not in uh.FRAMING and k not in _SHAPE_EXEMPT and not k.startswith("_")
    }


@tool_batches("name", _multi_key_candidates, member=_is_aggregation)
async def test_ad_multi_key_merge_keeps_the_single_key_access_path(monkeypatch, name):
    single = uh.result_payload(await _call(monkeypatch, name, uh.FakeUpstream()))
    multi = uh.result_payload(
        await _call(monkeypatch, name, uh.FakeUpstream(hosts_by_key=_two_key_hosts()), keys=_KEYS)
    )
    missing = _top_keys(single) - set(multi if isinstance(multi, dict) else {})
    assert missing == set(), f"{name}: multi-key result lacks the single-key keys {missing}"


async def _eligible_ae_empty_or_text_body_raises_naming_the_request(name):
    if name in NO_UPSTREAM:
        return False
    return True


# =========================================================================== (ae)
@class_axis(
    "name",
    lambda: _lz_READ_TOOLS(),
    body=lambda: ["empty", "text"],
    eligible=_eligible_ae_empty_or_text_body_raises_naming_the_request,
)
async def test_ae_empty_or_text_body_raises_naming_the_request(monkeypatch, name, body):
    if name in NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(get_body=body)
    try:
        await _call(monkeypatch, name, up)
    except ToolError as exc:
        msg = str(exc)
        assert "object has no attribute" not in msg, f"{name}: {msg}"
        assert "is not subscriptable" not in msg and "not iterable" not in msg, f"{name}: {msg}"


# =========================================================================== (af)
_KEYLABEL_PROMISE = re.compile(r"each record\s+carries an additive\s+_keyLabel")


def _all_description_text(t: Any) -> str:
    """The tool description plus every parameter description, whitespace-normalised."""
    texts = [t.description or ""]
    stack: list[Any] = [t.parameters]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if isinstance(node.get("description"), str):
                texts.append(node["description"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return " ".join(" ".join(texts).split())


@functools.cache
def _lz_KEYLABEL_PROMISE_TOOLS():
    return sorted(
        n for n, t in _lz_TOOLS().items() if _KEYLABEL_PROMISE.search(_all_description_text(t))
    )


@lazy_parametrize("name", lambda: _lz_KEYLABEL_PROMISE_TOOLS())
async def test_af_keylabel_promise_is_kept(monkeypatch, name):
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts())
    payload = uh.result_payload(
        await _call(monkeypatch, name, up, args=sc.conformance_args(name), keys=_KEYS)
    )
    assert '"_keyLabel"' in uh.all_strings(payload), f"{name}: promised _keyLabel missing"


# =========================================================================== (ag)
@pytest.mark.parametrize(
    "path",
    [
        "network/api/s/{site}/set/setting/mgmt",
        "network/api/s/{site}/upd/device/0000000000000000000000aa",
        "network/api/s/{site}/list/user",
        "network/api/s/{site}/group/user",
        "network/api/self",
        "network/api/stat/sites",
    ],
)
async def test_ag_relay_reaches_every_classic_namespace(monkeypatch, path):
    up = uh.FakeUpstream()
    args = {"host": uh.HOST, "site": uh.SITE, "path": path, "body": {"probe": "relay"}}
    res = uh.result_payload(await _call(monkeypatch, "fabric_connector_post", up, args))
    assert res["status"] == 200, res
    assert any(s.method == "POST" and "/proxy/network/api/" in s.path for s in up.served)


@pytest.mark.parametrize("name", ["fabric_connector_put", "fabric_connector_patch"])
async def test_ag_relay_forwards_params_on_write_and_reads(monkeypatch, name):
    # Generated data: the synthetic zone ids are no captured query, and an exact-capture
    # replay answers the relay's read-before / read-after GET with a harness LookupError
    # (unrecorded, so the GETs the relay sent would not be seen).
    up = uh.FakeUpstream(replay_recordings=False)
    args = {
        "host": uh.HOST,
        "site": uh.SITE,
        "path": "network/integration/v1/sites/{site_id}/firewall/policies/ordering",
        "body": {"orderedFirewallPolicyIds": {"beforeSystemDefined": []}},
        "params": {"sourceFirewallZoneId": "zs", "destinationFirewallZoneId": "zd"},
    }
    await _call(monkeypatch, name, up, args)
    relayed = [s for s in up.served if "/firewall/policies/ordering" in s.path]
    assert {s.method for s in relayed} >= {"GET", name.rsplit("_", 1)[1].upper()}, relayed
    for s in relayed:
        assert "sourceFirewallZoneId=zs" in s.query and "destinationFirewallZoneId=zd" in s.query


# =========================================================================== (bl)
# Writes that resolve their target before writing never write the wrong record. The
# Integration API serves these collections GET-only, so the tools write the controller
# UI's routes, where a wrong id is dangerous: a v2 DELETE of an unknown tag answers 200,
# and one networkconf collection holds LANs, VPN servers, tunnels and WANs, told apart by
# ``purpose``. Recorded networkconf fixture ids: remote-user-vpn external_id
# ...9000-...0038, wan external_id ...b000-...fa0040; the harness's record 0 is site-vpn.
_VPN_ID = "00000000-0000-4000-9000-000000000038"
_WAN_ID = "00000000-0000-4000-b000-000000fa0040"
_RESOLVING_WRITES: dict[str, tuple[str, str | None, str | None]] = {
    # tool: (id argument, networkconf purpose or None for v2 tags, an id of another purpose)
    "update_device_tag": ("tag_id", None, None),
    "delete_device_tag": ("tag_id", None, None),
    "update_vpn_server": ("server_id", "remote-user-vpn", _WAN_ID),
    "delete_vpn_server": ("server_id", "remote-user-vpn", _WAN_ID),
    "update_site_to_site_tunnel": ("tunnel_id", "site-vpn", _VPN_ID),
    "delete_site_to_site_tunnel": ("tunnel_id", "site-vpn", _WAN_ID),
    "update_wan_interface": ("wan_id", "wan", _VPN_ID),
    # site configuration CRUD: Classic rest/<collection>, v2 apgroups and v2 radius/users,
    # list-first
    **{
        f"{verb}_{kind}": (arg, None, None)
        for kind, arg in (
            ("user_group", "group_id"),
            ("static_route", "route_id"),
            ("radius_account", "account_id"),
            ("radius_profile", "profile_id"),
            ("ap_group", "group_id"),
        )
        for verb in ("update", "delete")
    },
    "delete_port_profile": ("profile_id", None, None),
    "delete_dynamic_dns": ("ddns_id", None, None),
}


_BL_CLASSIC = {
    "user_group": "usergroup",
    "static_route": "routing",
    "radius_profile": "radiusprofile",
    "port_profile": "portconf",
    "dynamic_dns": "dynamicdns",
    "vpn_server": "networkconf",
    "site_to_site_tunnel": "networkconf",
    "wan_interface": "networkconf",
}


def _bl_contract(name: str) -> tuple[str, str, str, bool]:
    """Independent per-tool expected method, GET collection, write collection and batching."""
    verb, kind = name.split("_", 1)
    prefix = f"/v1/connector/consoles/{uh.HOST_ID}/proxy/network"
    method = "PUT" if verb == "update" else "DELETE"
    if kind in _BL_CLASSIC:
        collection = prefix + "/api/s/default/rest/" + _BL_CLASSIC[kind]
        return method, collection, collection, False
    v2 = prefix + "/v2/api/site/default"
    if kind == "device_tag":
        listed = v2 + "/device-tags"
        written = prefix + "/v2/api/device-tags" if verb == "delete" else listed
        return method, listed, written, False
    if kind == "ap_group":
        return method, v2 + "/apgroups", v2 + "/apgroups", False
    assert kind == "radius_account", name
    collection = v2 + "/radius/users"
    return "POST", collection, collection + "/batch_" + verb, True


def _bl_records(up: uh.FakeUpstream, name: str, purpose: str | None) -> list[dict]:
    collection = _bl_contract(name)[1]
    return [
        rec
        for served in up.served
        if 200 <= served.status < 300
        and not served.resolution
        and served.method == "GET"
        and served.path == collection
        for rec in uh.upstream_records(served.body)
        if isinstance(rec, dict)
        and rec.get("_id")
        and (purpose is None or rec.get("purpose") == purpose)
    ]


def _bl_listed(up: uh.FakeUpstream, name: str, purpose: str | None) -> list[str]:
    return [str(rec["_id"]) for rec in _bl_records(up, name, purpose)]


@pytest.mark.parametrize("name", sorted(_RESOLVING_WRITES))
async def test_bl_unknown_target_sends_no_write(monkeypatch, name):
    arg, purpose, _foreign = _RESOLVING_WRITES[name]
    up = uh.FakeUpstream()
    args = {
        **tool_args.generated_args(_lz_TOOLS()[name]),
        arg: "00000000-0000-4000-8000-0000000000ee",
    }
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert up.writes() == [], f"{name}: wrote with an unknown target: {up.writes()}"
    listed = _bl_listed(up, name, purpose)
    assert listed, f"{name}: harness served no records of the target kind"
    missing = [v for v in listed if v not in str(exc.value)]
    assert missing == [], f"{name}: error omits valid targets {missing[:3]}"


@pytest.mark.parametrize(
    "name", sorted(n for n, (_a, purpose, _f) in _RESOLVING_WRITES.items() if purpose)
)
async def test_bl_id_of_another_purpose_is_never_written(monkeypatch, name):
    arg, _purpose, foreign = _RESOLVING_WRITES[name]
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(_lz_TOOLS()[name]), arg: foreign}
    with pytest.raises(ToolError):
        await _call(monkeypatch, name, up, args)
    assert up.writes() == [], f"{name}: wrote a record of another purpose: {up.writes()}"


def _bl_addressed_ids(write: uh.Served, name: str = "delete_radius_account") -> list[str]:
    """Addressed ids only when method, exact collection, action and body agree."""
    method, _listed, collection, batch = _bl_contract(name)
    if write.method != method:
        return []
    body = write.sent_json
    if batch:
        if write.path != collection or not (isinstance(body, list) and len(body) == 1):
            return []
        item = body[0]
        if name.startswith("update_"):
            if not isinstance(item, dict):
                return []
            item = item.get("_id")
        return [item] if isinstance(item, str) and item else []
    match = re.fullmatch(re.escape(collection) + r"/([^/]+)", write.path)
    if match is None:
        return []
    addressed = match.group(1)
    if method == "DELETE":
        return [addressed] if body is None else []
    if not isinstance(body, dict) or ("_id" in body and body["_id"] != addressed):
        return []
    return [addressed]


@pytest.mark.parametrize("name", sorted(_RESOLVING_WRITES))
async def test_bl_known_target_writes_exactly_one_resolved_record(monkeypatch, name):
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up)
    writes = up.writes()
    assert len(writes) == 1, f"{name}: {writes}"
    _arg, purpose, _f = _RESOLVING_WRITES[name]
    listed = _bl_listed(up, name, purpose)
    addressed = _bl_addressed_ids(writes[0], name)
    assert addressed and all(a in listed for a in addressed), (
        name,
        writes[0].method,
        writes[0].path,
        addressed,
    )
    args = tool_args.generated_args(_lz_TOOLS()[name])
    wanted = args[_arg]
    matches = [
        record
        for record in _bl_records(up, name, purpose)
        if any(
            isinstance(record.get(field), str)
            and record[field].casefold() == str(wanted).casefold()
            for field in ("_id", "id", "external_id", "name")
        )
    ]
    assert len(matches) == 1, (name, wanted, "target must resolve uniquely")
    assert addressed == [matches[0]["_id"]], (name, wanted, addressed)


def test_bl_policy_names_real_write_tools():
    assert set(_RESOLVING_WRITES) <= set(_lz_WRITE_TOOLS())
    expected = {
        f"{verb}_{kind}"
        for kind in _BL_CLASSIC
        for verb in ("update", "delete")
        if not (kind in {"port_profile", "dynamic_dns"} and verb == "update")
        and not (kind == "wan_interface" and verb == "delete")
    } | {
        f"{verb}_{kind}"
        for kind in ("device_tag", "radius_account", "ap_group")
        for verb in ("update", "delete")
    }
    assert expected == set(_RESOLVING_WRITES)
    assert all(_bl_contract(name) for name in expected)


# =========================================================================== (bm)
_SENTINEL = "probe-secret-sentinel"


def _secret_body(value: str) -> dict[str, Any]:
    return {
        "name": "probe-renamed",
        "x_passphrase": value,
        "radius": {"x_secret": value, "port": 1812},
        "peers": [{"private_key": value, "peer": "kept"}],
    }


def _schema_types(spec: dict[str, Any], defs: dict[str, Any], _seen: frozenset[str] = frozenset()):
    """The JSON types a parameter schema admits, following ``anyOf`` and ``$ref`` branches
    (the free-form relay body is a recursive union declared once under ``$defs``)."""
    types = {spec.get("type")}
    ref = spec.get("$ref")
    if isinstance(ref, str) and ref not in _seen:
        target = defs.get(ref.rsplit("/", 1)[-1])
        if isinstance(target, dict):
            types |= _schema_types(target, defs, _seen | {ref})
    for branch in spec.get("anyOf", []):
        types |= _schema_types(branch, defs, _seen)
    return types


def _secret_args(tool: Any, value: str) -> tuple[dict[str, Any], set[str]]:
    """Generated args with credential-shaped values in every object and secret parameter."""
    args = tool_args.generated_args(tool)
    props = tool.parameters.get("properties") or {}
    injected: set[str] = set()
    for pname, spec in props.items():
        types = _schema_types(spec, tool.parameters.get("$defs") or {})
        # An unconstrained JSON value also permits an object. Keep the secret
        # probe non-vacuous after a relay body widens from object to any JSON.
        unconstrained = set(spec) <= {"title", "description", "default", "examples", "deprecated"}
        if "object" in types or unconstrained:
            base = args.get(pname) if isinstance(args.get(pname), dict) else {}
            args[pname] = {**base, **_secret_body(value)}
            injected.add(pname)
        elif "string" in types and is_credential_field(pname):
            args[pname] = value
            injected.add(pname)
    return args, injected


async def _secret_run(monkeypatch, name: str, value: str) -> tuple[Any, list, set[str]]:
    up = uh.FakeUpstream()
    args, injected = _secret_args(_lz_TOOLS()[name], value)
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up, args))
    except ToolError as exc:
        payload = exc
    return payload, [w.sent_json for w in up.writes() if w.sent_json is not None], injected


@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_bm_masked_secret_never_written_back(monkeypatch, name):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    # With explicit redaction enabled, where a real secret reaches the body, its mask must
    # be dropped there (siblings kept) and reported; it must never be sent anywhere.
    sentinel_payload, sentinel_sent, _i = await _secret_run(monkeypatch, name, _SENTINEL)
    payload, sent, _j = await _secret_run(monkeypatch, name, REDACTION_MASK)
    leaked = [b for b in sent if REDACTION_MASK in uh.all_strings(b)]
    assert leaked == [], f"{name}: the redaction mask reached upstream: {leaked}"
    if not any(_SENTINEL in uh.all_strings(b) for b in sentinel_sent):
        return  # this tool never forwards those fields; nothing can be overwritten
    if not sent and isinstance(payload, Exception) and "held the redaction mask" in str(payload):
        # The secret was the only field the write sends (update_protect_device_password
        # sends {devicePassword}): with the mask dropped nothing is left, and the documented
        # empty-update refusal keeps the stored value. No write, nothing overwritten.
        return
    assert sent, f"{name}: no write sent when the body held masked fields"
    if isinstance(sentinel_payload, Exception):
        return  # the harness cannot complete this tool even with real values
    assert not isinstance(payload, Exception), f"{name}: write refused: {payload}"
    reported = payload.get(MASKED_FIELDS_KEY) if isinstance(payload, dict) else None
    if isinstance(payload, list):
        reported = sorted(
            {
                field
                for record in payload
                if isinstance(record, dict)
                for field in record.get(MASKED_FIELDS_KEY, [])
            }
        )
    assert reported, f"{name}: dropped masked fields not reported: {str(payload)[:300]}"
    leaves = [re.sub(r"\[\d+\]\Z", "", p.rsplit(".", 1)[-1]) for p in reported]
    assert all(is_credential_field(leaf) for leaf in leaves), (name, reported)
    if any("kept" in uh.all_strings(b) for b in sentinel_sent):
        assert any("kept" in uh.all_strings(b) for b in sent), f"{name}: a sibling was dropped"
    if any("1812" in uh.all_strings(b) for b in sentinel_sent):
        assert any("1812" in uh.all_strings(b) for b in sent), f"{name}: a sibling was dropped"


@pytest.mark.parametrize(
    "name",
    [
        "update_setting",
        "update_wlan_config",
        "update_dynamic_dns",
        "update_hotspot_operator",
        "update_vpn_server",
        "fabric_connector_put",
    ],
)
async def test_bm_round_trip_writes_forward_secret_fields(monkeypatch, name):
    # Guards against a vacuous (bm): these round-trip writes really forward the secret
    # fields, so the masked run above exercises the drop on them.
    _p, sent, _i = await _secret_run(monkeypatch, name, _SENTINEL)
    assert any(_SENTINEL in uh.all_strings(b) for b in sent), f"{name}: {sent}"


# =========================================================================== (bn)
# The connector relay honours every per-area write opt-out: a relayed mutation on a route
# class of an area whose opt-out is set is refused naming the variable, before ANY
# upstream call, for every mutating method. The area set is the (v) table above (minus the
# relay's own flag), so a new area opt-out without a relay entry fails here.
_RELAY_MUTATION_TOOLS = {
    "POST": "fabric_connector_post",
    "PUT": "fabric_connector_put",
    "PATCH": "fabric_connector_patch",
    "DELETE": "fabric_connector_delete",
}
# One representative path per allowlisted route class (every class must have one).
_RELAY_CLASS_PATHS = {
    "network-integration": "network/integration/v1/sites/{site_id}/networks",
    "network-classic-rest": "network/api/s/{site}/rest/networkconf",
    "network-classic-cmd": "network/api/s/{site}/cmd/devmgr",
    "network-classic-stat": "network/api/s/{site}/stat/device",
    "network-classic": "network/api/s/{site}/set/setting/mgmt",
    "network-classic-controller": "network/api/self",
    "network-v2": "network/v2/api/site/{site}/trafficrules",
    "protect-integration": "protect/integration/v1/sirens/" + uh.ARG_ID + "/play",
    "protect-private": "protect/api/cameras/" + uh.ARG_HEX,
    "innerspace-integration": "innerspace/integration/v1/shapes/" + uh.ARG_ID,
    "innerspace-legacy": "innerspace/api/shapes/" + uh.ARG_ID,
    "access-integration": "access/integration/v1/doors/" + uh.ARG_ID,
    "access-private": "access/api/doors/" + uh.ARG_ID,
}
_AREA_PREFIX = {env: prefix for prefix, env, _enabled, _reason in _connector._AREA_OPT_OUTS}
_RELAY_AREA_CASES = sorted(
    (env, route_class, method)
    for env in _AREA_PREFIX
    for route_class in _RELAY_CLASS_PATHS
    for method in _RELAY_MUTATION_TOOLS
)


def test_bn_relay_lists_every_area_opt_out_and_samples_every_route_class():
    areas = {v for k, v in _AREA_WRITE_OPT_OUTS.items() if k != "connector"}
    assert set(_AREA_PREFIX) == areas, (set(_AREA_PREFIX), areas)
    classes = {label for _p, label in _connector._ALLOWLIST}
    assert set(_RELAY_CLASS_PATHS) == classes, classes ^ set(_RELAY_CLASS_PATHS)
    for route_class, path in _RELAY_CLASS_PATHS.items():
        assert _connector._validate_relay_path(path, None) == route_class, path
    # Protect really is reachable through the relay, so its opt-out is not vacuous here.
    assert any(c.startswith(_AREA_PREFIX["UNIFI_PROTECT_MUTATIONS_ENABLED"]) for c in classes)


@pytest.mark.parametrize(("env_var", "route_class", "method"), _RELAY_AREA_CASES)
async def test_bn_relay_honours_every_area_opt_out(monkeypatch, env_var, route_class, method):
    up = uh.FakeUpstream()
    args = {
        "host": uh.HOST,
        "site": uh.SITE,
        "path": _RELAY_CLASS_PATHS[route_class],
        "body": {"probe": "relay"},
    }
    call = _call(monkeypatch, _RELAY_MUTATION_TOOLS[method], up, args, env={env_var: "0"})
    if route_class.startswith(_AREA_PREFIX[env_var]):
        with pytest.raises(ToolError) as exc:
            await call
        assert env_var in str(exc.value), f"{route_class} {method}: {exc.value}"
        assert up.served == [], f"{route_class} {method}: upstream called: {up.served}"
    else:
        # Another area's opt-out never blocks this route class.
        await call
        assert any(s.method == method for s in up.served), (route_class, method, up.served)


@pytest.mark.parametrize("method", sorted(_RELAY_MUTATION_TOOLS))
async def test_bn_relayed_mutation_is_sent_once_on_429(monkeypatch, method):
    # A relayed mutation is never auto-retried on 429 (a retry can repeat a physical
    # Protect action); the 429 is surfaced.
    async def _no_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
    up = uh.FakeUpstream(mode="error", error_status=429, error_body='{"error":"slow down"}')
    args = {
        "host": uh.HOST,
        "path": _RELAY_CLASS_PATHS["protect-integration"],
        "body": {"probe": "relay"},
    }
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, _RELAY_MUTATION_TOOLS[method], up, args)
    assert "429" in str(exc.value) and "NOT retried" in str(exc.value), str(exc.value)
    sent = [s for s in up.served if s.method == method]
    assert len(sent) == 1, f"{method}: {len(sent)} attempts: {sent}"


# =========================================================================== (bo)
# The documented result-envelope keys: the only non-underscore top-level keys a tool may
# add that no upstream body carries. Enumerated explicitly; a new one needs an entry here
# (and documentation in the tool's description).
RESULT_ENVELOPE_KEYS = frozenset(
    {
        # write outcome
        "status",  # outcome label (dry_run, unchanged, a relayed HTTP status ...)
        "response",  # the upstream write response body, verbatim
        "deleted",  # delete outcome
        "message",  # human-readable outcome of a delete
        "noOp",  # nothing to change: no write was sent
        "verified",  # a read-after confirmed every requested leaf
        "changed",  # whether the write changed the object
        "readBefore",  # the object read before the write, verbatim
        "readAfter",  # the object read after the write, verbatim
        "readAfterError",  # why the read-after failed (the write itself was applied)
        "noOpReason",  # why the relay noOp is null when the read-after did not fail
        "before",  # Protect verified updates: the object before the write, verbatim
        "after",  # Protect verified updates: the object after the write, verbatim
        "subscriber",  # Carrier writes: the subscriber body, verbatim
        "device",  # Mobility writes: the device-detail body, verbatim
        # dry-run preview (UNIFI_DRY_RUN)
        "dryRun",
        "preview",
        # per-item and per-key outcomes of fan-out writes and merges
        "byMac",
        "forgotten",
        "errors",
        "byKey",
        # drain markers
        "incomplete",
        "incompleteReason",
        # FastMCP's envelope for a list result
        "result",
        # connector relay envelope
        "method",
        "path",
        "resolvedPath",
        "routeClass",
        "scope",
        "body",
        "contentType",
        "bodyBase64",
        "sizeBytes",
        "writeEnabled",
        # binary body envelope (images, assets)
        "image_base64",
        "content_base64",  # a non-image file (the vehicle-group upload template)
        "size_bytes",
        "content_type",
    }
)


@functools.cache
def _lz_BO_TOOLS():
    return sorted(
        n
        for n in _lz_TOOLS()
        if n not in NO_UPSTREAM and n not in DERIVED and n not in MULTI_SOURCE_COMPOSITE
    )


def _upstream_keys(name: str, up: uh.FakeUpstream) -> set[str]:
    """Top-level keys of every body the tool read; for a record-selection tool (whose
    result is one selected record, or a projection of it) also the record keys."""
    keys: set[str] = set()
    for s in up.served:
        if s.resolution and name not in PRIMARY_RESOLUTION:
            continue
        if isinstance(s.body, dict):
            keys.update(str(k) for k in s.body)
        if name in SELECT:
            for rec in uh.upstream_records(s.body):
                if isinstance(rec, dict):
                    keys.update(str(k) for k in rec)
    return keys


def _invented_keys(name: str, payload: Any, up: uh.FakeUpstream) -> list[str]:
    if not isinstance(payload, dict):
        return []
    upstream = _upstream_keys(name, up)
    return sorted(
        k
        for k in payload
        if not str(k).startswith("_") and k not in upstream and k not in RESULT_ENVELOPE_KEYS
    )


@tool_batches("name", lambda: _lz_BO_TOOLS())
async def test_bo_no_invented_top_level_key(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    invented = _invented_keys(name, payload, up)
    assert invented == [], f"{name}: invented top-level key(s) {invented}"


@tool_batches("name", lambda: _lz_BO_TOOLS())
async def test_bo_no_invented_top_level_key_when_merging_keys(monkeypatch, name):
    """The multi-key merge shape (two keys, consoles split between them) invents no key
    either (no ``key_labels``: the keys covered are the additive ``_key_labels``)."""
    up = uh.FakeUpstream(hosts_by_key=_two_key_hosts())
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up, keys=_KEYS))
    except ToolError:
        return  # not drivable under two keys with generated args; covered single-key
    invented = _invented_keys(name, payload, up)
    assert invented == [], f"{name}: invented top-level key(s) {invented}"


def test_bo_list_wan_interfaces_returns_upstream_bodies(monkeypatch):
    """The pass-through contract's own case: the WAN list under its upstream key and the
    stat/health body verbatim (every subsystem, nothing filtered out) under ``_health``; no
    ``wans`` / ``wanHealth``."""
    up = uh.FakeUpstream()
    payload = uh.result_payload(asyncio.run(_call(monkeypatch, "list_wan_interfaces", up)))
    health = [s.body for s in up.served if s.path.endswith("/stat/health")]
    assert len(health) == 1 and payload["_health"] == health[0]
    assert "wans" not in payload and "wanHealth" not in payload
    assert payload["data"] == [
        r for s in up.served if s.path.endswith("/wans") for r in uh.upstream_records(s.body)
    ]


@tool_batches("name", lambda: _lz_BO_TOOLS())
async def test_bo_no_invented_key_when_upstream_records_are_sparse(monkeypatch, name):
    """Generic records only (no recorded real fields such as ``port_table``): a key the
    upstream record does not carry is never added, as ``null`` or otherwise."""
    up = uh.FakeUpstream(recorded_routes={})
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up))
    except ToolError:
        return  # not drivable without the recorded shapes; covered by the main bo case
    invented = _invented_keys(name, payload, up)
    assert invented == [], f"{name}: invented top-level key(s) {invented}"


def test_bo_sparse_case_drives_the_device_port_state_view(monkeypatch):
    up = uh.FakeUpstream(recorded_routes={})
    payload = uh.result_payload(asyncio.run(_call(monkeypatch, "get_device_port_state", up)))
    assert "_device_record" in payload
    assert "port_table" not in payload and "lldp_table" not in payload


# =========================================================================== (bp)
def _empty_body_upstream(name: str) -> uh.FakeUpstream:
    return (
        uh.FakeUpstream(write_body="empty")
        if name in _lz_WRITE_TOOLS()
        else uh.FakeUpstream(get_body="empty")
    )


@tool_batches("name", lambda: sorted(n for n in _lz_TOOLS() if n not in NO_UPSTREAM))
async def test_bp_empty_body_success_is_an_explicit_result(monkeypatch, name):
    from unifi_fabric.list_results import output_schema_admits_null_payload

    up = _empty_body_upstream(name)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError:
        return  # an actionable error (property ae / w), not an empty result
    assert res.content, f"{name}: an empty-body success produced an empty MCP result"
    if output_schema_admits_null_payload(_lz_TOOLS()[name].output_schema):
        assert res.structured_content is not None, f"{name}: no structuredContent"
    if uh.result_payload(res) == {"result": None}:
        assert [getattr(b, "text", None) for b in res.content] == ["null"]


_BP_WIRE_TOOLS = (
    "restart_device",
    "execute_device_action",
    "execute_port_action",
    "update_network",
    "update_dns_policy",
    "adopt_device",
)


@pytest.mark.parametrize("name", _BP_WIRE_TOOLS)
async def test_bp_empty_body_write_through_a_real_fastmcp_client(monkeypatch, name):
    from fastmcp import Client

    up = uh.FakeUpstream(write_body="empty")
    uh.install(monkeypatch, up, tool_mode="full")
    async with Client(server.mcp) as mcp_client:
        res = await mcp_client.call_tool(name, tool_args.generated_args(_lz_TOOLS()[name]))
    assert not res.is_error and up.writes()
    assert [getattr(b, "text", None) for b in res.content] == ["null"]
    assert res.structured_content == {"result": None}
    assert res.data is None


# =========================================================================== (bq)
_MAC_ID_PARAMS = ("device_id", "client_id")
# Tools whose argument is a MAC itself (not an id that may also be given as a MAC).
_MAC_ONLY = {
    "approve_pending_device": "takes the pending device's MAC (no id exists before adoption)",
}


def _accepts_mac_as_id(name: str, param: str) -> bool:
    props = (_lz_TOOLS()[name].parameters or {}).get("properties") or {}
    return param in props and "UUID or MAC" in (props[param].get("description") or "")


@functools.cache
def _lz_MAC_AS_ID():
    return sorted((n, p) for n in _lz_TOOLS() for p in _MAC_ID_PARAMS if _accepts_mac_as_id(n, p))


_MAC_FORMS = {
    "upper-colon": uh.ARG_MAC.upper(),
    "dash": uh.ARG_MAC.replace(":", "-"),
    "bare": uh.ARG_MAC.replace(":", "").upper(),
}


def test_bq_mac_as_id_covers_each_family():
    fams = families.build_family_index()
    tools = {n for n, _ in _lz_MAC_AS_ID()}
    assert {"get_device", "restart_device", "get_client", "block_client"} <= tools
    for param in _MAC_ID_PARAMS:
        accepting = {fams.get(n) for n, p in _lz_MAC_AS_ID() if p == param}
        for name, tool in _lz_TOOLS().items():
            props = (tool.parameters or {}).get("properties") or {}
            if param in props and fams.get(name) in accepting and name not in _MAC_ONLY:
                assert (name, param) in _lz_MAC_AS_ID(), (
                    f"{name}: {param} does not accept a MAC like the rest of its family"
                )


def _sent(up: uh.FakeUpstream) -> list[tuple[str, str, Any]]:
    return [(s.method, s.path, s.sent_json) for s in up.writes()]


@lazy_parametrize("form", lambda: sorted(_MAC_FORMS))
@lazy_parametrize(("name", "param"), lambda: _lz_MAC_AS_ID())
async def test_bq_mac_as_id_acts_like_the_id(monkeypatch, name, param, form):
    by_id = uh.FakeUpstream(replay_recordings=False)
    uh.install(monkeypatch, by_id)
    args = tool_args.generated_args(_lz_TOOLS()[name])
    res_id = await _call(monkeypatch, name, by_id, args={**args, param: uh.ARG_ID})
    by_mac = uh.FakeUpstream(replay_recordings=False)
    res_mac = await _call(monkeypatch, name, by_mac, args={**args, param: _MAC_FORMS[form]})
    if name in _lz_WRITE_TOOLS():
        assert _sent(by_mac) == _sent(by_id), f"{name}: the MAC wrote something else"
    else:
        assert uh.result_payload(res_mac) == uh.result_payload(res_id)
        target = [s.path for s in by_id.served if not s.resolution and uh.ARG_ID in s.path]
        assert target and all(any(s.path == t for s in by_mac.served) for t in target), (
            f"{name}: the MAC did not reach the id's request"
        )


_OFFLINE_MAC = "02:00:5e:ff:ff:fe"


def _carries(obj: Any, value: str) -> bool:
    """``value`` appears as a string anywhere in ``obj`` (a sent JSON body)."""
    if isinstance(obj, str):
        return obj.lower() == value
    if isinstance(obj, dict):
        return any(_carries(v, value) for v in obj.values())
    if isinstance(obj, list):
        return any(_carries(v, value) for v in obj)
    return False


_CONNECTED_ONLY = (re.compile(r"/sites/[^/]+/clients\Z"), re.compile(r"/stat/sta\Z"))


def _connected_only_reads(up: uh.FakeUpstream) -> list[str]:
    return [
        s.path
        for s in up.served
        if s.method == "GET" and any(rx.search(s.path) for rx in _CONNECTED_ONLY)
    ]


@lazy_parametrize(("name", "param"), lambda: _lz_MAC_AS_ID())
async def test_bq_unknown_mac_fails_listing_choices_before_any_write(monkeypatch, name, param):
    up = uh.FakeUpstream(replay_recordings=False)
    uh.install(monkeypatch, up)
    args = tool_args.generated_args(_lz_TOOLS()[name])
    try:
        await _call(monkeypatch, name, up, args={**args, param: _OFFLINE_MAC})
    except ToolError as err:
        assert up.writes() == [], f"{name}: wrote for an unknown MAC"
        msg = str(err)
        assert _OFFLINE_MAC in msg.lower() and (uh.ARG_ID in msg or uh.ARG_MAC in msg.lower()), (
            f"{name}: error lists no valid choice: {msg[:300]}"
        )
        return
    # No error: only a write addressed upstream by the MAC itself may proceed, sending the
    # MAC as given (the controller knows clients that no list shows, e.g. blocked ones).
    writes = up.writes()
    assert len(writes) == 1 and _carries(writes[0].sent_json, _OFFLINE_MAC), (
        f"{name}: an unknown MAC neither failed nor was sent as the write's address: "
        f"{[(w.method, w.path, w.sent_json) for w in writes]}"
    )


# =========================================================================== (bq2)
# Writes addressed upstream by the Integration client id: a MAC given is resolved to that
# id, which exists only while the client is connected (the tools say so).
_ID_ADDRESSED_CLIENT_WRITES = {
    "execute_client_action": "POST /clients/{clientId}/actions takes the Integration id",
}
_MAC_PARAM_NAMES = ("mac", "macs")
_STAMGR_TOOLS = ("block_client", "unblock_client", "reconnect_client")


def _offline_mac_args(name: str) -> dict[str, Any] | None:
    """Generated args with every MAC-taking argument set to an unlisted MAC (bare, upper
    case), or ``None`` when the tool takes no MAC."""
    args = dict(tool_args.generated_args(_lz_TOOLS()[name]))
    props = (_lz_TOOLS()[name].parameters or {}).get("properties") or {}
    params = [p for n, p in _lz_MAC_AS_ID() if n == name]
    params += [p for p in _MAC_PARAM_NAMES if p in props]
    if not params:
        return None
    for p in params:
        args[p] = _OFFLINE_MAC.replace(":", "").upper()
    return args


@functools.cache
def _lz_BQ2_TOOLS():
    return sorted(
        n
        for n in _lz_WRITE_TOOLS()
        if n not in _ID_ADDRESSED_CLIENT_WRITES and _offline_mac_args(n) is not None
    )


def test_bq2_covers_the_mac_addressed_writes():
    assert set(_STAMGR_TOOLS) <= set(_lz_BQ2_TOOLS()), _lz_BQ2_TOOLS()
    assert "forget_device" in _lz_BQ2_TOOLS() and "locate_device" in _lz_BQ2_TOOLS(), (
        _lz_BQ2_TOOLS()
    )


@lazy_parametrize("name", lambda: _lz_BQ2_TOOLS())
async def test_bq2_mac_write_never_reads_a_connected_only_list(monkeypatch, name):
    up = uh.FakeUpstream()
    args = _offline_mac_args(name)
    try:
        await _call(monkeypatch, name, up, args=args)
    except ToolError:
        pass  # e.g. a device MAC not among the site's adopted devices
    assert _connected_only_reads(up) == [], (
        f"{name}: a MAC-addressed write read a connected-only list "
        f"{_connected_only_reads(up)}, so an offline target could not be addressed"
    )


@pytest.mark.parametrize("name", _STAMGR_TOOLS)
async def test_bq2_stamgr_sends_an_unlisted_mac_once_with_no_read(monkeypatch, name):
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args=_offline_mac_args(name))
    writes = up.writes()
    assert len(writes) == 1 and writes[0].path.endswith("/cmd/stamgr"), writes
    assert writes[0].sent_json["mac"] == _OFFLINE_MAC
    reads = [s.path for s in up.served if s.method == "GET" and not s.resolution]
    assert reads == [], f"{name}: read {reads} before addressing a MAC"


# =========================================================================== (br)
# A hex id the caller typed in another case is matched case-insensitively
# (matching.same_id); the write must then address the matched record by the id the
# upstream reported (matching.py: "a resolver returns and sends the upstream form").
# Derived over every write tool taking a hex id: for each id argument, an unknown id that
# is refused with no write proves the tool matched it locally; an id written anyway is
# forwarded unmatched. MAC-shaped values are the MAC-form invariant's (bq), not this one.
_BR_MAC = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\Z|[0-9a-fA-F]{12}\Z")
_BR_HEX = re.compile(r"[0-9a-fA-F:-]+\Z")


def _br_id_args(args: dict[str, Any]) -> list[str]:
    """Top-level string arguments holding a hex id that has a lower-case form to upper."""
    return [
        k
        for k, v in args.items()
        if k not in ("host", "site")
        and isinstance(v, str)
        and _BR_HEX.match(v)
        and not _BR_MAC.match(v)
        and v != v.upper()
    ]


def _br_unknown(value: str) -> str:
    """An id of ``value``'s shape that no upstream list carries (upper-case)."""
    return (value[:-2] + "ee").upper()


@functools.cache
def _lz_BR_TOOLS():
    return sorted(
        n for n in _lz_WRITE_TOOLS() if _br_id_args(tool_args.generated_args(_lz_TOOLS()[n]))
    )


# The writes that resolve their target id in an upstream list before writing (the Classic
# REST / v2 item writes plus the networkconf / v2 tag / port-profile resolvers); the
# derivation must classify each of these ids as locally matched.
_BR_KNOWN_RESOLVED = {
    "update_port_forward": "forward_id",
    "delete_port_forward": "forward_id",
    "update_traffic_rule": "rule_id",
    "delete_traffic_rule": "rule_id",
    "update_traffic_route": "route_id",
    "delete_traffic_route": "route_id",
    "update_user": "user_id",
    "update_dynamic_dns": "ddns_id",
    "update_port_profile": "profile_id",
    "update_wlan_config": "wlan_id",
    "update_hotspot_operator": "operator_id",
    "delete_hotspot_operator": "operator_id",
    "update_arm_profile": "arm_profile_id",
    "update_device_tag": "tag_id",
    "delete_device_tag": "tag_id",
    "update_wan_interface": "wan_id",
    "update_site_to_site_tunnel": "tunnel_id",
    "delete_site_to_site_tunnel": "tunnel_id",
    "allow_network_on_port_profile": "profile_id",
    "exclude_network_on_port_profile": "profile_id",
}


def _br_requests(up: uh.FakeUpstream, payload: Any) -> list[dict[str, Any]]:
    """The writes a call sent (method, raw path, query, body), or -- under dry-run -- the
    previews it returned in their place."""
    sent = [
        {"method": s.method, "path": s.raw_path or s.path, "query": s.query, "body": s.sent_json}
        for s in up.writes()
    ]
    if sent:
        return sent
    previews: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if is_dry_run_preview(node) and isinstance(node.get("preview"), dict):
                pv = node["preview"]
                previews.append(
                    {
                        "method": pv.get("method"),
                        "path": pv.get("path"),
                        "query": pv.get("params"),
                        "body": pv.get("body"),
                    }
                )
                return
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(payload)
    return previews


def _br_diffs(base: Any, got: Any, where: str = "") -> list[tuple[str, Any, Any]]:
    """Every leaf where ``got`` differs from ``base`` (a shape difference is one leaf)."""
    if isinstance(base, dict) and isinstance(got, dict) and base.keys() == got.keys():
        return [d for k in base for d in _br_diffs(base[k], got[k], f"{where}.{k}")]
    if isinstance(base, list) and isinstance(got, list) and len(base) == len(got):
        return [
            d
            for i, (b, g) in enumerate(zip(base, got, strict=True))
            for d in _br_diffs(b, g, f"{where}[{i}]")
        ]
    return [] if base == got else [(where, base, got)]


async def _br_run(
    monkeypatch, name: str, args: dict[str, Any], env: dict[str, str], site_count: int
) -> tuple[list[dict[str, Any]], uh.FakeUpstream]:
    up = uh.FakeUpstream(site_count=site_count, replay_recordings=False)
    res = await _call(monkeypatch, name, up, dict(args), env=env)
    return _br_requests(up, uh.result_payload(res)), up


async def _br_locally_matched(monkeypatch, name: str, args: dict[str, Any], arg: str) -> bool:
    """True when an unknown ``arg`` is refused with no write (the tool matched it in a
    list); False when the tool writes it anyway (forwarded for the upstream to judge)."""
    up = uh.FakeUpstream(replay_recordings=False)
    try:
        await _call(monkeypatch, name, up, {**args, arg: _br_unknown(args[arg])})
    except ToolError:
        assert up.writes() == [], f"{name}: unknown {arg} refused only after a write"
        return True
    return False


def _br_with_body_id(name: str, args: dict[str, Any], value: str, field: str) -> dict[str, Any]:
    """``args`` with every object argument (a write body) carrying ``field: value``."""
    props = _lz_TOOLS()[name].parameters.get("properties") or {}
    out = dict(args)
    for pname, spec in props.items():
        types = {spec.get("type")} | {s.get("type") for s in spec.get("anyOf", [])}
        if "object" in types and isinstance(out.get(pname), dict):
            out[pname] = {**out[pname], field: value}
    return out


_BR_STATES = {
    "default": ({}, 1),
    "dry_run": ({"UNIFI_DRY_RUN": "1"}, 1),
    "multi_site": ({}, 2),
}


@class_axis("name", lambda: _lz_BR_TOOLS(), state=lambda: sorted(_BR_STATES))
async def test_br_matched_id_is_sent_in_the_upstream_spelling(monkeypatch, name, state):
    env, site_count = _BR_STATES[state]
    uh.install(monkeypatch, uh.FakeUpstream(replay_recordings=False))
    args = tool_args.generated_args(_lz_TOOLS()[name])
    ids = _br_id_args(args)
    local = {a for a in ids if await _br_locally_matched(monkeypatch, name, args, a)}
    if name in _BR_KNOWN_RESOLVED:
        assert _BR_KNOWN_RESOLVED[name] in local, f"{name}: target id not resolved locally"
    base, base_up = await _br_run(monkeypatch, name, args, env, site_count)
    assert base, f"{name} [{state}]: the upstream-spelling call sent no write"
    # A body identity field naming the target, in the record kind's own key (Classic / v2
    # ``_id``; Integration / Protect ``id``), spelt like the id argument.
    target = next(iter(sorted(local)), ids[0])
    field = "_id" if uh.family(str(base[0]["path"])) in ("classic", "v2") else "id"
    base_args = _br_with_body_id(name, args, args[target], field)
    upper = {k: args[k].upper() for k in ids}
    upper_args = _br_with_body_id(name, {**args, **upper}, upper[target], field)
    base, _ = await _br_run(monkeypatch, name, base_args, env, site_count)
    got, _ = await _br_run(monkeypatch, name, upper_args, env, site_count)
    assert len(got) == len(base), f"{name} [{state}]: {len(base)} writes became {len(got)}"
    # Only a FORWARDED id may differ, and only as the caller's spelling of it.
    forwarded = {args[a]: upper[a] for a in ids if a not in local}
    for b, g in zip(base, got, strict=True):
        for where, bv, gv in _br_diffs(b, g):
            respelt = isinstance(bv, str) and any(
                c in bv and gv == bv.replace(c, u) for c, u in forwarded.items()
            )
            assert respelt, (
                f"{name} [{state}]: {g['method']} {where} sent {gv!r} where the upstream "
                f"spelling sends {bv!r} (locally matched: {sorted(local)})"
            )
    # Every locally matched id: its caller spelling reaches no request at all.
    for a in local:
        leaked = [r for r in got if upper[a] in json.dumps(r)]
        assert leaked == [], f"{name} [{state}]: caller spelling of {a} sent: {leaked[:1]}"


def test_br_covers_the_resolving_writes():
    assert set(_BR_KNOWN_RESOLVED) <= set(_lz_BR_TOOLS()), set(_BR_KNOWN_RESOLVED) - set(
        _lz_BR_TOOLS()
    )


@pytest.mark.parametrize("name", sorted(_BR_KNOWN_RESOLVED))
async def test_br_unknown_upper_case_id_sends_no_write(monkeypatch, name):
    """An upper-case id that names no record is still refused before any write."""
    arg = _BR_KNOWN_RESOLVED[name]
    args = tool_args.generated_args(_lz_TOOLS()[name])
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, {**args, arg: _br_unknown(args[arg])})
    assert up.writes() == [], f"{name}: {up.writes()}"
    assert _br_unknown(args[arg]) in str(exc.value)


# Failed read-after never proves verification or a no-op, across the write catalog.
class _FailedReadAfter(uh.FakeUpstream):
    def __call__(self, req):
        if req.method == "GET" and self.writes():
            self.failed_read_after_calls = getattr(self, "failed_read_after_calls", 0) + 1
            if self.mode == "after_transport":
                raise httpx.ConnectError("catalog read-after transport reason", request=req)
            requested = getattr(self, "_requested", {})
            if not isinstance(requested, dict):
                requested = {"requested": requested}
            body = (
                self._wrong_shape(req.url.path, requested)
                if self.mode == "after_shape"
                else {**requested, "reason": "catalog read-after reason " * 80}
            )
            status = (
                200
                if self.mode == "after_shape"
                else 429
                if self.mode == "after_rate_limit"
                else 404
                if self.mode == "after_not_found"
                else 403
            )
            self._record(req, status, body, False)
            return httpx.Response(status, json=body)
        if req.method in {"PATCH", "PUT", "POST"} and req.content:
            try:
                self._requested = json.loads(req.content)
            except ValueError:
                self._requested = {}
        mode = self.mode
        self.mode = "normal"
        try:
            return super().__call__(req)
        finally:
            self.mode = mode

    def _wrong_shape(self, path: str, requested: dict) -> Any:
        """A read-after body whose shape the route cannot answer.

        A bare array holding the requested record is the documented shape of a v2
        collection or one-record settings route, and Classic and v2 collection readers
        accept a ``{data: [...]}`` envelope or a bare array (``_rows``, ``_singleton``,
        ``require_listed_record``): for those a list of the record is a successful read.
        So the array probe is kept for a route the tool first read as a plain object;
        any other route gets an array whose row is not an object, which no record
        reader accepts (the shape mismatch ``tests/test_invariants_read_after.py`` uses).
        """
        before = [s.body for s in self.served if s.method == "GET" and s.path == path]
        if not before or (isinstance(before[-1], dict) and "data" not in before[-1]):
            return [requested]
        return ["catalog read-after shape"]


@class_axis(
    "name",
    lambda: _lz_WRITE_TOOLS(),
    fault=lambda: ["http", "rate_limit", "transport", "shape"],
    scope=lambda: ["single", "multi", "capped"],
)
async def test_bs_failed_read_after_never_proves_verification(monkeypatch, name, fault, scope):
    up = _FailedReadAfter(mode=f"after_{fault}")
    keys = (
        [
            APIKeyConfig(key="synthetic-alpha", label="alpha"),
            APIKeyConfig(key="synthetic-beta", label="beta"),
        ]
        if scope == "multi"
        else None
    )
    env = {"UNIFI_PAGINATE_MAX_PAGES": "1"} if scope == "capped" else {}
    try:
        res = await _call(monkeypatch, name, up, env=env, keys=keys)
    except Exception as exc:
        if not up.writes():
            return  # Pre-write validation cannot claim a failed read-after succeeded.
        pytest.fail(f"{name}: read-after failure raised away write evidence: {exc}")
    if not up.writes():
        return  # A read-before no-op or capped resolution sent no write to verify.
    if not getattr(up, "failed_read_after_calls", 0):
        # A successful write may return the updated resource itself; no GET failed.
        # Error/unknown verdicts apply only when this mock actually injected a fault.
        return
    payload = uh.result_payload(res)
    nodes = list(_nested_objects(payload))
    if fault != "shape" and any(
        set(node).intersection({"verified", "_verified", "noOp", "_noOp", "readAfter"})
        for node in nodes
    ):
        assert any(node.get("readAfterError") or node.get("_readAfterError") for node in nodes), (
            name,
            fault,
            payload,
        )
    for node in nodes:
        for key in ("verified", "_verified"):
            assert node.get(key) is None, (name, fault, node)
        if fault != "shape" or "_verified" in node:
            for key in ("noOp", "_noOp"):
                assert node.get(key) is None, (name, fault, node)


def _input_models(annotation):
    from typing import get_args

    from pydantic import BaseModel

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
        for field in annotation.model_fields.values():
            yield from _input_models(field.annotation)
    else:
        for arg in get_args(annotation):
            yield from _input_models(arg)


@tool_batches("name", lambda: sorted(_lz_TOOLS()))
def test_bt_caller_models_hide_validation_input(name):
    from typing import get_type_hints

    from pydantic import ValidationError

    sentinel = "synthetic-validation-secret-sentinel"
    models = set()
    for annotation in get_type_hints(_lz_TOOLS()[name].fn).values():
        models.update(_input_models(annotation))
    for model in models:
        assert model.model_config.get("hide_input_in_errors") is True, (name, model)
        with pytest.raises(ValidationError) as caught:
            model.model_validate(sentinel)
        assert sentinel not in str(caught.value), (name, model)


# Upstream-failure probes for the AP-radio tools.
# Other Classic tool families are covered by their owning class lanes.
class _ClassicFailureUpstream(uh.FakeUpstream):
    def __call__(self, req):
        response = super().__call__(req)
        if "/network/api/" in req.url.path and 200 <= response.status_code < 300:
            body = {
                "meta": {"rc": "error", "msg": "catalog-classic-error"},
                "data": [{"probe": "failed-classic-envelope"}],
                "traceId": "full-classic-reason",
            }
            self.served[-1].body = body
            return httpx.Response(response.status_code, json=body)
        return response


@pytest.mark.parametrize("name", ["get_device_radios", "update_device_radio"])
async def test_bq_classic_error_envelopes_never_claim_success(monkeypatch, name):
    up = _ClassicFailureUpstream()
    try:
        result = uh.result_payload(await _call(monkeypatch, name, up))
    except ToolError as exc:
        result = str(exc)
    failed = [
        s
        for s in up.served
        if isinstance(s.body, dict) and s.body.get("meta", {}).get("rc") == "error"
    ]
    assert failed, f"{name}: failure envelope was not exercised"
    if failed:
        text = str(result)
        assert "catalog-classic-error" in text, name
        assert "failed-classic-envelope" in text, name
        assert "full-classic-reason" in text, name
        if isinstance(result, dict):
            for flag in ("verified", "_verified", "noOp", "_noOp", "changed"):
                assert result.get(flag) is None, (name, flag, result.get(flag))


class _ReadAfterFailureUpstream(uh.FakeUpstream):
    failure = "429"

    def __call__(self, req):
        if req.method == "GET" and self.writes() and not uh.is_resolution(req.url.path):
            if self.failure == "runtime":
                raise RuntimeError("catalog read-after failure")
            body = {
                "meta": {"rc": "error", "msg": "catalog read-after failure"},
                "data": [],
                "traceId": "read-after-whole-envelope",
            }
            status = 429 if self.failure == "429" else 500
            self._record(req, status, body, False)
            return httpx.Response(status, json=body)
        return super().__call__(req)


@pytest.mark.parametrize("name", ["update_device_radio"])
@pytest.mark.parametrize("failure", ["429", "runtime", "500"])
async def test_br_failed_read_after_keeps_write_evidence(monkeypatch, name, failure):
    up = _ReadAfterFailureUpstream()
    up.failure = failure
    try:
        payload = uh.result_payload(
            await _call(
                monkeypatch,
                name,
                up,
                {**tool_args.generated_args(_lz_TOOLS()[name]), "radios": {"na": {"ht": 40}}},
            )
        )
    except ToolError:
        pytest.fail(f"{name}: exception discarded an applied write")
    writes = up.writes()
    assert writes, f"{name}: write branch was not exercised"
    assert payload.get("readAfterError"), f"{name}: failed read-after was not exercised"
    # Every successful write body must survive even when subsequent verification fails.
    for write in writes:
        if isinstance(write.body, dict):
            assert any(
                all(node.get(k) == v for k, v in write.body.items())
                for node in _nested_objects(payload)
            ), f"{name}: write response lost"
    for flag in ("verified", "_verified", "noOp", "_noOp", "changed"):
        assert payload.get(flag) is None, (name, flag, payload.get(flag))


def test_record_counts_ignore_additive_projections_but_keep_upstream_duplicates():
    record = {"probe": "upstream-record"}
    payload = {"data": [record], "_device": record, "_projection": [record, record]}
    assert _probe_counts(payload) == {"upstream-record": 1}
    assert _max_multiplicity(payload) == 1
    duplicated = {"data": [record, record], "_device": record}
    assert _probe_counts(duplicated) == {"upstream-record": 2}
    assert _max_multiplicity(duplicated) == 2


@pytest.mark.parametrize("body", W_BODIES)
async def test_w_ap_write_malformed_classic_envelope_is_not_success(monkeypatch, body):
    up = uh.FakeUpstream(write_body=body)
    with pytest.raises(ToolError, match="Unexpected Classic response"):
        await _call(monkeypatch, "update_device_radio", up)
    assert len(up.writes()) == 1


class _NonAffirmativeClassicWriteUpstream(_ProtocolWriteBodyUpstream):
    rc = None

    def __call__(self, req):
        response = super().__call__(req)
        if (
            uh.is_write_request(req.method, req.url.path, uh.request_json(req))
            and uh.family(req.url.path) == "classic"
        ):
            body = self.served[-1].body
            body["meta"] = {} if self.rc is None else {"rc": self.rc}
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        return response


@pytest.mark.parametrize("rc", [None, "error", "OK"])
async def test_w_ap_write_requires_exact_classic_affirmative_rc(monkeypatch, rc):
    up = _NonAffirmativeClassicWriteUpstream(write_body="list")
    up.rc = rc
    with pytest.raises(ToolError, match="Classic API error|Classic operation failed"):
        await _call(monkeypatch, "update_device_radio", up)
    assert len(up.writes()) == 1


# Batch-route counter-examples: an id in a valid list must not excuse a wrong route.
_BAD_RADIUS_DELETES = [
    ("POST", "/v2/api/site/default/firewallgroups/batch_delete", ["record-a"]),
    ("POST", "/v2/api/site/default/radius/users/batch_update", ["record-a"]),
    ("PUT", "/v2/api/site/default/radius/users/batch_delete", ["record-a"]),
    ("DELETE", "/v2/api/site/default/radius/users/batch_delete", None),
    ("POST", "/v2/api/site/default/radius/users/batch_delete", {"_id": "record-a"}),
    ("POST", "/v2/api/site/default/radius/users/batch_delete", [{"_id": "record-a"}]),
    ("POST", "/v2/api/site/default/radius/users/batch_delete", []),
    ("POST", "/v2/api/site/default/radius/users/batch_delete", ["record-a", "record-b"]),
    ("POST", "/v2/api/site/default/radius/users/batch_delete", [None]),
]


@pytest.mark.parametrize("method,suffix,body", _BAD_RADIUS_DELETES)
def test_radius_delete_preview_rejects_wrong_collection_action_method_or_body(
    method,
    suffix,
    body,
):
    prefix = f"/v1/connector/consoles/{uh.HOST_ID}/proxy/network"
    assert not _is_delete_preview({"method": method, "path": prefix + suffix, "body": body})


@pytest.mark.parametrize("method,suffix,body", _BAD_RADIUS_DELETES)
def test_radius_addressed_ids_reject_wrong_collection_action_method_or_body(
    method,
    suffix,
    body,
):
    prefix = f"/v1/connector/consoles/{uh.HOST_ID}/proxy/network"
    write = uh.Served(method, prefix + suffix, 200, None, False, sent_json=body)
    assert _bl_addressed_ids(write) == []


async def test_delete_network_invariant_rejects_another_collection(monkeypatch):
    async def wrong_call(*_args, **_kwargs):
        return {
            "status": "dry_run",
            "dryRun": True,
            "message": "DRY RUN - no upstream write was performed",
            "preview": {
                "method": "DELETE",
                "path": (
                    f"/v1/connector/consoles/{uh.HOST_ID}/proxy/network"
                    f"/integration/v1/sites/{uh.SITE_ID}/wifi/broadcasts/{uh.ARG_ID}"
                ),
                "body": None,
            },
        }

    monkeypatch.setattr(__name__ + "._call", wrong_call)
    monkeypatch.setattr(uh, "result_payload", lambda value: value)
    with pytest.raises(AssertionError):
        await test_aa_every_delete_tool_previews_a_delete_under_dry_run.__wrapped__(
            monkeypatch,
            "delete_network",
        )


@pytest.mark.parametrize("corruption", ["collection", "target"])
async def test_radius_resolved_write_invariant_rejects_corrupted_transport(monkeypatch, corruption):
    original = _call

    async def corrupt_call(mp, name, up, *args, **kwargs):
        result = await original(mp, name, up, *args, **kwargs)
        write = up.writes()[0]
        if corruption == "collection":
            write.path = write.path.replace("/radius/users/", "/firewallgroups/")
        else:
            collection = write.path.removesuffix("/batch_delete")
            for served in up.served:
                if served.method == "GET" and served.path == collection:
                    served.body.append({**served.body[0], "_id": "another-listed-account"})
            write.sent_json = ["another-listed-account"]
        return result

    monkeypatch.setattr(__name__ + "._call", corrupt_call)
    with pytest.raises(AssertionError):
        await test_bl_known_target_writes_exactly_one_resolved_record(
            monkeypatch,
            "delete_radius_account",
        )


def __getattr__(name: str):
    """Lazy module attributes: the catalog-derived names, built on first access.

    ``cti.READ_TOOLS`` etc. keep working for importers without building the catalog
    when this module is imported.
    """
    if name == "TOOLS":
        return LazyCatalog()
    accessor = globals().get(f"_lz_{name}")
    if accessor is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return accessor()
