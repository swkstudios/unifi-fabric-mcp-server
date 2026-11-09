"""Cross-tool invariants (envelopes, totals, previews, descriptions), enforced across
EVERY registered tool they apply to.

The harness and helpers are those of ``tests/test_cross_tool_invariants``.

ca. Envelope pass-through: for every list tool, every top-level key of the upstream list
    envelope survives in the result: at the top level for a single-source list, inside
    the result for a fan-out or composite one (per site, per key, per list). With two keys
    a merged list keeps each key's envelope (``byKey``).
cb. A single-GET list whose upstream total exceeds the records it returned is
    ``incomplete: true`` with a reason, never presented as complete; nothing is invented.
cc. With the opt-in ``UNIFI_REDACT_SECRETS`` on, dry-run previews carry no secret: under
    ``dry-run policy`` no write tool's result contains a secret value the call supplied
    (password, passphrase, ``x_*`` secrets, psk, private keys, tokens), at any depth; the
    preview masks it. With redaction off (the default) the preview shows the caller's input
    verbatim (tests/test_dry_run_preview_redaction_optin.py).
cd. Every tool description states its result: it has a ``Returns`` statement and names
    every tool-owned top-level key of the result (keys no upstream body carries).
ce. Relay dry-run and no-op fidelity: a dry-run relay write is audited ``outcome=dry_run``
    with no status and returns ``status: "dry_run"``; ``noOp`` is true only when the write
    and both reads are 2xx and the reads are identical; a DELETE whose read-after is 404
    is ``changed: true``.
cf. Upload content types: every MIME type the Protect spec accepts for an asset upload is
    reachable from a filename extension; an explicit ``content_type`` is sent as given; an
    unmapped extension without one fails before any request, listing the accepted types.
cg. A ``page_token`` is honoured in multi-key deployments: list_hosts and list_sites fetch
    that one page (on the first configured key) instead of ignoring it.
"""

from __future__ import annotations

import base64
import functools
import json
import logging
import re
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import class_axis, tool_batches
from unifi_fabric.client import is_dry_run_preview
from unifi_fabric.tools.protect import UPLOAD_CONTENT_TYPES
from unifi_fabric.write_body import update_body_argument

TOOLS = cti.TOOLS
_call = cti._call


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _anywhere(obj: Any, key: str) -> bool:
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if key in node:
                return True
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


# =========================================================================== (ca)
# Tools whose result is not a list of the records read (documented record selections,
# derived documents): their contract is a projection, so an envelope has no place in it.
_NOT_LISTS = set(cti.SELECT) | set(cti.DERIVED)
# Fan-out / composite lists: several upstream lists feed one result, so each list's
# envelope is kept inside the result (per site, per list, under the relayed body).
COMPOSITE = {
    "get_site_inventory": "devices and clients lists: _devicesEnvelope / _clientsEnvelope",
    "list_all_clients": "one list per site: _siteEnvelopes",
    "compare_site_performance": "one stat/health body per site, verbatim in _comparison",
    "list_wan_interfaces": "the WAN list's envelope on top, the health body under _health",
    "list_site_warnings": "v2 network and Classic controller bodies under their source keys",
    **{n: "the relayed body, verbatim under body" for n in cti.RAW_RELAY},
}


@functools.cache
def _lz_LIST_CANDIDATES():
    return sorted(n for n in cti.READ_TOOLS if n not in cti.NO_UPSTREAM and n not in _NOT_LISTS)


# Every list tool known to carry an envelope, so the derived set cannot silently shrink.
_MUST_KEEP_ENVELOPE = {
    "list_mobility_workspaces",
    "list_mobility_admins",
    "list_mobility_devices",
    "list_carrier_service_plans",
    "list_carrier_subscribers",
    "list_innerspace_floor_plans",
    "list_innerspace_access_points",
    "list_innerspace_switches",
    "list_innerspace_inventory",
    "list_hosts",
    "list_sites",
    "list_devices",
    "list_sdwan_configs",
    "list_networks",
    "list_recognition_groups",
    "list_all_devices",
}


def _probed(up: uh.FakeUpstream, name: str) -> list[uh.Served]:
    """The list bodies the tool read that carry the envelope probe."""
    return [
        s
        for s in up.served
        if (not s.resolution or name in cti.PRIMARY_RESOLUTION)
        and not any(a in s.path for a in cti.AUXILIARY.get(name, ()))
        and isinstance(s.body, dict)
        and uh.ENVELOPE_PROBE_KEY in s.body
    ]


@tool_batches("name", lambda: _lz_LIST_CANDIDATES())
async def test_ca_every_upstream_envelope_key_survives(monkeypatch, name):
    up = uh.FakeUpstream(envelope_probe=True)
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    if not _probed(up, name):
        assert name not in _MUST_KEEP_ENVELOPE, f"{name}: read no list envelope"
        return  # not a list tool (an object body, a bare array, binary)
    if name in COMPOSITE:
        assert _anywhere(payload, uh.ENVELOPE_PROBE_KEY), (
            f"{name}: an upstream envelope key was dropped ({COMPOSITE[name]})"
        )
        return
    assert isinstance(payload, dict) and (
        payload.get(uh.ENVELOPE_PROBE_KEY) == uh.ENVELOPE_PROBE_VALUE
    ), f"{name}: the upstream top-level key {uh.ENVELOPE_PROBE_KEY!r} was dropped: {payload!r:.300}"


def test_ca_list_tool_set_covers_the_named_tools():
    assert _MUST_KEEP_ENVELOPE <= set(_lz_LIST_CANDIDATES()), sorted(
        _MUST_KEEP_ENVELOPE - set(_lz_LIST_CANDIDATES())
    )


@functools.cache
def _lz_MERGING_LIST_TOOLS():
    return sorted(
        n for n in cti.AGGREGATION_TOOLS if n in _lz_LIST_CANDIDATES() and n not in COMPOSITE
    )


async def _is_merging_list_tool(name: str) -> bool:
    """``_lz_MERGING_LIST_TOOLS`` membership for one tool, decided at execution."""
    return (
        name in _lz_LIST_CANDIDATES() and name not in COMPOSITE and await cti._is_aggregation(name)
    )


@tool_batches("name", lambda: _lz_LIST_CANDIDATES(), member=_is_merging_list_tool)
async def test_ca_two_key_merge_keeps_each_keys_envelope(monkeypatch, name):
    up = uh.FakeUpstream(envelope_probe=True, hosts_by_key=cti._two_key_hosts())
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up, keys=cti._KEYS))
    except ToolError:
        return  # not drivable under two keys with generated args; covered single-key
    if not _probed(up, name):
        return
    assert _anywhere(payload, uh.ENVELOPE_PROBE_KEY), (
        f"{name}: a two-key merge dropped the upstream envelope: {payload!r:.300}"
    )


# =========================================================================== (cb)
# Single-GET lists (the upstream pages none of them): one request answers the whole list.
SINGLE_GET_LISTS = [
    "list_mobility_workspaces",
    "list_mobility_admins",
    "list_carrier_service_plans",
    "list_innerspace_floor_plans",
    "list_innerspace_access_points",
    "list_innerspace_switches",
    "list_innerspace_inventory",
]


@pytest.mark.parametrize("name", SINGLE_GET_LISTS)
async def test_cb_single_get_list_is_one_request(monkeypatch, name):
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up)
    reads = [s for s in up.served if not s.resolution]
    assert len(reads) == 1, [(s.method, s.path) for s in reads]


@pytest.mark.parametrize("name", SINGLE_GET_LISTS)
@pytest.mark.parametrize("total_key", ["total", "totalCount"])
async def test_cb_total_above_rows_is_incomplete(monkeypatch, name, total_key):
    up = uh.FakeUpstream(envelope_extra={total_key: 10**6})
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    assert payload.get("incomplete") is True and payload.get("incompleteReason"), payload
    assert payload[total_key] == 10**6  # the upstream value, verbatim


@pytest.mark.parametrize("name", SINGLE_GET_LISTS)
async def test_cb_total_equal_to_rows_is_complete(monkeypatch, name):
    # Generated data: one record under a declared total of 1. A replayed capture keeps
    # its own record count (the InnerSpace inventory capture holds none).
    up = uh.FakeUpstream(envelope_extra={"total": 1}, replay_recordings=False)
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    assert "incomplete" not in payload, payload


async def test_cb_mobility_workspaces_body_is_verbatim(monkeypatch):
    """A Mobility workspaces body: every upstream key comes back, plus only ``_count``."""
    body = {
        "data": [{"workspace_id": uh.ARG_ID, "workspace_name": "w"}],
        "total": 1,
        "offset": 0,
        "limit": 50,
        "httpStatusCode": 200,
        "traceId": "T-1",
    }

    class Up(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/mobility/workspaces":
                self._record(req, 200, body, False)
                return httpx.Response(200, json=body)
            return super().__call__(req)

    payload = uh.result_payload(await _call(monkeypatch, "list_mobility_workspaces", Up(), {}))
    assert payload == {**body, "_count": 1}


# =========================================================================== (cc)
SECRET = "probe-secret-value-preview"
_SECRET_FIELDS = {
    "password": SECRET,
    "x_passphrase": SECRET,
    "passphrase": SECRET,
    "x_psk": SECRET,
    "psk": SECRET,
    "x_private_key": SECRET,
    "nested": {"x_password": SECRET, "token": SECRET},
}
_SECRET_ARG = re.compile(r"(password|passphrase|secret|psk|token)\Z")


def _with_secrets(name: str) -> tuple[dict[str, Any], bool]:
    """Generated args with every secret-named scalar argument and every free-form body
    carrying ``SECRET``; the flag says whether any secret was supplied."""
    tool = TOOLS[name]
    args = {**tool_args.generated_args(tool), **cti._SENT_OPTIONALS.get(name, {})}
    supplied = False
    props = tool.parameters.get("properties") or {}
    for pname in props:
        if _SECRET_ARG.search(pname) and isinstance(args.get(pname, ""), str):
            args[pname] = SECRET
            supplied = True
    body_arg = update_body_argument(tool)
    candidates = [body_arg] if body_arg else []
    candidates += [p for p, v in args.items() if isinstance(v, dict) and p != body_arg]
    for pname in candidates:
        if pname and isinstance(args.get(pname), dict):
            args[pname] = {**args[pname], **json.loads(json.dumps(_SECRET_FIELDS))}
            supplied = True
    return args, supplied


async def _eligible_cc_dry_run_preview_never_carries_a_secret(name):
    args, supplied = _with_secrets(name)
    if not supplied:
        return False
    return True


@tool_batches(
    "name", lambda: cti.WRITE_TOOLS, eligible=_eligible_cc_dry_run_preview_never_carries_a_secret
)
async def test_cc_dry_run_preview_never_carries_a_secret(monkeypatch, name):
    args, supplied = _with_secrets(name)
    if not supplied:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream()
    try:
        res = await _call(
            monkeypatch,
            name,
            up,
            args,
            env={"UNIFI_WRITE_POLICY": "dry-run", "UNIFI_REDACT_SECRETS": "1"},
        )
    except ToolError as exc:
        assert SECRET not in str(exc), f"{name}: the error echoes a secret: {exc}"
        return  # the body was refused (a schema-strict tool); nothing was previewed
    payload = uh.result_payload(res)
    text = json.dumps(payload)
    assert SECRET not in text, f"{name}: the dry-run result carries a secret: {text[:400]}"
    previews = [n for n in cti._nested_objects(payload) if is_dry_run_preview(n)]
    assert previews, f"{name}: no dry-run preview: {text[:300]}"


def test_cc_secret_bearing_write_set_is_non_trivial():
    supplied = [n for n in cti.WRITE_TOOLS if _with_secrets(n)[1]]
    assert len(supplied) >= 60, len(supplied)
    assert "update_mobility_device_wireless" in supplied
    assert "create_radius_profile" in supplied


# =========================================================================== (cd)
_RETURNS = re.compile(r"\bReturns?\b")


def _named(desc: str, key: str) -> bool:
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(key) + r"(?![A-Za-z0-9_])", desc) is not None


def _upstream_keys(up: uh.FakeUpstream) -> set[str]:
    keys: set[str] = set()
    for s in up.served:
        if isinstance(s.body, dict):
            keys |= {str(k) for k in s.body}
        for rec in uh.upstream_records(s.body):
            if isinstance(rec, dict):
                keys |= {str(k) for k in rec}
    return keys


@class_axis("name", lambda: sorted(TOOLS), sparse=lambda: [False, True])
async def test_cd_every_description_states_its_result_keys(monkeypatch, name, sparse):
    """Checked with the recorded real records and with sparse generic ones (no recorded
    fields such as ``port_table``): the keys a sparse record yields are named too."""
    desc = TOOLS[name].description or ""
    assert _RETURNS.search(desc), f"{name}: the description has no Returns statement"
    up = uh.FakeUpstream(recorded_routes={}) if sparse else uh.FakeUpstream()
    try:
        payload = uh.result_payload(await _call(monkeypatch, name, up))
    except ToolError:
        if not sparse:
            raise
        return  # not drivable without the recorded shapes; covered by the recorded case
    if not isinstance(payload, dict):
        return
    owned = [k for k in payload if k not in _upstream_keys(up)]
    if list(payload) == ["result"] and re.search(r"\barray\b", desc):
        owned = []  # FastMCP's {"result": [...]} envelope of a documented array result
    missing = [k for k in owned if not _named(desc, k)]
    assert missing == [], f"{name}: the description does not name result key(s) {missing}"


# =========================================================================== (ce)
class _RelayUpstream(uh.FakeUpstream):
    """Answers ``/probe-relay`` paths: GETs from ``reads`` in order, writes with
    ``write``."""

    reads: list[tuple[int, bytes]]
    write: tuple[int, bytes] = (200, b"")

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if "/probe-relay" in req.url.path:
            status, content = self.reads.pop(0) if req.method == "GET" else self.write
            self._record(req, status, content, False)
            headers = {"content-type": "application/json"} if content else {}
            return httpx.Response(status, content=content, headers=headers)
        return super().__call__(req)


_RELAY_ARGS = {"host": uh.HOST, "path": "access/api/probe-relay/thing"}


@pytest.mark.parametrize(
    ("before", "after", "noop", "changed"),
    [
        ((200, b""), (404, b""), False, True),  # the DELETE deleted
        ((200, b'{"a":1}'), (404, b'{"error":"gone"}'), False, True),
        # still readable after the DELETE: deletion not confirmed, never a no-op
        ((200, b'{"a":1}'), (200, b'{"a":1}'), None, None),
        ((404, b""), (404, b""), None, None),  # nothing to compare
        ((200, b""), (500, b""), None, None),  # the read-after failed
    ],
)
async def test_ce_relay_delete_no_op_needs_two_2xx_reads(monkeypatch, before, after, noop, changed):
    up = _RelayUpstream()
    up.reads = [before, after]
    payload = uh.result_payload(
        await _call(monkeypatch, "fabric_connector_delete", up, dict(_RELAY_ARGS))
    )
    assert payload["noOp"] is noop, payload
    assert payload.get("changed") is changed, payload
    if before[0] == 200 and after[0] == 200:
        assert "deletion not confirmed" in payload["noOpReason"], payload


async def test_ce_relay_no_op_needs_an_accepted_write(monkeypatch):
    up = _RelayUpstream()
    up.reads = [(200, b'{"a":1}'), (200, b'{"a":1}')]
    up.write = (409, b'{"error":"conflict"}')
    args = {**_RELAY_ARGS, "body": {"a": 1}}
    payload = uh.result_payload(await _call(monkeypatch, "fabric_connector_put", up, args))
    assert payload["noOp"] is None and "changed" not in payload, payload


@lazy_parametrize("name", lambda: sorted(cti.RAW_RELAY.intersection(cti.WRITE_TOOLS)))
async def test_ce_relay_dry_run_is_audited_dry_run_with_no_status(monkeypatch, tmp_path, name):
    audit = tmp_path / "audit.log"
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(TOOLS[name])}
    if name == "fabric_connector_get":
        args["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
    caplog_lines: list[str] = []

    class _Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            caplog_lines.append(record.getMessage())

    logging.disable(logging.NOTSET)
    relay_logger = logging.getLogger("unifi_fabric.tools.connector")
    handler = _Grab(level=logging.INFO)
    relay_logger.addHandler(handler)
    old_level = relay_logger.level
    relay_logger.setLevel(logging.INFO)
    try:
        env = {"UNIFI_WRITE_POLICY": "dry-run", "UNIFI_AUDIT_LOG": str(audit)}
        payload = uh.result_payload(await _call(monkeypatch, name, up, args, env=env))
    finally:
        relay_logger.removeHandler(handler)
        relay_logger.setLevel(old_level)
    assert up.writes() == []
    assert payload["status"] == "dry_run", payload
    assert is_dry_run_preview(payload.get("body")), payload
    lines = [line for line in caplog_lines if "connector-relay-audit" in line]
    assert lines, caplog_lines
    for line in lines:
        assert "outcome=dry_run" in line and "status=-" in line, line
        assert "outcome=success" not in line and "status=200" not in line, line


# =========================================================================== (cf)
_SPEC_TYPES = re.compile(r"(image|audio)/[a-z0-9.+-]+")


def _spec_upload_types() -> set[str]:
    spec = json.loads(
        (uh.Path(__file__).parent / "fixtures/openapi/protect-7.3.74.json").read_text()
    )
    post = spec["paths"]["/v1/files/{fileType}"]["post"]
    schema = post["requestBody"]["content"]["multipart/form-data"]["schema"]
    return {m.group(0) for m in _SPEC_TYPES.finditer(schema["description"])}


def test_cf_every_spec_type_is_reachable_from_an_extension():
    spec = _spec_upload_types()
    assert spec >= {"audio/wave", "audio/x-caf", "image/png"}, spec
    assert set(UPLOAD_CONTENT_TYPES.values()) == spec, (
        sorted(spec - set(UPLOAD_CONTENT_TYPES.values())),
        sorted(set(UPLOAD_CONTENT_TYPES.values()) - spec),
    )


def _upload_args(filename: str, **extra: Any) -> dict[str, Any]:
    return {
        "host": uh.HOST,
        "file_type": "animations",
        "filename": filename,
        "file_content_base64": base64.b64encode(b"probe-bytes").decode(),
        **extra,
    }


@pytest.mark.parametrize(("ext", "mime"), sorted(UPLOAD_CONTENT_TYPES.items()))
async def test_cf_extension_maps_to_the_spec_type(monkeypatch, ext, mime):
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(
            monkeypatch,
            "upload_protect_file",
            up,
            _upload_args(f"a{ext.upper() if ext == '.wav' else ext}"),
            env={"UNIFI_WRITE_POLICY": "dry-run"},
        )
    )
    assert payload["response"]["preview"]["multipart"][0]["contentType"] == mime


async def test_cf_wav_and_caf_are_sent_with_the_spec_types_on_the_wire(monkeypatch):
    for filename, mime in (("a.wav", "audio/wave"), ("a.caf", "audio/x-caf")):
        up = uh.FakeUpstream()
        sent: list[bytes] = []

        class Up(uh.FakeUpstream):
            def __call__(self, req: httpx.Request, sent: list[bytes] = sent) -> httpx.Response:
                if req.method == "POST" and "/files/" in req.url.path:
                    sent.append(req.content)
                return super().__call__(req)

        up = Up()
        await _call(monkeypatch, "upload_protect_file", up, _upload_args(filename))
        assert sent and f"Content-Type: {mime}".encode() in sent[0], sent


async def test_cf_explicit_content_type_is_passed_through(monkeypatch):
    up = uh.FakeUpstream()
    args = _upload_args("clip.bin", content_type="audio/wave")
    payload = uh.result_payload(
        await _call(
            monkeypatch, "upload_protect_file", up, args, env={"UNIFI_WRITE_POLICY": "dry-run"}
        )
    )
    assert payload["response"]["preview"]["multipart"][0]["contentType"] == "audio/wave"


@pytest.mark.parametrize("filename", ["notes.txt", "noext", "a.flac"])
async def test_cf_unmapped_extension_fails_fast_listing_accepted_types(monkeypatch, filename):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, "upload_protect_file", up, _upload_args(filename))
    message = str(exc.value)
    assert all(mime in message for mime in set(UPLOAD_CONTENT_TYPES.values())), message
    assert up.served == []


async def test_cf_malformed_content_type_fails_fast(monkeypatch):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(
            monkeypatch,
            "upload_protect_file",
            up,
            _upload_args("a.wav", content_type="audio/wave\r\nX-Injected: 1"),
        )
    assert up.served == []


# =========================================================================== (cg)
# A cursor belongs to the key whose listing issued it, so with several keys a manual
# page needs key_label (never a guessed first key); with it, that key's page is read.
@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("list_sites", "/v1/sites"),
        ("list_hosts", "/v1/hosts"),
        ("list_devices", "/v1/devices"),
        ("list_sdwan_configs", "/v1/sd-wan-configs"),
    ],
)
async def test_cg_page_token_with_several_keys_needs_key_label(monkeypatch, name, path):
    up = uh.FakeUpstream(hosts_by_key=cti._two_key_hosts())
    with pytest.raises(ToolError, match="key_label") as exc:
        await _call(monkeypatch, name, up, {"page_token": "probe-token"}, keys=cti._KEYS)
    assert "alpha" in str(exc.value) and "beta" in str(exc.value)
    assert up.served == [], [(s.path, s.query) for s in up.served]
    up = uh.FakeUpstream(hosts_by_key=cti._two_key_hosts())
    payload = uh.result_payload(
        await _call(
            monkeypatch,
            name,
            up,
            {"page_token": "probe-token", "key_label": "beta"},
            keys=cti._KEYS,
        )
    )
    reads = [s for s in up.served if s.path == path]
    assert len(reads) == 1, [(s.path, s.query, s.api_key) for s in reads]
    assert "nextToken=probe-token" in reads[0].query, reads[0].query
    assert reads[0].api_key == "k-beta"
    assert payload["_key_labels"] == ["beta"], payload


_PORT_STATE_CONDITIONAL = ("port_table", "lldp_table", "meta")


@pytest.mark.parametrize("sparse", [False, True], ids=["recorded", "sparse"])
async def test_cd_device_port_state_description_matches_the_actual_keys(monkeypatch, sparse):
    """Every key the device view returns is named in the description, and every key the
    description lists that a sparse record leaves out is described as conditional."""
    desc = " ".join((TOOLS["get_device_port_state"].description or "").split())
    up = uh.FakeUpstream(recorded_routes={}) if sparse else uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, "get_device_port_state", up))
    assert isinstance(payload, dict)
    for k in ("_device", "_device_record", "_port_idx", "_source", "_thermal_power"):
        assert k in payload and _named(desc, k), k
    assert [k for k in payload if not _named(desc, k)] == [], payload.keys()
    absent = [k for k in _PORT_STATE_CONDITIONAL if k not in payload]
    if sparse:
        assert {"port_table", "lldp_table"} <= set(absent), payload.keys()
    assert "port_table and lldp_table only when the selected record has them" in desc
    assert "meta only when the upstream envelope has it" in desc
