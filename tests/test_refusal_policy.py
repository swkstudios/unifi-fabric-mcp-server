"""Pre-upstream refusal policy, enforced over the WHOLE tool catalog.

A tool may refuse a call before its upstream request only for the server's own selector
syntax, a pinned-spec constraint, a live-probed closed enum or JSON validity
(``unifi_fabric.refusals``); everything else is passed through for the upstream to judge.

1. Behaviour: every registered tool is fed, one argument at a time, a blank string and a
   whitespace string (string arguments), an empty list and a list holding one blank string
   (array arguments), a negative and an out-of-range large number (numeric arguments), and
   an empty object plus the body with each key left out (object arguments); and, for
   combinations, every optional argument the generated call leaves out given ALONE (a
   dependency between arguments, such as one filter honoured only with another, must not
   be a refusal) and all of them given at once. Every call must
   either reach the upstream (a write verb for a write tool, a non-resolution request for a
   read) or fail with a message matching a refusal in the registry. An unregistered
   refusal, a refusal of an upstream-judged kind raised with no request at all, and a
   generated call that never reaches the upstream are failures.
2. Inventory: every ``raise`` in the package sits in a function the registry names, or in
   one :data:`NON_REFUSAL_RAISES` names with the reason it is not a pre-upstream refusal.
   A new raise site anywhere is a failure until it is classified.
3. ``tools._payload.require_fields`` is called only with a label the registry lists in
   ``SPEC_REQUIRED_FIELDS``, and each listed field set is required by the vendored spec of
   the operation the tool really calls.
"""

from __future__ import annotations

import ast
import functools
import logging
from pathlib import Path
from typing import Any

import pytest

from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import LazyCatalog, lazy_parametrize
from tests._tool_classes import tool_batches
from tests.spec_limits_gen import LOGICAL_PAGINATION_COUNT_ARGS, accept_value
from unifi_fabric import refusals, server
from unifi_fabric.generated_api_facts._spec_limits_table import SPEC_LIMITS

PACKAGE = Path(server.__file__).resolve().parent


TOOLS = LazyCatalog()

#: Tools with no upstream request at all (their whole answer is local).
NO_UPSTREAM = {
    "list_configured_api_keys": "reports the server's own key configuration",
    "get_server_diagnostic_bundle": "local diagnostics; no request unless a probe is asked for",
    "get_event_stream_status": "reports the recorded stream compatibility and local listeners",
}


def _is_write(tool: Any) -> bool:
    ann = tool.annotations
    return not (ann and getattr(ann, "read_only_hint", None))


def _types(spec: dict[str, Any]) -> set[Any]:
    return {spec.get("type")} | {s.get("type") for s in spec.get("anyOf") or []}


#: Valid values for the server's own selector / enum arguments, so a combination call
#: gets past them and exercises what follows (a refused sample would make it vacuous).
VALID_SAMPLES: dict[str, Any] = {
    "key_label": "default",
    "client_type": "WIRED",
    "session_type": "all",
    "mode": "2D",
    "content_type": "image/png",
    "section": "labels",
    "plan_id": uh.ARG_ID,
    "host_ids": [uh.HOST_ID],
    "client_ids": [uh.ARG_MAC],
    "client_id": uh.ARG_MAC,
    "order_direction": "ASC",
    "sort": "name",
    "smart_detect_types": "person",
    "types": "motion",
    "categories": "motion",
    "host_address": "192.0.2.1",
    "dhcp_range_start": "192.0.2.100",
    "dhcp_range_stop": "192.0.2.200",
    # the newer route of a list tool's optional source argument (list_clients,
    # list_known_clients, list_guests); its other value is that tool's default route
    "source": "v2",
    # the _id of a generated networkconf record (set_client_fixed_ip and
    # create_client_reservation resolve it by _id, Integration id or name)
    "network": uh.ARG_HEX,
}

#: Samples that hold for one tool only: an argument name another tool types differently
#: (get_camera_analytics' ``step`` is an integer bucket size).
TOOL_SAMPLES: dict[tuple[str, str], Any] = {
    ("enroll_doorbell_credential", "step"): "enroll",  # enroll / assign / cancel
    # HOUR / DAY / WEEK / MONTH, live-probed on Network 11.0.89; DAY is the default
    ("get_latest_traffic_flow_stats", "period"): "HOUR",
    # firmware locations the console is told to fetch: http(s) URLs with a host
    ("upgrade_device", "firmware_url"): "https://firmware.example.invalid/fw.bin",
    ("update_device_battery_settings", "url"): "https://firmware.example.invalid/bat.bin",
    # a list of event types (list_protect_events takes one type as a string)
    ("collect_protect_incident_evidence", "types"): ["motion"],
    # only the read-allowlisted system-log class can be collected (read_post_routes)
    ("collect_network_incident_evidence", "log_classes"): ["all"],
}


def _sample(tool: str, arg: str, spec: dict[str, Any]) -> Any:
    """A valid value for an optional argument: the explicit sample, else the shared recipe,
    else one the spec limits accept, else a plausible value of its type."""
    if (tool, arg) in LOGICAL_PAGINATION_COUNT_ARGS:
        return 1
    if tool == "set_protect_event_favorite" and arg == "objects":
        return [{"eventId": uh.ARG_ID, "objectId": uh.ARG_ID}]
    if (tool, arg) in TOOL_SAMPLES:
        return TOOL_SAMPLES[(tool, arg)]
    if arg in VALID_SAMPLES:
        return VALID_SAMPLES[arg]
    if arg in tool_args.BY_NAME:
        return tool_args.BY_NAME[arg]
    frag = SPEC_LIMITS.get(tool, {}).get(arg)
    if frag:
        value = accept_value(frag)
        if value is not None:
            return value
    types = _types(spec)
    if "boolean" in types:
        return True
    if "integer" in types:
        return 1
    if "number" in types:
        return 0.1
    if "object" in types:
        return {"probeSetting": True}
    if "array" in types:
        return ["probe-value"]
    if arg.endswith("_id") or arg.endswith("id"):
        return uh.ARG_ID
    return "probe-value"


#: Optional arguments that exclude another one (the server's own argument grammar,
#: registered as argument-grammar): {tool: {argument left out of the all-optional call}}.
EXCLUSIVE: dict[str, frozenset[str]] = {
    "get_client_link_diagnostics": frozenset({"client_ids"}),  # exactly one of client_id(s)
    # client_type excludes filter; offset / limit / filter (Integration source) exclude the
    # v2 source and its include_* flags, which the all-optional call exercises
    "list_clients": frozenset({"client_type", "offset", "limit", "filter"}),
    "list_guests": frozenset({"source"}),  # source v2 excludes the Classic within_hours window
    # vpn_user_id (the VPN-user connection log) excludes the class / window arguments
    "list_network_events": frozenset({"vpn_user_id"}),
    "query_isp_metrics": frozenset({"sites"}),  # sites excludes host + site
    "update_carrier_subscriber": frozenset({"clear_fields"}),  # a field cleared and set
    "set_protect_event_favorite": frozenset({"object_id"}),  # single-id form only
    "export_protect_case": frozenset({"export_id"}),  # download only; the baseline prepares
    "get_client_observability": frozenset({"timestamp"}),  # topology only; the baseline is a window
    "control_packet_capture": frozenset({"capture_id"}),  # pcap-start takes no capture id
    "get_topology_snapshot": frozenset({"at"}),  # at selects the history/at route
    "export_edge_recording": frozenset({"filename"}),  # download only; the baseline may prepare
    "get_multicast_insights": frozenset({"client_mac"}),  # client_mac only with view client
    "enroll_doorbell_credential": frozenset({"fingerprint_id", "ulp_id", "fields"}),  # assign only
}


def combinations(tool: Any) -> list[tuple[str, dict[str, Any]]]:
    """(label, arguments): each optional argument the generated call omits, given alone,
    then all of them at once."""
    base = tool_args.generated_args(tool)
    props = (tool.parameters or {}).get("properties") or {}
    omitted = {
        a: v
        for a, s in sorted(props.items())
        if a not in base and (v := _sample(tool.name, a, s)) is not None
    }
    out = [(f"given-{a}", {**base, a: v}) for a, v in omitted.items()]
    out.append(("given-all-optional", all_optional(tool)))
    return out


def all_optional(tool: Any) -> dict[str, Any]:
    """The generated call plus every optional argument it omits (valid samples), minus
    the arguments :data:`EXCLUSIVE` says exclude another."""
    base = tool_args.generated_args(tool)
    props = (tool.parameters or {}).get("properties") or {}
    skip = EXCLUSIVE.get(tool.name, frozenset())
    extra = {
        a: v
        for a, s in sorted(props.items())
        if a not in base and a not in skip and (v := _sample(tool.name, a, s)) is not None
    }
    return {**base, **extra}


@pytest.mark.parametrize(("name", "arg"), sorted(LOGICAL_PAGINATION_COUNT_ARGS))
def test_logical_requested_count_baselines_are_positive(name, arg):
    tool = TOOLS[name]
    assert _sample(name, arg, tool.parameters["properties"][arg]) == 1
    if arg not in EXCLUSIVE.get(name, frozenset()):
        assert all_optional(tool)[arg] == 1
    calls = combinations(tool)
    assert calls
    assert all(args[arg] == 1 for _label, args in calls if arg in args)


def perturbations(tool: Any) -> list[tuple[str, str, Any]]:
    """(argument, label, value) for every perturbation of ``tool``'s arguments."""
    base = tool_args.generated_args(tool)
    props = (tool.parameters or {}).get("properties") or {}
    out: list[tuple[str, str, Any]] = []
    for arg, spec in sorted(props.items()):
        types = _types(spec)
        if "string" in types:
            out += [(arg, "blank", ""), (arg, "whitespace", "   ")]
        if "array" in types:
            out += [(arg, "empty-list", []), (arg, "blank-item", [""])]
        if arg == "poll_count" and tool.name in {
            "collect_protect_events",
            "collect_protect_device_changes",
        }:
            # Counts request actual work, not elapsed windows. Exercise complete
            # one/two-poll workloads here; the collector suite separately admits
            # huge counts through its control validator without trillion-poll I/O.
            out += [(arg, "negative", -1), (arg, "zero", 0), (arg, "one", 1), (arg, "two", 2)]
        elif "integer" in types or "number" in types:
            out += [(arg, "negative", -1), (arg, "huge", 10**12)]
        if "object" in types:
            out.append((arg, "empty-object", {}))
            if isinstance(base.get(arg), dict):
                for key in base[arg]:
                    rest = {k: v for k, v in base[arg].items() if k != key}
                    out.append((arg, f"without-{key}", rest))
    return out


async def _attempt(name: str, args: dict[str, Any]) -> tuple[str, str | None, uh.FakeUpstream]:
    """('ok' | 'error', message, upstream) for one call with default flags.

    The sweep sends synthetic optional values (filters, offsets, limits) that no capture
    recorded, and an exact-capture replay answers an unrecorded query with a harness
    LookupError instead of a response. Whether a call reaches the upstream does not depend
    on the recorded content, so every route is answered with generated data.
    """
    up = uh.FakeUpstream(replay_recordings=False)
    with pytest.MonkeyPatch.context() as mp:
        if name in {"collect_protect_events", "collect_protect_device_changes"}:
            # Poll count controls completed work; replace pacing with a no-op,
            # preserving every request and the complete requested one/two polls.
            async def complete_pacing(_delay: float) -> None:
                pass

            mp.setattr(server.protect, "_sleep", complete_pacing)
        for k, v in tool_args.TOOL_ENV.get(name, {}).items():
            mp.setenv(k, v)
        uh.install(mp, up)
        try:
            await server.mcp.call_tool(name, args)
        except Exception as exc:  # noqa: BLE001 - every failure is classified below
            if isinstance(exc, TimeoutError):
                raise
            return "error", str(exc), up
    return "ok", None, up


#: Read tools whose own upstream is a console / site enumeration endpoint.
PRIMARY_RESOLUTION = frozenset(
    {"list_hosts", "list_sites", "list_local_sites", "list_all_sites_aggregated"}
)


def _reached(name: str, up: uh.FakeUpstream) -> bool:
    if _is_write(TOOLS[name]):
        return bool(up.writes())
    if name in PRIMARY_RESOLUTION:
        return bool(up.served)
    return any(not s.resolution for s in up.served)


#: Perturbations that blank or empty ONE argument: a refusal they cause must be about
#: that argument (a message-text match alone could register a refusal of another one).
BLANK_LABELS = frozenset({"blank", "whitespace", "empty-list", "blank-item", "empty-object"})


def _verdict(
    name: str,
    outcome: str,
    message: str | None,
    up: uh.FakeUpstream,
    arg: str | None = None,
    label: str | None = None,
) -> str | None:
    """Why this outcome breaks the policy, or None."""
    assert outcome in {"ok", "error"}, f"unmeasured outcome: {outcome}"
    if outcome == "ok":
        return None
    assert message is not None
    refusal = refusals.classify(message)
    if _reached(name, up) and (refusal is None or refusal.category == refusals.UPSTREAM_JUDGED):
        return None
    if refusal is None:
        return f"unregistered refusal before any upstream request: {message[:300]!r}"
    if _is_write(TOOLS[name]) and refusal.category != refusals.UPSTREAM_JUDGED and up.served:
        return (
            f"local refusal {refusal.id!r} sent {len(up.served)} "
            f"upstream requests: {message[:300]!r}"
        )
    if refusal.category == refusals.UPSTREAM_JUDGED and not refusal.upstream_reason:
        return f"{refusal.id!r} has no registered upstream dependency reason"
    if refusal.category == refusals.UPSTREAM_JUDGED and not up.served:
        return f"{refusal.id!r} is upstream-judged but no request was sent: {message[:300]!r}"
    if label in BLANK_LABELS and arg is not None and refusal.category != refusals.UPSTREAM_JUDGED:
        if arg not in message:
            return f"{refusal.id!r} refusal does not name the blanked {arg!r}: {message[:300]!r}"
        if refusal.id == "argument-grammar":
            # A blank / empty value names nothing, so it cannot conflict with another
            # argument (one of two exclusive arguments given empty is simply not given).
            return f"blank {arg!r} treated as given in an argument conflict: {message[:300]!r}"
    return None


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


@functools.cache
def _lz_SWEPT():
    return sorted(n for n in TOOLS if n not in NO_UPSTREAM)


@tool_batches("name", lambda: _lz_SWEPT())
async def test_every_pre_upstream_failure_is_a_registered_refusal(name):
    tool = TOOLS[name]
    base = tool_args.generated_args(tool)
    outcome, message, up = await _attempt(name, base)
    assert outcome != "error" or _reached(name, up), (
        f"{name}: the generated call never reaches the upstream: {message!r}"
    )
    optional = all_optional(tool)
    outcome, message, up = await _attempt(name, optional)
    assert outcome != "error" or _reached(name, up), (
        f"{name}: the all-optional baseline never reaches the upstream: {message!r}"
    )
    problems = []
    for arg, label, value in perturbations(tool):
        # each perturbation on the generated call AND paired with every optional argument
        for basis, args in (("", base), ("all-optional+", optional)):
            outcome, message, up = await _attempt(name, {**args, arg: value})
            problem = _verdict(name, outcome, message, up, arg, label)
            if problem is not None:
                problems.append(f"{basis}{arg}={label}: {problem}")
    for label, args in combinations(tool):
        outcome, message, up = await _attempt(name, args)
        problem = _verdict(name, outcome, message, up)
        if problem is not None:
            problems.append(f"{label}: {problem}")
    assert not problems, f"{name}:\n  " + "\n  ".join(problems)


def test_combinations_cover_the_dependent_filters():
    labels = {label for label, _ in combinations(TOOLS["list_protect_events"])}
    assert {"given-smart_detect_types", "given-types", "given-all-optional"} <= labels


@functools.cache
def _lz_RELAY_WRITE_TOOLS():
    return sorted(n for n in TOOLS if n.startswith("fabric_connector_"))


@lazy_parametrize("name", lambda: _lz_RELAY_WRITE_TOOLS())
@lazy_parametrize("site_name", lambda: (["global_switch", "setting", "device", "rest"]))
async def test_relay_site_name_is_never_read_as_a_route_class(name, site_name):
    """A literal site named like a route segment selects nothing: a device route under
    it with scope='device' is relayed (the route class is read after the site)."""
    args = {
        **tool_args.generated_args(TOOLS[name]),
        "path": f"network/api/s/{site_name}/rest/device/{uh.ARG_HEX}",
        "scope": "device",
    }
    outcome, message, up = await _attempt(name, args)
    assert outcome != "error" or not (message and "site-global" in message), message
    assert any(not s.resolution for s in up.served), message


def test_sweep_covers_every_argument_kind():
    """The sweep is not vacuous: it perturbs every tool that takes an argument, and every
    perturbation kind occurs."""
    labels = {label.split("-")[0] for n in _lz_SWEPT() for _, label, _ in perturbations(TOOLS[n])}
    assert {"blank", "whitespace", "empty", "negative", "huge", "without"} <= labels
    bare = [
        n
        for n in _lz_SWEPT()
        if (TOOLS[n].parameters or {}).get("properties") and not perturbations(TOOLS[n])
    ]
    assert not bare, f"tools with arguments but no perturbation: {bare}"


# --------------------------------------------------------------------------- inventory
#: Reasons shared by the audit-chain, audit-verify and credential-provider raise sites.
_CHAIN_STARTUP = (
    "configuration (UNIFI_AUDIT_CHAIN with its key, the JSON format and the file sink); "
    "Settings refuses the combination first, so this is a startup invariant and never a "
    "tool call"
)
_VERIFY_CLI = (
    "operator CLI (unifi-fabric-audit-verify): a usage or key-file fault reported on "
    "stderr with an exit code; never a tool call"
)
_PROVIDER_STARTUP = (
    "startup (UNIFI_API_KEY* file and command providers): a ProviderError names the "
    "setting, never the content; never a tool call"
)

#: Raise sites that are not pre-upstream argument refusals: {module.py:qualname: reason}.
NON_REFUSAL_RAISES: dict[str, str] = {
    "audit.py:AuditStream._put": _CHAIN_STARTUP,
    "audit.py:_build_chain": _CHAIN_STARTUP,
    "audit_verify.py:_Parser.error": _VERIFY_CLI,
    "audit_verify.py:_anchor": _VERIFY_CLI,
    "audit_verify.py:cli": _VERIFY_CLI,
    "audit_verify.py:load_keys": _VERIFY_CLI,
    "audit_verify.py:main": _VERIFY_CLI,
    "audit_verify.py:read_key_file": _VERIFY_CLI,
    "credential_providers.py:_check_conflicts": _PROVIDER_STARTUP,
    "credential_providers.py:_decode": _PROVIDER_STARTUP,
    "credential_providers.py:_parse": _PROVIDER_STARTUP,
    "credential_providers.py:_read_file": _PROVIDER_STARTUP,
    "credential_providers.py:_run_command": _PROVIDER_STARTUP,
    "credential_providers.py:parse_command": _PROVIDER_STARTUP,
    "credential_providers.py:resolve_into": _PROVIDER_STARTUP,
    "diagnostic_bundle.py:validate_probes": (
        "defence in depth: the live_probes schema enumerates the probes (Literal), so an "
        "unknown name is refused by schema validation before this function runs"
    ),
    "families/protect/protect.py:_global_alarm_manager_hint": "upstream error re-raised with a hint",
    "shared_shapes/_incident_document.py:PostStatusTap.post": (
        "defence in depth behind post_read, which already refuses an unlisted POST; the "
        "collector reaches the tap only through post_read and validates log_classes first"
    ),
    "shared_shapes/_incident_document.py:Window._ordered": (
        "closed incident-evidence schema invariant on the server's own output document; "
        "the collectors build it from validated arguments, never from caller input"
    ),
    "shared_shapes/_incident_document.py:EventTime._consistent": (
        "closed incident-evidence schema invariant on the server's own output document; "
        "the collectors build it from validated arguments, never from caller input"
    ),
    "shared_shapes/_incident_document.py:SourceResult._outcome_rules": (
        "closed incident-evidence schema invariant on the server's own output document; "
        "the collectors build it from validated arguments, never from caller input"
    ),
    "shared_shapes/_incident_document.py:IncidentEvidence._document_rules": (
        "closed incident-evidence schema invariant on the server's own output document; "
        "the collectors build it from validated arguments, never from caller input"
    ),
    "stream_buffers.py:EventBuffer.__init__": (
        "programming invariant: the buffer capacity is a server constant, never a tool argument"
    ),
    "stream_buffers.py:StreamListener.__init__": (
        "programming invariant: the reconnect delays are a server constant"
    ),
    "stream_buffers.py:StreamManager.attach": (
        "programming invariant: the tools report an unsupported product before attaching, "
        "so no tool call reaches this refusal"
    ),
    "families/statistics/event_streams.py:read_recent_event_buffer": (
        "programming invariant: the server registry exists whenever a supported product "
        "needs host resolution (inside the server lifespan)"
    ),
    "families/statistics/statistics.py:_list_speedtest_results": (
        "re-raises an observed upstream archive.speedtest error; only a 403 host-not-found "
        "response gets host-id guidance appended, with status and request_sent preserved"
    ),
    "families/site_manager/site_manager.py:register.query_isp_metrics": (
        "re-raises a selector-resolution failure gathered from the per-key resolvers: an "
        "invalid selector fails the whole call before any metrics request, a partial or "
        "failed listing is scoped to its key, and a cancellation propagates"
    ),
    "families/site_manager/site_manager.py:register.query_isp_metrics._query": (
        "re-raises an already-observed host/site selector-resolution failure through the "
        "existing per-key fan-out; selector ValueErrors propagate before metrics requests"
    ),
    "fingerprint.py:key_fingerprint": (
        "programming invariant: internal helper whose length is a code constant (8) at every "
        "call site; it is never a tool argument and adds no caller-visible refusal"
    ),
    "route_secrets.py:matching": (
        "programming invariant: the internal registry query requires string method/path "
        "values supplied by typed client routes or validated relay routes; this is not "
        "an additional constraint on upstream tool arguments"
    ),
    "protect_resources.py:ProtectResources.snapshot": (
        "a snapshot resource read: re-raises the backing get_camera_snapshot error (already "
        "scrubbed by the tool chain) with the snapshot-index URI appended, or reports a result "
        "shape or base64 the tool never produces; no argument is judged here"
    ),
    "protect_resources.py:ResourceExposureMiddleware._visible": (
        "resources/list policy-header error: the same invalid_policy_header MCP error the "
        "tools/list request-policy filter raises, not a tool-argument refusal"
    ),
    "protect_resources.py:_records": (
        "unexpected backing-tool result shape (no record array), raised with the type received"
    ),
    "protect_resources.py:_record": (
        "unexpected upstream record shape in a resource index, raised with describe_shape"
    ),
    "protect_resources.py:_object_field": (
        "unexpected upstream field shape in a resource index, raised with describe_shape"
    ),
    "protect_resources.py:summarize": (
        "unexpected upstream event shape in the event summary, raised with describe_shape"
    ),
    # configuration and process start (not a tool call)
    "server.py:": "module __main__ entrypoint exits before the tool catalog is imported",
    "audit.py:AuditStream.__post_init__": (
        "configuration (UNIFI_AUDIT_LOG_FORMAT, UNIFI_AUDIT_LEVEL)"
    ),
    "audit.py:configure_audit_stream": (
        "configuration (UNIFI_AUDIT_HMAC_IDENTIFIERS without a key); Settings refuses the "
        "flag first, so this is a startup invariant and never a tool call"
    ),
    "audit_identifiers.py:IdentifierHasher.__init__": (
        "configuration (UNIFI_AUDIT_HMAC_KEY decoded length); startup, never a tool call"
    ),
    "audit_remote.py:RemoteConfig.__post_init__": (
        "configuration (UNIFI_AUDIT_REMOTE_* numeric and TLS-file settings, named without "
        "their values); startup, never a tool call"
    ),
    "audit_remote.py:check_url": (
        "configuration (UNIFI_AUDIT_REMOTE_URL shape and plaintext opt-in, named without "
        "the value); startup, never a tool call"
    ),
    "audit.py:FileSink.write": "audit sink fault: converted to SinkWriteError and handled "
    "fail-open inside AuditStream._write; never reaches a tool call",
    "audit.py:StderrSink.write": "audit sink fault: converted to SinkWriteError and handled "
    "fail-open inside AuditStream._write; never reaches a tool call",
    "server.py:AuditContextMiddleware.on_call_tool": "re-raises the tool's own error, with the "
    "audit_unavailable notice appended while the audit sink is failing",
    "profiles.py:Profile.__post_init__": "configuration (a profile naming unknown families)",
    "profiles.py:selection_profile": "configuration (family allowlist / exclusion list)",
    "catalog.py:Catalog.from_dict": "catalog generation/validation (startup:catalog), "
    "never a tool call",
    "catalog.py:overlay": "catalog contract fixture overlay (startup:catalog), never a tool call",
    "catalog.py:validate_catalog": "catalog validation at startup/generation "
    "(startup:catalog:<reason>), never a tool call",
    "catalog_build.py:registered_tools": "catalog generation invariant (discovery meta tools "
    "registered), never a tool call",
    "catalog_build.py:build_catalog": "catalog generation (unclassified source), never a tool call",
    "tool_annotations.py:install_tool_annotations": "server construction (import time): the\n"
    "registered tool catalog cannot be read to annotate it; fails closed, never a tool call",
    # Code Mode (UNIFI_TOOL_MODE=codemode, experimental): its own closed codes per the Code
    # Mode contract (code_mode_invalid_source and code_mode_busy before any upstream call; the
    # post-dispatch code_mode_* results), or the shared read broker's existing refusals.
    "code_mode.py:check_source": "code_mode_invalid_source before slot/interpreter/upstream",
    "code_mode.py:_canonical_argument_bytes": (
        "programming invariant: the bounded strict-JSON preflight byte count must equal the "
        "canonical materialization; it adds no caller-visible argument refusal"
    ),
    "code_mode.py:finish_output": "code_mode_invalid_text for script output (post-dispatch)",
    "code_mode.py:render_output": "code_mode_script_error: final value not strict JSON",
    "code_mode.py:_Run.call_tool": "sandbox-side end of an already-ended script",
    "code_mode.py:_Run._call": "33rd attempt or surrogate response ends the script",
    "code_mode.py:_Run._deliver": "response byte limits / strict encoding end the script",
    "code_mode.py:_run_sandbox": "code_mode_unavailable / recorded script failure",
    "code_mode.py:_drive_pool": "recorded script failure or mapped sandbox error",
    "code_mode.py:run_script": "code_mode_busy before any upstream call",
    "discovery.py:apply_tool_mode.code_search_tools": "server lifecycle has ended",
    "discovery.py:apply_tool_mode.code_describe_tool": "write_denied: Code Mode is read-only",
    "discovery.py:apply_tool_mode.execute": "re-raises a code_mode_* result as its MCP error",
    "discovery.py:apply_tool_mode": "configuration (UNIFI_TOOL_MODE) and server construction "
    "(meta-tool names colliding with registered tools)",
    "discovery.py:apply_tool_mode.search_tools": "server lifecycle has ended; the meta-tool "
    "has already been removed and no registered tool argument is refused",
    "discovery.py:DiscoveryMiddleware.on_call_tool": "re-raises a dispatched meta-tool's "
    "framework argument error, formatted, or a dispatcher missing at server construction",
    "api_sources.py:parse_disabled_sources": "configuration (UNIFI_EXCLUDE)",
    "api_sources.py:route_source": "classification of a request path (build time and "
    "server construction, never a tool call)",
    "api_sources.py:primary_pair": "classification invariant (a tool touches a pair)",
    "api_sources.py:class_id": "classification invariant (access is read or write)",
    "read_post_routes.py:ReadPostRoute.__post_init__": "allowlist definition (import time)",
    "read_post_routes.py:ReadCommand.__post_init__": "read-command list definition (import time)",
    "read_post_routes.py:post_read": "programming invariant: typed tools pass only "
    "allowlisted read-POST routes (unlisted routes go through client.post as writes)",
    "switches.py:parse_bool": "configuration (boolean environment variables)",
    # transport authentication (the JWKS download behind MCP_AUTH_MODE=oauth): not a tool call
    "transport_security.py:_CappedStream.__aiter__": "JWKS download over the 1 MiB cap",
    "transport_security.py:_CappedTransport.handle_async_request": "JWKS download over the "
    "1 MiB cap (declared Content-Length)",
    "transport_security.py:StrictJWTVerifier.__init__": "server construction (the FastMCP "
    "JWKS refresh internals this verifier replaces are missing)",
    "transport_security.py:StrictJWTVerifier._fetch_jwks": "hands a shared JWKS download "
    "failure to FastMCP, which rejects the token",
    "list_results.py:install_structured_list_results": "server construction",
    "server.py:lifespan": "server start without an API key",
    "server.py:main": "process start: a missing or malformed API key exits before serving",
    "server.py:build_auth": "configuration (MCP_AUTH_MODE)",
    "server.py:_require": "server not initialised",
    "server.py:SecretScrubMiddleware._call_scrubbed": "re-raises a scrubbed tool error",
    "server.py:FabricMCP.call_tool": (
        "re-raises an upstream HTTP failure with its fallback notes; "
        "no pre-upstream argument is refused"
    ),
    "client.py:UniFiClient._default_key": "configuration (no API key)",
    "client.py:UniFiClient._new_http_client": "configuration (a key HTTP cannot carry)",
    "audit.py:FileSink._check_existing": "configuration (UNIFI_AUDIT_LOG names an unsafe "
    "existing file): refused at sink creation, never a tool call",
    "server.py:startup_policy": "configuration (the startup policy of UNIFI_WRITE_POLICY, "
    "UNIFI_WRITE_EXCEPTIONS and UNIFI_EXCLUDE): refuses to start, never a tool call",
    # Policy grammar: environment-variable parsing and the catalog the policy is built on
    # (startup), plus the invariants of the closed policy record; none is a tool-call refusal.
    "policy.py:Catalog.build": "policy catalog construction (startup), never a tool call",
    "policy.py:_family_id": "configuration grammar (family id in UNIFI_WRITE_EXCEPTIONS)",
    "policy.py:_tokens": "configuration grammar (list separators and empty items)",
    "policy.py:_tool_target": "configuration grammar (tool:<name> in UNIFI_WRITE_EXCEPTIONS)",
    "policy.py:check_retired_settings": "configuration (a retired setting refuses startup)",
    "policy.py:operator_policy": "configuration (the operator's policy settings)",
    "policy.py:parse_exclude": "configuration grammar (UNIFI_EXCLUDE)",
    "policy.py:parse_write_exceptions": "configuration grammar (UNIFI_WRITE_EXCEPTIONS)",
    "policy.py:parse_write_policy": "configuration grammar (UNIFI_WRITE_POLICY)",
    "policy.py:_header_value": "request policy header grammar: reaches the caller as the "
    "registered invalid_policy_header refusal (request_policy.py)",
    "policy.py:_parse_header": "request policy header grammar: reaches the caller as the "
    "registered invalid_policy_header refusal (request_policy.py)",
    "policy.py:_selectors_for": "invariant: exclusions are parsed at configuration time",
    "policy.py:refusal_record": "invariant of the closed policy.refusal record (code, ids)",
    "request_policy.py:RequestPolicyMiddleware.on_list_tools": "tools/list, not a tool call: "
    "an invalid policy header answers with the invalid_policy_header MCP error",
    # shared contracts: construction invariants of internal values
    "contracts.py:CredentialHandle.__post_init__": "construction invariant (internal value)",
    "contracts.py:EffectivePolicy.__post_init__": "construction invariant (internal value)",
    "contracts.py:RequestContext.__post_init__": "construction invariant (internal value)",
    "contracts.py:RequestContext.child": "construction invariant (internal value)",
    "contracts.py:credentials_index": "construction invariant (internal value)",
    "contracts.py:require_selected_credential": "internal caller contract (a selected key)",
    # header credentials (UNIFI_KEY_MODE=header): the closed pre-dispatch refusals are the
    # registered header-credential refusal; the remaining raises are startup configuration or
    # internal invariants.
    "header_credentials.py:ActiveRequest.handle_for_config": "internal caller contract",
    "header_credentials.py:CredentialCache.client": "internal caller contract (cache closed)",
    "header_credentials.py:CredentialLeaseMiddleware.on_call_tool": "re-raises the tool's "
    "own error after releasing the credential lease",
    "header_credentials.py:CredentialTransport.key_config": "internal caller contract",
    "header_credentials.py:check_startup": "configuration (UNIFI_KEY_MODE startup check)",
    "header_credentials.py:children_for": "internal caller contract",
    "header_credentials.py:hostless_selection": "internal caller contract",
    "header_credentials.py:key_mode": "configuration (UNIFI_KEY_MODE)",
    # tool registration (import time): the catalog contract, never a tool call
    "registration.py:HandlerRef.parse": "catalog registration (import time)",
    "registration.py:_check_signature": "catalog registration (import time)",
    "registration.py:_resolve": "catalog registration (import time)",
    "registration.py:validate_catalog": "catalog registration (import time)",
    "families/innerspace/placement_snapshot.py:build_snapshot": "internal caller contract (aware datetime)",
    "client.py:gather_or_cancel": "re-raise concurrent upstream failure after cancellation",
    "families/protect/protect.py:_collector_id": "upstream poll-record identity shape",
    "families/devices/_device_config.py:require_classic_success": "failed or malformed upstream Classic read",
    "families/devices/device_radios.py:_radio_rows": "upstream radio table shape",
    "families/devices/device_radios.py:_radios_by_band": "ambiguous or malformed upstream radio band",
    "families/devices/device_radios.py:_validated_changes": "device-reported capability bounds after GET",
    "families/devices/device_radios.py:_update_device_radio.read_after": "post-read device identity changed",
    "families/devices/switch_port_overrides.py:_update_switch_port_overrides.read_after": (
        "post-write device identity changed; reported as readAfterError"
    ),
    "families/devices/switch_port_overrides.py:_by_port": (
        "unexpected upstream port_overrides entry shape (no port_idx), raised with describe_shape"
    ),
    "families/devices/switch_port_overrides.py:_require_string_id": (
        "unexpected upstream portconf/networkconf record shape (no string _id), raised with "
        "describe_shape"
    ),
    "families/protect/protect_door_locks.py:list_door_lock_unlock_events": (
        "re-raises the upstream error of a paged read once GET /locks lists the lock id as given"
    ),
    "families/network/network_wifi_radio.py:configure_wifi_wan.read_after": (
        "post-write read-after collection omitted the WAN record"
    ),
    "families/network/network_security_diagnostics.py:_records": "upstream shape",
    "families/network/network_security_diagnostics.py:_update_setting": "upstream setting shape "
    "(read-before answered a non-object; no write was sent)",
    "families/network/network_security_diagnostics.py:get_unified_ip_thread_topology": "every "
    "topology source failed upstream (the first failure is re-raised)",
    "families/network/network_proav_sandbox.py:get_port_forward_statistics": (
        "upstream Classic stat/portforward without meta.rc ok"
    ),
    "families/network/network_dpi_policy.py:_collection_record": "upstream v2 collection shape",
    "families/network/network_dpi_policy.py:_v2_rows": "upstream v2 collection shape",
    "families/network/network_dpi_policy.py:_batch_delete_firewall_policies": "upstream DELETE error",
    "families/network/network_dpi_policy.py:_official_record": "upstream Integration object shape",
    "families/protect/protect_ptz_doorbell.py:_verified_update._read": (
        "post-write read-after did not locate the updated record (reported, never raised)"
    ),
    # upstream responses the tool cannot read (raised after the request, naming it)
    "client.py:finite_number": "upstream value of the wrong type",
    "client.py:read_page_token": "upstream paging control of the wrong type",
    "client.py:page_total": "upstream paging control of the wrong type",
    "client.py:page_has_next_link": "upstream paging control of the wrong type",
    "client.py:page_has_more": "upstream paging control of the wrong type",
    "client.py:object_records": "upstream records of the wrong shape",
    "client.py:UniFiClient.paginate": "upstream shape / paging protocol failure",
    "client.py:UniFiClient.paginate_offset": "upstream shape / paging protocol failure",
    "client.py:UniFiClient.paginate_links": "upstream shape / paging protocol failure",
    "registry.py:ea_site_labels": "upstream site meta of the wrong type",
    "shared_shapes/_pagination.py:_page_items": "upstream page of the wrong shape",
    "shared_shapes/_device_wrappers.py:wrapper_devices": "upstream wrapper of the wrong shape",
    "shared_shapes/_classic_objects.py:consumed_string_array": "upstream array shape",
    "shared_shapes/_classic_objects.py:_classic_data": "upstream Classic envelope of the wrong shape",
    "families/site_manager/aggregation.py:_count_key": "upstream field of the wrong type",
    "families/site_manager/aggregation.py:_unwrap_ea_devices": "upstream wrapper of the wrong shape",
    "families/carrier/carrier_fabric.py:_unwrap_data_obj": "upstream envelope of the wrong shape",
    "families/carrier/carrier_fabric.py:_paginate_cursor": "upstream paging protocol failure",
    "families/carrier/carrier_fabric.py:list_carrier_service_plans._fetch": "upstream shape",
    "families/carrier/carrier_fabric.py:list_carrier_subscribers._page": "upstream shape",
    "families/hotspot/hotspot.py:_list_hotspot_operators": "upstream shape",
    "families/innerspace/innerspace.py:_extract_list": "upstream shape",
    "families/innerspace/innerspace.py:_require_objects": "upstream shape",
    "families/innerspace/innerspace.py:_validated_project": "upstream shape",
    "families/innerspace/innerspace.py:_fetch_project_document": "upstream shape / both paths failed",
    "families/innerspace/innerspace.py:get_innerspace_project": "upstream shape (legacy project route)",
    "families/innerspace/innerspace_internal.py:_project_plans": "upstream shape",
    "families/mobility/mobility.py:_device_from_body": "upstream shape",
    "families/network/matter.py:_list": "upstream shape",
    "families/network/matter.py:commission_matter_node": "internal caller contract (SecretStr setup code)",
    "families/network/matter.py:rename_matter_node": "internal caller contract (str name)",
    "families/mobility/mobility.py:_extract_list": "upstream shape",
    "families/network/network.py:list_wan_interfaces": "upstream shape",
    "families/network/network_services_proxy.py:_classic_records": "upstream shape",
    "families/network/network_services_proxy.py:_setting_state": "upstream shape",
    "families/protect/protect.py:_as_list": "upstream shape",
    "families/protect/protect.py:_require_object": "upstream shape",
    "families/site_manager/site_manager.py:_object_body": "upstream shape",
    "families/site_manager/site_manager.py:isp_metric_records": "upstream shape",
    "families/site_manager/site_manager.py:search_across_sites._search_site": "upstream field of the wrong type",
    "families/network/site_config.py:_config_rows": "upstream shape",
    "families/statistics/statistics.py:_stat_records": "upstream shape",
    "shared_shapes/_pagination.py:collect_batch": "upstream page shape / pagination protocol",
    "shared_shapes/_pagination.py:PageSizeBatch.observe": "upstream page-size metadata shape",
    # upstream errors re-raised (with a hint appended) or aggregated
    "client.py:UniFiClient._request": "transport / HTTP errors of the request it sent (its "
    "pre-send refusals are registered: unsafe-api-path, empty-update)",
    "shared_shapes/_keys.py:fan_out_scopes": "every API key failed upstream",
    "shared_shapes/_keys.py:first_success": "no API key could serve the request",
    "families/site_manager/aggregation.py:_fleet_devices": "every API key failed upstream",
    "families/site_manager/aggregation.py:_fleet_summary": "every API key failed upstream",
    "families/site_manager/aggregation.py:_list_all_clients_fleet": "every key / site failed upstream",
    "families/site_manager/site_manager.py:_aggregate_lists_over_keys": "every API key failed upstream",
    "families/site_manager/site_manager.py:compare_site_performance": "every site failed upstream",
    "families/site_manager/site_manager.py:search_across_sites": "no site could be searched upstream",
    "families/innerspace/innerspace.py:_fetch_integration_list": "upstream error re-raised with context",
    "families/innerspace/innerspace.py:get_innerspace_asset": "upstream error re-raised with context",
    "families/devices/device_mgmt.py:_call_with_device_id": "upstream error re-raised",
    "families/devices/device_mgmt.py:_device_mac": "upstream device without a MAC",
    "shared_shapes/_classic_objects.py:_object_rows": "upstream shape",
    "registry.py:_require_native_id": "upstream record without a native id",
    "shared_shapes/_classic_objects.py:listed_record_id": "upstream record without a valid native _id",
    "families/site_manager/site_manager.py:_unique_proxy_sites": "upstream console site without a native id",
    "families/clients/clients.py:_stamgr_mac": "upstream client without a MAC",
    "families/protect/protect.py:collect_protect_events": "a failing first poll re-raises its error",
    "families/protect/protect.py:list_protect_events": "upstream error re-raised with a host hint",
    "families/network/network.py:create_wifi_broadcast": "upstream SSID-limit error re-raised with a hint",
    "families/network/network_dpi_policy.py:update_predefined_firewall_policy": (
        "upstream system-defined-policy refusal re-raised with a patch_firewall_policy hint"
    ),
    "families/protect/protect.py:_poll_device_snapshot": "upstream error re-raised with a host hint",
    "families/protect/recognition.py:list_recognition_groups": "upstream error with a host hint",
    "families/protect/recognition.py:get_recognition_group_counts": "upstream error with a host hint",
    "families/protect/recognition.py:get_recognition_group_image": "upstream error with a host hint",
    "families/protect/recognition.py:list_recognition_detections": "upstream error with a host hint",
    "families/protect/recognition.py:get_thumbnail": "upstream error with a host hint",
    "families/statistics/statistics.py:_list_known_clients": "upstream error with a host hint",
    "shared_shapes/_payload.py:with_upstream_hint": "re-raises an upstream error with a hint appended",
    "shared_shapes/_results.py:deletion_readback_ids": (
        "post-write readback contains a row without a usable identity; deletion remains unverified"
    ),
    "families/network/network_dpi_policy.py:preview_policy_engine_rule": (
        "re-raises an upstream HTTP 405 after POST with controller-version guidance"
    ),
    "families/devices/device_commands.py:export_site": (
        "re-raises the upstream error; Network's 400 api.err.BackupFailed gets a hint appended"
    ),
    "families/network/network_proav_sandbox.py:get_5g_topology": "re-raises the upstream error; an "
    "HTTP 404 gets a hint appended",
    "families/connector/connector.py:connector_write": "a relayed mutation answered 429 is not retried "
    "(its pre-send method check is registered: relay-path)",
    "families/protect/protect.py:update_arm_profile._read": "read-after lookup after the write: a "
    "missing profile is captured as readAfterError by safe_read_after",
    "families/protect/protect_private.py:_update": "read-before response of the wrong shape (raised "
    "after the GET, naming it)",
    "families/protect/protect_private.py:_action": "upstream transport error of the action it sent, "
    "re-raised as outcome unknown",
    "redaction.py:install_response_redaction": "server construction: UNIFI_REDACT_SECRETS "
    "is on but no tool handler could be wrapped; fails closed, never a tool call",
    "families/innerspace/innerspace_internal.py:get_innerspace_ucore_manifest": "upstream 403 re-raised "
    "with a permission hint",
    "families/innerspace/innerspace_internal.py:list_innerspace_doors": "upstream 502 re-raised with a "
    "UniFi Access hint",
    "families/network/network_device_operations.py:get_device_adoption_info": "upstream 404 re-raised "
    "with a pending-adoption hint",
    "families/network/network_device_operations.py:recover_switch_port": "upstream "
    "api.err.InvalidTargetPort re-raised with a recoverable-state hint",
    "families/network/network_nat_qos_traffic.py:get_poe_info": "upstream 400 re-raised with a hint",
    "families/network/network_nat_qos_traffic.py:get_traffic_stats": "upstream 400 re-raised with a hint",
    "families/vpn/network_vpn_dns.py:delete_wireguard_users.read_after": "post-write read-after "
    "list of the wrong shape (raised after the GET, naming it)",
    "families/vpn/network_vpn_dns.py:get_openvpn_client_config": "upstream 404 re-raised with a hint",
    "families/network/network_wifi_radio.py:get_wifi_quick_scan_status": "upstream 400 re-raised with a hint",
    "families/protect/protect_automation_backup.py:_get_cloud_archive_status": "upstream 500 re-raised "
    "with a hint",
    "families/protect/protect_automation_backup.py:_import_unifi_video_cameras": "upstream 500 re-raised "
    "with a hint",
    "families/protect/protect_recognition_search.py:_search_detections": "upstream 404 searchHost "
    "re-raised with a hint",
}


def _raise_sites() -> dict[str, list[int]]:
    """Inventory explicit raises and the in-place upstream_hint/raise handler form."""
    out: dict[str, list[int]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(PACKAGE).as_posix()
        if rel.startswith("_") and "/" not in rel and rel != "__init__.py":
            continue  # build-time audit / generated modules (no tool call reaches them)
        if rel in {"config.py", "entrypoint.py", "placement_snapshot_cli.py"}:
            continue  # configuration parsing and the CLI: not a tool call
        tree = ast.parse(path.read_text())

        def walk(
            node: ast.AST, stack: list[str], caught_name: str | None = None, rel: str = rel
        ) -> None:
            if isinstance(node, ast.ExceptHandler):
                caught_name = node.name
            hinted_reraises = set()
            if caught_name:
                for _, body in ast.iter_fields(node):
                    if not isinstance(body, list):
                        continue
                    for previous, current in zip(body, body[1:], strict=False):
                        if (
                            isinstance(current, ast.Raise)
                            and current.exc is None
                            and isinstance(previous, ast.Expr)
                            and isinstance(call := previous.value, ast.Call)
                            and isinstance(call.func, ast.Name)
                            and call.func.id == "upstream_hint"
                            and len(call.args) == 2
                            and not call.keywords
                            and isinstance(call.args[0], ast.Name)
                            and call.args[0].id == caught_name
                        ):
                            hinted_reraises.add(current)
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    walk(child, [*stack, child.name])
                elif isinstance(child, ast.Raise) and (
                    child.exc is not None or child in hinted_reraises
                ):
                    out.setdefault(f"{rel}:{'.'.join(stack)}", []).append(child.lineno)
                    walk(child, stack, caught_name)
                else:
                    walk(child, stack, caught_name)

        walk(tree, [])
    return out


@pytest.mark.parametrize(
    "handler_body,expected",
    [
        ("upstream_hint(exc, hint)\nraise", True),
        ("if condition:\n    upstream_hint(exc, hint)\n    raise", True),
        ("raise", False),
        ("other_hint(exc, hint)\nraise", False),
        ("upstream_hint(other, hint)\nraise", False),
        ("upstream_hint(exc)\nraise", False),
        ("upstream_hint(exc, hint=hint)\nraise", False),
        ("upstream_hint(exc, hint)\nother()\nraise", False),
        ("if condition:\n    upstream_hint(exc, hint)\nelse:\n    raise", False),
        ("def inner():\n    upstream_hint(exc, hint)\n    raise", False),
        ("async def inner():\n    upstream_hint(exc, hint)\n    raise", False),
        ("class Inner:\n    upstream_hint(exc, hint)\n    raise", False),
        ("try:\n    pass\nexcept Error as other:\n    upstream_hint(exc, hint)\n    raise", False),
    ],
)
def test_raise_sites_counts_only_the_hinted_handler_form(
    tmp_path, monkeypatch, handler_body, expected
):
    import sys
    import textwrap

    source = "def caller():\n    try:\n        pass\n    except Error as exc:\n"
    source += textwrap.indent(handler_body, "        ") + "\n"
    (tmp_path / "example.py").write_text(source)
    monkeypatch.setattr(sys.modules[__name__], "PACKAGE", tmp_path)
    assert set(_raise_sites()) == ({"example.py:caller"} if expected else set())


def test_raise_sites_ignores_hint_and_reraise_outside_a_handler(tmp_path, monkeypatch):
    import sys

    (tmp_path / "example.py").write_text("def caller():\n    upstream_hint(exc, hint)\n    raise\n")
    monkeypatch.setattr(sys.modules[__name__], "PACKAGE", tmp_path)
    assert not _raise_sites()


def test_every_raise_site_is_a_registered_refusal_or_inventoried():
    sites = _raise_sites()
    registered = refusals.registered_sites()
    unknown = sorted(s for s in sites if s not in registered and s not in NON_REFUSAL_RAISES)
    assert not unknown, "raise sites neither registered nor inventoried:\n  " + "\n  ".join(
        f"{s} (lines {sites[s]})" for s in unknown
    )


@pytest.mark.parametrize(
    "message",
    [
        "X-UniFi-Api-Key was sent more than once; send it once.",
        "This server runs in header mode: send your UniFi API key(s) in the header.",
        "key_label is not accepted in header mode; send only the key(s) this call should use.",
        "This server uses its configured keys (UNIFI_KEY_MODE=environment).",
        "All 4 credential slots are serving active calls; retry in a few seconds.",
    ],
)
def test_header_credential_refusals_classify(message):
    refusal = refusals.classify(message)
    assert refusal is not None and refusal.id == "header-credential", message


def test_registry_names_only_live_raise_sites():
    sites = _raise_sites()
    stale = sorted(
        s for s in refusals.registered_sites() | set(NON_REFUSAL_RAISES) if s not in sites
    )
    assert not stale, f"registry / inventory names functions that raise nothing: {stale}"


def test_every_refusal_has_a_policy_category_and_citation():
    assert len({r.id for r in refusals.REFUSALS}) == len(refusals.REFUSALS)
    for refusal in refusals.REFUSALS:
        assert refusal.category in refusals.CATEGORIES, refusal.id
        assert refusal.citation.strip(), refusal.id


# --------------------------------------------------------------------------- require_fields
def _require_fields_labels() -> dict[str, str]:
    """label -> ``module.py:line`` of every ``require_fields(<label>, ...)`` call."""
    out: dict[str, str] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "id", getattr(node.func, "attr", None)) == "require_fields"
            ):
                first = node.args[0] if node.args else None
                label = (
                    first.value if isinstance(first, ast.Constant) else f"<dynamic@{node.lineno}>"
                )
                out[str(label)] = f"{path.relative_to(PACKAGE)}:{node.lineno}"
    return out


def test_require_fields_is_called_only_for_spec_required_fields():
    calls = _require_fields_labels()
    unregistered = {k: v for k, v in calls.items() if k not in refusals.SPEC_REQUIRED_FIELDS}
    assert not unregistered, (
        "require_fields refuses a body the pinned spec does not require (pass it through "
        f"and append the guidance to an upstream error instead): {unregistered}"
    )
    assert set(calls) == set(refusals.SPEC_REQUIRED_FIELDS), "registry lists unused labels"


def _deref(spec: sc.Spec, node: Any) -> Any:
    while isinstance(node, dict) and "$ref" in node:
        node = sc._resolve(spec, node)[0]
    return node


def _required(spec: sc.Spec, schema: Any) -> set[str]:
    """Keys every alternative of ``schema`` requires (allOf merged, oneOf/anyOf
    intersected, a discriminator's property required)."""
    schema = _deref(spec, schema)
    out = set(schema.get("required") or ())
    for sub in schema.get("allOf") or ():
        out |= _required(spec, sub)
    alts = [_required(spec, s) for s in (schema.get("oneOf") or schema.get("anyOf") or ())]
    if alts:
        out |= set.intersection(*alts)
    if isinstance(schema.get("discriminator"), dict):
        out.add(schema["discriminator"]["propertyName"])
    return out


@pytest.mark.parametrize("label", sorted(refusals.SPEC_REQUIRED_FIELDS))
def test_spec_required_fields_are_required_by_the_vendored_spec(label):
    tool, fields, _citation = refusals.SPEC_REQUIRED_FIELDS[label]
    writes = [r for r in sc.capture(tool) if r.method != "GET" and not r.resolution]
    assert writes, f"{tool}: no write request captured"
    req = writes[-1]
    family, inner = sc.route(req.path)
    candidates = (
        [sc.specs()[s] for s in sc.DIRECT_SPECS] if family == "direct" else [sc.specs()[family]]
    )
    for spec in candidates:
        hit = sc._match(spec, inner)
        if hit is None:
            continue
        op = spec.doc["paths"][hit[0]][req.method.lower()]
        required = {
            _deref(spec, p)["name"]
            for p in op.get("parameters") or ()
            if _deref(spec, p).get("in") == "query" and _deref(spec, p).get("required")
        }
        body = op.get("requestBody")
        if body:
            content = _deref(spec, body)["content"]["application/json"]["schema"]
            required |= _required(spec, content)
        assert fields <= required, f"{label}: {sorted(fields - required)} not required by {hit[0]}"
        return
    pytest.fail(f"{label}: {req.method} {req.path} matches no vendored spec operation")


def test_upstream_refusal_exemptions_have_explicit_reasons():
    assert "path-segment" in {refusal.id for refusal in refusals.REFUSALS}
    for refusal in refusals.REFUSALS:
        assert bool(refusal.upstream_reason) == (refusal.category == refusals.UPSTREAM_JUDGED), (
            refusal.id
        )


def test_path_segment_registers_padded_id_refusal():
    message = (
        "Invalid plan_id  probe-object : contains a control character or "
        "surrounding whitespace (a trailing newline is not an id)"
    )
    assert refusals.classify(message).id == "path-segment"


@pytest.mark.parametrize(
    "message,expected",
    [
        ("camera_id must not be empty", "protect-private-selector"),
        ("sensor_id must not be empty", "protect-private-selector"),
        (
            "device_id contains a control character (newline, tab ...): 'a\\n'",
            "protect-private-selector",
        ),
        ("Unknown camera '   '; valid choices: 'Door' (cam-1)", "lookup-miss"),
        ("Ambiguous sensor 'Door'; valid choices: 'Door' (s-1); 'Door' (s-2)", "lookup-miss"),
        ("Unexpected Protect cameras response: dict", "upstream-shape"),
        ("Read-before GET protect/api/nvr needs an object, received list", "upstream-shape"),
        (
            "PATCH connector relay is refused: (family:connector=deny=0)",
            "area-write-opt-out",
        ),
    ],
)
def test_private_protect_refusals_carry_their_policy_category(message, expected):
    """The private Protect pre-upstream refusals are registered under their R15 category."""
    refusal = refusals.classify(message)
    assert refusal is not None and refusal.id == expected, (message, refusal)


@pytest.mark.parametrize(
    "message,expected,category",
    [
        (
            "url must be an http or https URL with a host.",
            "firmware-url-scheme",
            refusals.SELECTOR_SYNTAX,
        ),
        ("body is not supported for client view", "n12-route-grammar", refusals.SELECTOR_SYNTAX),
        (
            "max_events must be a positive integer or None",
            "collector-control-bounds",
            refusals.RULED_KEEP,
        ),
        (
            "max_changes must be a positive integer or None",
            "collector-control-bounds",
            refusals.RULED_KEEP,
        ),
        (
            "device_type must be camera or sensor",
            "protect-private-device-type",
            refusals.SELECTOR_SYNTAX,
        ),
        (
            "camera shortcut is missing required fields: placement, shortcut",
            "camera-shortcut-opt-in-shape",
            refusals.RULED_KEEP,
        ),
        (
            "shortcut.placement.y must be a number",
            "camera-shortcut-opt-in-shape",
            refusals.RULED_KEEP,
        ),
        (
            "shortcut.shortcut.type must be linkedCamera, linkedDoor, or webhook",
            "camera-shortcut-opt-in-shape",
            refusals.RULED_KEEP,
        ),
        (
            "webhook shortcut timeout must be a number",
            "camera-shortcut-opt-in-shape",
            refusals.RULED_KEEP,
        ),
        (
            "Read-before subscriber identity does not match the addressed subscriber",
            "carrier-subscriber-read-before-identity",
            refusals.UPSTREAM_JUDGED,
        ),
    ],
)
def test_fix_batch_refusals_are_registered_under_their_category(message, expected, category):
    """The 0.7.0 fix batch's new pre-upstream checks (and the carrier read-before identity
    decision) classify as their registry entry, prefixed or not by the framework."""
    for text in (message, f"Error calling tool 'probe': {message}"):
        refusal = refusals.classify(text)
        assert refusal is not None and refusal.id == expected, (text, refusal)
        assert refusal.category == category


def test_fix_batch_raise_sites_are_registered():
    sites = refusals.registered_sites()
    for site in (
        "families/network/network_device_operations.py:update_device_battery_settings",
        "families/network/network_proav_sandbox.py:get_multicast_insights",
        "families/protect/protect.py:_validate_collector_limit",
        "families/protect/protect_private.py:reboot_protect_device",
        "families/protect/protect_private.py:adopt_protect_device",
        "families/protect/protect_private.py:unadopt_protect_device",
        "families/protect/protect_ptz_doorbell.py:_validate_shortcut_element",
        "families/carrier/carrier_fabric.py:update_carrier_subscriber",
    ):
        assert site in sites, site


async def test_attempt_propagates_timeout_instead_of_accepting_unfinished_call(monkeypatch):
    async def unfinished(*_args, **_kwargs):
        raise TimeoutError("synthetic unfinished request")

    monkeypatch.setattr(server.mcp, "call_tool", unfinished)
    with pytest.raises(TimeoutError, match="synthetic unfinished request"):
        await _attempt("list_hosts", {})


@pytest.mark.parametrize(
    ("poll_count", "cadence"),
    [(0, 0), (-1, 0), (True, 0), (1.5, 0), (1, -1), (1, float("inf")), (1, True)],
)
def test_collector_work_and_pacing_refusals_are_registered(poll_count, cadence):
    with pytest.raises(ValueError) as exc:
        server.protect._validate_collector_controls(poll_count, cadence)
    refusal = refusals.classify(str(exc.value))
    assert refusal is not None
    assert refusal.id == "collector-control-bounds"
    assert refusal.category == refusals.RULED_KEEP


def test_retired_collector_window_is_not_registered_as_a_current_control():
    refusal = refusals.classify("window_seconds must be a finite number")
    assert refusal is None or refusal.id != "collector-control-bounds"


@pytest.mark.parametrize(
    "message",
    ["ports cannot be combined with legacy body or port_id.", "legacy port_id requires body."],
)
def test_legacy_reset_compatibility_calls_have_no_refusal_entry(message):
    assert refusals.classify(message) is None
    assert (
        "families/network/network_device_operations.py:register.reset_switch_port"
        not in refusals.registered_sites()
    )
