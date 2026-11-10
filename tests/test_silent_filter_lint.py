"""AST lint: no new silent type filter over upstream data.

An unexpected upstream shape raises naming what was
received; it is never read as "empty" or skipped without a trace. The classic ways code
does that are type filters:

* ``x if isinstance(x, list) else []`` (or ``{}`` / ``()``, either branch order);
* a comprehension filter ``... for r in rows if isinstance(r, dict)``;
* ``if not isinstance(x, dict): continue`` / ``return []`` (or ``{}`` / ``()``).

(``x.get(k) if isinstance(x, dict) else None`` reads a field as absent; it is not a list
filter and the caller decides what an absent value means, so it is out of scope.)

Each such site in ``src/`` is listed in :data:`ALLOWED` with the reason it is not a
silent skip of upstream data (a lookup that cannot match a non-object and lists the
choices on a miss, a caller-requested filter, a documented empty case, a value that is
not upstream data, an additive projection whose verbatim source is kept, or a count
reported under ``_unprojected`` / ``_withheld``). A new site fails this test until it
either raises with the shape received or is classified here with its reason; a stale
entry fails too.

Sites are keyed by (file, enclosing function, normalized source of the node), never by
line number, so unrelated edits do not churn the list.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "unifi_fabric"

_CONTAINERS = frozenset({"list", "dict", "tuple"})
_FILTER_TYPES = frozenset({"list", "dict", "tuple", "str"})

LOOKUP = (
    "lookup: selects the record whose id/name/MAC matches; a non-object entry cannot carry "
    "that key, and a miss raises listing the choices"
)
FILTER = (
    "caller-requested filter: a record that is not an object has no field to match, so it "
    "is outside the selection the caller asked for (the unfiltered call returns it verbatim)"
)
NOT_UPSTREAM = "not upstream response data (configuration, schema or the server's own values)"
ENVELOPE = (
    "envelope copy: a drained list without an envelope (a plain array) has documented-empty "
    "envelope fields; the records themselves are shape-checked where they are read"
)
LABELS = (
    "label read for matching/reporting: an absent or non-object reportedState carries no "
    "hostname; the host is still matched by id and listed among the choices"
)
RAISES = "the type test selects what to raise on (the error names the shape received)"
ADDITIVE = (
    "additive projection: the verbatim upstream field is kept unchanged on the record; only "
    "the additive '_' view is limited to values it can render"
)

CHOICES = (
    "choices text for a not-found error: lists every entry that can name a choice; the "
    "error itself is raised"
)
LOOKUP_RECORDS = (
    "record list read only by id/name/MAC lookups and selections (never returned or counted "
    "as a whole): a non-object entry cannot match, and a miss raises listing the choices"
)
SNAPSHOT_INPUT = (
    "placement snapshot input: the server's own tool results or the project object already "
    "shape-checked by innerspace._validated_project (absent 'project' metadata is "
    "documented-empty); non-object entries are counted under _unprojected and values "
    "omitted under UNIFI_REDACT_SECRETS under _withheld"
)

SCRUB_VALUES = (
    "scrub-value set: only a non-blank string can be scrubbed from text; the values are "
    "never returned to the caller"
)
RELAY_ENVELOPES = (
    "the relay's own result envelopes (result, readBefore, readAfter): one that is not an "
    "object, or carries no body, has no body to mask; nothing upstream is dropped"
)
ADDITIVE_WARNING = (
    "additive warning: a logs-all body that is not an object carries no page count to "
    "warn about; the body itself is returned verbatim"
)
CALLER_IDS = (
    "the caller's body: only a list of id strings is resolved in the rule list first; any "
    "other body is sent verbatim, unfiltered"
)
MERGE_BASE = (
    "write-body merge base: a current snooze setting that is not an object has no field "
    "to preserve; the requested validUntil is sent and the read-after verifies it"
)
CALLER_MERGE = (
    "masked-field merge of the caller's body: a prior value of another type has no "
    "sibling to keep, so the caller's value is sent as given"
)

HOST_MACS = (
    "console MAC selector matching: a reportedState or hardware value that is not an object "
    "carries no MAC to compare; the console stays matchable by id and name, and nothing is "
    "returned or counted from it"
)

#: {(file relative to src/unifi_fabric, function qualname, kind, normalized source): reason}
ALLOWED: dict[tuple[str, str, str, str], str] = {
    (
        "refusal_audit.py",
        "denial_reason",
        "ifexp-empty",
        "arguments if isinstance(arguments, dict) else {}",
    ): (
        "Classification only: names the denying setting in the audit record of a call the "
        "policy already refused. A non-object argument value is rejected by the tool's own "
        "argument validation, and the substitute {} never reaches an upstream request."
    ),
    (
        "code_mode.py",
        "project_result",
        "comprehension-filter",
        "isinstance(t, str)",
    ): (
        "Joins the text of a tool result's content blocks; a non-text block (image, "
        "resource link) has no text attribute and carries no JSON value for a script. "
        "Structured content, when present, is returned verbatim instead of this join."
    ),
    (
        "read_only_tools.py",
        "dispatch_target",
        "ifexp-empty",
        "inner if isinstance(inner, dict) else {}",
    ): (
        "Classification only: names the dispatcher's target for the write-policy check. "
        "The dispatcher call itself declares object arguments and rejects any other shape, "
        "so the substitute {} never reaches an upstream request."
    ),
    (
        "families/__init__.py",
        "_route_literals",
        "comprehension-filter",
        "isinstance(child, ast.Constant) and isinstance(child.value, str) and "
        "(id(child) not in docstrings) and (not any((c.isspace() for c in child.value)))",
    ): "parses this package's own source (route literals of the tool call graph), "
    "never upstream data",
    (
        "_spec_drift.py",
        "_copy_json.fresh",
        "ifexp-empty",
        "{} if isinstance(item, dict) else []",
    ): (
        "Container allocation for a lossless deep copy of a schema document: every dict "
        "key/list element is copied, shared and cyclic containers are re-linked; neither "
        "branch filters upstream records."
    ),
    (
        "_spec_drift.py",
        "_raw_changes",
        "ifexp-empty",
        "old if isinstance(old, list) else []",
    ): (
        "Spec-document structural diff, not a tool response: scalar/list replacements "
        "explicitly retain the parent path in changes."
    ),
    (
        "_spec_drift.py",
        "_raw_changes",
        "ifexp-empty",
        "new if isinstance(new, list) else []",
    ): (
        "Spec-document structural diff, not a tool response: scalar/list replacements "
        "explicitly retain the parent path in changes."
    ),
    (
        "_spec_drift.py",
        "_project_operation_contract",
        "if-skip",
        "not isinstance(raw, list)",
    ): "OpenAPI schema normalization, not a tool response: absent parameter arrays are omitted.",
    (
        "config.py",
        "MCPTransportSettings._split_csv",
        "if-skip",
        "v is None or (isinstance(v, str) and (not v.strip()))",
    ): (
        "Environment configuration: absent/blank OAuth CSV means unset; "
        "each present item is validated."
    ),
    (
        "families/connector/connector.py",
        "_twin_records",
        "comprehension-filter",
        (
            "isinstance(row, dict) and (same_id(device_id, row.get('_id')) or "
            "(isinstance(row.get('mac'), str) and row['mac'].lower() == wanted))"
        ),
    ): (
        "Device twin selection after object_records validates every source row; a missing "
        "device is reported in twinError and leaves noOp unknown. Malformed rows retain the "
        "original upstream body and report the shape in twinError."
    ),
    (
        "families/connector/connector.py",
        "connector_write",
        "ifexp-empty",
        "sorted(body) if isinstance(body, dict) else []",
    ): "Comparison field metadata from the caller's request body, not upstream response data.",
    (
        "argument_errors.py",
        "_type_label",
        "comprehension-filter",
        "isinstance(v, dict) and 'type' in v",
    ): NOT_UPSTREAM,
    (
        "families/protect/protect.py",
        "_resolve_camera_refs",
        "comprehension-filter",
        "isinstance(c.get('id'), str) and c.get('id')",
    ): (
        "ID field match eligibility after object_records validates every camera row; only "
        "non-empty string IDs can match an ID reference. Name-selected records have their "
        "native ID validated separately before use."
    ),
    (
        "families/protect/protect.py",
        "_resolve_camera_refs",
        "comprehension-filter",
        "isinstance(c.get('name'), str)",
    ): (
        "name field match eligibility after object_records validates every camera row; a "
        "non-string name cannot match a name reference. Name-selected records have their "
        "native ID validated separately before use."
    ),
    ("client.py", "object_records", "comprehension-filter", "not isinstance(item, dict)"): RAISES,
    ("client.py", "page_envelope", "if-skip", "not isinstance(page, dict)"): ENVELOPE,
    (
        "registry.py",
        "_host_labels",
        "ifexp-empty",
        "reported if isinstance(reported, dict) else {}",
    ): LABELS,
    (
        "matching.py",
        "tiered_name_matches",
        "comprehension-filter",
        "isinstance(label, str) and label",
    ): LOOKUP,
    ("registry.py", "_valid_site_choices", "if-skip", "not isinstance(site, dict)"): CHOICES,
    (
        "registry.py",
        "_host_mac_values",
        "ifexp-empty",
        "reported if isinstance(reported, dict) else {}",
    ): HOST_MACS,
    (
        "registry.py",
        "_host_mac_values",
        "ifexp-empty",
        "hardware if isinstance(hardware, dict) else {}",
    ): HOST_MACS,
    (
        "secret_scrub.py",
        "_env_secrets",
        "comprehension-filter",
        "isinstance(item, dict) and isinstance(item.get('key'), str)",
    ): NOT_UPSTREAM,
    (
        "secret_scrub.py",
        "configured_secrets",
        "comprehension-filter",
        "isinstance(v, str) and v.strip()",
    ): NOT_UPSTREAM,
    (
        "secret_scrub.py",
        "scrubbable",
        "comprehension-filter",
        "isinstance(s, str) and s.strip()",
    ): NOT_UPSTREAM,
    (
        "secret_scrub.py",
        "_scrub_format",
        "comprehension-filter",
        "isinstance(s, str)",
    ): NOT_UPSTREAM,
    (
        "spec_limits.py",
        "limit_problems",
        "if-skip",
        "value is None or (write_redaction_enabled() and isinstance(value, str) and "
        "(value == REDACTION_MASK))",
    ): NOT_UPSTREAM,
    (
        "shared_shapes/_pagination.py",
        "_single_page_envelope",
        "if-skip",
        "not isinstance(page, dict)",
    ): ENVELOPE,
    (
        "shared_shapes/_pagination.py",
        "_envelope_of",
        "ifexp-empty",
        "dict(envelope) if isinstance(envelope, dict) else {}",
    ): ENVELOPE,
    (
        "shared_shapes/_pagination.py",
        "verbatim_list_result",
        "ifexp-empty",
        "dict(raw) if isinstance(raw, dict) else {}",
    ): ENVELOPE,
    (
        "families/site_manager/aggregation.py",
        "_fleet_devices._one",
        "ifexp-empty",
        "dict(envelope) if isinstance(envelope, dict) else {}",
    ): ENVELOPE,
    (
        "families/site_manager/aggregation.py",
        "_get_all_host_site_pairs",
        "ifexp-empty",
        "reported if isinstance(reported, dict) else {}",
    ): LABELS,
    (
        "families/site_manager/aggregation.py",
        "_list_all_devices_fleet",
        "comprehension-filter",
        (
            "isinstance(d, dict) and str(d.get('status') or d.get('state'"
            ") or '').lower() == status_lower"
        ),
    ): FILTER,
    (
        "families/site_manager/aggregation.py",
        "_search_device",
        "comprehension-filter",
        "isinstance(d, dict)",
    ): FILTER,
    (
        "families/site_manager/aggregation.py",
        "_search_device",
        "ifexp-empty",
        "reported if isinstance(reported, dict) else {}",
    ): FILTER,
    (
        "families/site_manager/aggregation.py",
        "_search_device",
        "comprehension-filter",
        "isinstance(field, str)",
    ): FILTER,
    (
        "families/devices/device_mgmt.py",
        "_forget_device",
        "comprehension-filter",
        "not isinstance(m, str) or not _is_mac(m)",
    ): RAISES,
    (
        "families/network/network_services_proxy.py",
        "_resolve_profile_networkconf",
        "comprehension-filter",
        "isinstance(v, str) and v",
    ): ADDITIVE,
    (
        "families/network/network_services_proxy.py",
        "_mutate_port_profile_exclusion",
        "comprehension-filter",
        "isinstance(p, dict) and same_id(upstream_id, p.get('_id'))",
    ): LOOKUP,
    (
        "families/network/network_services_proxy.py",
        "annotate_auto_exclusions",
        "if-skip",
        "not isinstance(profile, dict)",
    ): ADDITIVE,
    (
        "families/network/network_services_proxy.py",
        "get_wlan_group",
        "comprehension-filter",
        "isinstance(g, dict)",
    ): LOOKUP,
    (
        "families/network/network_services_proxy.py",
        "list_rogue_aps",
        "comprehension-filter",
        "isinstance(ap, dict) and ap.get('is_rogue')",
    ): FILTER,
    (
        "families/innerspace/placement_snapshot.py",
        "_objects",
        "if-skip",
        "not isinstance(items, list)",
    ): SNAPSHOT_INPUT,
    (
        "families/innerspace/placement_snapshot.py",
        "_fingerprint_icon",
        "if-skip",
        "not isinstance(value, str)",
    ): LOOKUP,
    (
        "families/innerspace/placement_snapshot.py",
        "_topology_inventory",
        "if-skip",
        "not isinstance(source, list)",
    ): SNAPSHOT_INPUT,
    (
        "families/innerspace/placement_snapshot.py",
        "_list_records",
        "if-skip",
        "not isinstance(list_result, dict)",
    ): SNAPSHOT_INPUT,
    (
        "families/innerspace/placement_snapshot.py",
        "_project_snapshot",
        "ifexp-empty",
        "project if isinstance(project, dict) else {}",
    ): SNAPSHOT_INPUT,
    (
        "families/innerspace/placement_snapshot.py",
        "_project_snapshot",
        "ifexp-empty",
        "project_meta_raw if isinstance(project_meta_raw, dict) else {}",
    ): SNAPSHOT_INPUT,
    (
        "families/innerspace/placement_snapshot.py",
        "_project_snapshot",
        "comprehension-filter",
        "isinstance(result, dict) and context_value(result, 'incomplete')",
    ): SNAPSHOT_INPUT,
    (
        "families/protect/protect.py",
        "_resolve_camera_refs",
        "comprehension-filter",
        "isinstance(c, dict) and isinstance(c.get('name'), str)",
    ): LOOKUP,
    (
        "families/site_manager/site_manager.py",
        "_aggregate_lists_over_keys._fetch",
        "ifexp-empty",
        "dict(envelope) if isinstance(envelope, dict) else {}",
    ): ENVELOPE,
    (
        "families/site_manager/site_manager.py",
        "_tier_match",
        "comprehension-filter",
        "isinstance(w, str) and w",
    ): LOOKUP,
    (
        "families/site_manager/site_manager.py",
        "_tier_match",
        "comprehension-filter",
        "isinstance(value, str) and value",
    ): LOOKUP,
    (
        "families/site_manager/site_manager.py",
        "_console_site_choices",
        "comprehension-filter",
        "isinstance(s, dict)",
    ): CHOICES,
    (
        "write_body.py",
        "require_update_fields",
        "ifexp-empty",
        "clean if isinstance(clean, dict) else {}",
    ): NOT_UPSTREAM,
    (
        "write_body.py",
        "missing_required_keys",
        "if-skip",
        "not isinstance(body, dict)",
    ): NOT_UPSTREAM,
    (
        "catalog_descriptions.py",
        "install_compact_selector_descriptions",
        "if-skip",
        "not isinstance(parameters, dict)",
    ): NOT_UPSTREAM,
    (
        "secret_scrub.py",
        "_bound_values",
        "comprehension-filter",
        "isinstance(v, str) and v.strip()",
    ): SCRUB_VALUES,
    (
        "families/connector/connector.py",
        "_failed_write_result",
        "if-skip",
        "not isinstance(response, dict) or 'body' not in response",
    ): RELAY_ENVELOPES,
    (
        "families/network/network_clients_guests.py",
        "_write_client_target",
        "comprehension-filter",
        "isinstance(r.get('id'), str) and r.get('id')",
    ): LOOKUP,
    (
        "families/network/network_clients_guests.py",
        "_unrequestable_pages",
        "if-skip",
        "not isinstance(body, dict)",
    ): ADDITIVE_WARNING,
    (
        "families/network/network_clients_guests.py",
        "_sent_fields",
        "ifexp-empty",
        "body if isinstance(body, dict) else {}",
    ): NOT_UPSTREAM,
    (
        "families/network/network_dpi_policy.py",
        "_native_url",
        "comprehension-filter",
        "isinstance(n, str) and n",
    ): LOOKUP,
    (
        "families/network/network_mobile_wan.py",
        "_changes",
        "ifexp-empty",
        "clean if isinstance(clean, dict) else {}",
    ): NOT_UPSTREAM,
    (
        "families/network/network_nat_qos_traffic.py",
        "delete_qos_rule",
        "ifexp-empty",
        "[i for i in payload if isinstance(i, str)] if isinstance(payload, list) else []",
    ): CALLER_IDS,
    (
        "families/network/network_nat_qos_traffic.py",
        "delete_qos_rule",
        "comprehension-filter",
        "isinstance(i, str)",
    ): CALLER_IDS,
    (
        "families/network/network_routing_topology.py",
        "_listed_record",
        "comprehension-filter",
        "isinstance(row.get(field), str) and row[field]",
    ): CHOICES,
    (
        "families/network/network_security_diagnostics.py",
        "_records",
        "comprehension-filter",
        "isinstance(item, dict)",
    ): LOOKUP_RECORDS,
    (
        "families/network/network_security_diagnostics.py",
        "_vertices",
        "comprehension-filter",
        "isinstance(v, dict)",
    ): ADDITIVE,
    (
        "families/network/network_security_diagnostics.py",
        "_routers",
        "if-skip",
        "not isinstance(network, dict)",
    ): ADDITIVE,
    (
        "families/network/network_security_diagnostics.py",
        "_routers",
        "if-skip",
        "not isinstance(listed, list)",
    ): ADDITIVE,
    (
        "families/network/network_switching_power.py",
        "_target_id",
        "comprehension-filter",
        "isinstance(record.get(field), str) and record[field].lower() == wanted",
    ): LOOKUP,
    (
        "families/vpn/network_vpn_dns.py",
        "_select_users",
        "comprehension-filter",
        "isinstance(r.get('_id'), str)",
    ): LOOKUP,
    (
        "families/vpn/network_vpn_dns.py",
        "control_site_vpn",
        "comprehension-filter",
        "isinstance(params, dict) and k in params",
    ): NOT_UPSTREAM,
    (
        "families/protect/protect_automation_backup.py",
        "_known",
        "comprehension-filter",
        "isinstance(row, dict) and same_id(ident, row.get('id'))",
    ): LOOKUP,
    (
        "families/protect/protect_automation_backup.py",
        "_known",
        "comprehension-filter",
        "isinstance(row, dict) and isinstance(row.get('id'), str)",
    ): LOOKUP,
    (
        "families/protect/protect_private.py",
        "_resolve",
        "comprehension-filter",
        "isinstance(v.get('id'), str) and id_key(v['id']) == id_key(ref)",
    ): LOOKUP,
    (
        "families/protect/protect_private.py",
        "_resolve",
        "comprehension-filter",
        "isinstance(v.get('name'), str) and name_keys(v['name'])[tier] == target",
    ): LOOKUP,
    (
        "families/protect/protect_recognition_search.py",
        "_find_group",
        "comprehension-filter",
        "isinstance(g, dict) and isinstance(g.get('id'), str)",
    ): LOOKUP,
    (
        "families/protect/protect_users_assets.py",
        "_find",
        "comprehension-filter",
        "isinstance(r, dict) and isinstance(r.get('id'), str)",
    ): LOOKUP,
    (
        "families/protect/protect_users_assets.py",
        "set_protect_notifications_muted",
        "ifexp-empty",
        "before if isinstance(before, dict) else {}",
    ): MERGE_BASE,
    (
        "families/network/site_config.py",
        "_merge_config_body.keep",
        "ifexp-empty",
        "prior if isinstance(prior, dict) else {}",
    ): CALLER_MERGE,
    (
        "families/network/site_config.py",
        "_merge_config_body.keep",
        "ifexp-empty",
        "prior if isinstance(prior, list) else []",
    ): CALLER_MERGE,
    (
        "families/statistics/system_log.py",
        "_vpn_user_connection_log",
        "comprehension-filter",
        "value is not None and (not (isinstance(value, str) and (not value.strip())))",
    ): NOT_UPSTREAM,
    (
        "credential_providers.py",
        "_resolve",
        "comprehension-filter",
        "isinstance(item, dict) and isinstance(item.get('key'), str)",
    ): SCRUB_VALUES,
    (
        "shared_shapes/_incident_document.py",
        "network_identity",
        "if-skip",
        "not isinstance(ident, str)",
    ): (
        "identity extraction: only a string id can be an identifier (documented: names and "
        "other ids are skipped); the row itself is carried verbatim in the evidence record"
    ),
    (
        "shared_shapes/_incident_document.py",
        "protect_attributes",
        "comprehension-filter",
        "isinstance(t, str)",
    ): (
        "reported, not silent: a smartDetectTypes list with a non-string entry is named under "
        "the row's wrong-shape fields (len(detect) != len(types))"
    ),
}


def _isinstance_of(node: ast.AST, kinds: frozenset[str]) -> bool:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isinstance"
        and len(node.args) == 2
    ):
        return False
    target = node.args[1]
    elts = target.elts if isinstance(target, ast.Tuple) else [target]
    return any(isinstance(e, ast.Name) and e.id in kinds for e in elts)


def _negated_isinstance(node: ast.AST, kinds: frozenset[str]) -> bool:
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and _isinstance_of(node.operand, kinds)
    )


def _mentions_isinstance(node: ast.AST, kinds: frozenset[str]) -> bool:
    return any(_isinstance_of(sub, kinds) for sub in ast.walk(node))


def _empty(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, (ast.List, ast.Tuple)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _CONTAINERS
        and not node.args
    )


class _Finder(ast.NodeVisitor):
    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.stack: list[str] = []
        self.found: list[tuple[str, str, str, str, int]] = []

    def _add(self, node: ast.AST, kind: str) -> None:
        text = " ".join(ast.unparse(node).split())
        self.found.append((self.rel, ".".join(self.stack), kind, text, node.lineno))  # type: ignore[attr-defined]

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_IfExp(self, node: ast.IfExp) -> None:
        if (_isinstance_of(node.test, _CONTAINERS) and _empty(node.orelse)) or (
            _negated_isinstance(node.test, _CONTAINERS) and _empty(node.body)
        ):
            self._add(node, "ifexp-empty")
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        for cond in node.ifs:
            if _mentions_isinstance(cond, _FILTER_TYPES):
                self._add(cond, "comprehension-filter")
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if _mentions_isinstance(node.test, _FILTER_TYPES) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Continue) or (
                isinstance(first, ast.Return) and _empty(first.value)
            ):
                self._add(node.test, "if-skip")
        self.generic_visit(node)


def find_silent_filters() -> list[tuple[str, str, str, str, int]]:
    found: list[tuple[str, str, str, str, int]] = []
    for path in sorted(SRC.rglob("*.py")):  # every module, so a new one is covered
        finder = _Finder(str(path.relative_to(SRC)))
        finder.visit(ast.parse(path.read_text(encoding="utf-8")))
        found.extend(finder.found)
    return found


def test_every_silent_type_filter_is_classified():
    found = find_silent_filters()
    unclassified = [
        f"{rel}:{line} in {func or '<module>'} [{kind}]: {text}"
        for rel, func, kind, text, line in found
        if (rel, func, kind, text) not in ALLOWED
    ]
    assert unclassified == [], (
        "New silent type filter(s) over possibly-upstream data. Raise with the shape received "
        "(describe_shape), report a count under an explicit key, or classify the site in "
        "ALLOWED with its reason:\n  " + "\n  ".join(unclassified)
    )


def test_no_stale_allowlist_entries():
    present = Counter(
        (rel, func, kind, text) for rel, func, kind, text, _line in find_silent_filters()
    )
    stale = [key for key in ALLOWED if key not in present]
    assert stale == [], f"ALLOWED entries that no longer match any site: {stale}"


def test_every_allowlist_reason_is_given():
    assert all(isinstance(reason, str) and reason.strip() for reason in ALLOWED.values())


def test_the_lint_flags_each_silent_pattern():
    """The finder itself is under test: each silent form is flagged, a raise is not."""
    sample = """
def a(raw):
    return raw if isinstance(raw, list) else []
def b(rows):
    return [r for r in rows if isinstance(r, dict)]
def c(rows):
    for r in rows:
        if not isinstance(r, dict):
            continue
def d(x):
    if not isinstance(x, list):
        return []
def e(x):
    if not isinstance(x, list):
        raise ValueError(x)
"""
    finder = _Finder("sample.py")
    finder.visit(ast.parse(sample))
    assert sorted(f for _r, f, _k, _t, _l in finder.found) == ["a", "b", "c", "d"]
