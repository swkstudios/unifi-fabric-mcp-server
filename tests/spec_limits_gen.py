"""Derive the spec-limit table (``src/unifi_fabric/generated_api_facts/_spec_limits_table.py``) from the
vendored OpenAPI specs.

Every tool is run once through the shape-faithful fake upstream with valid arguments
(``tests/test_spec_conformance.py``). For each request that reaches a published spec
operation, the value constraints of its path / query parameters and request body
(``minimum`` / ``maximum`` / ``exclusiveMinimum`` / ``exclusiveMaximum`` / ``minLength`` /
``maxLength`` / ``pattern`` / ``enum`` (``const`` included) / ``minItems`` / ``maxItems``) are
mapped back to the tool argument that carries the value:

* a scalar or list argument named like the parameter / top-level body property
  (``snake_case`` of the wire name, or :data:`ALIASES`), CONFIRMED by tracing: the tool is
  re-run with a constraint-valid probe value and the probe must arrive at exactly that
  place in the request (an argument that is only name-alike never gets a limit);
* an object argument whose value IS the request body (every key the caller passed arrives
  at the body's top level with the same value): the whole body schema's constraints, at
  any depth (properties, array items, ``allOf``; ``anyOf`` / ``oneOf`` kept as
  alternatives, a value failing only when it fails every alternative).

Limits a spec states only in prose apply exactly like keyword limits: a parameter's in
:data:`DESCRIBED_LIMITS`, a schema property's (reached through any request body, by every
tool whose body carries it) in :data:`DESCRIBED_SCHEMA_LIMITS`, each with the exact
sentence it comes from (asserted present). Every limit-like sentence of a request-side
description (:func:`prose_limit_candidates`) has a disposition in
:data:`PROSE_LIMIT_DISPOSITIONS` (applied as a keyword, applied from prose here, applied by
the tool, or why it is not a value limit), so a prose limit is never silently skipped.
Length limits the spec applies AFTER trimming are left out of the table
(:data:`TRIMMED_LENGTH_ARGS`): a raw-length check would refuse values the upstream
accepts, so the tool checks the trimmed value itself.

Regenerate with ``python -m tests.spec_limits_gen --write`` (then ``ruff format``);
``tests/test_spec_limits.py`` fails while the committed table differs.
"""

from __future__ import annotations

import json
import re
import sys
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

from tests import test_spec_conformance as sc

TABLE_PATH = Path(__file__).resolve().parents[1] / "src" / "unifi_fabric" / "_spec_limits_table.py"

#: These logical requested-count arguments have a positive local domain even though
#: their upstream limit schemas permit zero. Preserve those upstream schema facts.
LOGICAL_PAGINATION_COUNT_ARGS = frozenset(
    (name, "limit")
    for name in (
        "list_acl_rules",
        "list_clients",
        "list_countries",
        "list_dns_policies",
        "list_dpi_applications",
        "list_dpi_categories",
        "list_firewall_policies",
        "list_firewall_zones_proxy",
        "list_hotspot_vouchers",
        "list_integration_device_tags",
        "list_lags",
        "list_local_sites",
        "list_mc_lag_domains",
        "list_networks",
        "list_pending_devices",
        "list_radius_profiles",
        "list_site_devices",
        "list_site_to_site_tunnels",
        "list_switch_stacks",
        "list_traffic_matching_lists",
        "list_vpn_servers",
        "list_wan_interfaces",
        "list_wifi_broadcasts",
    )
)

#: The value keywords a limit is made of (``const`` is folded into ``enum``).
VALUE_KEYWORDS = (
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "enum",
    "minItems",
    "maxItems",
)

#: The generic connector relays forward a caller-chosen path and body: which operation
#: (and so which limits) applies is the caller's choice, and the upstream validates it.
RELAY_TOOLS = frozenset(
    {
        "fabric_connector_get",
        "fabric_connector_post",
        "fabric_connector_put",
        "fabric_connector_patch",
        "fabric_connector_delete",
    }
)

#: (tool, wire parameter name) -> tool argument, where the argument is not named after the
#: parameter.
ALIASES: dict[tuple[str, str], str] = {
    ("relay_activate_output", "outputId"): "output_id",
    ("alarm_hub_trigger_output", "outputId"): "output_id",
}

#: Arguments the tool converts before sending (so the wire limit does not bind the
#: argument as given): {(tool, argument): reason}. Asserted to still be derived candidates.
TRANSFORMED_ARGS: dict[tuple[str, str], str] = {
    (tool, "mode"): "case-insensitive and stripped; normalized to '2D' / '3D' (and validated "
    "against them) before it is sent"
    for tool in ("get_innerspace_project", "get_innerspace_summary", "list_innerspace_devices")
}

#: String arguments whose ``minLength`` / ``maxLength`` the spec counts AFTER trimming:
#: {(tool, argument): (service, schema name, property, exact sentence of the property's
#: description)}. The raw-length keywords are dropped from the table (the tool validates
#: the trimmed length itself); the sentence is asserted present in the pinned spec.
TRIMMED_LENGTH_ARGS: dict[tuple[str, str], tuple[str, str, str, str]] = {
    ("update_carrier_subscriber", "subscriber_number"): (
        "carrier-fabric",
        "SubscriberPatch",
        "subscriberNumber",
        "A value is 1-32 characters after trimming.",
    ),
}
_LENGTH_KEYWORDS = ("minLength", "maxLength")

#: Limits stated only in prose: {(tool, argument): (limit, (service, path template,
#: parameter name, exact sentence of the parameter's spec description))}.
DESCRIBED_LIMITS: dict[tuple[str, str], tuple[dict[str, Any], tuple[str, str, str, str]]] = {
    ("ptz_patrol_start", "slot"): (
        {"minimum": 0, "maximum": 4},
        (
            "protect",
            "/v1/cameras/{id}/ptz/patrol/start/{slot}",
            "slot",
            "The slot number (0-4) of the patrol",
        ),
    ),
    ("ptz_goto_preset", "slot"): (
        {"minimum": -1},
        (
            "protect",
            "/v1/cameras/{id}/ptz/goto/{slot}",
            "slot",
            "Which slot this preset belongs to (-1 home preset, >=0 other presets).",
        ),
    ),
    ("relay_activate_output", "output_id"): (
        {"maximum": 1},
        ("protect", "/v1/relays/{id}/outputs/{outputId}/activate", "outputId", "(0 or 1)"),
    ),
    ("alarm_hub_trigger_output", "output_id"): (
        {"maximum": 1},
        ("protect", "/v1/alarm-hubs/{id}/outputs/{outputId}/trigger", "outputId", "(0 or 1)"),
    ),
}


#: Limits stated only in a schema property's prose (no value keyword), applied wherever
#: the schema is reached: {(service, JSON pointer of the property schema): (limit, exact
#: sentence of its description)}.
DESCRIBED_SCHEMA_LIMITS: dict[tuple[str, str], tuple[dict[str, Any], str]] = {
    ("protect", "#/components/schemas/humiditySettings/properties/highThreshold"): (
        {"minimum": 1, "maximum": 99},
        "Humidity high level threshold from 1 to 99 (%).",
    ),
    ("protect", "#/components/schemas/lightSettings/properties/highThreshold"): (
        {"minimum": 1, "maximum": 503192},
        "Ambient light interrupt threshold high level from 1 to 503192 (Lux).",
    ),
    ("protect", "#/components/schemas/temperatureSettings/properties/highThreshold"): (
        {"minimum": -39, "maximum": 124},
        "Temperature high level threshold from -39 to 124 (C).",
    ),
}

_KEYWORD = "keyword: the schema states the same limit as a value keyword (in the table)"
_BYTES = (
    "tool: carrier_fabric._validate_bytes (a UTF-8 byte count, which the character-based "
    "maxLength keyword cannot express)"
)
_METADATA = "tool: carrier_fabric._validate_metadata (serialized JSON, UTF-8 bytes)"

#: Every limit-like sentence of a request-side description, by (service, location), and
#: how it is applied (or why it is not a value limit). ``tests/test_spec_limits_prose.py``
#: fails on a candidate missing here and on an entry no longer a candidate.
PROSE_LIMIT_DISPOSITIONS: dict[tuple[str, str], str] = {
    ("carrier-fabric", "#/components/schemas/SubscriberCreate/properties/email"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberCreate/properties/name"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberCreate/properties/notes"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberCreate/properties/serviceAddress"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberPatch/properties/email"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberPatch/properties/name"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberPatch/properties/notes"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberPatch/properties/serviceAddress"): _BYTES,
    ("carrier-fabric", "#/components/schemas/SubscriberCreate/properties/metadata"): _METADATA,
    ("carrier-fabric", "#/components/schemas/SubscriberPatch/properties/metadata"): _METADATA,
    ("carrier-fabric", "#/components/schemas/SubscriberCreate/properties/subscriberNumber"): (
        _KEYWORD
    ),
    ("carrier-fabric", "#/components/schemas/SubscriberPatch/properties/subscriberNumber"): (
        "trimmed: TRIMMED_LENGTH_ARGS (1-32 after trimming, checked by the tool)"
    ),
    ("carrier-fabric", "GET /v1/carrier/subscribers param limit"): _KEYWORD,
    ("mobility", "#/components/schemas/UpdateDeviceNameReq/properties/name"): _KEYWORD,
    ("mobility", "GET /v1/mobility/workspaces/{workspaceID}/devices param limit"): (
        "not a limit: 'Capped at 200' is what the upstream serves, not a value it rejects"
    ),
    (
        "mobility",
        "GET /v1/mobility/workspaces/{workspaceID}/devices/{deviceID}/clients param limit",
    ): ("not a limit: 'Capped at 200' is what the upstream serves, not a value it rejects"),
    ("network", "#/components/schemas/Create or update Network/properties/vlanId"): (
        "keyword (1-4009); the '1 for the default network, >= 2 for additional networks' "
        "rule depends on which network is the default, which only the controller knows"
    ),
    ("protect", "#/components/schemas/glassBreakSettings/properties/sensitivity"): _KEYWORD,
    ("protect", "#/components/schemas/glassBreakSettings/properties/sensitivityWhenArmed"): (
        _KEYWORD
    ),
    ("protect", "#/components/schemas/humiditySettings/properties/lowThreshold"): _KEYWORD,
    ("protect", "#/components/schemas/humiditySettings/properties/highThreshold"): (
        "described: DESCRIBED_SCHEMA_LIMITS"
    ),
    ("protect", "#/components/schemas/lightDeviceSettings/properties/ledLevel"): _KEYWORD,
    ("protect", "#/components/schemas/lightDeviceSettings/properties/pirSensitivity"): _KEYWORD,
    ("protect", "#/components/schemas/lightSettings/properties/lowThreshold"): _KEYWORD,
    ("protect", "#/components/schemas/lightSettings/properties/highThreshold"): (
        "described: DESCRIBED_SCHEMA_LIMITS"
    ),
    ("protect", "#/components/schemas/motionSettings/properties/sensitivity"): _KEYWORD,
    ("protect", "#/components/schemas/motionSettings/properties/sensitivityWhenArmed"): _KEYWORD,
    ("protect", "#/components/schemas/temperatureSettings/properties/lowThreshold"): _KEYWORD,
    ("protect", "#/components/schemas/temperatureSettings/properties/highThreshold"): (
        "described: DESCRIBED_SCHEMA_LIMITS"
    ),
    ("protect", "#/components/schemas/micVolume"): _KEYWORD,
    ("protect", "#/components/schemas/speakerVolume"): _KEYWORD,
    ("protect", "#/components/schemas/speakerMicVolume"): _KEYWORD,
    ("protect", "#/components/schemas/sirenVolume"): _KEYWORD,
    ("protect", "#/components/schemas/posTransactionRequest/properties/timestamp"): (
        "not a static limit: 'within the last 24 hours and no more than 5 minutes ahead of "
        "server time' is relative to the console's clock, which only the upstream knows"
    ),
    ("protect", "POST /v1/alarm-hubs/{id}/outputs/{outputId}/trigger param outputId"): (
        "described: DESCRIBED_LIMITS"
    ),
    ("protect", "POST /v1/relays/{id}/outputs/{outputId}/activate param outputId"): (
        "described: DESCRIBED_LIMITS"
    ),
    ("protect", "POST /v1/cameras/{id}/ptz/goto/{slot} param slot"): "described: DESCRIBED_LIMITS",
    ("protect", "POST /v1/cameras/{id}/ptz/patrol/start/{slot} param slot"): (
        "described: DESCRIBED_LIMITS"
    ),
    ("site-manager", "GET /v1/isp-metrics/{type} param endTimestamp"): (
        "not a limit: 'up to' describes the window end, a timestamp"
    ),
}

#: A limit-like phrase in a description.
PROSE_LIMIT_RE = re.compile(
    r"\(\s*-?\d+\s*(?:-|\u2013|to|or)\s*-?\d+\s*\)|\b\d+\s*-\s*\d+\s*(?:characters\b|%)"
    r"|\bnumber from -?\d+\s*-\s*-?\d+|\b(?:at most|at least|must not exceed|no more than"
    r"|up to|capped at|limit is|must be (?:an? )?(?:integer )?from)\b|\b(?:between|from) -?\d+ "
    r"(?:and|to) -?\d+\b|>=\s*-?\d+|<=\s*-?\d+|\b\d+\s*limit\b",
    re.I,
)


def _pointer_target(spec: sc.Spec, pointer: str) -> Any:
    node: Any = spec.doc
    for part in pointer.lstrip("#/").split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


@cache
def _described_by_id() -> dict[int, dict[str, Any]]:
    """id(schema node) -> its prose limit (:data:`DESCRIBED_SCHEMA_LIMITS`)."""
    out: dict[int, dict[str, Any]] = {}
    for (service, pointer), (limit, sentence) in DESCRIBED_SCHEMA_LIMITS.items():
        node = _pointer_target(sc.specs()[service], pointer)
        assert sentence in str(node.get("description", "")), (service, pointer)
        out[id(node)] = limit
    return out


def _walk_prose(spec: sc.Spec, node: Any, where: str, out: dict[str, str], seen: frozenset) -> None:
    if isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if ref in seen:
            return
        seen = seen | {ref}
        where = ref
        node = sc._resolve(spec, node)[0]
    if not isinstance(node, dict):
        return
    text = node.get("description")
    if isinstance(text, str) and PROSE_LIMIT_RE.search(text):
        out.setdefault(where, " ".join(text.split()))
    for name, sub in (node.get("properties") or {}).items():
        _walk_prose(spec, sub, f"{where}/properties/{name}", out, seen)
    for key in ("items", "additionalProperties"):
        if isinstance(node.get(key), dict):
            _walk_prose(spec, node[key], f"{where}/{key}", out, seen)
    for key in ("allOf", "anyOf", "oneOf"):
        for index, sub in enumerate(node.get(key) or []):
            _walk_prose(spec, sub, f"{where}/{key}/{index}", out, seen)


def prose_limit_candidates() -> dict[tuple[str, str], str]:
    """Every request-side description (operation parameters and request-body schemas, at
    any depth) with a limit-like phrase: {(service, location): description}."""
    out: dict[tuple[str, str], str] = {}
    for service, spec in sc.specs().items():
        found: dict[str, str] = {}
        for path, item in spec.doc["paths"].items():
            for method, op in item.items():
                if method not in ("get", "post", "put", "patch", "delete"):
                    continue
                for raw in [*(item.get("parameters") or []), *(op.get("parameters") or [])]:
                    p = sc._resolve(spec, raw)[0]
                    schema = sc._resolve(spec, p.get("schema") or {})[0]
                    for text in (p.get("description"), schema.get("description")):
                        if isinstance(text, str) and PROSE_LIMIT_RE.search(text):
                            key = f"{method.upper()} {path} param {p.get('name')}"
                            found.setdefault(key, " ".join(text.split()))
                body = op.get("requestBody")
                if body:
                    body = sc._resolve(spec, body)[0]
                    for media in (body.get("content") or {}).values():
                        where = f"{method.upper()} {path} body"
                        _walk_prose(spec, media.get("schema") or {}, where, found, frozenset())
        for key, text in found.items():
            out[(service, key)] = text
    return out


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _deref(spec: sc.Spec, node: Any) -> Any:
    seen = 0
    while isinstance(node, dict) and "$ref" in node:
        node = sc._resolve(spec, node)[0]
        seen += 1
        if seen > 50:
            raise RuntimeError("$ref chain too deep")
    return node


def fragment(spec: sc.Spec, schema: Any, depth: int = 0) -> dict[str, Any]:
    """The limit fragment of one schema (value keywords + properties/items/anyOf), {} when
    it constrains nothing."""
    if depth > 12:
        return {}
    schema = _deref(spec, schema)
    if not isinstance(schema, dict):
        return {}
    out: dict[str, Any] = {}
    for key in VALUE_KEYWORDS:
        if key in schema and not isinstance(schema[key], bool):
            out[key] = schema[key]
    for key, value in _described_by_id().get(id(schema), {}).items():
        out.setdefault(key, value)
    if "const" in schema:
        out["enum"] = [schema["const"]]
    # OpenAPI 3.0 boolean exclusives -> the numeric (2020-12) form
    for flag, bound in (("exclusiveMinimum", "minimum"), ("exclusiveMaximum", "maximum")):
        if schema.get(flag) is True and bound in out:
            out[flag] = out.pop(bound)
    if "enum" in out:
        out["enum"] = [v for v in out["enum"] if v is not None]
        if not out["enum"]:
            del out["enum"]
        elif schema.get("type") == "integer" and all(
            isinstance(v, str) and re.fullmatch(r"-?[0-9]+", v) for v in out["enum"]
        ):
            # Some upstream schemas declare integers with decimal-string enums.
            # Preserve the published forms and accept their declared integer forms too.
            out["integerEnum"] = True
    if out.get("minItems") == 0:
        del out["minItems"]  # vacuous
    if out.get("minLength") == 0:
        del out["minLength"]  # vacuous
    props: dict[str, Any] = {}
    for branch in schema.get("allOf") or []:
        sub = fragment(spec, branch, depth + 1)
        for key, value in sub.items():
            if key == "properties":
                props.update(value)
            else:
                out.setdefault(key, value)
    for name, sub_schema in (schema.get("properties") or {}).items():
        sub = fragment(spec, sub_schema, depth + 1)
        if sub:
            props[name] = sub
    if props:
        out["properties"] = props
    if "items" in schema:
        items = fragment(spec, schema["items"], depth + 1)
        if items:
            out["items"] = items
    alternatives = [*(schema.get("anyOf") or []), *(schema.get("oneOf") or [])]
    if alternatives:
        frags = _alternative_fragments(spec, alternatives, depth)
        if all(f and set(f) == {"enum"} for f in frags):
            merged = [v for f in frags for v in f["enum"]]
            out["enum"] = merged
        elif any(frags):
            # an alternative with no constraint accepts every value: nothing to check
            if all(frags):
                out["anyOf"] = frags
    return out


def _alternative_fragments(spec: sc.Spec, alternatives: list[Any], depth: int) -> list[Any]:
    """The fragments of ``anyOf`` / ``oneOf`` alternatives. When the alternatives are of
    different JSON types (``removedQualities``: an array or a scalar), each constraining
    alternative carries its own ``type``: value keywords bind only values of their own
    type, so without it the array alternative (``minItems`` / ``items``) would accept every
    scalar, and a scalar breaking the scalar alternative would pass."""
    frags = [fragment(spec, alt, depth + 1) for alt in alternatives]
    kinds = []
    for alt in alternatives:
        own = _deref(spec, alt)
        kinds.append(own.get("type") if isinstance(own, dict) else None)
    if len({k for k in kinds if isinstance(k, str)}) > 1:
        frags = [
            {"type": kind, **frag} if frag and isinstance(kind, str) else frag
            for frag, kind in zip(frags, kinds, strict=True)
        ]
    return frags


def _tool_types(prop: dict[str, Any]) -> set[str]:
    types = {prop.get("type")} | {b.get("type") for b in prop.get("anyOf", [])}
    return {t for t in types if isinstance(t, str)}


def _spec_types(spec: sc.Spec, schema: Any) -> set[str]:
    schema = _deref(spec, schema) or {}
    t = schema.get("type")
    out = set(t) if isinstance(t, list) else ({t} if t else set())
    for alt in [*(schema.get("anyOf") or []), *(schema.get("oneOf") or [])]:
        out |= _spec_types(spec, alt)
    return {x for x in out if x != "null"}


def accept_value(frag: dict[str, Any]) -> Any:
    """A value satisfying ``frag`` at its boundary (or None when none can be derived)."""
    if "anyOf" in frag:
        for alt in frag["anyOf"]:
            value = accept_value(alt)
            if value is not None:
                return value
        return None
    if "enum" in frag:
        return frag["enum"][0]
    if "minimum" in frag or "maximum" in frag or "exclusiveMinimum" in frag:
        if "minimum" in frag:
            return frag["minimum"]
        if "exclusiveMinimum" in frag:
            return frag["exclusiveMinimum"] + 1
        return frag["maximum"]
    if "items" in frag or "minItems" in frag:
        item = accept_value(frag.get("items", {}))
        if item is None:
            return None
        return [item] * max(1, frag.get("minItems", 1))
    if "minLength" in frag or "maxLength" in frag or "pattern" in frag:
        n = max(1, frag.get("minLength", 1))
        for ch in ("a", "A", "0"):
            value = ch * n
            if "pattern" not in frag or re.search(frag["pattern"], value):
                return value
        return None
    return None


def _as_tool_type(value: Any, tool_prop: dict[str, Any]) -> Any:
    types = _tool_types(tool_prop)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and "string" in types:
        if not types & {"integer", "number"}:
            return str(value)
    return value


def _op_for(req: sc.Request) -> tuple[sc.Spec, str, dict[str, Any], dict[str, str]] | None:
    fam, inner = sc.route(req.path)
    if fam.startswith("unspecced:") or fam == "unknown":
        return None
    cands = [sc.specs()[s] for s in sc.DIRECT_SPECS] if fam == "direct" else [sc.specs()[fam]]
    for spec in cands:
        hit = sc._match(spec, inner)
        if hit:
            item = spec.doc["paths"][hit[0]]
            op = item.get(req.method.lower())
            if op is None:
                return None
            return spec, hit[0], {"item": item, "op": op}, hit[1]
    return None


def _params(spec: sc.Spec, item: dict[str, Any], op: dict[str, Any]) -> list[dict[str, Any]]:
    out = {}
    for raw in [*item.get("parameters", []), *op.get("parameters", [])]:
        p = sc._resolve(spec, raw)[0]
        out[(p["name"], p["in"])] = p
    return list(out.values())


def _body_schema(spec: sc.Spec, op: dict[str, Any]) -> Any:
    rb = op.get("requestBody")
    if not rb:
        return None
    rb = sc._resolve(spec, rb)[0]
    return ((rb.get("content") or {}).get("application/json") or {}).get("schema")


def _top_properties(spec: sc.Spec, schema: Any) -> dict[str, Any]:
    schema = _deref(spec, schema) or {}
    out: dict[str, Any] = {}
    for branch in schema.get("allOf") or []:
        out.update(_top_properties(spec, branch))
    out.update(schema.get("properties") or {})
    return out


def _request_body(req: sc.Request) -> Any:
    if not req.content or not req.content_type.startswith("application/json"):
        return None
    try:
        return json.loads(req.content)
    except ValueError:
        return None


def _is_target_request(tool: str, request: sc.Request) -> bool:
    """Distinguish a tool's collection from shared host/site resolution reads."""
    # This Network collection is also the site's resolution route. Its own tool
    # must retain the limits from network-11.0.97.json:10300 (GET /v1/sites).
    return not request.resolution or (
        tool == "list_local_sites"
        and request.method == "GET"
        and sc.route(request.path) == ("network", "/v1/sites")
    )


def _arrived(
    tool: str, requests: list[sc.Request], where: tuple[str, str, str], probe: Any
) -> bool:
    """True when ``probe`` reached the parameter / body property ``where`` of an operation."""
    template, loc, name = where
    for req in requests:
        if not _is_target_request(tool, req):
            continue
        hit = _op_for(req)
        if hit is None or hit[1] != template:
            continue
        if loc == "path" and hit[3].get(name) == str(probe):
            return True
        if loc == "query":
            sent = [v for k, v in parse_qsl(req.query, keep_blank_values=True) if k == name]
            want = [
                str(p).lower() if isinstance(p, bool) else str(p)
                for p in (probe if isinstance(probe, list) else [probe])
            ]
            if sent == want or (len(sent) == 1 and sent[0] == ",".join(want)):
                return True
        if loc == "body":
            body = _request_body(req)
            if isinstance(body, dict) and name in body:
                got = body[name]
                if got == probe or str(got) == str(probe):
                    return True
    return False


def _rerun(tool: str, args: dict[str, Any]) -> list[sc.Request]:
    import asyncio
    import logging

    import pytest

    from tests import tool_args
    from tests import upstream_harness as uh
    from unifi_fabric import server

    upstream = sc.CapturingUpstream()
    logging.disable(logging.CRITICAL)
    try:
        with pytest.MonkeyPatch.context() as mp:
            for k, v in tool_args.TOOL_ENV.get(tool, {}).items():
                mp.setenv(k, v)
            uh.install(mp, upstream)
            try:
                asyncio.run(server.mcp.call_tool(tool, args))
            except Exception:  # noqa: S110 - a probe that fails simply did not arrive
                pass
    finally:
        logging.disable(logging.NOTSET)
    return upstream.requests


@cache
def derive() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """(table, report): ``table[tool][arg]`` is the limit fragment. ``report`` lists the
    name-alike candidates left out, by reason: ``untraced`` (the probe value did not arrive
    where the name suggests), ``type_converted`` (see :func:`_typed`) and ``transformed``
    (:data:`TRANSFORMED_ARGS`)."""
    from unifi_fabric import server  # noqa: F401 - registry import side effects

    table: dict[str, dict[str, Any]] = {}
    untraced: dict[str, list[str]] = {}
    converted: dict[str, list[str]] = {}
    transformed: set[tuple[str, str]] = set()
    trimmed: set[tuple[str, str]] = set()
    tools = sc._tools()
    for name in sc._lz_TOOL_NAMES():
        if name in RELAY_TOOLS:
            continue
        requests = sc.captured_all()[name]
        if sc.classify(requests) != "specced":
            continue
        props = (tools[name].parameters or {}).get("properties", {})
        args = sc.conformance_args(name)
        scalar: dict[str, tuple[dict[str, Any], tuple[str, str, str]]] = {}
        whole: dict[str, dict[str, Any]] = {}
        for req in requests:
            if not _is_target_request(name, req):
                continue
            hit = _op_for(req)
            if hit is None:
                continue
            spec, template, parts, _values = hit
            for p in _params(spec, parts["item"], parts["op"]):
                frag = fragment(spec, p.get("schema", {}))
                arg = ALIASES.get((name, p["name"])) or snake(p["name"])
                if frag and arg in props:
                    frag = _typed(frag, props[arg], _spec_types(spec, p.get("schema", {})))
                    if frag is None:
                        converted.setdefault(name, []).append(arg)
                    else:
                        scalar.setdefault(arg, (frag, (template, p["in"], p["name"])))
            body_schema = _body_schema(spec, parts["op"])
            if body_schema is None:
                continue
            for prop, sub in _top_properties(spec, body_schema).items():
                frag = fragment(spec, sub)
                arg = ALIASES.get((name, prop)) or snake(prop)
                if frag and arg in props and "object" not in _tool_types(props[arg]):
                    frag = _typed(frag, props[arg], _spec_types(spec, sub))
                    if frag is None:
                        converted.setdefault(name, []).append(arg)
                    else:
                        scalar.setdefault(arg, (frag, (template, "body", prop)))
            body = _request_body(req)
            if isinstance(body, dict):
                for arg, value in args.items():
                    if (
                        isinstance(value, dict)
                        and value
                        and "object" in _tool_types(props.get(arg, {}))
                        and all(k in body and body[k] == v for k, v in value.items())
                    ):
                        frag = fragment(spec, body_schema)
                        if frag:
                            whole.setdefault(arg, frag)
        limits: dict[str, Any] = dict(whole)
        for arg, (frag, where) in sorted(scalar.items()):
            if (name, arg) in TRANSFORMED_ARGS:
                transformed.add((name, arg))
                continue
            probe = accept_value({k: v for k, v in frag.items() if k != "integerString"})
            if (name, arg) in LOGICAL_PAGINATION_COUNT_ARGS and probe == 0:
                # Trace the valid local count; keep the upstream minimum-zero fragment.
                probe = 1
            if probe is None:
                untraced.setdefault(name, []).append(f"{arg}: no derivable probe for {frag}")
                continue
            requests2 = _rerun(name, {**args, arg: _as_tool_type(probe, props[arg])})
            if _arrived(name, requests2, where, probe):
                if (name, arg) in TRIMMED_LENGTH_ARGS:
                    trimmed.add((name, arg))
                    frag = {k: v for k, v in frag.items() if k not in _LENGTH_KEYWORDS}
                if frag:
                    limits[arg] = frag
            else:
                untraced.setdefault(name, []).append(f"{arg} -> {where[1]} {where[2]}")
        for (tool, arg), (frag, _cite) in DESCRIBED_LIMITS.items():
            if tool == name:
                limits[arg] = {**limits.get(arg, {}), **frag}
        if limits:
            table[name] = dict(sorted(limits.items()))
    return table, {
        "untraced": untraced,
        "type_converted": converted,
        "transformed": sorted(f"{t}.{a}" for t, a in transformed),
        "trimmed": sorted(f"{t}.{a}" for t, a in trimmed),
    }


def _typed(
    frag: dict[str, Any], tool_prop: dict[str, Any], spec_types: set[str]
) -> dict[str, Any] | None:
    """``frag`` for an argument of the tool's own type, or None when the tool converts the
    value's type before sending (a boolean argument sent as the string ``"true"`` /
    ``"false"``): the wire limit then constrains the tool's output, not its input.

    An integer sent from a string argument (``output_id`` "0" -> path integer 0) keeps the
    limit with ``integerString`` (the string must be a decimal integer), also when the
    argument accepts the integer itself (``int | str``)."""
    tool_types = _tool_types(tool_prop) - {"null"}
    if not spec_types or not tool_types:
        return frag
    numeric_spec = {"integer", "number"} & spec_types
    if "string" in tool_types and numeric_spec and "string" not in spec_types:
        return {**frag, "integerString": True}
    if tool_types & spec_types:
        return frag
    if {"integer", "number"} & spec_types and {"integer", "number"} & tool_types:
        return frag  # both numeric (an integer argument for a number field, or the reverse)
    if "string" in tool_types and spec_types & {"integer", "number"}:
        return {**frag, "integerString": True}
    return None


def render(table: dict[str, dict[str, Any]]) -> str:
    return (
        '"""GENERATED by ``python -m tests.spec_limits_gen --write`` from the vendored OpenAPI\n'
        "specs (tests/fixtures/openapi/); do not edit by hand. See\n"
        ":mod:`unifi_fabric.spec_limits`.\n"
        '"""\n\n'
        "from __future__ import annotations\n\n"
        "from typing import Any\n\n"
        f"SPEC_LIMITS: dict[str, dict[str, dict[str, Any]]] = {table!r}\n"
    )


if __name__ == "__main__":
    table, report = derive()
    if "--write" in sys.argv:
        TABLE_PATH.write_text(render(table), encoding="utf-8")
    print(json.dumps({"tools": len(table), **report}, indent=1))
    if "--show" in sys.argv:
        print(json.dumps(table, indent=1))
