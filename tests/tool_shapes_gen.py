"""Generate advisory MCP body shapes from pinned specs and traced requests.

Run python -m tests.tool_shapes_gen --write. No hand-maintained tool/route map.
Types are guidance: anyOf's empty branch accepts every JSON value. Spec unions,
enums, required keys and bounds are prose annotations, never refusal keywords.

The shape is bounded so the catalog stays small (tests/test_catalog_size_budget.py):
the body's top-level fields and one further level are real ``properties`` with a type
and a one-line spec note; anything deeper is summarised as a compact TypeScript-like
outline in the description (``{zoneId: string(uuid), trafficFilter?: ...}``), and a
discriminated union is listed once as its tag values and per-variant fields.

Every advertised property carries a description. A field the pinned spec leaves
undescribed takes, in order: the description of the component it references, its
union's tag values (for a discriminator tag), or its ``FIELD_NOTES`` entry. Generation
fails on a field none of these describe and on a ``FIELD_NOTES`` entry nothing uses.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import sys
import typing
from collections import Counter
from functools import cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from tests import spec_limits_gen as limits
from tests import test_spec_conformance as sc

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src/unifi_fabric/generated_api_facts/_tool_shapes_table.py"
# Real JSON-schema ``properties`` stop at this depth (body = 0); deeper is an outline.
PROPERTY_DEPTH = 1
REQUIRED_MARK = "\x00required"  # internal placeholder; never a spec value
# Once per shaped parameter: the pinned route stays in SHAPE_SOURCES, not on the wire.
ROOT_NOTE = "Advisory spec fields; any JSON passes."
NOTE_LIMIT = 100
ALL_TYPES = ["array", "boolean", "null", "number", "object", "string"]
QUIET_FORMATS = {"int32", "int64", "float", "double"}

# Body fields the pinned spec declares without a description, keyed by
# (service, body schema, field); the body schema is the request body's ``$ref``, or
# ``METHOD path`` for an inline body. A value starting with ``#/`` is a pointer to the
# same field's description elsewhere in that pinned spec; any other value is written
# from the field's spec semantics (its variant, type and bounds).
_DNS = "#/components/schemas/Create or update DNS policy"
_FIREWALL = "#/components/schemas/Create or update firewall policy"
_NETWORK = "#/components/schemas/Create or update Network"
_WIFI = "#/components/schemas/Wifi broadcast create or update"
FIELD_NOTES: dict[tuple[str, str, str], str] = {
    ("network", "#/components/schemas/ACL rule update", "enabled"): "Whether the rule is active.",
    ("network", "#/components/schemas/IntegrationDeviceAdoptionRequestDto", "ignoreDeviceLimit"): (
        "Whether to adopt even when the device limit is reached."
    ),
    ("network", "#/components/schemas/IntegrationDeviceAdoptionRequestDto", "macAddress"): (
        "MAC address of the device to adopt."
    ),
    ("network", "#/components/schemas/Patch firewall policy", "loggingEnabled"): (
        "#/components/schemas/Firewall policy/properties/loggingEnabled"
    ),
    ("network", _DNS, "domain"): "Domain name of the record, or the domain to forward.",
    ("network", _DNS, "enabled"): "Whether the policy is active.",
    ("network", _DNS, "ipv4Address"): "IPv4 address of the A record.",
    ("network", _DNS, "ipv6Address"): "IPv6 address of the AAAA record.",
    ("network", _DNS, "mailServerDomain"): "Mail server domain of the MX record.",
    ("network", _DNS, "port"): "Service port of the SRV record.",
    ("network", _DNS, "targetDomain"): "Target domain of the CNAME record.",
    ("network", _FIREWALL, "description"): "Policy description.",
    ("network", _FIREWALL, "enabled"): "Whether the policy is active.",
    ("network", _FIREWALL, "name"): "Policy name.",
    ("network", _NETWORK, "enabled"): "Whether the network is enabled.",
    ("network", _NETWORK, "name"): "Network name.",
    ("network", "#/components/schemas/Create or update traffic matching list", "name"): (
        "List name."
    ),
    ("network", _WIFI, "arpProxyEnabled"): "Whether the access point answers ARP for clients.",
    ("network", _WIFI, "bandSteeringEnabled"): "Whether capable clients are steered to 5 GHz.",
    ("network", _WIFI, "bssTransitionEnabled"): "Whether 802.11v BSS transition is enabled.",
    ("network", _WIFI, "clientIsolationEnabled"): "Whether clients are isolated from each other.",
    ("network", _WIFI, "enabled"): "Whether the broadcast is enabled.",
    ("network", _WIFI, "hideName"): "Whether the SSID is hidden.",
    ("network", _WIFI, "mloEnabled"): "Whether WiFi 7 Multi-Link Operation is enabled.",
    ("network", _WIFI, "multicastToUnicastConversionEnabled"): (
        "Whether multicast is converted to unicast."
    ),
    ("network", _WIFI, "name"): "Network name (SSID).",
    ("protect", "PATCH /v1/sensors/{id}", "hasCustomSensitivityWhenArmed"): (
        "#/components/schemas/sensorHasCustomSensitivityWhenArmed"
    ),
}


DESCRIPTION_OVERRIDES = {
    "Transaction time in epoch milliseconds.": (
        "Transaction time in epoch milliseconds; within the past 24 hours and no more than "
        "5 minutes in the future."
    ),
    "Mic volume: a number from 0-100.": "Mic volume: 1-100; mute with isMicEnabled.",
}


def resolve(spec: sc.Spec, raw: Any, seen: frozenset[str]) -> tuple[dict[str, Any], frozenset[str]]:
    node = raw if isinstance(raw, dict) else {}
    while "$ref" in node:
        ref = node["$ref"]
        if ref in seen:
            return {"description": "Recursive schema; arbitrary JSON accepted."}, seen
        seen = seen | {ref}
        siblings = {k: v for k, v in node.items() if k != "$ref"}
        node = {**sc._resolve(spec, node)[0], **siblings}
    return node, seen


def json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


# A period ending one of these is not a sentence end ("e.g. USD" stays whole).
ABBREVIATIONS = ("e.g.", "i.e.", "vs.", "cf.")


def note(text: Any) -> str:
    """The spec description's first sentence, on one line, capped."""
    line = " ".join(str(text or "").split())
    for match in re.finditer(r"(?<=[.!?])\s", line):
        if not line[: match.start()].lower().endswith(ABBREVIATIONS):
            line = line[: match.start()]
            break
    return line if len(line) <= NOTE_LIMIT else line[: NOTE_LIMIT - 1].rstrip() + "..."


def deprecated_note(node: dict[str, Any]) -> str:
    """The spec's whole text for a deprecated field: its effect is the point ("" if live)."""
    if node.get("deprecated") is not True:
        return ""
    text = " ".join(str(node.get("description") or "").split())
    return text if "deprecated" in text.lower() else f"Deprecated per spec. {text}".strip()


def narrowed_note(node: dict[str, Any], target: dict[str, Any]) -> str:
    """Bounds this field sets over the component it references ("" when it sets none)."""
    parts = [
        f"{key} {node[key]}"
        for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")
        if key in node and node[key] != target.get(key)
    ]
    return " This route narrows it: " + ", ".join(parts) + "." if parts else ""


def branches(node: dict[str, Any]) -> list[Any]:
    return [b for key in ("allOf", "anyOf", "oneOf") for b in node.get(key) or []]


def variants(spec: sc.Spec, node: dict[str, Any]) -> tuple[str | None, list[tuple[str, Any]]]:
    """(tag property, [(label, schema)]) of a discriminated or plain union."""
    disc = node.get("discriminator") or {}
    mapping = disc.get("mapping") or {}
    if mapping:
        tag = disc.get("propertyName")
        # Mapping keys identify subtypes; the property enum defines wire values.
        # Upstream uses e.g. TCP/AX_25 for tcp/ax.25. Resolve only unique matches.
        props, _ = fields(spec, node, frozenset(), with_variants=False)
        values = resolve(spec, *props[tag])[0].get("enum", []) if tag in props else []

        def normalized(value: Any) -> str:
            return re.sub(r"[^a-z0-9]", "", str(value).lower())

        alts = []
        for label, ref in mapping.items():
            sub, _ = fields(spec, {"$ref": ref}, frozenset(), with_variants=False)
            sub_values = resolve(spec, *sub[tag])[0].get("enum", []) if tag in sub else []
            choices = sub_values or values
            matches = [v for v in choices if normalized(v) == normalized(label)]
            if label not in choices and choices:
                assert len(matches) == 1, (tag, label, choices)
                label = matches[0]
            assert not values or label in values, (tag, label, values)
            assert not sub_values or label in sub_values, (tag, label, sub_values)
            alts.append((label, {"$ref": ref}))
        return tag, alts
    alts = [*(node.get("oneOf") or []), *(node.get("anyOf") or [])]
    return disc.get("propertyName"), [("", b) for b in alts]


def kinds(spec: sc.Spec, raw: Any, seen: frozenset[str]) -> list[str]:
    node, seen = resolve(spec, raw, seen)
    kind = node.get("type")
    if kind is not None:
        return sorted(kind) if isinstance(kind, list) else [kind]
    if "properties" in node:
        return ["object"]
    if "items" in node:
        return ["array"]
    found: set[str] = set()
    for branch in branches(node):
        found.update(kinds(spec, branch, seen))
    if not found and ("enum" in node or "const" in node):
        found = {json_type(v) for v in node.get("enum", [node.get("const")])}
    return sorted(found) or ALL_TYPES


def fields(
    spec: sc.Spec, raw: Any, seen: frozenset[str], *, with_variants: bool = True
) -> tuple[dict[str, Any], set[str]]:
    """Own + allOf properties (and, optionally, every variant's) with required names.

    Each value is ``(schema, seen)``; a name that variants declare differently becomes
    an ``anyOf`` of every declaration, so its advisory type is the union of them all.
    """
    found: dict[str, list[tuple[Any, frozenset[str]]]] = {}
    required = _collect(spec, raw, seen, found, with_variants)
    props: dict[str, Any] = {}
    for name, decls in found.items():
        unique = list({json.dumps(r, sort_keys=True): (r, s) for r, s in decls}.values())
        if len(unique) == 1:
            props[name] = unique[0]
            continue
        described = [resolve(spec, r, s)[0].get("description") for r, s in unique]
        merged: dict[str, Any] = {"anyOf": [r for r, _ in unique]}
        if any(described):
            merged["description"] = next(d for d in described if d)
        props[name] = (merged, frozenset.intersection(*(s for _, s in unique)))
    return props, required


def _collect(
    spec: sc.Spec,
    raw: Any,
    seen: frozenset[str],
    found: dict[str, list[tuple[Any, frozenset[str]]]],
    with_variants: bool,
) -> set[str]:
    node, seen = resolve(spec, raw, seen)
    required = set(node.get("required") or [])
    for name, child in (node.get("properties") or {}).items():
        found.setdefault(name, []).append((child, seen))
    # An allOf base's own discriminator lists this very variant among its siblings
    # (OpenAPI polymorphism), so a base contributes only its declared fields.
    for branch in node.get("allOf") or []:
        required |= _collect(spec, branch, seen, found, False)
    if with_variants:
        for _, branch in variants(spec, node)[1]:
            _collect(spec, branch, seen, found, True)
    return required


def lit(value: Any) -> str:
    """A literal for prose/outlines; single quotes avoid JSON-escaped double quotes."""
    return f"'{value}'" if isinstance(value, str) else json.dumps(value)


def enum_text(values: list[Any], sep: str) -> str:
    """Render every upstream enum value; advisory notes must never hide choices."""
    return sep.join(lit(v) for v in values)


def outline(spec: sc.Spec, raw: Any, seen: frozenset[str]) -> str:
    """A compact TypeScript-like rendering of the whole subtree (guidance only)."""
    node, seen = resolve(spec, raw, seen)
    if node.get("const") == REQUIRED_MARK:
        return "(required)"
    if "enum" in node:
        return enum_text(node["enum"], "|")
    if "const" in node:
        return lit(node["const"])
    tag, alts = variants(spec, node)
    if alts:
        common, required = fields(spec, node, seen, with_variants=False)
        # The mapped labels (in wire casing) are the only valid choices for the
        # tag, so a shared base enum that also lists unmapped values must not
        # re-advertise them next to the mapped subtypes.
        if tag and all(label for label, _ in alts):
            common.pop(tag, None)
            union = _tagged(spec, tag, alts, seen, common, required)
        else:
            members = (m for _, b in alts for m in _members(outline(spec, b, seen)))
            union = "|".join(dict.fromkeys(members))
        return f"{_object(spec, common, required)}&({union})" if common else union
    props, required = fields(spec, node, seen)
    if props:
        return _object(spec, props, required)
    if "items" in node:
        inner = outline(spec, node["items"], seen)
        return f"({inner})[]" if "|" in inner else f"{inner}[]"
    found = kinds(spec, node, seen)
    if found == ALL_TYPES:
        return "any"
    text = "|".join(k for k in found)
    fmt = node.get("format")
    return f"{text}({fmt})" if fmt and fmt not in QUIET_FORMATS else text


def _objects(text: str) -> list[tuple[int, int]]:
    """Balanced objects, enum expressions and formatted types outside literals."""
    stack: list[int] = []
    spans = []
    quoted = False
    for i, ch in enumerate(text):
        if ch == "'":
            quoted = not quoted
        elif not quoted and ch == "{":
            stack.append(i)
        elif not quoted and ch == "}":
            spans.append((stack.pop(), i + 1))
    # Repeated enum unions can differ only in their containing property's
    # required marker, so share their exact expression independently as well.
    for match in re.finditer(r"'[^']*'(?:\|'[^']*')+", text):
        spans.append(match.span())
        # Unions with different branch-specific values can still share a long
        # prefix or suffix. Union is associative, so factoring these is lossless.
        choices = list(re.finditer(r"'[^']*'", match.group()))
        spans.extend((match.start(), match.start() + choice.end()) for choice in choices)
        spans.extend((match.start() + choice.start(), match.end()) for choice in choices)
    literals = [match.span() for match in re.finditer(r"'[^']*'", text)]
    spans += [
        match.span()
        for match in re.finditer(r"\b(?:string|number|integer)\([\w-]+\)", text)
        if not any(start < match.start() < end for start, end in literals)
    ]
    return list(dict.fromkeys(spans))


def compact_outline(text: str) -> str:
    """Factor repeated subtrees into named definitions without dropping any guidance.

    The definitions are local to this outline. Only exact object subtrees, enum
    expressions and formatted types are shared; required markers stay intact.
    """
    definitions: dict[str, str] = {}
    while True:
        counts: Counter[str] = Counter()
        for source in [text, *definitions.values()]:
            counts.update(source[start:end] for start, end in _objects(source))
        alias = f"T{len(definitions) + 1}"
        savings = {
            obj: (count - 1) * len(obj) - (count + 1) * len(alias) - 8
            for obj, count in counts.items()
            if count > 1 and len(obj) >= 16
        }
        if not savings or max(savings.values()) <= 0:
            break
        target = max(savings, key=lambda obj: (savings[obj], obj))

        def replace(source: str, target: str = target, alias: str = alias) -> str:
            matches = [
                (start, end) for start, end in _objects(source) if source[start:end] == target
            ]
            for start, end in sorted(matches, reverse=True):
                source = source[:start] + alias + source[end:]
            return source

        text = replace(text)
        definitions = {name: replace(body) for name, body in definitions.items()}
        definitions[alias] = target
    if definitions:
        text += " where " + ";".join(f"{name}={body}" for name, body in definitions.items())
    return text


def _tagged(
    spec: sc.Spec,
    tag: str,
    alts: list[tuple[str, Any]],
    seen: frozenset[str],
    common: dict[str, Any],
    required: set[str],
) -> str:
    """``{tag:'A',a:T}|{tag:'B'|'C'}``; fields every variant shares are hoisted.

    A hoisted field that only some variants require stays listed in those variants
    as ``name:(required)`` so the hoisting loses no required-key guidance.
    """
    subs = []
    for label, branch in alts:
        sub, req = fields(spec, branch, seen)
        tag_field = sub.pop(tag, None)
        if tag_field is not None:
            declared = outline(spec, *tag_field)
            labels = {lit(value) for value, _ in alts}
            if (
                declared not in {"any", "string", lit(label)}
                and not set(_members(declared)) >= labels
                and (tag not in common or declared != outline(spec, *common[tag]))
            ):
                sub[tag] = tag_field
        # A base declaration can be unconstrained (for example radiusConfiguration),
        # while a variant gives it a type, nested required keys or enum choices.
        # Elide only identical outlines, preserving conditional requiredness too.
        for name in common.keys() & sub.keys():
            if outline(spec, *sub[name]) == outline(spec, *common[name]):
                del sub[name]
                if name in req and name not in required:
                    sub[name] = ({"const": REQUIRED_MARK}, frozenset())
        subs.append((label, sub, req))
    if len(subs) > 1:
        first = subs[0][1]
        for name in list(first):
            if name in common:
                continue
            text = outline(spec, *first[name])
            if all(name in sub and outline(spec, *sub[name]) == text for _, sub, _ in subs):
                common[name] = first[name]
                if all(name in req for _, _, req in subs):
                    required.add(name)
                for _, sub, req in subs:
                    del sub[name]
                    if name in req and name not in required:
                        sub[name] = ({"const": REQUIRED_MARK}, frozenset())
    rendered = [
        (
            "{" + f"{tag}:{lit(label)}" + "}&" + _object(spec, sub, req)
            if tag in sub
            else "{" + f"{tag}:{lit(label)}," + _object(spec, sub, req)[1:]
        )
        for label, sub, req in subs
        if sub
    ]
    bare = sorted(lit(label) for label, sub, _ in subs if not sub)
    if bare:
        rendered.append("{" + f"{tag}:" + "|".join(bare) + "}")
    return "|".join(rendered)


def _object(spec: sc.Spec, props: dict[str, Any], required: set[str]) -> str:
    parts = [
        f"{name}{'' if name in required else '?'}:{outline(spec, raw, seen)}"
        for name, (raw, seen) in sorted(props.items())
    ]
    return "{" + ",".join(parts) + "}"


def _members(text: str) -> list[str]:
    """Split an outline at its top-level ``|`` (outside brackets and strings)."""
    out, depth, start, quoted = [], 0, 0, False
    for i, ch in enumerate(text):
        if ch == "'":
            quoted = not quoted
        elif not quoted and ch in "({[":
            depth += 1
        elif not quoted and ch in ")}]":
            depth -= 1
        elif not quoted and ch == "|" and depth == 0:
            out.append(text[start:i])
            start = i + 1
    return [*out, text[start:]]


def advisory(
    spec: sc.Spec,
    raw: Any,
    name: str,
    seen: frozenset[str] = frozenset(),
    depth: int = 0,
    *,
    owner: str = "",
    used: set[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    """A universally accepting schema carrying the spec's structural guidance.

    ``owner`` names the body schema (see ``FIELD_NOTES``); ``used`` collects the
    ``FIELD_NOTES`` keys that described a field.
    """
    node, seen = resolve(spec, raw, seen)
    found = kinds(spec, node, seen)
    out: dict[str, Any] = {"anyOf": [{"type": found[0] if len(found) == 1 else found}, {}]}
    description = deprecated_note(node) or note(node.get("description") or node.get("title"))
    notes = [DESCRIPTION_OVERRIDES.get(description, description)]
    if "enum" in node:
        notes.append("One of: " + enum_text(node["enum"], ", ") + ".")
    props, required = fields(spec, node, seen)
    tag, alts = variants(spec, node)
    structured = bool(props or alts or "items" in node)
    if depth >= PROPERTY_DEPTH or (depth and not props and structured and "items" not in node):
        if structured:
            shape = compact_outline(outline(spec, node, seen))
            if owner == _FIREWALL and name in {"destination", "source", "ipProtocolScope"}:
                # Bare enum tokens are strings; preserve every value and structural marker.
                shape = re.sub(r"(?<!type:)'([A-Za-z0-9_.-]+)'", r"\1", shape)
                legend = "bare enum values are strings"
                if name == "ipProtocolScope":
                    for field, alias in (
                        ("protocolFilter", "P"),
                        ("matchOpposite", "M"),
                        ("ipVersion", "V"),
                        ("typenameFilter", "T"),
                    ):
                        shape = shape.replace(field + ":", alias + ":").replace(
                            field + "?:", alias + "?:"
                        )
                    legend += "; P=protocolFilter, M=matchOpposite, V=ipVersion, T=typenameFilter"
                notes.append(f"Shape ({legend}): " + shape)
            else:
                notes.append("Shape: " + shape)
    else:
        if required:
            notes.append("Required: " + ", ".join(sorted(required)) + ".")
        if tag and alts:
            notes.append(f"Variants by {tag}: " + "; ".join(variant_notes(spec, node, seen)) + ".")
        if props:
            labels = [label for label, _ in alts]
            out["properties"] = {}
            for prop, (child, child_seen) in sorted(props.items()):
                shaped = advisory(spec, child, prop, child_seen, depth + 1, owner=owner, used=used)
                if not shaped.get("description"):
                    tags = labels if prop == tag and all(labels) else []
                    text = fallback_note(spec, child, child_seen, (owner, prop), tags, used)
                    if text:
                        shaped["description"] = text
                out["properties"][prop] = shaped
            out["additionalProperties"] = True
        elif "items" in node:
            item = advisory(
                spec, node["items"], f"{name} item", seen, depth, owner=owner, used=used
            )
            if item.get("properties") or item.get("description"):
                out["items"] = item
    text = " ".join(n for n in dict.fromkeys(notes) if n)
    if text:
        out["description"] = text
    return out


def fallback_note(
    spec: sc.Spec,
    raw: Any,
    seen: frozenset[str],
    where: tuple[str, str],
    tags: list[str],
    used: set[tuple[str, str, str]] | None,
) -> str:
    """A description for a field the pinned spec declares without one ("" if none).

    In order: the description of the component the field references (directly or as
    an ``allOf`` member), the tag values of the union the field discriminates, or the
    field's ``FIELD_NOTES`` entry (a spec pointer or a note from its spec semantics).
    """
    node, seen = resolve(spec, raw, seen)
    for branch in node.get("allOf") or []:
        target = resolve(spec, branch, seen)[0]
        text = note(target.get("description"))
        if text:
            return text + narrowed_note(node, target)
    if tags:
        return "Variant tag; one of: " + enum_text(tags, ", ") + "."
    key = (spec.service, *where)
    entry = FIELD_NOTES.get(key)
    if entry is None:
        return ""
    if used is not None:
        used.add(key)
    if not entry.startswith("#/"):
        return entry
    target: Any = spec.doc
    for part in entry[2:].split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    text = note(resolve(spec, target, frozenset())[0].get("description"))
    assert text, f"FIELD_NOTES pointer has no description: {entry}"
    return text


def undescribed(schema: Any, path: str = "") -> list[str]:
    """Paths of properties without a description, at every depth of a schema."""
    out: list[str] = []
    if isinstance(schema, list):
        for item in schema:
            out += undescribed(item, path)
    elif isinstance(schema, dict):
        for prop, sub in (schema.get("properties") or {}).items():
            if not isinstance(sub, dict) or not str(sub.get("description") or "").strip():
                out.append(f"{path}.{prop}")
            out += undescribed(sub, f"{path}.{prop}")
        for key in ("items", "additionalProperties", "anyOf", "oneOf", "allOf"):
            out += undescribed(schema.get(key), path)
    return out


def variant_notes(spec: sc.Spec, node: dict[str, Any], seen: frozenset[str]) -> list[str]:
    """``LABEL (requires a, b; optional c)`` per variant of a top-level union.

    ``requires`` is every key the variant's spec ``required`` lists name beyond the
    body's common Required keys (and the tag); ``optional`` is the variant's other own
    fields. A bare label adds no field and requires nothing beyond the common keys.
    """
    tag, alts = variants(spec, node)
    common, base = fields(spec, node, seen, with_variants=False)
    out = []
    for label, branch in alts:
        sub, req = fields(spec, branch, seen)
        needs = sorted(req - base - {tag})
        extra = sorted(k for k in sub if k not in common and k != tag and k not in needs)
        parts = [f"requires {', '.join(needs)}"] if needs else []
        if extra:
            parts.append(f"optional {', '.join(extra)}" if needs else ", ".join(extra))
        out.append(f"{label} ({'; '.join(parts)})" if parts else label)
    return out


@cache
def derive() -> tuple[dict[str, Any], dict[str, Any]]:
    """Inventory every catalog object parameter; trace bodies to pinned operations."""
    table: dict[str, Any] = {}
    inventory: dict[str, Any] = {}
    used: set[tuple[str, str, str]] = set()
    manifest = json.loads((sc.OPENAPI_DIR / "manifest.json").read_text())
    for name, tool in sorted(sc._tools().items()):
        args = sc.conformance_args(name)
        for arg, prop in tool.parameters.get("properties", {}).items():
            if "object" not in limits._tool_types(prop):
                continue
            key = f"{name}.{arg}"
            if key == "update_device_radio.radios":
                from unifi_fabric.families.devices.device_radios import RadioChanges

                fixture = "tests/fixtures/recorded/ap_radio_table.json"
                captured = (ROOT / fixture).read_bytes()
                record = json.loads(captured)
                rows = record["body"]["data"][0]["radio_table"]
                fields = sorted(RadioChanges.model_fields)
                assert all(set(fields) <= set(row) for row in rows)
                inventory[key] = {
                    "classification": "recorded-typed",
                    "file": fixture,
                    "sha256": hashlib.sha256(captured).hexdigest(),
                    "path": record["request"]["path"],
                    "method": record["request"]["method"],
                    "pointer": "#/body/data/0/radio_table",
                    "bands": sorted(row["radio"] for row in rows),
                    "fields": fields,
                }
                # Already typed by the handler; advisory installation would loosen it.
                continue
            model = handler_model(tool, arg)
            if model is not None:
                # Typed by the handler's own pydantic model (its fields are the schema's
                # properties); advisory installation would loosen it.
                inventory[key] = {
                    "classification": "handler-typed",
                    "model": f"{model.__module__}.{model.__qualname__}",
                }
                continue
            inventory[key] = {"classification": "free-form"}
            if name in limits.RELAY_TOOLS:
                continue
            value = args.get(arg)
            if not isinstance(value, dict) or not value:
                continue
            for req in sc.captured_all()[name]:
                if req.resolution:
                    continue
                hit = limits._op_for(req)
                if hit is None:
                    continue
                spec, path, parts, _ = hit
                raw = limits._body_schema(spec, parts["op"])
                body = limits._request_body(req)
                if not isinstance(body, dict) or not all(
                    body.get(k) == v for k, v in value.items()
                ):
                    continue
                owner = raw.get("$ref") or f"{req.method} {path}"
                shape = advisory(spec, raw, arg, owner=owner, used=used)
                if not shape.get("properties"):
                    continue
                marker = {"surfaceShapeProbe": {"marker": "body-trace"}}
                traced = limits._rerun(name, {**args, arg: {**value, **marker}})
                if not any(
                    r.method == req.method
                    and limits._op_for(r) is not None
                    and limits._op_for(r)[1] == path
                    and isinstance(limits._request_body(r), dict)
                    and limits._request_body(r).get("surfaceShapeProbe")
                    == marker["surfaceShapeProbe"]
                    for r in traced
                ):
                    raise AssertionError(f"Body trace failed: {key}")
                source = {
                    "classification": "shaped",
                    "service": spec.service,
                    "file": manifest[spec.service]["file"],
                    "sha256": manifest[spec.service]["file_sha256"],
                    "source_url": manifest[spec.service]["source_url"],
                    "path": path,
                    "method": req.method,
                    "pointer": body_pointer(spec, parts["op"], path, req.method),
                    "schema": raw,
                }
                if inventory[key]["classification"] == "shaped":
                    assert inventory[key] == source, f"Multiple body shapes: {key}"
                inventory[key] = source
                shape["description"] = ROOT_NOTE + (
                    " " + shape["description"] if shape.get("description") else ""
                )
                table.setdefault(name, {})[arg] = shape
    missing = [
        f"{tool}.{arg}{path}"
        for tool, args in table.items()
        for arg, shape in args.items()
        for path in undescribed(shape)
    ]
    assert missing == [], f"Undescribed spec fields (add FIELD_NOTES entries): {missing}"
    stale = sorted(set(FIELD_NOTES) - used)
    assert stale == [], f"FIELD_NOTES entries no shaped field uses: {stale}"
    return table, inventory


def handler_model(tool: Any, arg: str) -> type[BaseModel] | None:
    """The pydantic model the tool function annotates ``arg`` with (``X`` or ``X | None``)."""
    fn = inspect.unwrap(tool.fn)
    annotation = typing.get_type_hints(fn).get(arg)
    for candidate in (annotation, *typing.get_args(annotation)):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def body_pointer(spec: sc.Spec, op: dict[str, Any], path: str, method: str) -> str:
    """JSON pointer (within the pinned spec file) of the operation's JSON body schema."""
    rb = op["requestBody"]
    escaped = path.replace("~", "~0").replace("/", "~1")
    base = rb.get("$ref") or f"#/paths/{escaped}/{method.lower()}/requestBody"
    pointer = f"{base}/content/application~1json/schema"
    target: Any = spec.doc
    for part in pointer.lstrip("#/").split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    assert target == limits._body_schema(spec, op), pointer
    return pointer


def render(table: dict[str, Any], inventory: dict[str, Any]) -> str:
    return (
        '"""GENERATED by python -m tests.tool_shapes_gen --write; do not edit."""\n'
        "from __future__ import annotations\n\n"
        "# ruff: noqa: E501 - generated spec descriptions\nfrom typing import Any\n\n"
        f"TOOL_SHAPES: dict[str, Any] = {table!r}\n\n"
        f"SHAPE_SOURCES: dict[str, Any] = {inventory!r}\n"
    )


def require_clean_environment() -> None:
    """Refuse to derive a partial catalog from ambient server settings."""
    if any(key.startswith(("UNIFI_", "MCP_", "FASTMCP_")) for key in os.environ):
        raise RuntimeError("ambient server settings must be cleared before generating shapes")


if __name__ == "__main__":
    require_clean_environment()
    table, inventory = derive()
    if "--write" in sys.argv:
        OUTPUT.write_text(render(table, inventory))
    print(json.dumps(inventory, indent=2, sort_keys=True))
