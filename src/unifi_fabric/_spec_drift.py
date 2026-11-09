"""Spec-drift audit: published UniFi OpenAPI contracts vs. what we last recorded.

The target console rides the Early-Access / weekly-auto-update channel, so the per-app
UniFi APIs move constantly. Ubiquiti publishes machine-readable contracts at
``developer.ui.com/{service}/{version}/openapi.json`` behind a root index at
``developer.ui.com/llms.txt``. Today nothing detects when one of those contracts moves;
we only find out when a tool breaks or when someone manually re-reads the docs.

This module holds the **pure, hermetic** comparison logic so it can run in CI with no
network and no credentials — the same split the ``_catalog_audit`` precedent
uses: pure diff logic here, live I/O in ``scripts/check_spec_drift.py``.

The unit of comparison is a :class:`SpecSnapshot`: the set of published services, each
service's published *version* and its ``METHOD /path`` endpoint set (every endpoint
carrying a resolved-schema *signature* so a same-path contract change is detectable), plus
the versions those apps are actually running on the deployment. A run diffs the freshly
fetched snapshot against the committed baseline and reports, per service:

* **VERSION_DRIFT** — published version differs from the recorded baseline.
* **CONSOLE_GAP** — the console runs a version other than the published contract (e.g.
  Network publishes ``10.4.57`` while the deployment runs a higher build such as ``10.5.x`` — the
  deployment is *ahead* of the documented contract).
* **NEW endpoint** — a ``METHOD /path`` present now but absent from the baseline: a
  capability we could add. Elevated when it is a write method or lands on a service whose
  coverage we track (e.g. the day InnerSpace grows a write route).
* **CHANGED endpoint** — same ``METHOD /path``, different signature: a contract change and
  a field-level diff. Breaking schema changes are elevated regardless of coverage.
* **REMOVED endpoint** — in the baseline, gone now: a breakage risk. Elevated when we
  implement it.
* **NEW_SERVICE / REMOVED_SERVICE** — a family appearing in (or vanishing from) the root
  index. A new trackable family (Access / Talk / Connect / Drive / Identity, or any other)
  triggers the product's build-from-spec directive.

Comparing the fetched snapshot against a *committed* baseline (rather than against our
live tool set on every run) is deliberate: it means drift is reported once, when it
happens, and not re-reported every run — the baseline is advanced with
``--update-baseline`` after a run is reviewed. The optional per-service *coverage* overlay
(:data:`SPEC_COVERAGE`) is what ties a changed/removed endpoint back to "…and we
implement it, so this is breakage, not just news".

Closed-world compatibility contract: SUPPORTED_KEYWORDS is mechanically derived from
all schema positions in the pinned Ubiquiti specs. Those keywords receive full
request/response directional semantics. A changed schema containing any other keyword
fails safe as CHANGED with breakage=True and an actionable needs_review JSON pointer.
Unresolved references, changed recursive regions and unsupported dialects require breaking review.
The regeneration test fails when Ubiquiti adds a keyword; supporting its directional
semantics is then required before advancing the pinned set.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy as _deepcopy
from dataclasses import dataclass, field

#: Root catalog that lists every published service, its current version, and its
#: ``openapi.json`` URL. Watching this (not just per-service versions) is what surfaces a
#: brand-new family the first day it publishes an API.
ROOT_INDEX_URL = "https://developer.ui.com/llms.txt"

#: HTTP methods that mutate state. A NEW endpoint using one of these is elevated: this event
#: is a product directive — report when a read-only family (e.g. InnerSpace) grows a write
#: route.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Per-service coverage overlay: the ``METHOD /path`` endpoints our tools actually
#: implement, keyed by the service slug used in the root index. Declared here so a
#: CHANGED / REMOVED endpoint we depend on is flagged as *breakage* (not merely news) and
#: a NEW endpoint on a covered service is flagged as an unimplemented capability.
#:
#: InnerSpace is declared in full — its published v1.3.23 surface is exactly six GET
#: endpoints, all read-only, and our five list/get tools plus ``get_innerspace_project``
#: cover every one. Services without an entry here are still fully drift-checked (version,
#: new/changed/removed endpoints, new-service); they simply are not yet annotated with an
#: implemented/unimplemented verdict. Extend this map as typed coverage is added.
SPEC_COVERAGE: dict[str, frozenset[str]] = {
    "innerspace": frozenset(
        {
            "GET /v1/project",
            "GET /v1/floor_plans",
            "GET /v1/access_points",
            "GET /v1/switches",
            "GET /v1/inventory",
            "GET /v1/assets/{planId}/{filename}",
        }
    ),
}

# A markdown link in llms.txt whose target ends in ``/openapi.json``. The URL carries the
# service slug and the ``vX.Y.Z`` version, e.g.
#   - [Network OpenAPI Spec](https://developer.ui.com/network/v10.4.57/openapi.json): ...
_OPENAPI_LINK_RE = re.compile(
    r"\]\((?P<url>https://developer\.ui\.com/(?P<service>[^/]+)/v(?P<version>[^/]+)/openapi\.json)\)"
)

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})


def parse_root_index(text: str) -> dict[str, tuple[str, str]]:
    """Parse ``llms.txt`` into ``{service_slug: (version, openapi_url)}``.

    Only lines advertising an ``openapi.json`` are taken, so the result is exactly the set
    of families that currently publish a machine-readable contract. A family that appears
    here but not in the baseline is a new trackable service; one that drops out is a
    removed service.

    Raises ``ValueError`` when no OpenAPI spec links are found at all, so a fetch that
    silently returned an error page (or a reshaped index) fails loud rather than looking
    like "every service disappeared".
    """
    found: dict[str, tuple[str, str]] = {}
    for match in _OPENAPI_LINK_RE.finditer(text):
        service = match.group("service").strip().lower()
        version = match.group("version").strip()
        url = match.group("url").strip()
        # First occurrence wins; the index lists each spec once under "OpenAPI
        # Specifications" but may also reference the URL elsewhere.
        found.setdefault(service, (version, url))
    if not found:
        raise ValueError(
            "no OpenAPI spec links found in root index — expected at least one "
            "'.../{service}/v{version}/openapi.json' link; the index may be an error page "
            "or its shape changed"
        )
    return found


_EXAMPLE_ANNOTATIONS = frozenset({"example", "examples"})
# OpenAPI maps whose members are user-chosen names. An entry named ``example``
# in one of these maps is a schema/property name, not an annotation.
_EXAMPLE_NAME_MAPS = frozenset(
    {
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentRequired",
        "schemas",
        "parameters",
        "responses",
        "headers",
        "content",
        "paths",
        "requestBodies",
        "securitySchemes",
        "variables",
        "mapping",
    }
)
_EXAMPLE_LITERAL_VALUES = frozenset({"enum", "const", "default"})


def strip_example_annotations(value: object, parent_key: str | None = None) -> object:
    """Project an OpenAPI document without non-semantic sample payloads.

    Published specs can put arbitrary values in ``example`` / ``examples`` annotations.
    They do not participate in validation or drift compatibility, but committing them
    can leak credential-shaped or device-shaped sample material. Preserve every schema
    and semantic literal while removing those annotation payloads. Name maps and
    enum/const/default values remain literal data, so a property named ``example`` and
    an enum object containing that key are never mistaken for annotations.

    Iterate rather than recurse: public specs can legitimately exceed Python's recursion
    limit through nested Link Objects or schema property maps.
    """
    if not isinstance(value, (Mapping, list)):
        return value
    root: object = {} if isinstance(value, Mapping) else []
    pending: list[tuple[object, object, str | None]] = [(value, root, parent_key)]
    while pending:
        source, target, context = pending.pop()
        if isinstance(source, Mapping) and isinstance(target, dict):
            in_name_map = context in _EXAMPLE_NAME_MAPS
            for key, child in source.items():
                if not in_name_map and key in _EXAMPLE_ANNOTATIONS:
                    continue
                literal = not in_name_map and key in _EXAMPLE_LITERAL_VALUES
                if isinstance(child, Mapping) and not literal:
                    copied: object = {}
                    target[key] = copied
                    pending.append((child, copied, str(key)))
                elif isinstance(child, list) and not literal:
                    copied = []
                    target[key] = copied
                    pending.append((child, copied, str(key)))
                else:
                    target[key] = child
        elif isinstance(source, list) and isinstance(target, list):
            for child in source:
                if isinstance(child, Mapping):
                    copied = {}
                    target.append(copied)
                    pending.append((child, copied, None))
                elif isinstance(child, list):
                    copied = []
                    target.append(copied)
                    pending.append((child, copied, None))
                else:
                    target.append(child)
    return root


# Schema annotations never affect compatibility. Mapping containers retain property names
# such as "description" and "examples"; enum/const/default values remain literal JSON.
_ANNOTATIONS = frozenset({"description", "summary", "example", "examples", "title", "externalDocs"})
_SCHEMA_MAPS = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
)


def _json(value: object) -> str:
    """Canonical JSON value equality, including nested numeric literals.

    JSON Schema equates numbers by value (1 == 1.0), while booleans and
    strings retain distinct JSON types. Canonicalize before both comparison
    and hashing so enum/const/default and raw-document checks agree.
    """

    def canonical(item: object) -> object:
        if isinstance(item, float) and item.is_integer():
            return int(item)
        if isinstance(item, Mapping):
            return {key: canonical(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [canonical(child) for child in item]
        return item

    return json.dumps(canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _copy_json(value: object) -> object:
    """Copy nested JSON containers without recursion (deepcopy overflows past ~500 levels).

    Shared and cyclic containers are copied once and re-linked, as with deepcopy.
    Non-container leaves are immutable JSON scalars; anything else is deep-copied.
    """
    if not isinstance(value, (dict, list)):
        return value if isinstance(value, (str, int, float, bool, type(None))) else _deepcopy(value)
    memo: dict[int, object] = {}

    def fresh(item: object) -> tuple[object, bool]:
        if isinstance(item, (dict, list)):
            if id(item) in memo:
                return memo[id(item)], False
            copied: object = {} if isinstance(item, dict) else []
            memo[id(item)] = copied
            return copied, True
        if isinstance(item, (str, int, float, bool, type(None))):
            return item, False
        return _deepcopy(item), False

    root, _ = fresh(value)
    pending: list[tuple[object, object]] = [(value, root)]
    while pending:
        source, target = pending.pop()
        if isinstance(source, dict) and isinstance(target, dict):
            for key, child in source.items():
                copied, new = fresh(child)
                target[key] = copied
                if new:
                    pending.append((child, copied))
        elif isinstance(source, list) and isinstance(target, list):
            for child in source:
                copied, new = fresh(child)
                target.append(copied)
                if new:
                    pending.append((child, copied))
    return root


def _strip_examples(value: object) -> object:
    """Remove OpenAPI example annotations before retaining a public snapshot."""
    copied = _copy_json(value)
    pending: list[tuple[object, str | None]] = [(copied, None)]
    while pending:
        node, parent_key = pending.pop()
        if isinstance(node, dict):
            in_name_map = parent_key in _EXAMPLE_NAME_MAPS
            for key in list(node):
                if not in_name_map and key in _EXAMPLE_ANNOTATIONS:
                    del node[key]
                    continue
                pending.append((node[key], key))
        elif isinstance(node, list):
            pending.extend((child, None) for child in node)
    return copied


def _reference_target(ref: object, document: Mapping) -> object:
    """Read one JSON Pointer edge; schema references must retain their own siblings."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError(f"unsupported OpenAPI reference: {ref!r}")
    target: object = document
    try:
        for part in ref[2:].split("/"):
            if re.search(r"~(?![01])", part):
                raise ValueError("invalid pointer escape")
            key = part.replace("~1", "/").replace("~0", "~")
            if isinstance(target, Mapping):
                target = target[key]
            elif isinstance(target, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", key):
                    raise ValueError("invalid array index")
                target = target[int(key)]
            else:
                raise KeyError(key)
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError(f"unresolved OpenAPI reference: {ref!r}") from exc
    return target


class _ReferenceReviewError(ValueError):
    """Carry the contract position when a Reference Object cannot be expanded."""

    def __init__(self, pointer: str, reason: str) -> None:
        super().__init__(f"{pointer}/$ref needs_review: {reason}")


_REVIEW_MARKER = "_spec_drift_needs_review"
# Normalization depth (one unit per nested schema/map/list position). Pure
# "$ref" -> "$ref" links are followed iteratively and do not consume depth.
# Identical regions at or beyond the bound are clean; the marker is a breaking
# fail-safe only when the compared regions differ (see _review_reasons) and the
# raw-document net catches differences the bound hides.
_SCHEMA_DEPTH_BOUND = 128
_DEPTH_BOUND_REASON = "schema expansion depth bound reached"
_DEEP_NESTING_REASON = "nesting exceeds the comparison depth; review manually"
_RAW_REVIEW_MARKER = "_spec_drift_raw_schema_review"
# Explicit dialect recognition is separate from the pinned keyword inventory.
_SUPPORTED_DIALECTS = frozenset(
    {
        "http://json-schema.org/draft-04/schema",
        "http://json-schema.org/draft-06/schema",
        "http://json-schema.org/draft-07/schema",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema",
        "https://spec.openapis.org/oas/3.1/dialect/base",
    }
)
_LEGACY_DIALECTS = frozenset(dialect for dialect in _SUPPORTED_DIALECTS if "/draft-" in dialect)


def _known_dialect(value: object) -> bool:
    return isinstance(value, str) and value.rstrip("#") in _SUPPORTED_DIALECTS


def _resolve_object(
    value: object,
    document: Mapping,
    trail: tuple[str, ...] = (),
    *,
    path_item: bool = False,
    pointer: str = "#",
) -> object:
    """Expand non-schema Reference Objects, rejecting unresolved contracts."""
    overrides = []
    seen = set(trail)
    while isinstance(value, Mapping) and "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str):
            raise _ReferenceReviewError(pointer, f"unsupported OpenAPI reference: {ref!r}")
        if ref in seen:
            raise _ReferenceReviewError(pointer, f"cyclic OpenAPI reference: {ref!r}")
        seen.add(ref)
        try:
            target = _reference_target(ref, document)
        except ValueError as exc:
            raise _ReferenceReviewError(pointer, str(exc)) from exc
        if not isinstance(target, Mapping):
            raise _ReferenceReviewError(pointer, f"OpenAPI reference is not an object: {ref!r}")
        if path_item:
            overrides.append({k: v for k, v in value.items() if k != "$ref"})
        elif not str(document.get("openapi", "")).startswith("3.0"):
            overrides.append({k: v for k, v in value.items() if k in {"summary", "description"}})
        value = target
    for override in reversed(overrides):
        if isinstance(value, Mapping):
            value = {**value, **override}
    return value


# Only these positions contain subschemas. Everything else is literal JSON, including
# dependentRequired and discriminator.mapping, whose keys can be annotation names.
_SCHEMA_SINGLE = frozenset(
    {
        "items",
        "additionalItems",
        "contains",
        "additionalProperties",
        "unevaluatedProperties",
        "unevaluatedItems",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "contentSchema",
    }
)
_SCHEMA_ARRAYS = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})

# Enumerated from all schema positions in the six baseline-pinned specs,
# including unused components. The pinned-spec regeneration test guards this set.
SUPPORTED_KEYWORDS = frozenset(
    {
        "$ref",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "default",
        "deprecated",
        "description",
        "discriminator",
        "enum",
        "example",
        "examples",
        "exclusiveMinimum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "nullable",
        "oneOf",
        "pattern",
        "prefixItems",
        "properties",
        "required",
        "title",
        "type",
        "uniqueItems",
        "x-enum-descriptions",
        "x-enum-varnames",
        "x-properties-order",
        "x-tags",
    }
)


def schema_keywords(schema: object) -> set[str]:
    """Enumerate keyword positions, never property names or literal JSON."""
    if not isinstance(schema, Mapping):
        return set()
    result = set(schema)
    for key, child in schema.items():
        if key in _SCHEMA_MAPS and isinstance(child, Mapping):
            for subschema in child.values():
                result.update(schema_keywords(subschema))
        elif key in _SCHEMA_SINGLE:
            if isinstance(child, list):
                for subschema in child:
                    result.update(schema_keywords(subschema))
            else:
                result.update(schema_keywords(child))
        elif key in _SCHEMA_ARRAYS and isinstance(child, list):
            for subschema in child:
                result.update(schema_keywords(subschema))
    return result


def spec_schema_keywords(document: object) -> set[str]:
    """Scan real OpenAPI/snapshot schema positions, including unused components."""
    result: set[str] = set()

    def walk(value: object, mode: str) -> None:
        if mode == "schema":
            result.update(schema_keywords(value))
        elif mode.startswith("map:") and isinstance(value, Mapping):
            for child in value.values():
                walk(child, mode.removeprefix("map:"))
        elif mode.startswith("list:") and isinstance(value, list):
            for child in value:
                walk(child, mode.removeprefix("list:"))
        elif mode == "callback" and isinstance(value, Mapping):
            for child in value.values():
                walk(child, "path")
        elif isinstance(value, Mapping):
            for key, child_mode in _RAW_OBJECT_CHILDREN.get(mode, {}).items():
                if key in value:
                    walk(value[key], child_mode)

    if isinstance(document, Mapping) and isinstance(document.get("services"), Mapping):
        for service in document["services"].values():
            if not isinstance(service, Mapping):
                continue
            walk(service.get("raw_document"), "document")
            contracts = service.get("endpoint_contracts", {})
            if isinstance(contracts, Mapping):
                for contract in contracts.values():
                    if isinstance(contract, Mapping):
                        for schema in _contract_schemas(contract).values():
                            walk(schema, "schema")
    else:
        walk(document, "document")
    return result


def _unsupported_keywords(old: object, new: object) -> set[str]:
    if _json(old) == _json(new):
        return set()
    return {
        key
        for key in (schema_keywords(old) | schema_keywords(new))
        - SUPPORTED_KEYWORDS
        - {_RAW_REVIEW_MARKER}
        - _ANNOTATIONS
        if not key.startswith("x-")
    }


def _normalize_schema(
    value: object,
    document: Mapping,
    trail: tuple[str, ...] = (),
    *,
    names: bool = False,
    depth: int = 0,
) -> object:
    """Keep raw review evidence before reference semantics discard any siblings."""
    if depth >= _SCHEMA_DEPTH_BOUND:
        return {_REVIEW_MARKER: _DEPTH_BOUND_REASON}
    raw_review = {}
    if not names and isinstance(value, Mapping) and "$ref" in value:
        for keyword, pointer, child in _schema_keyword_paths(value):
            if keyword == "$schema":
                if not _known_dialect(child):
                    raw_review[pointer] = f"unsupported dialect $schema {child!r}"
            elif (
                keyword not in SUPPORTED_KEYWORDS
                and keyword not in _ANNOTATIONS
                and not keyword.startswith("x-")
            ):
                raw_review[pointer] = f"unsupported keyword {keyword}"
    normalized = _normalize_schema_value(value, document, trail, names=names, depth=depth)
    if raw_review:
        if not isinstance(normalized, Mapping):
            normalized = {"allOf": [normalized]}
        return {**normalized, _RAW_REVIEW_MARKER: raw_review}
    return normalized


def _normalize_schema_value(
    value: object,
    document: Mapping,
    trail: tuple[str, ...] = (),
    *,
    names: bool = False,
    depth: int = 0,
) -> object:
    """Resolve schemas without treating literal maps as schema keyword positions.

    OpenAPI 3.0 Reference Objects ignore siblings. OpenAPI 3.1 / JSON Schema
    2020-12 schemas apply both the referenced schema and siblings, represented
    as a conjunction rather than an overwriting dictionary merge.
    """
    if not isinstance(value, Mapping):
        if isinstance(value, list):
            return [_normalize_schema(child, document, trail, depth=depth + 1) for child in value]
        return value
    if names:
        return {
            key: _normalize_schema(child, document, trail, depth=depth + 1)
            for key, child in value.items()
        }
    dialect = value.get("$schema", document.get("jsonSchemaDialect"))
    if "$schema" in value and not _known_dialect(dialect):
        normalized = _normalize_schema(
            {key: child for key, child in value.items() if key != "$schema"},
            document,
            trail,
            depth=depth + 1,
        )
        if isinstance(normalized, Mapping):
            return {**normalized, "$schema": dialect}
        return {"allOf": [normalized], "$schema": dialect}
    oas_nullable = str(document.get("openapi", "")).startswith("3.0") and dialect is None
    if _known_dialect(dialect):
        document = {
            **document,
            "openapi": "3.0.0" if str(dialect).rstrip("#") in _LEGACY_DIALECTS else "3.1.0",
            "jsonSchemaDialect": dialect,
        }
    if "$ref" in value:
        ref = value["$ref"]
        siblings = {key: child for key, child in value.items() if key != "$ref"}
        legacy = str(document.get("openapi", "")).startswith("3.0")
        if ref in trail:
            return {"$ref": ref, _REVIEW_MARKER: f"cyclic schema $ref: {ref!r}"}
        try:
            target = _reference_target(ref, document)
        except ValueError as exc:
            return {"$ref": ref, _REVIEW_MARKER: str(exc)}
        chain = (*trail, str(ref))
        expanded: object = None
        # A target that is exactly {"$ref": ...} has no siblings, keywords or
        # dialect of its own: expanding it equals expanding its target. Follow
        # such links iteratively so long alias chains neither recurse nor
        # exhaust the depth bound.
        while isinstance(target, Mapping) and set(target) == {"$ref"}:
            link = target["$ref"]
            if link in chain:
                expanded = {"$ref": link, _REVIEW_MARKER: f"cyclic schema $ref: {link!r}"}
                break
            try:
                target = _reference_target(link, document)
            except ValueError as exc:
                expanded = {"$ref": link, _REVIEW_MARKER: str(exc)}
                break
            chain = (*chain, str(link))
        if expanded is None:
            expanded = _normalize_schema(target, document, chain, depth=depth + 1)
        sibling_schema = (
            _normalize_schema(siblings, document, trail, depth=depth + 1) if not legacy else {}
        )
        if sibling_schema:
            return {"allOf": [expanded, sibling_schema]}
        return expanded
    # nullable is a 3.0 type modifier, not a JSON Schema keyword in 3.1.
    if "nullable" in value:
        value = dict(value)
        nullable = value.pop("nullable")
        if oas_nullable and nullable is True:
            raw_type = value.get("type")
            if isinstance(raw_type, str):
                value["type"] = sorted({raw_type, "null"})
    result = {}
    for key, child in value.items():
        if (
            key in _ANNOTATIONS
            or str(key).startswith("x-")
            or (key == "$schema" and _known_dialect(child))
        ):
            continue
        if key in _SCHEMA_MAPS:
            result[key] = _normalize_schema(child, document, trail, names=True, depth=depth + 1)
        elif key in _SCHEMA_SINGLE or key in _SCHEMA_ARRAYS:
            result[key] = _normalize_schema(child, document, trail, depth=depth + 1)
        elif key in {"enum", "required", "type"} and isinstance(child, list):
            result[key] = sorted(child, key=_json)
        else:
            result[key] = child
    return result


def _content_schemas(value: object, document: Mapping) -> dict:
    if not isinstance(value, Mapping):
        return {}
    content = value.get("content")
    if not isinstance(content, Mapping):
        return {}
    return {
        str(media): _normalize_schema(body["schema"], document)
        for media, body in content.items()
        if isinstance(body, Mapping) and "schema" in body
    }


def _project_operation_contract(
    operation: object, document: Mapping, path_parameters: object = None
) -> object:
    """Project all request/response/parameter schemas, including inherited parameters."""
    if not isinstance(operation, Mapping):
        return operation
    params: dict[str, object] = {}
    for raw in (path_parameters, operation.get("parameters")):
        if not isinstance(raw, list):
            continue
        for item in raw:
            param = _resolve_object(item, document, pointer="parameters#")
            if isinstance(param, Mapping):
                key = f"{param.get('in', '')}.{param.get('name', '')}"
                contract: dict[str, object] = {"required": bool(param.get("required", False))}
                if "schema" in param:
                    contract["schema"] = _normalize_schema(param["schema"], document)
                contract["content"] = _content_schemas(param, document)
                params[key] = contract

    body = _resolve_object(operation.get("requestBody"), document, pointer="requestBody#")
    responses = operation.get("responses")
    response_schemas = {}
    if isinstance(responses, Mapping):
        for code, raw_response in responses.items():
            response = _resolve_object(raw_response, document, pointer=f"responses.{code}#")
            contract = _content_schemas(response, document)
            if isinstance(response, Mapping) and isinstance(response.get("headers"), Mapping):
                headers = {}
                for name, raw_header in response["headers"].items():
                    header = _resolve_object(
                        raw_header, document, pointer=f"responses.{code}.headers.{name}#"
                    )
                    if isinstance(header, Mapping):
                        projected: dict[str, object] = {
                            "content": _content_schemas(header, document)
                        }
                        if "schema" in header:
                            projected["schema"] = _normalize_schema(header["schema"], document)
                        projected["required"] = bool(header.get("required", False))
                        headers[str(name).lower()] = projected
                if headers:
                    contract["headers"] = headers
            response_schemas[str(code)] = contract
    return {
        "operationId": operation.get("operationId"),
        "parameters": params,
        "requestBody": {
            "present": isinstance(body, Mapping),
            "required": bool(body.get("required", False)) if isinstance(body, Mapping) else False,
            "schemas": _content_schemas(body, document),
        },
        "responses": response_schemas,
    }


def _operation_contract(
    operation: object, document: Mapping, path_parameters: object = None
) -> object:
    try:
        contract = _project_operation_contract(operation, document, path_parameters)
    except _ReferenceReviewError as exc:
        return {_REVIEW_MARKER: str(exc)}
    dialect = document.get("jsonSchemaDialect", document.get("$schema"))
    if dialect is not None and not _known_dialect(dialect) and isinstance(contract, Mapping):
        return {
            **contract,
            _REVIEW_MARKER: f"#/$schema needs_review: unsupported dialect {dialect!r}",
        }
    return contract


def endpoint_signature(operation: object, openapi_doc: Mapping | None = None) -> str:
    """Hash the normalized, reference-expanded operation contract, excluding prose."""
    contract = _operation_contract(operation, openapi_doc or {})
    return "sha256:" + hashlib.sha256(_json(contract).encode("utf-8")).hexdigest()


def _extract_contracts(openapi_doc: object) -> dict[str, object]:
    if not isinstance(openapi_doc, Mapping):
        raise ValueError("OpenAPI document is not an object")
    paths = openapi_doc.get("paths")
    if not isinstance(paths, Mapping):
        raise ValueError("OpenAPI document has no 'paths' object")
    contracts: dict[str, object] = {}
    for path, raw_operations in paths.items():
        try:
            operations = _resolve_object(raw_operations, openapi_doc, path_item=True)
        except _ReferenceReviewError as exc:
            # A broken Path Item can hide every method. Preserve a review contract for
            # each method so any previously recorded endpoint is classified CHANGED.
            for method in sorted(_HTTP_METHODS):
                contracts[f"{method.upper()} {path}"] = {_REVIEW_MARKER: str(exc)}
            continue
        if not isinstance(operations, Mapping):
            continue
        for method, operation in operations.items():
            if method.lower() in _HTTP_METHODS:
                endpoint = f"{method.upper()} {path}"
                try:
                    contract = _operation_contract(
                        operation, openapi_doc, operations.get("parameters")
                    )
                    _json(contract)  # literal payloads are kept verbatim; prove hashable
                except RecursionError:
                    contract = {_REVIEW_MARKER: f"{endpoint} needs_review: {_DEEP_NESTING_REASON}"}
                contracts[endpoint] = contract
    return contracts


def extract_service_endpoints(openapi_doc: object) -> dict[str, str]:
    """Extract stable semantic hashes of every published HTTP operation."""
    return {
        endpoint: "sha256:" + hashlib.sha256(_json(contract).encode("utf-8")).hexdigest()
        for endpoint, contract in _extract_contracts(openapi_doc).items()
    }


# Compatibility compares accepted value sets: requests cannot shrink; responses
# cannot grow. Unknown regex/format/composition relationships are conservative.
_MINIMUMS = frozenset({"minLength", "minItems", "minProperties", "minContains"})
_MAXIMUMS = frozenset({"maxLength", "maxItems", "maxProperties", "maxContains"})
_RESTRICTIONS = frozenset({"pattern", "format", "contentEncoding", "contentMediaType"})


def _types(schema: Mapping) -> set[str]:
    raw = schema.get("type")
    values = (
        set(raw)
        if isinstance(raw, list)
        else {raw}
        if isinstance(raw, str)
        else {"null", "boolean", "object", "array", "number", "integer", "string"}
    )
    if "number" in values:
        values.add("integer")
    for branch in schema.get("allOf", []):
        if isinstance(branch, Mapping):
            values &= _types(branch)
    for keyword in ("anyOf", "oneOf"):
        branches = schema.get(keyword, [])
        if branches and all(isinstance(branch, Mapping) for branch in branches):
            values &= set().union(*(_types(branch) for branch in branches))
    return values


_TYPE_KEYWORDS = {
    "number": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"},
    "string": {
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "contentEncoding",
        "contentMediaType",
        "contentSchema",
    },
    "array": {
        "minItems",
        "maxItems",
        "uniqueItems",
        "items",
        "additionalItems",
        "prefixItems",
        "contains",
        "minContains",
        "maxContains",
        "unevaluatedItems",
    },
    "object": {
        "minProperties",
        "maxProperties",
        "required",
        "properties",
        "additionalProperties",
        "patternProperties",
        "propertyNames",
        "dependentRequired",
        "dependentSchemas",
        "unevaluatedProperties",
    },
}


def _applicable(schema: Mapping, types: set[str]) -> dict:
    ignored = set().union(
        *(
            keywords
            for domain, keywords in _TYPE_KEYWORDS.items()
            if domain not in types and not (domain == "number" and "integer" in types)
        )
    )
    return {key: value for key, value in schema.items() if key not in ignored}


def _array_tightens(old: Mapping, new: Mapping) -> bool:
    """Compare every reachable tuple position and the homogeneous tail domain."""
    before, after = old.get("prefixItems", []), new.get("prefixItems", [])
    count = max(len(before), len(after))
    for index in range(count):
        if index >= old.get("maxItems", float("inf")):
            break
        left = before[index] if index < len(before) else old.get("items", True)
        right = after[index] if index < len(after) else new.get("items", True)
        if _tightens(left, right):
            return True
    if count < old.get("maxItems", float("inf")):
        return _tightens(old.get("items", True), new.get("items", True))
    return False


def _bound(schema: Mapping, lower: bool) -> tuple[int | float, bool]:
    key = "minimum" if lower else "maximum"
    exclusive = "exclusiveMinimum" if lower else "exclusiveMaximum"
    value = schema.get(key, float("-inf") if lower else float("inf"))
    strict = schema.get(exclusive) is True
    raw = schema.get(exclusive)
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        if (lower and raw >= value) or (not lower and raw <= value):
            value, strict = raw, True
    return value, strict


def _disjoint(left: object, right: object) -> bool:
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        return left is False or right is False
    if not (_types(left) & _types(right)):
        return True

    def literals(schema: Mapping) -> set[str] | None:
        if "enum" in schema:
            return {_json(value) for value in schema["enum"]}
        if "const" in schema:
            return {_json(schema["const"])}
        return None

    before, after = literals(left), literals(right)
    if before is not None and after is not None:
        return not (before & after)
    return False


def _property_pattern_matches(pattern: object, name: str) -> bool | None:
    r"""Match the supported literal-only patternProperties subset without a regex VM.

    Literal text, escaped regex punctuation and optional ^ / $ / \Z anchors are
    supported. Every other regex construct returns unknown: a schema requiring it
    needs review rather than executing an arbitrary backtracking program. The scan
    is deterministic; matching uses literal string operations. Dollar retains
    Python's original before-final-newline semantics, while \Z means the exact end.
    """
    if not isinstance(pattern, str):
        return None
    anchored_start = pattern.startswith("^")
    index = int(anchored_start)
    literal: list[str] = []
    end_anchor = ""
    punctuation = frozenset(r"\.^$*+?{}[]|()")
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 == len(pattern):
                return None
            escaped = pattern[index + 1]
            if escaped == "Z" and index + 2 == len(pattern):
                end_anchor = "Z"
                break
            if escaped not in punctuation:
                return None
            literal.append(escaped)
            index += 2
            continue
        if char == "$" and index + 1 == len(pattern):
            end_anchor = "$"
            break
        if char in punctuation:
            return None
        literal.append(char)
        index += 1
    text = "".join(literal)
    if end_anchor:

        def at_end(candidate: str) -> bool:
            return candidate == text if anchored_start else candidate.endswith(text)

        return at_end(name) or (end_anchor == "$" and name.endswith("\n") and at_end(name[:-1]))
    return name.startswith(text) if anchored_start else text in name


def _property_schema(schema: Mapping, name: str) -> object:
    """Constraints on one literal key, including matching patternProperties."""
    constraints = []
    properties = schema.get("properties", {})
    if name in properties:
        constraints.append(properties[name])
    for pattern, child in schema.get("patternProperties", {}).items():
        matches = _property_pattern_matches(pattern, name)
        if matches is None:
            # Unsupported regex constructs/dialects are an unknown relation.
            return None
        if matches and not any(_json(child) == _json(existing) for existing in constraints):
            constraints.append(child)
    if not constraints:
        return schema.get("additionalProperties", True)
    return constraints[0] if len(constraints) == 1 else {"allOf": constraints}


def _tightens(old: object, new: object, *, context: set[str] | None = None) -> bool:
    """Does new introduce a restriction not guaranteed by old?

    Covers validation keywords, nested applicators and both boolean schemas.
    This is a structural compatibility check, not a general schema SAT solver:
    pattern/format replacements and unproven oneOf overlaps are potential breaks.
    Definitions and annotations have no independent validation effect.
    """
    if _json(old) == _json(new) or old is False or new is True:
        return False
    if new is False:
        return True
    if old is True:
        old = {}
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        return True
    before_types, after_types = _types(old), _types(new)
    if context is not None:
        before_types &= context
        after_types &= context
    if not before_types <= after_types:
        return True
    domain = before_types & after_types
    old, new = _applicable(old, domain), _applicable(new, domain)
    for lower in (True, False):
        before, before_strict = _bound(old, lower)
        after, after_strict = _bound(new, lower)
        if (after > before if lower else after < before) or (
            after == before and after_strict and not before_strict
        ):
            return True
    for key in _MINIMUMS:
        if new.get(key, 0) > old.get(key, 0):
            return True
    for key in _MAXIMUMS:
        if new.get(key, float("inf")) < old.get(key, float("inf")):
            return True
    if new.get("uniqueItems") is True and old.get("uniqueItems") is not True:
        return True
    for key in _RESTRICTIONS:
        if key in new and new[key] != old.get(key):
            return True
    if "multipleOf" in new and new["multipleOf"] != old.get("multipleOf"):
        # Decimal JSON numbers are compared exactly, avoiding float remainder errors.
        from fractions import Fraction

        divisor = old.get("multipleOf")
        if divisor is None or Fraction(str(divisor)) % Fraction(str(new["multipleOf"])):
            return True
    for key in ("enum", "const"):
        if key in new:
            after_values = new[key] if key == "enum" else [new[key]]
            if key not in old:
                return True
            before_values = old[key] if key == "enum" else [old[key]]
            if not {_json(v) for v in before_values} <= {_json(v) for v in after_values}:
                return True
    if not set(new.get("required", [])) <= set(old.get("required", [])):
        return True
    for key in (
        "additionalProperties",
        "unevaluatedProperties",
        "unevaluatedItems",
        "additionalItems",
        "propertyNames",
        "contains",
        "contentSchema",
    ):
        if _tightens(old.get(key, True), new.get(key, True)):
            return True
    if "array" in domain and _array_tightens(old, new):
        return True
    if "not" in new and ("not" not in old or _tightens(new["not"], old["not"])):
        return True
    before_properties, after_properties = old.get("properties", {}), new.get("properties", {})
    for name in set(before_properties) | set(after_properties):
        before_property, after_property = _property_schema(old, name), _property_schema(new, name)
        if before_property is None or after_property is None:
            return True
        if _tightens(before_property, after_property):
            return True
    for key in ("patternProperties", "dependentSchemas"):
        before_map, after_map = old.get(key, {}), new.get(key, {})
        for name, child in after_map.items():
            fallback = old.get("additionalProperties", True) if key == "patternProperties" else True
            if _tightens(before_map.get(name, fallback), child):
                return True
        if key == "patternProperties":
            for name, child in before_map.items():
                if name not in after_map and _tightens(
                    child, new.get("additionalProperties", True)
                ):
                    return True
    before_dependencies = old.get("dependentRequired", {})
    for name, required in new.get("dependentRequired", {}).items():
        if not set(required) <= set(before_dependencies.get(name, [])):
            return True
    for key in ("allOf", "anyOf", "oneOf"):
        before_branches, after_branches = old.get(key, []), new.get(key, [])
        if _json(before_branches) == _json(after_branches):
            continue
        # Match occurrences, not sets: a duplicated oneOf branch rejects all
        # values matching that branch and is a real tightening.
        before_left = list(before_branches)
        after_left = []
        for branch in after_branches:
            match = next(
                (
                    index
                    for index, previous in enumerate(before_left)
                    if _json(previous) == _json(branch)
                ),
                None,
            )
            if match is None:
                after_left.append(branch)
            else:
                before_left.pop(match)
        if key == "allOf":
            if len(after_left) > len(before_left):
                return True
            if any(
                _tightens(a, b, context=domain)
                for a, b in zip(before_left, after_left, strict=False)
            ):
                return True
        elif key == "anyOf":
            if before_branches and not after_branches:
                # Removing the applicator removes its restriction.
                continue
            if not before_branches and after_branches:
                return True
            if len(before_left) > len(after_left):
                return True
            if any(
                _tightens(a, b, context=domain)
                for a, b in zip(before_left, after_left, strict=False)
            ):
                return True
        elif key == "oneOf":
            if not after_branches:
                continue
            if not before_branches:
                return True
            if len(before_left) > len(after_left) and any(
                not any(not _tightens(removed, kept, context=domain) for kept in after_branches)
                for removed in before_left
            ):
                return True
            if any(
                _tightens(a, b, context=domain)
                for a, b in zip(before_left, after_left, strict=False)
            ):
                return True
            # Added/replaced branches can INVALIDATE previously accepted values
            # by overlapping another final branch (exactly one must match).
            # A replaced old branch is not itself an overlapping final peer.
            for branch in after_left:
                peers = list(after_branches)
                for index, peer in enumerate(peers):
                    if _json(branch) == _json(peer):
                        peers.pop(index)
                        break
                if any(not _disjoint(branch, peer) for peer in peers):
                    return True
    # Conditional replacements cannot be ordered without proving the predicate relation.
    if any(_json(new.get(key)) != _json(old.get(key)) for key in ("if", "then", "else")):
        if any(key in new for key in ("then", "else")):
            return True
    return False


def _schema_breaks(old: object, new: object, direction: str) -> bool:
    if _unsupported_keywords(old, new):
        return True
    return _tightens(new, old) if direction == "response" else _tightens(old, new)


def _breaking_contract_paths(old: Mapping, new: Mapping) -> list[str]:
    broken = []
    before_params, after_params = old.get("parameters", {}), new.get("parameters", {})
    for name, param in after_params.items():
        before = before_params.get(name, {})
        if name not in before_params and not param.get("required"):
            # An optional introduction has no former supplied-value domain.
            continue
        if param.get("required") and not before.get("required"):
            broken.append(f"parameters.{name}")
        if _schema_breaks(before.get("schema", True), param.get("schema", True), "request"):
            broken.append(f"parameters.{name}.schema")
        _media_breaks(
            before.get("content", {}),
            param.get("content", {}),
            "request",
            f"parameters.{name}.content",
            broken,
        )
    before_body, after_body = old.get("requestBody", {}), new.get("requestBody", {})
    if after_body.get("required") and not before_body.get("required"):
        broken.append("requestBody.required")
    _media_breaks(
        before_body.get("schemas", {}),
        after_body.get("schemas", {}),
        "request",
        "requestBody.schemas",
        broken,
    )
    before_responses, after_responses = old.get("responses", {}), new.get("responses", {})
    for code in set(before_responses) | set(after_responses):
        before, after = before_responses.get(code, {}), after_responses.get(code, {})
        base = f"responses.{code}"
        if code not in after_responses:
            broken.append(base)
        _media_breaks(
            {k: v for k, v in before.items() if k != "headers"},
            {k: v for k, v in after.items() if k != "headers"},
            "response",
            base,
            broken,
        )
        before_headers, after_headers = before.get("headers", {}), after.get("headers", {})
        for name in set(before_headers) | set(after_headers):
            left, right = before_headers.get(name, {}), after_headers.get(name, {})
            header_path = f"{base}.headers.{name}"
            if left.get("required") and not right.get("required"):
                broken.append(header_path)
            if _schema_breaks(left.get("schema", True), right.get("schema", True), "response"):
                broken.append(header_path + ".schema")
            _media_breaks(
                left.get("content", {}),
                right.get("content", {}),
                "response",
                header_path + ".content",
                broken,
            )
    return broken


def _media_breaks(old: Mapping, new: Mapping, direction: str, path: str, broken: list[str]) -> None:
    for media in set(old) | set(new):
        if media not in new:
            if direction == "request":
                broken.append(f"{path}.{media}")
        elif media not in old:
            if direction == "response":
                broken.append(f"{path}.{media}")
        elif _schema_breaks(old[media], new[media], direction):
            broken.append(f"{path}.{media}")


def _contract_schemas(contract: Mapping) -> dict[str, object]:
    result: dict[str, object] = {}

    def parameter(value: Mapping, path: str) -> None:
        if "schema" in value:
            result[path + ".schema"] = value["schema"]
        for media, schema in value.get("content", {}).items():
            result[f"{path}.content.{media}"] = schema

    for name, value in contract.get("parameters", {}).items():
        parameter(value, f"parameters.{name}")
    for media, schema in contract.get("requestBody", {}).get("schemas", {}).items():
        result[f"requestBody.schemas.{media}"] = schema
    for code, response in contract.get("responses", {}).items():
        for media, schema in response.items():
            if media != "headers":
                result[f"responses.{code}.{media}"] = schema
        for name, value in response.get("headers", {}).items():
            parameter(value, f"responses.{code}.headers.{name}")
    return result


def _schema_keyword_paths(schema: object, pointer: str = "") -> list[tuple[str, str, object]]:
    """Visit keyword positions with RFC 6901 escaping, excluding literal maps."""
    result = []
    pending = [(schema, pointer)]
    while pending:
        value, parent = pending.pop()
        if not isinstance(value, Mapping):
            continue
        children: list[tuple[object, str]] = []
        for key, child in value.items():
            path = f"{parent}/{_pointer_part(key)}"
            result.append((str(key), path, child))
            if key in _SCHEMA_MAPS and isinstance(child, Mapping):
                children.extend(
                    (subschema, f"{path}/{_pointer_part(name)}")
                    for name, subschema in child.items()
                )
            elif key in _SCHEMA_ARRAYS or (key in _SCHEMA_SINGLE and isinstance(child, list)):
                if isinstance(child, list):
                    children.extend(
                        (subschema, f"{path}/{index}") for index, subschema in enumerate(child)
                    )
            elif key in _SCHEMA_SINGLE:
                children.append((child, path))
        pending.extend(reversed(children))
    return result


def _review_reasons(old: object, new: object) -> list[str]:
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        return []
    before, after = _contract_schemas(old), _contract_schemas(new)
    reasons = set()
    for contract in (old, new):
        if _REVIEW_MARKER in contract:
            reasons.add(str(contract[_REVIEW_MARKER]))
    for path in sorted(set(before) | set(after)):
        left, right = before.get(path, True), after.get(path, True)
        unsupported = _unsupported_keywords(left, right)
        for schema in (left, right):
            for keyword, pointer, value in _schema_keyword_paths(schema):
                if keyword == _RAW_REVIEW_MARKER and isinstance(value, Mapping):
                    parent = pointer.rsplit("/", 1)[0]
                    for raw_pointer, reason in value.items():
                        if _json(left) != _json(right) or "unsupported dialect" in reason:
                            reasons.add(f"{path}#{parent}{raw_pointer} needs_review: {reason}")
                elif keyword == _REVIEW_MARKER:
                    parent = pointer.rsplit("/", 1)[0]
                    # Cycles and the depth bound are comparison limits, not defects:
                    # identical normalized regions are clean (raw edits hidden past
                    # the bound remain caught by the raw-document net).
                    comparison_limit = str(value).startswith("cyclic schema $ref:") or (
                        value == _DEPTH_BOUND_REASON
                    )
                    if not comparison_limit or _json(left) != _json(right):
                        reasons.add(f"{path}#{parent}/$ref needs_review: {value}")
                elif keyword == "$schema" and not _known_dialect(value):
                    reasons.add(
                        f"{path}#{pointer} needs_review: unsupported dialect $schema {value!r}"
                    )
                elif keyword in unsupported:
                    reasons.add(f"{path}#{pointer} needs_review: unsupported keyword {keyword}")
    return sorted(reasons)


def _contract_changes(
    old: object, new: object, path: str = "", *, names: bool = False, keyword: str | None = None
) -> tuple[list[str], list[str]]:
    """Render field deltas, then classify schemas with explicit request/response polarity."""
    changes: list[str] = []
    if _json(old) == _json(new):
        if not path and isinstance(old, Mapping) and isinstance(new, Mapping):
            reasons = _review_reasons(old, new)
            return reasons, reasons
        return [], []
    if keyword in {"enum", "required"} and isinstance(old, list) and isinstance(new, list):
        before, after = {_json(v) for v in old}, {_json(v) for v in new}
        if after - before:
            changes.append(f"{path} +[{','.join(sorted(after - before))}]")
        if before - after:
            changes.append(f"{path} -[{','.join(sorted(before - after))}]")
    elif isinstance(old, Mapping) and isinstance(new, Mapping):
        for key in sorted(set(old) | set(new)):
            child_path = f"{path}.{key}" if path else str(key)
            if key not in new:
                changes.append(f"{child_path} -{_json(old[key])}")
            elif key not in old:
                changes.append(f"{child_path} +{_json(new[key])}")
            else:
                children, _ = _contract_changes(
                    old[key],
                    new[key],
                    child_path,
                    names=not names
                    and key
                    in _SCHEMA_MAPS
                    | {
                        "parameters",
                        "responses",
                        "schemas",
                        "headers",
                        "dependentRequired",
                        "mapping",
                    },
                    keyword=None if names else str(key),
                )
                changes.extend(children)
    elif (
        isinstance(old, list)
        and isinstance(new, list)
        and keyword not in {"type", "const", "default"}
    ):
        for index in range(max(len(old), len(new))):
            child_path = f"{path}[{index}]"
            if index >= len(new):
                changes.append(f"{child_path} -{_json(old[index])}")
            elif index >= len(old):
                changes.append(f"{child_path} +{_json(new[index])}")
            else:
                children, _ = _contract_changes(old[index], new[index], child_path)
                changes.extend(children)
    else:
        changes.append(f"{path} {_json(old)} -> {_json(new)}")
    breaking = []
    if not path and isinstance(old, Mapping) and isinstance(new, Mapping):
        roots = _breaking_contract_paths(old, new)
        breaking = [
            change
            for change in changes
            if any(
                change.startswith(root + ".")
                or change.startswith(root + "[")
                or change.startswith(root + " ")
                or root.startswith(change.split(" ", 1)[0] + ".")
                for root in roots
            )
        ]
        reasons = _review_reasons(old, new)
        changes.extend(reasons)
        breaking.extend(reasons)
    return changes, breaking


@dataclass(frozen=True)
class ServiceSpec:
    """One published service: its slug, version, spec URL, and signed endpoint set."""

    name: str
    version: str
    spec_url: str
    endpoints: dict[str, str] = field(default_factory=dict)
    endpoint_contracts: dict[str, object] = field(default_factory=dict)
    info_version: str | None = None
    raw_document: object = None


def build_service_spec(name: str, version: str, spec_url: str, openapi_doc: object) -> ServiceSpec:
    """Build a :class:`ServiceSpec` from a fetched OpenAPI document."""
    projected = strip_example_annotations(openapi_doc)
    return ServiceSpec(
        name=name.lower(),
        version=version,
        spec_url=spec_url,
        raw_document=_copy_json(projected),
        endpoints=extract_service_endpoints(projected),
        endpoint_contracts=_extract_contracts(projected),
        info_version=(
            str(projected["info"]["version"])
            if isinstance(projected, Mapping)
            and isinstance(projected.get("info"), Mapping)
            and "version" in projected["info"]
            else None
        ),
    )


@dataclass(frozen=True)
class SpecSnapshot:
    """A point-in-time view of every published service plus deployment-running versions.

    ``services`` maps service slug -> :class:`ServiceSpec`. ``console_versions`` maps
    service slug -> the version that service is actually running on the deployment (observed
    live; carried in the committed baseline). ``captured_at`` is informational provenance
    and never participates in the diff.
    """

    services: dict[str, ServiceSpec] = field(default_factory=dict)
    console_versions: dict[str, str] = field(default_factory=dict)
    captured_at: str | None = None


def snapshot_to_dict(snapshot: SpecSnapshot) -> dict:
    """Serialise a :class:`SpecSnapshot` to a JSON-safe dict (stable key order)."""
    return {
        "captured_at": snapshot.captured_at,
        "console_versions": dict(sorted(snapshot.console_versions.items())),
        "services": {
            name: {
                "version": spec.version,
                "spec_url": spec.spec_url,
                "endpoints": dict(sorted(spec.endpoints.items())),
                "endpoint_contracts": dict(sorted(spec.endpoint_contracts.items())),
                "info_version": spec.info_version,
                **({"raw_document": spec.raw_document} if spec.raw_document is not None else {}),
            }
            for name, spec in sorted(snapshot.services.items())
        },
    }


def snapshot_from_dict(payload: object) -> SpecSnapshot:
    """Rebuild a :class:`SpecSnapshot` from :func:`snapshot_to_dict` output.

    Raises ``ValueError`` on an unrecognised shape so a corrupt baseline fails loud instead
    of diffing against an empty snapshot (which would flag everything as removed).
    """
    if not isinstance(payload, Mapping) or not isinstance(payload.get("services"), Mapping):
        raise ValueError("unrecognised snapshot shape: expected a {'services': {...}} object")
    services: dict[str, ServiceSpec] = {}
    for name, body in payload["services"].items():
        if not isinstance(body, Mapping):
            raise ValueError(f"service {name!r} entry is not an object")
        endpoints = body.get("endpoints", {})
        if not isinstance(endpoints, Mapping):
            raise ValueError(f"service {name!r} has a non-object 'endpoints'")
        contracts = body.get("endpoint_contracts", {})
        if not isinstance(contracts, Mapping):
            raise ValueError(f"service {name!r} has non-object endpoint_contracts")
        services[str(name).lower()] = ServiceSpec(
            name=str(name).lower(),
            version=str(body.get("version", "")),
            spec_url=str(body.get("spec_url", "")),
            endpoints={str(k): str(v) for k, v in endpoints.items()},
            endpoint_contracts={str(k): v for k, v in contracts.items()},
            raw_document=_copy_json(body.get("raw_document")),
            info_version=(
                str(body["info_version"]) if body.get("info_version") is not None else None
            ),
        )
    console_versions = payload.get("console_versions", {})
    if not isinstance(console_versions, Mapping):
        raise ValueError("'console_versions' must be an object when present")
    return SpecSnapshot(
        services=services,
        console_versions={str(k).lower(): str(v) for k, v in console_versions.items()},
        captured_at=(str(payload["captured_at"]) if payload.get("captured_at") else None),
    )


@dataclass(frozen=True)
class EndpointFinding:
    """A single NEW / CHANGED / REMOVED endpoint on one service."""

    kind: str  # "NEW" | "CHANGED" | "REMOVED"
    endpoint: str  # "METHOD /path"
    implemented: bool
    breakage: bool  # Breaking schema delta, or a legacy/removed implemented endpoint.
    write_capability: bool  # NEW write-method endpoint we do not implement
    changes: tuple[str, ...] = ()
    breaking_changes: tuple[str, ...] = ()

    @property
    def method(self) -> str:
        return self.endpoint.split(" ", 1)[0]


@dataclass(frozen=True)
class ServiceDiff:
    """Drift for one service between the baseline and the current snapshot."""

    name: str
    old_version: str | None
    new_version: str | None
    console_version: str | None
    endpoint_findings: list[EndpointFinding] = field(default_factory=list)
    service_added: bool = False
    service_removed: bool = False
    info_version: str | None = None

    @property
    def version_changed(self) -> bool:
        return (
            not self.service_added
            and not self.service_removed
            and self.old_version is not None
            and self.new_version is not None
            and self.old_version != self.new_version
        )

    @property
    def console_gap(self) -> bool:
        # Published-vs-running divergence, only meaningful while the service is published.
        # This is *informational*: on the EA channel the deployment routinely runs ahead of the
        # documented contract, so it is a standing condition the watcher cannot resolve and
        # must NOT treat as actionable drift (that would make the weekly monitor permanently
        # red — the failure mode the monitor is designed to avoid). It is always
        # surfaced in the report body.
        return (
            self.new_version is not None
            and self.console_version is not None
            and self.console_version != self.new_version
        )

    @property
    def has_actionable_findings(self) -> bool:
        """Deltas vs. the baseline that flip the run RED until the baseline is advanced.

        Deliberately excludes :attr:`console_gap`, which is a standing informational
        condition rather than a run-to-run delta.
        """
        return bool(
            self.endpoint_findings
            or self.version_changed
            or self.service_added
            or self.service_removed
        )

    def _by_kind(self, kind: str) -> list[EndpointFinding]:
        return [f for f in self.endpoint_findings if f.kind == kind]

    @property
    def new_endpoints(self) -> list[EndpointFinding]:
        return self._by_kind("NEW")

    @property
    def changed_endpoints(self) -> list[EndpointFinding]:
        return self._by_kind("CHANGED")

    @property
    def removed_endpoints(self) -> list[EndpointFinding]:
        return self._by_kind("REMOVED")


def _endpoint_findings(
    old: ServiceSpec | None,
    new: ServiceSpec | None,
    implemented: frozenset[str],
) -> list[EndpointFinding]:
    old_eps = old.endpoints if old else {}
    new_eps = new.endpoints if new else {}
    findings: list[EndpointFinding] = []

    for ep in sorted(set(new_eps) - set(old_eps)):
        method = ep.split(" ", 1)[0]
        is_impl = ep in implemented
        review = (
            _review_reasons({}, new.endpoint_contracts[ep])
            if new and ep in new.endpoint_contracts
            else []
        )
        findings.append(
            EndpointFinding(
                kind="CHANGED" if review else "NEW",
                endpoint=ep,
                implemented=is_impl,
                breakage=bool(review),
                write_capability=(method in WRITE_METHODS and not is_impl and not review),
                changes=tuple(review),
                breaking_changes=tuple(review),
            )
        )
    for ep in sorted(set(old_eps) & set(new_eps)):
        review = (
            _review_reasons(old.endpoint_contracts[ep], new.endpoint_contracts[ep])
            if old and new and ep in old.endpoint_contracts and ep in new.endpoint_contracts
            else []
        )
        if old_eps[ep] != new_eps[ep] or review:
            is_impl = ep in implemented
            has_contracts = bool(
                old and new and ep in old.endpoint_contracts and ep in new.endpoint_contracts
            )
            changes, breaking = (
                _contract_changes(old.endpoint_contracts[ep], new.endpoint_contracts[ep])
                if has_contracts and old and new
                else ([], [])
            )
            findings.append(
                EndpointFinding(
                    kind="CHANGED",
                    endpoint=ep,
                    implemented=is_impl,
                    breakage=bool(breaking) if has_contracts else is_impl,
                    write_capability=False,
                    changes=tuple(changes),
                    breaking_changes=tuple(breaking),
                )
            )
    for ep in sorted(set(old_eps) - set(new_eps)):
        is_impl = ep in implemented
        review = (
            _review_reasons(old.endpoint_contracts[ep], {})
            if old and ep in old.endpoint_contracts
            else []
        )
        findings.append(
            EndpointFinding(
                kind="REMOVED",
                endpoint=ep,
                implemented=is_impl,
                breakage=is_impl or bool(review),
                write_capability=False,
                changes=tuple(review),
                breaking_changes=tuple(review),
            )
        )
    findings.extend(_document_findings(old, new, findings))
    return findings


# Raw-document coverage is independent of the endpoint projection. Keep literal
# map keys (even "description" or "x-*") and literal JSON values significant.
_RAW_ANNOTATIONS = _ANNOTATIONS | {"externalDocs"}
_RAW_LITERALS = {"const", "enum", "default", "required", "dependentRequired", "mapping", "security"}
_MISSING = object()


def _pointer_part(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _pointer_parts(pointer: str) -> tuple[str, ...]:
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:])


# Positive annotation contexts: unknown objects are literal until recognized.
# This avoids an ever-growing exception list for maps with annotation-like names.
_RAW_OBJECT_CHILDREN = {
    "document": {
        "info": "info",
        "paths": "map:path",
        "webhooks": "map:path",
        "components": "components",
        "servers": "list:server",
        "tags": "list:tag",
    },
    "components": {
        "schemas": "map:schema",
        "parameters": "map:parameter",
        "responses": "map:response",
        "requestBodies": "map:requestBody",
        "headers": "map:parameter",
        "links": "map:link",
        "callbacks": "map:callback",
        "pathItems": "map:path",
        "securitySchemes": "map:securityScheme",
    },
    "path": {
        **{method: "operation" for method in _HTTP_METHODS},
        "parameters": "list:parameter",
        "servers": "list:server",
    },
    "operation": {
        "parameters": "list:parameter",
        "requestBody": "requestBody",
        "responses": "map:response",
        "callbacks": "map:callback",
        "servers": "list:server",
    },
    "parameter": {"schema": "schema", "content": "map:media"},
    "requestBody": {"content": "map:media"},
    "response": {"content": "map:media", "headers": "map:parameter", "links": "map:link"},
    "media": {"schema": "schema", "encoding": "map:encoding"},
    "encoding": {"headers": "map:parameter"},
    "server": {"variables": "map:variable"},
    "securityScheme": {"flows": "map:flow"},
    "flow": {},  # scopes and their names are arbitrary literal data
    "link": {},  # requestBody/parameters are arbitrary literal JSON
    "info": {"contact": "contact", "license": "license"},
    "variable": {},
    "tag": {},
    "contact": {},
    "license": {},
    "schema": {
        **{key: "map:schema" for key in _SCHEMA_MAPS},
        **{key: "schema" for key in _SCHEMA_SINGLE},
        **{key: "list:schema" for key in _SCHEMA_ARRAYS},
    },
}


def _canonical_raw(
    value: object,
    document: Mapping,
    mode: str = "document",
    *,
    normalize_nullable: bool = False,
    inherited_dialect: object = None,
) -> object:
    def child(raw: object, kind: str, dialect: object = inherited_dialect) -> object:
        return _canonical_raw(
            raw, document, kind, normalize_nullable=normalize_nullable, inherited_dialect=dialect
        )

    if isinstance(value, list):
        child_mode = mode.removeprefix("list:") if mode.startswith("list:") else "literal"
        if mode == "schema":
            child_mode = "schema"  # legacy tuple items
        return [child(raw, child_mode) for raw in value]
    if not isinstance(value, Mapping):
        return value
    if mode.startswith("map:"):
        child_mode = mode.removeprefix("map:")
        return {key: child(raw, child_mode) for key, raw in value.items()}
    if mode == "callback":
        return {key: child(raw, "path") for key, raw in value.items()}
    dialect = inherited_dialect
    if mode == "schema":
        dialect = value.get("$schema", inherited_dialect or document.get("jsonSchemaDialect"))
    transitions = _RAW_OBJECT_CHILDREN.get(mode)
    result = {
        key: child(raw, transitions.get(key, "literal") if transitions else "literal", dialect)
        for key, raw in value.items()
        if transitions is None or not (key in _RAW_ANNOTATIONS or str(key).startswith("x-"))
    }
    if normalize_nullable and mode == "schema":
        legacy = dialect is None and str(document.get("openapi", "")).startswith("3.0")
        if legacy and isinstance(value.get("type"), str) and value.get("nullable") is True:
            result["type"] = sorted({value["type"], "null"})
            result.pop("nullable", None)
        elif legacy and value.get("nullable") is False:
            result.pop("nullable", None)
        raw_type = result.get("type")
        if isinstance(raw_type, list):
            result["type"] = sorted(raw_type, key=_json)
    return result


def _canonical_document(document: Mapping) -> object:
    return _canonical_raw(document, document, normalize_nullable=True)


def _document_inventory(document: Mapping) -> dict[str, tuple]:
    """Inventory raw edges without recursively expanding reference chains.

    Strongly connected regions distinguish legitimate cycles from unresolved
    targets. Their raw fingerprints preserve changes hidden by semantic expansion.
    """
    inventory: dict[str, tuple] = {}
    graph: dict[str, set[str]] = {}
    values: dict[str, object] = {}
    references: dict[str, tuple[str, str | None]] = {}
    invalid: set[str] = set()
    # role: "discriminator" for a Discriminator Object at a real schema position,
    # "mapping" for its mapping. Only that mapping's values are schema references;
    # the same key path inside example/default/const/enum payloads is literal data.
    pending: list[tuple[object, str, bool, bool, bool, str]] = [
        (document, "", False, False, False, "")
    ]
    completed = set()
    while pending:
        value, pointer, schema, names, literal, role = pending.pop()
        state = (pointer, schema, names, literal, role)
        if state in completed:
            continue
        completed.add(state)
        graph.setdefault(pointer, set())
        values[pointer] = value
        if isinstance(value, Mapping):
            mapping_ref = role == "mapping" and not literal
            for key, child in value.items():
                path = f"{pointer}/{_pointer_part(key)}"
                if key == "$ref" or mapping_ref:
                    ref = child
                    if (
                        mapping_ref
                        and isinstance(ref, str)
                        and not ref.startswith("#")
                        and not any(char in ref for char in "/:#?")
                    ):
                        ref = f"#/components/schemas/{_pointer_part(ref)}"
                    try:
                        target = _reference_target(ref, document)
                        target_pointer = ref[1:]
                    except (ValueError, TypeError):
                        target_pointer = None
                        invalid.add(pointer)
                    else:
                        graph[pointer].add(target_pointer)
                        pending.append(
                            (
                                target,
                                target_pointer,
                                mapping_ref or (schema and not names and not literal),
                                False,
                                False,
                                "",
                            )
                        )
                    references[path] = (pointer, target_pointer)
                    inventory[path] = ("reference", _json(child), target_pointer is not None)
                elif key in {"$schema", "jsonSchemaDialect"}:
                    inventory[path] = ("dialect", _json(child), _known_dialect(child))
                elif (
                    schema
                    and not names
                    and not literal
                    and key not in SUPPORTED_KEYWORDS
                    and key not in _RAW_ANNOTATIONS
                    and not str(key).startswith("x-")
                ):
                    inventory[path] = ("unsupported keyword", _json(child), True)
                # References/dialects are always scanned, including literal values.
                child_literal = literal or (
                    schema
                    and (
                        key in _RAW_LITERALS or key in _RAW_ANNOTATIONS or str(key).startswith("x-")
                    )
                )
                if names:
                    child_schema, child_names = True, False
                elif not child_literal and (
                    (schema and key in _SCHEMA_SINGLE)
                    or (key == "schema" and _raw_kind(document, _pointer_parts(path)) == "schema")
                ):
                    child_schema, child_names = True, False
                elif not child_literal and (
                    (schema and key in _SCHEMA_MAPS)
                    or (
                        key == "schemas"
                        and _raw_kind(document, _pointer_parts(path)) == "map:schema"
                    )
                ):
                    child_schema, child_names = True, True
                elif not child_literal and schema and key in _SCHEMA_ARRAYS:
                    child_schema, child_names = True, False
                elif schema and key not in SUPPORTED_KEYWORDS and not child_literal:
                    # Unknown applicators cannot hide nested unsupported semantics.
                    child_schema, child_names = True, False
                else:
                    child_schema, child_names = False, False
                if schema and not names and not literal and key == "discriminator":
                    child_role = "discriminator"
                elif role == "discriminator" and not literal and key == "mapping":
                    child_role = "mapping"
                else:
                    child_role = ""
                graph[pointer].add(path)
                pending.append((child, path, child_schema, child_names, child_literal, child_role))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                path = f"{pointer}/{index}"
                graph[pointer].add(path)
                pending.append((child, path, schema, names, literal, ""))

    # Iterative Kosaraju traversal: no Python call stack depends on chain length.
    reverse: dict[str, set[str]] = {pointer: set() for pointer in graph}
    for pointer, children in graph.items():
        for child in children:
            reverse[child].add(pointer)
    visited = set()
    order = []
    for pointer in graph:
        if pointer in visited:
            continue
        stack = [(pointer, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                order.append(node)
            elif node not in visited:
                visited.add(node)
                stack.append((node, True))
                stack.extend((child, False) for child in sorted(graph[node], reverse=True))
    regions: dict[str, str] = {}
    fingerprints: dict[str, str] = {}
    for pointer in reversed(order):
        if pointer in regions:
            continue
        members = []
        region_stack = [pointer]
        while region_stack:
            node = region_stack.pop()
            if node in regions:
                continue
            regions[node] = pointer
            members.append(node)
            region_stack.extend(reverse[node])
        if len(members) > 1 or pointer in graph[pointer]:
            fingerprints[pointer] = _json({node: values[node] for node in sorted(members)})
    # An unresolved descendant makes incoming edges unresolved, independently
    # of whether any of those edges also belongs to a recursive region.
    invalid_stack = list(invalid)
    while invalid_stack:
        node = invalid_stack.pop()
        for parent in reverse[node] - invalid:
            invalid.add(parent)
            invalid_stack.append(parent)
    for path, (source, target) in references.items():
        region = regions[source]
        cyclic = target is not None and regions[target] == region and region in fingerprints
        inventory[path] = (
            *inventory[path][:2],
            target is not None and target not in invalid,
            cyclic,
            fingerprints.get(region) if cyclic else None,
        )
    return inventory


def _raw_changes(old: object, new: object, parts: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Canonical leaf diff; additions cannot hide unclassified siblings."""
    if old is not _MISSING and new is not _MISSING and _json(old) == _json(new):
        return []
    if isinstance(old, Mapping) or isinstance(new, Mapping):
        left = old if isinstance(old, Mapping) else {}
        right = new if isinstance(new, Mapping) else {}
        changes = [
            pointer
            for key in sorted(set(left) | set(right))
            for pointer in _raw_changes(
                left.get(key, _MISSING), right.get(key, _MISSING), (*parts, str(key))
            )
        ]
        if not changes or (
            old is not _MISSING and new is not _MISSING and not isinstance(old, type(new))
        ):
            changes.append(parts)
        return changes
    if isinstance(old, list) or isinstance(new, list):
        left_list = old if isinstance(old, list) else []
        right_list = new if isinstance(new, list) else []
        changes = [
            pointer
            for index in range(max(len(left_list), len(right_list)))
            for pointer in _raw_changes(
                left_list[index] if index < len(left_list) else _MISSING,
                right_list[index] if index < len(right_list) else _MISSING,
                (*parts, str(index)),
            )
        ]
        if not changes or (
            old is not _MISSING and new is not _MISSING and not isinstance(old, type(new))
        ):
            changes.append(parts)
        return changes
    return [parts]


def _raw_at(value: object, parts: tuple[str, ...]) -> object:
    for part in parts:
        if isinstance(value, Mapping):
            value = value.get(part, _MISSING)
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return _MISSING
    return value


def _without_pointer(document: Mapping, parts: tuple[str, ...], replacement: object) -> object:
    """Revert a single leaf in the document where its parents already exist."""
    result = _copy_json(document)
    if not parts:
        return replacement
    parent = _raw_at(result, parts[:-1])
    key = parts[-1]
    if isinstance(parent, dict):
        if replacement is _MISSING:
            parent.pop(key, None)
        else:
            parent[key] = _copy_json(replacement)
    elif isinstance(parent, list) and key.isdigit() and int(key) < len(parent):
        if replacement is _MISSING:
            parent.pop(int(key))
        else:
            parent[int(key)] = _copy_json(replacement)
    return result


def _raw_kind(document: object, parts: tuple[str, ...]) -> str:
    kind = "document"
    current = document
    for part in parts:
        if isinstance(current, list):
            kind = kind.removeprefix("list:") if kind.startswith("list:") else "literal"
        elif kind.startswith("map:"):
            kind = kind.removeprefix("map:")
        elif kind == "callback":
            kind = "path"
        else:
            kind = _RAW_OBJECT_CHILDREN.get(kind, {}).get(part, "literal")
        current = _raw_at(current, (part,))
    return kind


def _pointer_classified(
    old: ServiceSpec, new: ServiceSpec, parts: tuple[str, ...], findings: list[EndpointFinding]
) -> bool:
    before = _raw_at(old.raw_document, parts)
    after = _raw_at(new.raw_document, parts)
    # Explicit false has the same fully supported meaning as the default for
    # an introduced optional parameter/body/header. Attribute it to that object's
    # classified introduction, rather than mistaking the absent field for unknown
    # semantics. Standalone redundant default edits still reach the raw safety net.
    if parts and parts[-1] == "required":
        base_document = new.raw_document if after is not _MISSING else old.raw_document
        other_document = old.raw_document if after is not _MISSING else new.raw_document
        value = after if after is not _MISSING else before
        if (
            value is False
            and _raw_kind(base_document, parts[:-1]) in {"parameter", "requestBody"}
            and _raw_at(other_document, parts[:-1]) is _MISSING
        ):
            return _pointer_classified(old, new, parts[:-1], findings)
    # Revert additions on the new side, removals on the old side. This ensures an
    # ignored leaf in a newly added operation is not attributed to operation creation.
    base = new if after is not _MISSING else old
    replacement = before if after is not _MISSING else after
    if not isinstance(base.raw_document, Mapping):
        return False
    reverted = _without_pointer(base.raw_document, parts, replacement)
    try:
        isolated = _extract_contracts(reverted)
    except (ValueError, TypeError):
        return False
    classified_endpoints = {finding.endpoint for finding in findings}
    for endpoint in set(base.endpoint_contracts) | set(isolated):
        if endpoint not in classified_endpoints:
            continue
        left = isolated.get(endpoint, {})
        right = base.endpoint_contracts.get(endpoint, {})
        changes, _ = _contract_changes(left, right)
        if changes:
            return True
    return False


def _document_findings(
    old: ServiceSpec | None, new: ServiceSpec | None, classified: list[EndpointFinding]
) -> list[EndpointFinding]:
    """Raw-document net; pathological nesting fails safe instead of crashing."""
    try:
        return _raw_document_findings(old, new, classified)
    except RecursionError:
        return [_deep_nesting_finding("raw document")]


def _deep_nesting_finding(subject: str) -> EndpointFinding:
    evidence = (f"# needs_review: {subject} {_DEEP_NESTING_REASON}",)
    return EndpointFinding(
        kind="CHANGED",
        endpoint="DOCUMENT #",
        implemented=False,
        breakage=True,
        write_capability=False,
        changes=evidence,
        breaking_changes=evidence,
    )


def _raw_document_findings(
    old: ServiceSpec | None, new: ServiceSpec | None, classified: list[EndpointFinding]
) -> list[EndpointFinding]:
    documents = [spec for spec in (old, new) if spec and isinstance(spec.raw_document, Mapping)]
    if not documents:
        if old is None and new is None:
            return []
        evidence: tuple[str, ...] = ("# needs_review: raw-document evidence unavailable",)
        return [
            EndpointFinding(
                kind="CHANGED",
                endpoint="DOCUMENT #",
                implemented=False,
                breakage=True,
                write_capability=False,
                changes=evidence,
                breaking_changes=evidence,
            )
        ]
    before = (
        _document_inventory(old.raw_document)
        if old and isinstance(old.raw_document, Mapping)
        else {}
    )
    after = (
        _document_inventory(new.raw_document)
        if new and isinstance(new.raw_document, Mapping)
        else {}
    )
    reasons: set[str] = set()
    for pointer in set(before) | set(after):
        left, right = before.get(pointer), after.get(pointer)
        if left != right or any(item and not item[2] for item in (left, right)):
            kind = (right or left or ("unknown", "", False))[0]
            reasons.add(f"#{pointer} needs_review: {kind} changed or unresolved/unknown")
    if (
        old
        and new
        and isinstance(old.raw_document, Mapping)
        and isinstance(new.raw_document, Mapping)
    ):
        raw_before = _canonical_document(old.raw_document)
        raw_after = _canonical_document(new.raw_document)
        equivalent = (
            str(old.raw_document.get("openapi", "")) != str(new.raw_document.get("openapi", ""))
            and isinstance(raw_before, Mapping)
            and isinstance(raw_after, Mapping)
            and _json({k: v for k, v in raw_before.items() if k != "openapi"})
            == _json({k: v for k, v in raw_after.items() if k != "openapi"})
            and _json(old.endpoint_contracts) == _json(new.endpoint_contracts)
        )
        # Nullable equivalence is canonicalized only for comparing equivalent
        # dialect representations. Other deltas retain their actual raw pointers.
        compared_before = (
            raw_before if equivalent else _canonical_raw(old.raw_document, old.raw_document)
        )
        compared_after = (
            raw_after if equivalent else _canonical_raw(new.raw_document, new.raw_document)
        )
        for parts in _raw_changes(compared_before, compared_after):
            pointer = "/" + "/".join(_pointer_part(part) for part in parts) if parts else ""
            # Recognized OAS dialect migration is equivalent only when complete
            # normalized documents and endpoint semantics otherwise agree.
            if parts == ("openapi",):
                left_version = str(old.raw_document.get("openapi", ""))
                right_version = str(new.raw_document.get("openapi", ""))
                if (
                    left_version.startswith(("3.0.", "3.1."))
                    and right_version.startswith(("3.0.", "3.1."))
                    and isinstance(raw_before, Mapping)
                    and isinstance(raw_after, Mapping)
                    and _json({k: v for k, v in raw_before.items() if k != "openapi"})
                    == _json({k: v for k, v in raw_after.items() if k != "openapi"})
                    and _json(old.endpoint_contracts) == _json(new.endpoint_contracts)
                    and not reasons
                ):
                    continue
            if not _pointer_classified(old, new, parts, classified):
                reasons.add(f"#{pointer} needs_review: unexplained raw-document change")
    elif old and new:
        reasons.add("# needs_review: raw-document evidence missing on one side")
    if not reasons:
        return []
    evidence = tuple(sorted(reasons))
    return [
        EndpointFinding(
            kind="CHANGED",
            endpoint="DOCUMENT #",
            implemented=False,
            breakage=True,
            write_capability=False,
            changes=evidence,
            breaking_changes=evidence,
        )
    ]


def diff_service(
    name: str,
    old: ServiceSpec | None,
    new: ServiceSpec | None,
    console_version: str | None = None,
    coverage: Mapping[str, frozenset[str]] | None = None,
) -> ServiceDiff:
    """Diff one service's baseline spec against its current spec."""
    implemented = (coverage or SPEC_COVERAGE).get(name, frozenset())
    try:
        findings = _endpoint_findings(old, new, implemented)
    except RecursionError:
        # Comparison could not complete; never crash and never report clean.
        findings = [_deep_nesting_finding("endpoint contracts")]
    return ServiceDiff(
        name=name,
        old_version=old.version if old else None,
        new_version=new.version if new else None,
        console_version=console_version,
        endpoint_findings=findings,
        service_added=old is None and new is not None,
        service_removed=old is not None and new is None,
        info_version=new.info_version if new else None,
    )


@dataclass(frozen=True)
class SpecDriftReport:
    """The full cross-service drift report between a baseline and current snapshot."""

    service_diffs: list[ServiceDiff] = field(default_factory=list)

    @property
    def drifted(self) -> list[ServiceDiff]:
        """Services with actionable drift (excludes informational console gaps)."""
        return [d for d in self.service_diffs if d.has_actionable_findings]

    @property
    def is_clean(self) -> bool:
        """True when no actionable drift exists. A standing console gap does not fail a run."""
        return not self.drifted

    @property
    def console_gaps(self) -> list[ServiceDiff]:
        """Services whose published version differs from the running console version."""
        return [d for d in self.service_diffs if d.console_gap]

    @property
    def new_services(self) -> list[str]:
        return sorted(d.name for d in self.service_diffs if d.service_added)

    @property
    def breakage_findings(self) -> list[tuple[str, EndpointFinding]]:
        out: list[tuple[str, EndpointFinding]] = []
        for d in self.service_diffs:
            for f in d.endpoint_findings:
                if f.breakage:
                    out.append((d.name, f))
        return out

    @property
    def write_capability_findings(self) -> list[tuple[str, EndpointFinding]]:
        out: list[tuple[str, EndpointFinding]] = []
        for d in self.service_diffs:
            for f in d.new_endpoints:
                if f.write_capability:
                    out.append((d.name, f))
        return out

    def _console_gap_lines(self) -> list[str]:
        gaps = self.console_gaps
        if not gaps:
            return []
        lines = ["Console/contract version gaps (informational — deployment vs. published):"]
        for d in sorted(gaps, key=lambda x: x.name):
            lines.append(
                f"  [{d.name}] published v{d.new_version}, console runs v{d.console_version}"
            )
        return lines

    def _spec_version_lines(self) -> list[str]:
        return [
            f"  [{d.name}] llms.txt {d.new_version}; info.version {d.info_version}"
            for d in sorted(self.service_diffs, key=lambda item: item.name)
            if d.new_version is not None and d.info_version is not None
        ]

    def summary(self) -> str:
        if self.is_clean:
            n = len(self.service_diffs)
            head = f"spec in sync: {n} published service(s) match the recorded baseline."
            gap_lines = [*self._spec_version_lines(), *self._console_gap_lines()]
            return "\n".join([head, *gap_lines]) if gap_lines else head
        lines = [
            f"SPEC DRIFT: {len(self.drifted)} of {len(self.service_diffs)} service(s) drifted."
        ]
        for d in sorted(self.drifted, key=lambda x: x.name):
            if d.service_added:
                lines.append(
                    f"  [{d.name}] NEW SERVICE in root index (v{d.new_version}) — "
                    "build-from-spec directive applies."
                )
                continue
            if d.service_removed:
                lines.append(f"  [{d.name}] REMOVED from root index (was v{d.old_version}).")
                continue
            header = f"  [{d.name}]"
            if d.version_changed:
                header += f" VERSION_DRIFT {d.old_version} -> {d.new_version}"
            if d.console_gap:
                header += (
                    f" | CONSOLE_GAP: published v{d.new_version}, console runs v{d.console_version}"
                )
            lines.append(header)
            for f in d.new_endpoints:
                tag = " (WRITE capability)" if f.write_capability else ""
                lines.append(f"      NEW      {f.endpoint}{tag}")
            for f in d.changed_endpoints:
                tag = " (BREAKAGE: implemented)" if f.breakage else ""
                tag = " (BREAKAGE: schema)" if f.breaking_changes else tag
                lines.append(f"      CHANGED  {f.endpoint}{tag}")
                for change in f.changes:
                    risk = " (BREAKAGE)" if change in f.breaking_changes else ""
                    lines.append(f"          {f.endpoint} {change}{risk}")
            for f in d.removed_endpoints:
                tag = " (BREAKAGE: implemented)" if f.breakage else ""
                lines.append(f"      REMOVED  {f.endpoint}{tag}")
        lines.extend(self._spec_version_lines())
        lines.extend(self._console_gap_lines())
        return "\n".join(lines)


def diff_snapshot(
    baseline: SpecSnapshot,
    current: SpecSnapshot,
    coverage: Mapping[str, frozenset[str]] | None = None,
) -> SpecDriftReport:
    """Diff a freshly fetched snapshot against the committed baseline.

    Console-version gaps are read from ``current.console_versions`` when present, else the
    baseline's (the checker's public-spec live mode does not touch the deployment, so the
    committed console observation is used unless a caller supplies a fresher one).
    """
    names = sorted(set(baseline.services) | set(current.services))
    diffs: list[ServiceDiff] = []
    for name in names:
        console_version = current.console_versions.get(name) or baseline.console_versions.get(name)
        diffs.append(
            diff_service(
                name,
                baseline.services.get(name),
                current.services.get(name),
                console_version=console_version,
                coverage=coverage,
            )
        )
    return SpecDriftReport(service_diffs=diffs)


def build_snapshot(
    root_index: Mapping[str, tuple[str, str]],
    openapi_docs: Mapping[str, object],
    console_versions: Mapping[str, str] | None = None,
    captured_at: str | None = None,
) -> SpecSnapshot:
    """Assemble a :class:`SpecSnapshot` from a parsed root index and fetched specs.

    ``root_index`` is :func:`parse_root_index` output; ``openapi_docs`` maps service slug
    to its parsed OpenAPI document. A service present in the index but absent from
    ``openapi_docs`` is skipped (its spec could not be fetched) rather than recorded as
    empty, so a transient fetch failure never masquerades as "all endpoints removed".
    """
    services: dict[str, ServiceSpec] = {}
    for name, (version, url) in root_index.items():
        if name not in openapi_docs:
            continue
        services[name] = build_service_spec(name, version, url, openapi_docs[name])
    return SpecSnapshot(
        services=services,
        console_versions={str(k).lower(): str(v) for k, v in (console_versions or {}).items()},
        captured_at=captured_at,
    )


#: Synthetic "deployment runs ahead of the published contract" derivation for the committed
#: baseline. On the EA channel the console genuinely runs a higher build than the published
#: spec, but the TRUE running build is a live deployment observation that must never be
#: persisted into the committed baseline fixture — that file reaches the public repository,
#: so a real, distinct console build sitting in it is an unintended disclosure. A
#: committed console version is therefore only ever one of two safe values: the
#: published version itself (which discloses nothing beyond the public spec), or a value
#: DERIVED from the published version — bump the minor by :data:`_CONSOLE_AHEAD_MINOR` and
#: pin the patch to :data:`_CONSOLE_AHEAD_PATCH`. The derivation's input is the public spec
#: version, so it can never coincide with a real build, yet it is deterministically
#: reproducible (a CI check asserts the committed baseline is a fixed point of the write-
#: boundary rule) and differs from the published version, keeping the CONSOLE_GAP path
#: exercised.
_CONSOLE_AHEAD_MINOR = 1
_CONSOLE_AHEAD_PATCH = 99


def synthetic_console_version(published_version: str) -> str:
    """Derive a synthetic "deployment is ahead" console build from a *published* spec version.

    Deterministic and public-input-only: for the usual ``major.minor.patch`` numeric dotted
    form, bump the minor by :data:`_CONSOLE_AHEAD_MINOR` and pin the patch to
    :data:`_CONSOLE_AHEAD_PATCH`, which guarantees a value ahead of — and always different
    from — ``published_version`` without ever reflecting a real console build. A version
    string that is not that numeric form falls back to a suffixed marker (still
    deterministic, still distinct from the input).
    """
    parts = published_version.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except (IndexError, ValueError):
        return f"{published_version}+ahead"
    return f"{major}.{minor + _CONSOLE_AHEAD_MINOR}.{_CONSOLE_AHEAD_PATCH}"


def synthesize_console_versions(
    console_versions: Mapping[str, str],
    services: Mapping[str, ServiceSpec],
) -> dict[str, str]:
    """Normalise console observations so no real, distinct deployment build is ever persisted.

    This is the single normalisation applied at the baseline **write boundary** (see
    ``scripts/check_spec_drift.py``), common to every path that persists a baseline. For
    each service that carries a console observation AND is present in ``services``:

    * a value equal to that service's *published* version is kept verbatim — it discloses
      nothing beyond the public spec (no gap), and
    * any DISTINCT value is a potential live deployment observation and is replaced by the
      deterministic :func:`synthetic_console_version` of the published version, regardless
      of the magnitude the incoming observation held.

    An observation for a service not present in ``services`` has no published version to
    anchor a synthetic and is dropped (it is undiffable anyway). The result is a fixed point
    of this function, so re-running it on a normalised baseline is a no-op. Returns a new
    dict in sorted key order.
    """
    out: dict[str, str] = {}
    for name, observed in console_versions.items():
        spec = services.get(name)
        if spec is None:
            continue
        published = spec.version
        out[name] = observed if observed == published else synthetic_console_version(published)
    return dict(sorted(out.items()))


def known_service_slugs(*snapshots: SpecSnapshot) -> list[str]:
    """Union of service slugs across the given snapshots (sorted)."""
    slugs: set[str] = set()
    for snap in snapshots:
        slugs.update(snap.services)
    return sorted(slugs)


def coverage_gaps(
    snapshot: SpecSnapshot, coverage: Mapping[str, frozenset[str]] | None = None
) -> dict[str, list[str]]:
    """For each covered service, the published endpoints we do not yet implement.

    A pure convenience for the ``--emit`` view: it answers "of the endpoints published
    today, which does our declared coverage not include" without any diff against a
    baseline. Services with no coverage declaration are omitted.
    """
    cov = coverage or SPEC_COVERAGE
    gaps: dict[str, list[str]] = {}
    for name, spec in snapshot.services.items():
        if name not in cov:
            continue
        missing = sorted(set(spec.endpoints) - cov[name])
        gaps[name] = missing
    return gaps
