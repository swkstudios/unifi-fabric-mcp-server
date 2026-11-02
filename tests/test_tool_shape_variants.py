"""Independent pinned-spec coverage of required keys and enum values in outlines."""

from __future__ import annotations

import json
import re
from typing import Any

from tests import test_spec_conformance as sc
from unifi_fabric._tool_shapes_table import SHAPE_SOURCES

Path = tuple[str, ...]
Constraint = tuple[Path, str]
_TOKEN = re.compile(r"'[^']*'|[^\s{}\[\](),:?|&]+|[{}\[\](),:?|&]")


def _literal(token: str) -> str | None:
    if token.startswith("'"):
        return json.dumps(token[1:-1], sort_keys=True)
    try:
        value = json.loads(token)
    except ValueError:
        return None
    return json.dumps(value, sort_keys=True)


def _read_outline(
    text: str, path: Path, required: set[Path], enums: set[Constraint], definitions=None
) -> None:
    """Read property paths from the advertised grammar, independently of its renderer."""
    text, _, declarations = text.partition(" where ")
    if definitions is None:
        definitions = dict(part.split("=", 1) for part in declarations.split(";") if part)
    tokens = _TOKEN.findall(text)
    pos = 0

    def expression(at: Path, stops: set[str]) -> None:
        nonlocal pos
        while pos < len(tokens) and tokens[pos] not in stops:
            token = tokens[pos]
            pos += 1
            if token == "{":
                while tokens[pos] != "}":
                    name = tokens[pos]
                    pos += 1
                    optional = tokens[pos] == "?"
                    if optional:
                        pos += 1
                    assert tokens[pos] == ":", (text, tokens[pos:])
                    pos += 1
                    child = (*at, name)
                    if not optional:
                        required.add(child)
                    expression(child, {",", "}"})
                    if tokens[pos] == ",":
                        pos += 1
                pos += 1
            elif token == "(":
                expression(at, {")"})
                assert tokens[pos] == ")", text
                pos += 1
            elif token in definitions:
                _read_outline(definitions[token], at, required, enums, definitions)
            else:
                literal = _literal(token)
                if literal is not None:
                    enums.add((at, literal))

    expression(path, set())
    assert pos == len(tokens), text


def _advertised_constraints(schema: dict[str, Any], path: Path = ()):
    required: set[Path] = set()
    enums: set[Constraint] = set()
    description = schema.get("description", "")
    for match in re.finditer(r"Required: ([^.]+)\.|requires ([^;)]+)", description):
        for name in (match[1] or match[2]).split(", "):
            required.add((*path, name))
    for match in re.finditer(r"[Oo]ne of: (.*?)\.(?: |$)", description):
        for token in _TOKEN.findall(match[1]):
            literal = _literal(token)
            if literal is not None:
                enums.add((path, literal))
    if "Shape: " in description:
        _read_outline(description.split("Shape: ", 1)[1], path, required, enums)
    for name, child in schema.get("properties", {}).items():
        r, e = _advertised_constraints(child, (*path, name))
        required |= r
        enums |= e
    for child in ([schema["items"]] if "items" in schema else []) + schema.get("anyOf", []):
        r, e = _advertised_constraints(child, path)
        required |= r
        enums |= e
    return required, enums


def _spec_constraints(spec, raw, path: Path = (), seen=frozenset()):
    """Walk spec declarations, not generator fields/outline/variant helpers."""
    node = raw
    while "$ref" in node:
        ref = node["$ref"]
        if ref in seen:
            return set(), set()
        seen = seen | {ref}
        target = spec.doc
        for part in ref[2:].split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        node = {**target, **{k: v for k, v in node.items() if k != "$ref"}}
    required = {(*path, name) for name in node.get("required", [])}
    enums = {(path, json.dumps(v, sort_keys=True)) for v in node.get("enum", [])}
    children = [(child, (*path, name)) for name, child in node.get("properties", {}).items()]
    children += [(child, path) for child in node.get("allOf", [])]
    if "items" in node:
        children.append((node["items"], path))
    children += [(child, path) for key in ("oneOf", "anyOf") for child in node.get(key, [])]
    disc = node.get("discriminator", {})
    mapped_values = set()
    for label, ref in disc.get("mapping", {}).items():
        # Mapping labels name subtypes, but an explicit enum defines wire casing.
        values = node.get("properties", {}).get(disc["propertyName"], {}).get("enum", [])
        if values and label not in values:
            matches = [
                v
                for v in values
                if re.sub(r"\W|_", "", v).casefold() == re.sub(r"\W|_", "", label).casefold()
            ]
            assert len(matches) == 1, (label, values)
            label = matches[0]
        enums.add(((*path, disc["propertyName"]), json.dumps(label)))
        mapped_values.add(json.dumps(label))
        children.append(({"$ref": ref}, path))
    for child, at in children:
        r, e = _spec_constraints(spec, child, at, seen)
        required |= r
        enums |= e
    if mapped_values:
        # Only mapped labels are valid choices for the tag; a shared base enum can list more.
        tag_path = (*path, disc["propertyName"])
        enums = {e for e in enums if e[0] != tag_path or e[1] in mapped_values}
    return required, enums


def test_every_spec_variant_required_property_and_enum_is_advertised() -> None:
    tools, specs = sc._tools(), sc.specs()
    missing = {}
    checked = 0
    for key, source in sorted(SHAPE_SOURCES.items()):
        if source["classification"] != "shaped":
            continue
        name, arg = key.split(".")
        expected_required, expected_enums = _spec_constraints(
            specs[source["service"]], source["schema"]
        )
        required, enums = _advertised_constraints(tools[name].parameters["properties"][arg])
        absent = {
            "required": sorted(expected_required - required),
            "enums": sorted(expected_enums - enums),
        }
        if any(absent.values()):
            missing[key] = absent
        checked += 1
    assert checked == 40
    assert missing == {}, missing


def test_variant_refinements_of_common_fields_preserve_types_and_requiredness() -> None:
    from tests import tool_shapes_gen as gen

    spec = sc.specs()["network"]
    raw = {
        "type": "object",
        "properties": {"kind": {"type": "string"}, "config": {}, "same": {"type": "string"}},
        "discriminator": {"propertyName": "kind"},
        "oneOf": [
            {
                "properties": {
                    "kind": {"const": "ENTERPRISE"},
                    "config": {
                        "type": "object",
                        "required": ["profileId"],
                        "properties": {"profileId": {"type": "string", "enum": ["alpha", "beta"]}},
                    },
                    "same": {"type": "string"},
                },
                "required": ["kind", "config", "same"],
            },
            {"properties": {"kind": {"const": "PERSONAL"}}, "required": ["kind"]},
        ],
    }
    # Untagged oneOf/anyOf and mapped discriminators use the same constraints.
    for key in ("oneOf", "anyOf"):
        candidate = {**raw, key: raw["oneOf"]}
        if key == "anyOf":
            candidate.pop("oneOf")
        text = gen.outline(spec, candidate, frozenset())
        assert "config:{profileId:'alpha'|'beta'}" in text
        assert "same:string" in text
    mapped = {
        **raw,
        "discriminator": {
            "propertyName": "kind",
            "mapping": {"ENTERPRISE": "#/enterprise", "PERSONAL": "#/personal"},
        },
    }
    # Supply local references without depending on the production spec inventory.
    synthetic = sc.Spec(
        "test", {"enterprise": raw["oneOf"][0], "personal": raw["oneOf"][1]}, "urn:test:variants"
    )
    text = gen.outline(synthetic, mapped, frozenset())
    assert "config:{profileId:'alpha'|'beta'}" in text
    assert "same:(required)" in text
    synthetic.doc["enterprise"]["properties"]["kind"] = {
        "type": "string",
        "enum": ["legacy-enterprise", "enterprise"],
    }
    text = gen.outline(synthetic, mapped, frozenset())
    assert "kind:'legacy-enterprise'|'enterprise'" in text
    assert "kind:'enterprise'" in text
    assert "'ENTERPRISE'" not in text


def test_outline_factoring_preserves_every_path_and_enum() -> None:
    from tests import tool_shapes_gen as gen

    child = (
        "{mode:'T1'|'B',format:'string(uuid)',id:string(uuid),"
        "nested:{profile:string,requiredChoice:'x'|'y'}}"
    )
    original = "{T1:" + child + ",other?:" + child + ",third:" + child + "}"
    compact = gen.compact_outline(original)
    assert " where " in compact
    assert len(compact) < len(original)
    before_required, before_enums = set(), set()
    after_required, after_enums = set(), set()
    _read_outline(original, (), before_required, before_enums)
    _read_outline(compact, (), after_required, after_enums)
    assert (after_required, after_enums) == (before_required, before_enums)


def test_every_mapped_variant_has_a_satisfiable_tag_enum() -> None:
    from tests import tool_shapes_gen as gen

    checked = 0
    for spec in sc.specs().values():
        for name, node in spec.doc.get("components", {}).get("schemas", {}).items():
            disc = node.get("discriminator", {})
            if not disc.get("mapping"):
                continue
            tag, alts = gen.variants(spec, node)
            common, _ = gen.fields(spec, node, frozenset(), with_variants=False)
            text = gen.outline(spec, node, frozenset())
            for label, branch in alts:
                props, _ = gen.fields(spec, branch, frozenset(), with_variants=False)
                for declared in (common.get(tag), props.get(tag)):
                    if declared is None:
                        continue
                    field, _ = gen.resolve(spec, *declared)
                    if "enum" in field:
                        assert label in field["enum"], (spec.service, name, tag, label, field)
                    if "const" in field:
                        assert label == field["const"], (name, tag, label, field)
                # The label is the tagged literal, or a member of the tag's compacted enum.
                assert re.search(
                    rf"{re.escape(tag)}:(?:'[^']+'\|)*{re.escape(gen.lit(label))}", text
                ), (name, tag, label, text)
                checked += 1
    assert checked > 0


def test_protocol_mapping_uses_exact_pinned_wire_values() -> None:
    from tests import tool_shapes_gen as gen

    spec = sc.specs()["network"]
    shapes: dict[str, tuple[set[str], str]] = {}
    for family in ("IPv4", "IPv6", "IPv4 and IPv6"):
        node = spec.doc["components"]["schemas"][f"Firewall policy {family} named protocol"]
        tag, alts = gen.variants(spec, node)
        assert tag == "name"
        assert ("tcp", {"$ref": node["discriminator"]["mapping"]["TCP"]}) in alts
        text = gen.outline(spec, node, frozenset())
        assert "name:'tcp'" in text or "|'tcp'" in text
        assert "'TCP'" not in text
        props, _ = gen.fields(spec, node, frozenset(), with_variants=False)
        enum = gen.resolve(spec, *props["name"])[0]["enum"]

        def wire(key: str, enum: list[str] = enum) -> str:
            hits = [
                v
                for v in enum
                if re.sub(r"[^a-z0-9]", "", v.lower()) == re.sub(r"[^a-z0-9]", "", key.lower())
            ]
            assert len(hits) == 1, (key, hits)
            return hits[0]

        expected = {wire(key) for key in node["discriminator"]["mapping"]}
        assert {label for label, _ in alts} == expected
        assert len(alts) == len(expected) < len(enum)
        choices = set(re.findall(r"'([^']+)'", text))
        assert expected <= choices
        shapes[family] = ({label for label, _ in alts}, text)
    assert {f: len(v[0]) for f, v in shapes.items()} == {
        "IPv4": 48,
        "IPv6": 25,
        "IPv4 and IPv6": 19,
    }
    for family in ("IPv4 and IPv6", "IPv6"):
        names, text = shapes[family]
        assert "icmp" not in names and "'icmp'" not in text
    for family in ("IPv4 and IPv6", "IPv4"):
        names, text = shapes[family]
        assert "tcp_udp" not in names and "'tcp_udp'" not in text


def test_short_formatted_types_stay_inline() -> None:
    from tests import tool_shapes_gen as gen

    for kind in ("string(uuid)", "string(date)"):
        text = "{" + ",".join(f"field{i}:{kind}" for i in range(20)) + "}"
        assert gen.compact_outline(text) == text


def test_unmapped_enum_choices_are_dropped_and_mapped_subtype_fields_kept() -> None:
    from tests import tool_shapes_gen as gen

    spec = sc.Spec(
        "test",
        {"alpha": {"properties": {"payload": {"type": "string"}}, "required": ["payload"]}},
        "urn:test:unmapped",
    )
    node = {
        "properties": {"kind": {"enum": ["a", "b"]}},
        "discriminator": {"propertyName": "kind", "mapping": {"a": "#/alpha"}},
    }
    assert gen.outline(spec, node, frozenset()) == "{kind:'a',payload:string}"


def test_partial_enum_factoring_preserves_every_path_and_literal() -> None:
    from tests import tool_shapes_gen as gen

    shared = "'common-first'|'common-second'|'common-third'|'common-fourth'"
    original = "{one:'a'|" + shared + ",two:'b'|" + shared + "}"
    compact = gen.compact_outline(original)
    assert " where " in compact
    assert len(compact) < len(original)
    before_required, before_enums = set(), set()
    after_required, after_enums = set(), set()
    _read_outline(original, (), before_required, before_enums)
    _read_outline(compact, (), after_required, after_enums)
    assert (after_required, after_enums) == (before_required, before_enums)
    assert all(len(body) >= 16 for body in compact.split(" where ")[1].split(";"))
