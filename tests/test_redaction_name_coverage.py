"""Derive opt-in redaction coverage from every pinned schema and recorded key."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from unifi_fabric.redaction import (
    CREDENTIAL_FIELDS,
    REDACTION_MASK,
    drop_masked_fields,
    is_credential_field,
    redact_credentials,
)
from unifi_fabric.redaction_nonsecrets import NONSECRET_FIELDS

ROOT = Path(__file__).resolve().parents[1]
CREDENTIAL_NAME = re.compile(
    r"(?i)(password|passwd|passphrase|secret|psk|token|auth|private|credential|apikey|api_key|_key$|^key$|certificate)"
)
SENTINEL = "synthetic-coverage-value"


def credential_name_sources(
    root: Path = ROOT, *, string_lists: dict[str, set[str]] | None = None
) -> dict[str, set[str]]:
    """Enumerate OpenAPI property/parameter names and every recorded JSON key.

    Component titles and security-scheme labels are OpenAPI document structure,
    not response fields. Recurse through all schemas, including composition and
    array items, without depending on today's service list or schema names.
    """
    found: dict[str, set[str]] = {}

    def remember(name, source, *, list_value=False):
        if isinstance(name, str) and CREDENTIAL_NAME.search(name):
            found.setdefault(name, set()).add(source)
            if list_value and string_lists is not None:
                string_lists.setdefault(name, set()).add(source)

    def schema_nodes(schema, document, seen=frozenset()):
        """Follow local schema references and composition without looping on cycles."""
        if not isinstance(schema, dict):
            return
        yield schema
        reference = schema.get("$ref")
        if reference and reference not in seen:
            assert reference.startswith("#/"), f"Unresolved schema reference: {reference}"
            target = document
            for part in reference[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
            yield from schema_nodes(target, document, seen | {reference})
        for composition in ("allOf", "anyOf", "oneOf"):
            for branch in schema.get(composition, []):
                yield from schema_nodes(branch, document, seen)

    def has_type(schema, name):
        declared = schema.get("type")
        return declared == name or isinstance(declared, list) and name in declared

    def string_list_schema(schema, document):
        for node in schema_nodes(schema, document):
            if has_type(node, "array"):
                for item in schema_nodes(node.get("items", {}), document):
                    if has_type(item, "string") or (
                        bool(item.get("enum"))
                        and all(isinstance(value, str) for value in item["enum"])
                    ):
                        return True
        return False

    def walk(node, source, *, spec, document):
        if isinstance(node, dict):
            if spec:
                for name, schema in node.get("properties", {}).items():
                    remember(
                        name,
                        source + "/properties/" + name,
                        list_value=string_list_schema(schema, document),
                    )
                if node.get("in") in ("query", "path", "header", "cookie"):
                    remember(
                        node.get("name"),
                        source + "/name",
                        list_value=string_list_schema(node.get("schema", {}), document),
                    )
            for key, value in node.items():
                location = source + "/" + key
                if not spec:
                    remember(
                        key,
                        location,
                        list_value=isinstance(value, list)
                        and all(isinstance(item, str) for item in value),
                    )
                walk(value, location, spec=spec, document=document)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{source}/{index}", spec=spec, document=document)

    for directory, spec in (("openapi", True), ("recorded", False)):
        files = sorted((root / "tests/fixtures" / directory).rglob("*.json"))
        assert files, f"No {directory} JSON inputs found under {root}"
        for path in files:
            document = json.loads(path.read_text())
            walk(document, path.relative_to(root).as_posix(), spec=spec, document=document)
    return found


def assert_name_coverage(
    sources: dict[str, set[str]], string_lists: dict[str, set[str]] | None = None
) -> None:
    """Fail with every unknown name, its source and the classification options."""
    failures = []
    for name, locations in sorted(sources.items()):
        probes = [("string", SENTINEL, locations)]
        if string_lists and name in string_lists:
            probes.append(("string list", [SENTINEL], string_lists[name]))
        for shape, value, origins in probes:
            masked = (
                is_credential_field(name)
                and redact_credentials({name: value})[name] == REDACTION_MASK
            )
            if not masked and not NONSECRET_FIELDS.get(name, "").strip():
                failures.append(f"{name!r} ({shape}): " + ", ".join(sorted(origins)))
    assert not failures, (
        "Unclassified credential-like field names:\n"
        + "\n".join(failures)
        + "\nHint: add real credentials to CREDENTIAL_FIELDS (with string/list tests), "
        "or document a spec/recorded-field reason in redaction_nonsecrets.NONSECRET_FIELDS."
    )


def assert_fixture_name_coverage(root: Path = ROOT) -> None:
    string_lists: dict[str, set[str]] = {}
    sources = credential_name_sources(root, string_lists=string_lists)
    assert_name_coverage(sources, string_lists)


def test_pinned_and_recorded_credential_names_are_classified():
    assert_fixture_name_coverage()


@pytest.mark.parametrize("directory", ["openapi", "recorded"])
def test_newly_pinned_or_recorded_unknown_name_fails_with_source_and_hint(tmp_path, directory):
    for folder in ("openapi", "recorded"):
        path = tmp_path / "tests/fixtures" / folder / "new.json"
        path.parent.mkdir(parents=True)
        payload = {}
        if folder == directory:
            payload = {"newCredentialMaterial": "synthetic"}
            if folder == "openapi":
                payload = {
                    "allOf": [
                        {
                            "properties": {
                                "nested": {
                                    "items": {
                                        "properties": {"newCredentialMaterial": {"type": "string"}}
                                    }
                                }
                            }
                        }
                    ]
                }
        path.write_text(json.dumps(payload))
    with pytest.raises(AssertionError) as failure:
        assert_fixture_name_coverage(tmp_path)
    message = str(failure.value)
    assert "newCredentialMaterial" in message
    assert f"tests/fixtures/{directory}/new.json" in message
    assert "CREDENTIAL_FIELDS" in message and "redaction_nonsecrets" in message


def test_openapi_parameter_names_are_covered(tmp_path):
    for folder in ("openapi", "recorded"):
        path = tmp_path / "tests/fixtures" / folder / "new.json"
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "parameters": [
                        {"in": "header", "name": "futureAuthMaterial", "schema": {"type": "string"}}
                    ]
                }
                if folder == "openapi"
                else {}
            )
        )
    with pytest.raises(AssertionError, match="futureAuthMaterial"):
        assert_fixture_name_coverage(tmp_path)


@pytest.mark.parametrize(
    "value", [SENTINEL, [SENTINEL, "synthetic-second"], [], [{"password": SENTINEL, "vlan": 20}]]
)
@pytest.mark.parametrize("name", ["sae_psk", "device_auth"])
def test_explicit_secret_fields_mask_scalar_and_container_values(name, value, monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    assert name in CREDENTIAL_FIELDS
    original = {name: value, "enabled": True}
    masked = redact_credentials(original)
    assert masked == {name: REDACTION_MASK, "enabled": True}
    assert original[name] == value
    assert drop_masked_fields(masked) == ({"enabled": True}, [name])


@pytest.mark.parametrize("name", ["x_ssh_username", "x_paypal_username", "x_certificate_pem"])
def test_public_x_fields_are_never_credential_masked(name):
    for value in (SENTINEL, [SENTINEL]):
        assert not is_credential_field(name)
        assert redact_credentials({name: value}) == {name: value}


def test_recorded_ppsk_objects_keep_structure_and_mask_nested_passwords():
    path = ROOT / "tests/fixtures/recorded/network_classic/network_api_s_SITE_rest_wlanconf.json"
    payload = json.loads(path.read_text())
    rows = payload["body"]["data"]
    found = 0
    for row in rows:
        keys = row.get("private_preshared_keys", [])
        if keys:
            found += 1
            masked = redact_credentials({"private_preshared_keys": keys})
            assert isinstance(masked["private_preshared_keys"], list)
            assert len(masked["private_preshared_keys"]) == len(keys)
            for original, redacted in zip(keys, masked["private_preshared_keys"], strict=True):
                assert "password" in original
                assert redacted == {**original, "password": REDACTION_MASK}
    assert found, "The recorded PPSK fixture must exercise nested password coverage."


def test_nonsecret_registry_reasons_are_nonempty_single_lines_and_do_not_hide_secrets():
    assert "authorization" in NONSECRET_FIELDS
    for name, reason in NONSECRET_FIELDS.items():
        assert CREDENTIAL_NAME.search(name), name
        assert reason.strip() and "\n" not in reason, name
        assert not is_credential_field(name), name


@pytest.mark.parametrize("directory", ["openapi", "recorded"])
@pytest.mark.parametrize("list_value", [False, True])
def test_suffix_match_must_mask_the_observed_scalar_or_string_list(tmp_path, directory, list_value):
    # A suffix masks a scalar, but must not silently pass a newly discovered secret list.
    for folder in ("openapi", "recorded"):
        path = tmp_path / "tests/fixtures" / folder / "new.json"
        path.parent.mkdir(parents=True)
        payload = {}
        if folder == directory:
            if folder == "openapi":
                schema = (
                    {"type": "array", "items": {"type": "string"}}
                    if list_value
                    else {"type": "string"}
                )
                payload = {"properties": {"future_secret": schema}}
            else:
                payload = {"future_secret": [SENTINEL] if list_value else SENTINEL}
        path.write_text(json.dumps(payload))
    if list_value:
        with pytest.raises(AssertionError, match="future_secret.*string list") as failure:
            assert_fixture_name_coverage(tmp_path)
        assert f"tests/fixtures/{directory}/new.json" in str(failure.value)
    else:
        assert_fixture_name_coverage(tmp_path)


@pytest.mark.parametrize("wrapper", ["reference", "allOf", "anyOf", "oneOf"])
def test_referenced_and_composed_string_arrays_retain_list_probe(tmp_path, wrapper):
    schemas = {
        # Include a reference cycle to prove traversal terminates without a depth cap.
        "StringSecrets": {
            "allOf": [
                {"$ref": "#/components/schemas/StringSecrets"},
                {"type": "array", "items": {"$ref": "#/components/schemas/StringValue"}},
            ]
        },
        "StringValue": {"type": ["string", "null"]},
    }
    reference = {"$ref": "#/components/schemas/StringSecrets"}
    field = reference if wrapper == "reference" else {wrapper: [reference]}
    for folder in ("openapi", "recorded"):
        path = tmp_path / "tests/fixtures" / folder / "new.json"
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "components": {"schemas": schemas},
                    "properties": {"future_secret": field},
                }
                if folder == "openapi"
                else {}
            )
        )
    with pytest.raises(AssertionError, match="future_secret.*string list"):
        assert_fixture_name_coverage(tmp_path)
