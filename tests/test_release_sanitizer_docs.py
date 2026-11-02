"""Release data and documentation regressions."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "sanitizer_v", ROOT / ".github/scripts/check_fixtures_sanitization.py"
)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
KEYS = [
    "api_key",
    "apiKey",
    "api-key",
    "X-API-KEY",
    "token",
    "accessToken",
    "refresh_token",
    "secret",
    "clientSecret",
    "password",
    "x_passphrase",
    "privateKey",
    "psk",
    "sae_psk",
    "saePsk",
    "device_auth",
    "deviceAuth",
    "secret_key",
    "access_key",
    "sessionToken",
    "api_secret",
    "UNIFI_API_KEY",
    "controller_password",
    "service-passphrase",
    "service.private_key",
]


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("fmt", ["json", "yaml", "env", "toml", "jsonl"])
def test_credential_fields_across_fixture_formats(key, fmt):
    value = "synthetic-sensitive-value"
    if fmt == "json":
        text = json.dumps({"outer": [{"nested": {key: value}}]}, indent=2)
    elif fmt == "jsonl":
        text = json.dumps({"safe": 1}) + "\n" + json.dumps({key: value})
    elif fmt == "yaml":
        text = f"outer:\n  {key}: >-\n    {value}\n"
    elif fmt == "env":
        text = f"export {key}={value}\n"
    else:
        text = f'[section]\n"{key}" = "{value}"\n'
    assert gate.credential_hits(text), (key, fmt)
    assert value not in str(gate.credential_hits(text))


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "***REDACTED***",
        "xxxxxxxx",
        "Bearer ${API_KEY}",
        "<your-key>",
        "${API_KEY}",
        "token-0001",
        "YOUR_API_KEY",
        "YOUR_PASSWORD",
        "your-api-key-here",
        "example-api-key",
        "example-token",
        "example-secret",
        "example-password",
        "$(openssl rand -hex 32)",
    ],
)
def test_explicit_placeholders_are_allowed(value):
    assert gate.credential_hits(json.dumps({"apiKey": value})) == []


@pytest.mark.parametrize(
    "key",
    ["tokenCount", "secretEnabled", "passwordLength", "apiKeyRequired", "monkey", "tokenizer"],
)
def test_noncredential_keys_are_allowed(key):
    assert gate.credential_hits(json.dumps({key: "ordinary-value"})) == []


def test_documentation_matches_runtime_modes():
    readme = (ROOT / "README.md").read_text()
    assert "A preview never carries a secret:" not in readme
    generated = (ROOT / "scripts/gen_tools_doc.py").read_text()
    assert "separately gated and inactive by default" not in generated
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert "Results are the v2 tag object verbatim." not in changelog
    assert "return the Classic envelope." not in changelog


def test_every_runtime_credential_field_and_spelling_is_detected():
    from unifi_fabric.redaction import CREDENTIAL_FIELDS

    assert CREDENTIAL_FIELDS
    for key in CREDENTIAL_FIELDS:
        parts = key.split("_")
        spellings = {
            key,
            key.upper(),
            key.replace("_", "-"),
            parts[0] + "".join(p.title() for p in parts[1:]),
        }
        for spelling in spellings:
            assert gate.credential_hits(json.dumps({spelling: "synthetic-sensitive-value"})), (
                spelling
            )


@pytest.mark.parametrize("value", ["production-1234", "warehouse-key-1234", "password-1234"])
def test_arbitrary_numbered_credentials_are_not_placeholders(value):
    assert gate.credential_hits(json.dumps({"api_key": value}))


@pytest.mark.parametrize("value", ["secret-0001", "api-key-0001", "access-key-0001"])
def test_known_numbered_credential_placeholders_are_allowed(value):
    assert gate.credential_hits(json.dumps({"api_key": value})) == []


def test_boolean_credential_configuration_flag_is_not_material():
    assert gate.credential_hits(json.dumps({"radius_macacl_empty_password": False})) == []
    assert gate.credential_hits(json.dumps({"radius_macacl_empty_password": True})) == []


@pytest.mark.parametrize(
    "placeholder",
    ["<your-key>", "YOUR_API_KEY", "your-api-key-here", "example-token", "$(openssl rand -hex 32)"],
)
@pytest.mark.parametrize("fmt", ["json", "env", "yaml", "toml", "markdown"])
def test_documentation_placeholders_across_formats(placeholder, fmt):
    if fmt == "json":
        text = json.dumps({"apiKey": placeholder})
    elif fmt == "env":
        text = f'export UNIFI_API_KEY="{placeholder}"'
    elif fmt == "yaml":
        text = f'apiKey: "{placeholder}"'
    elif fmt == "toml":
        text = f'[auth]\napiKey = "{placeholder}"'
    else:
        text = "```json\n" + json.dumps({"apiKey": placeholder}) + "\n```"
    assert gate.credential_hits(text) == []


@pytest.mark.parametrize(
    "placeholder",
    ["<your-key>", "YOUR_API_KEY", "your-api-key-here", "example-token", "$(openssl rand -hex 32)"],
)
def test_placeholder_does_not_hide_other_material(placeholder):
    material = "-".join(["synthetic", "sensitive", "value"])
    # Check separate fields on one line and a placeholder inside a real value.
    assert gate.credential_hits(json.dumps({"apiKey": placeholder, "password": material}))
    assert gate.credential_hits(json.dumps({"apiKey": placeholder + material}))
    assert gate.credential_hits(f'export UNIFI_API_KEY="{placeholder}"\npassword={material}')


@pytest.mark.parametrize(
    "value",
    [
        "YOUR",
        "YOUR_KEY-with-extra-material",
        "example-real-material",
        "$(openssl rand -hex 32",
        "your-api-key-here-extra",
    ],
)
def test_near_placeholder_values_still_fail(value):
    assert gate.credential_hits(json.dumps({"apiKey": value}))


def test_readme_credential_examples_are_placeholders():
    assert gate.credential_hits((ROOT / "README.md").read_text()) == []


@pytest.mark.parametrize(
    "value",
    [
        "$(printf '" + "0123456789abcdef" * 4 + "')",
        "$(echo " + "ghp_" + "aB9c" * 9 + ")",
        "$(printf '" + "short" + "-password')",
        "$(helper --token=" + "aB9c" * 9 + ")",
        "$(helper " + "aB9c" * 4 + ")",
        "$(printf '<" + "aB9c" * 9 + ">')",
        "$(printf '" + "Bearer " + "aB9c" * 9 + "')",
    ],
)
@pytest.mark.parametrize("fmt", ["json", "env", "markdown"])
def test_shell_substitution_does_not_hide_literal_credentials(value, fmt):
    if fmt == "json":
        text = json.dumps({"apiKey": value})
    elif fmt == "env":
        text = f'export UNIFI_API_KEY="{value}"'
    else:
        text = "```json\n" + json.dumps({"apiKey": value}) + "\n```"
    hits = gate.credential_hits(text)
    assert hits
    assert value not in str(hits)


@pytest.mark.parametrize(
    "value",
    [
        "$(openssl rand -hex 32)",
        "$(openssl rand -base64 32)",
        "$(printf '%s' \"${API_TOKEN}\")",
        "$(echo example-token)",
        "$(printf '%s' $UNIFI_LONG_API_TOKEN_REFERENCE)",
        "$(echo secret-0001)",
    ],
)
def test_shell_substitution_without_literal_credentials_is_allowed(value):
    assert gate.credential_hits(json.dumps({"apiKey": value})) == []
