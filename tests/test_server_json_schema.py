"""Validation and contract tests for server.json and package identifiers."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SERVER_JSON = ROOT / "server.json"
SCHEMA_JSON = ROOT / "schemas" / "server.schema.json"
PYPROJECT_TOML = ROOT / "pyproject.toml"


def test_server_json_validates_against_vendored_schema():
    assert SERVER_JSON.is_file(), f"{SERVER_JSON} does not exist"
    assert SCHEMA_JSON.is_file(), f"{SCHEMA_JSON} does not exist"

    instance = json.loads(SERVER_JSON.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_JSON.read_text(encoding="utf-8"))

    validator = jsonschema.validators.validator_for(schema)(schema)
    errors = list(validator.iter_errors(instance))
    assert not errors, f"server.json schema validation failed: {[e.message for e in errors]}"


def test_every_server_json_package_identifier_has_matching_console_script():
    server_data = json.loads(SERVER_JSON.read_text(encoding="utf-8"))
    pyproject_data = tomllib.loads(PYPROJECT_TOML.read_text(encoding="utf-8"))

    scripts = pyproject_data.get("project", {}).get("scripts", {})

    for pkg in server_data.get("packages", []):
        if pkg.get("registryType") == "pypi":
            identifier = pkg.get("identifier")
            assert scripts[identifier] == scripts["unifi-fabric-mcp"]
            assert identifier in scripts, (
                f"server.json PyPI package identifier '{identifier}' has no matching "
                f"entry in pyproject.toml [project.scripts]: {list(scripts.keys())}"
            )


def test_authorization_header_declares_required_secret_variable():
    data = json.loads(SERVER_JSON.read_text())
    headers = [
        header
        for package in data["packages"]
        for header in package.get("transport", {}).get("headers", [])
        if header["name"] == "Authorization"
    ]
    assert headers
    for header in headers:
        variable = header["variables"]["MCP_BEARER_TOKEN"]
        assert variable["description"]
        assert variable["isRequired"] is True
        assert variable["isSecret"] is True
