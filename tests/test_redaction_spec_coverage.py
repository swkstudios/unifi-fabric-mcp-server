"""Description-driven coverage of all vendored OpenAPI schema properties."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from unifi_fabric import route_secrets
from unifi_fabric.redaction import REDACTION_MASK, is_credential_field, redact_credentials
from unifi_fabric.secret_scrub import log_secret_values, scrub_log_text, secret_scope

ROOT = Path(__file__).parent / "fixtures"
MATERIAL = re.compile(r"secret|password|passphrase|private[ _-]?key|psk|token|key", re.IGNORECASE)
SENTINEL = "synthetic-spec-coverage-sentinel"

# Exact descriptions prevent a new credential with an existing benign name slipping through.
ALLOWLIST = {
    (
        "metadata",
        "Free-form key/value metadata. The serialized JSON object must not exceed "
        "8192 bytes (8 KiB); a larger object is rejected with 400.",
    ): "Free-form metadata object; key means a map member; children remain recursive.",
    (
        "metadata",
        "Free-form key/value metadata. A supplied object REPLACES the whole "
        "document. Absent leaves it unchanged, and so does JSON null - send an empty"
        " object to empty it. The serialized JSON must not exceed 8192 bytes (8 "
        "KiB); larger is rejected with 400.",
    ): "Free-form metadata object; key means a map member; children remain recursive.",
    (
        "code",
        "Stable machine-readable code, switch on this and never on the message text."
        " unauthorized: missing, malformed, unknown, expired or revoked API key",
    ): "Stable machine-readable error enum, not a credential.",
    (
        "code",
        "Stable machine-readable code, switch on this and never on the message text."
        " insufficient_scope: the key lacks the scope this endpoint requires",
    ): "Stable machine-readable error enum, not a credential.",
    (
        "code",
        "Stable machine-readable code, switch on this and never on the message text."
        " subscriber_not_found: unknown subscriber id, or out of scope for a group-"
        "restricted key",
    ): "Stable machine-readable error enum, not a credential.",
    (
        "code",
        "Stable machine-readable code, switch on this and never on the message text."
        " service_plan_not_found: unknown plan id for this organization; "
        "subscriber_not_found: unknown subscriber id, or out of scope for a group-"
        "restricted key",
    ): "Stable machine-readable error enum, not a credential.",
    (
        "code",
        "Stable machine-readable code, switch on this and never on the message text."
        " organization_not_found: your key's organization is not a registered ISP "
        "fabric; service_plan_not_found: unknown plan id for this organization",
    ): "Stable machine-readable error enum, not a credential.",
    (
        "groupRekeyIntervalSeconds",
        "Group rekey interval in seconds. Sets how often connected device groups are"
        " assigned a new key. If null, then it is disabled. This feature is not "
        "available for IoT configuration.",
    ): "Rekey interval in seconds, not key material.",
    ("presharedKeys", ""): "PPSK container; nested credentials are checked recursively.",
    ("presharedKeyNetworkIds", ""): "Network UUID list referencing PPSK networks.",
    ("modelKey", ""): "Protect model discriminator, not cryptographic key material.",
    (
        "channelCount",
        "If a capability key is absent (`undefined`), the capability should be "
        "treated as not supported. When present, a positive value indicates how many"
        " independent channels of that measurement or input the sensor exposes. For "
        "example, two temperature probes would report as two channels.",
    ): "Capability channel count; key means a schema member.",
    ("keypadSettings", ""): "Keypad settings container; nested properties are checked recursively.",
    ("hasKeypad", "Whether the device has a PIN keypad."): "Keypad capability boolean.",
    ("beepEnabled", "Whether a keypress beeps."): "Keypress sound enable boolean.",
    ("beepVolume", "Keypress beep volume, 0-100%."): "Keypress sound volume percentage.",
    (
        "inputToken",
        "The ONVIF token of the camera digital input",
    ): "ONVIF digital input identifier/container, not an authentication token.",
    (
        "nextToken",
        "Pagination token for fetching the next set of results",
    ): "Pagination cursor, not an authentication token.",
    ("hasKeypad", ""): "Keypad capability boolean.",
    ("inputToken", ""): "ONVIF digital input identifier/container, not an authentication token.",
    ("nextToken", ""): "Pagination cursor, not an authentication token.",
}


def collect(root):
    found = []

    def walk(node, source):
        if isinstance(node, dict):
            properties = node.get("properties", {})
            if isinstance(properties, dict):
                for name, schema in properties.items():
                    if not isinstance(schema, dict):
                        continue
                    description = schema.get("description", "")
                    if MATERIAL.search(name + " " + description):
                        found.append((name, description, source + "/properties/" + name))
            for name, value in node.items():
                walk(value, source + "/" + name)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{source}/{index}")

    for directory in ("openapi", "spec_drift"):
        files = sorted((root / directory).rglob("*.json"))
        assert files, directory
        for path in files:
            walk(json.loads(path.read_text()), str(path.relative_to(root)))
    return found


def assert_coverage(fields):
    unknown = []
    for name, description, source in fields:
        if is_credential_field(name):
            assert redact_credentials({name: SENTINEL})[name] == REDACTION_MASK
        elif (
            name == "code"
            and description == "Secret code to active the voucher using the Hotspot portal"
        ):
            # Option ii: voucher codes are returned unchanged but bound for log scrubbing.
            entries = [e for e in route_secrets.ROUTE_SECRETS if "code" in e.response_log_fields]
            assert entries
            for entry in entries:
                for method in entry.methods:
                    with secret_scope():
                        route_secrets.bind_response(
                            method,
                            entry.relay_path,
                            json.dumps({"code": SENTINEL}).encode(),
                            (("content-type", "application/json"),),
                            status_code=200,
                        )
                        assert SENTINEL in log_secret_values()
                        assert SENTINEL not in scrub_log_text(SENTINEL, log_secret_values())

        elif not ALLOWLIST.get((name, description), "").strip():
            unknown.append(f"{source}: {name}: {description}")
    assert not unknown, "Unclassified secret-like schema properties:\n" + "\n".join(unknown)


def test_vendored_schema_secret_coverage():
    fields = collect(ROOT)
    assert fields
    assert_coverage(fields)


@pytest.mark.parametrize("directory", ["openapi", "spec_drift"])
@pytest.mark.parametrize(
    "name,description",
    [
        ("newSecretMaterial", ""),
        ("innocuous", "Private key for authentication"),
        ("nextToken", "Secret password for authentication"),
    ],
)
def test_new_unclassified_property_fails(tmp_path, directory, name, description):
    for folder in ("openapi", "spec_drift"):
        path = tmp_path / folder / "spec.json"
        path.parent.mkdir()
        path.write_text(
            json.dumps({"properties": {name: {"description": description}}})
            if folder == directory
            else "{}"
        )
    with pytest.raises(AssertionError, match="Unclassified"):
        assert_coverage(collect(tmp_path))
