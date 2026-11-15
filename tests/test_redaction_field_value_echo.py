"""A validation echo that names a credential field in a value is masked."""

from __future__ import annotations

import json
import logging

import pytest

from tests._synthetic_secrets import synth
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.redaction import REDACTION_MASK, mask_error_text, redact_credentials


@pytest.mark.parametrize("name_key", ["field", "fieldName", "property"])
@pytest.mark.parametrize("value_key", ["value", "rejectedValue"])
def test_the_echoed_value_is_masked_in_a_response(name_key, value_key):
    secret = synth("echo")
    body = {"errors": [{name_key: "x_passphrase", value_key: secret, "message": "too short"}]}
    out = redact_credentials(body)
    assert out["errors"][0][value_key] == REDACTION_MASK
    assert out["errors"][0]["message"] == "too short"


def test_a_non_credential_field_echo_is_unchanged():
    body = {"field": "name", "value": "Office VLAN"}
    assert redact_credentials(body) == body
    assert mask_error_text(json.dumps(body)) == json.dumps(body)


def test_the_echoed_value_is_masked_in_caller_facing_error_text():
    secret = synth("echo")
    text = "HTTP 400 from PUT /x: " + json.dumps({"field": "x_passphrase", "value": secret})
    masked = mask_error_text(text)
    assert secret not in masked
    assert REDACTION_MASK in masked


@pytest.mark.parametrize("redact", [False, True])
async def test_the_echoed_value_is_masked_in_the_write_error_log(tmp_path, caplog, redact):
    secret = synth("echo")
    client = UniFiClient(
        Settings(api_key="synthetic-only", audit_log=str(tmp_path / "a.log"), redact_secrets=redact)
    )
    body = json.dumps({"error": "invalid", "field": "x_passphrase", "value": secret})
    with caplog.at_level(logging.WARNING, logger="unifi_fabric.client"):
        client._audit_write("PUT", "/sites", "http_400", 400, upstream_error=body)
    await client.close()
    assert "upstream write error" in caplog.text
    assert secret not in caplog.text
