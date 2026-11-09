"""Every enumerated environment setting is read case-insensitively, edge whitespace ignored.

The enumerated settings are found by behaviour, not from a list: a setting is
enumerated when an unknown value is refused naming its variable with the closed set of
choices ("must be one of", the boolean spellings, the valid tool families). Each one
then loads its valid value written in upper case and padded with whitespace, to the
same value as the canonical spelling. ``MCP_OAUTH_ALGORITHM`` is the one exception: JWT
``alg`` values are case-sensitive, so a wrong-case algorithm is refused.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from tests.test_core_strict_readers_and_name_tiers import _BAD_SETTINGS
from unifi_fabric.config import MCPTransportSettings, Settings

#: field -> a valid value in its canonical spelling (every enumerated setting).
VALID: dict[str, str] = {
    "log_level": "WARNING",
    "audit_log_format": "json",
    "audit_sink": "stderr",
    "audit_level": "debug",
    "audit_calls": "true",
    "audit_log_mode": "0640",
    "auth_mode": "bearer",
    "tls_mode": "https",
    "tls_cert_reqs": "required",
    "oauth_algorithm": "ES256",
    "redact_secrets": "true",
    "host_origin_protection": "off",
    "tool_mode": "discovery",
    "write_policy": "deny",
    "family_allow": "network,protect",
    "health_route": "true",
}
#: Enumerated settings whose values are case-sensitive by definition.
#: The policy settings are case-sensitive lower-case by contract (policy grammar).
CASE_SENSITIVE = {"oauth_algorithm", "write_policy", "family_allow"}

#: Values another setting needs for a valid combination (keyed by the field under test).
_COMPANIONS: dict[str, dict[str, str]] = {
    "auth_mode": {"MCP_BEARER_TOKEN": "probe-bearer-token-0123456789"},
    "tls_mode": {"MCP_TLS_CERTFILE": "/probe/cert.pem", "MCP_TLS_KEYFILE": "/probe/key.pem"},
    "tls_cert_reqs": {
        "MCP_TLS_MODE": "mtls",
        "MCP_TLS_CERTFILE": "/probe/cert.pem",
        "MCP_TLS_KEYFILE": "/probe/key.pem",
        "MCP_TLS_CA_CERTS": "/probe/ca.pem",
    },
}
_CHOICE_MARKERS = ("must be one of", "must be a boolean", "valid families")


def _model(field: str) -> Any:
    return Settings if field in Settings.model_fields else MCPTransportSettings


def _load(monkeypatch, field: str, value: str) -> Any:
    env = _BAD_SETTINGS[field][0]
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    for k, v in _COMPANIONS.get(field, {}).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv(env, value)
    return getattr(_model(field)(), field)


def _enumerated_fields() -> set[str]:
    found: set[str] = set()
    for field, (env, _bad) in _BAD_SETTINGS.items():
        saved = os.environ.get(env)
        os.environ[env] = "probe-not-a-choice"
        try:
            _model(field)()
        except Exception as exc:  # noqa: BLE001 - the refusal text is what is inspected
            text = str(exc)
            if f"{env} " in text and any(m in text for m in _CHOICE_MARKERS):
                found.add(field)
        finally:
            if saved is None:
                del os.environ[env]
            else:
                os.environ[env] = saved
    return found


def test_the_table_covers_every_enumerated_setting(monkeypatch):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    found = _enumerated_fields()
    assert len(found) >= 10, found
    assert found == set(VALID), {"missing": found - set(VALID), "extra": set(VALID) - found}


def _shouted(value: str) -> str:
    return f"  {value.swapcase()}\t "


def _meaning(field: str, value: Any) -> Any:
    """What a loaded value means (every enumerated setting is kept as loaded)."""
    return value


@pytest.mark.parametrize("field", sorted(set(VALID) - CASE_SENSITIVE))
def test_an_enumerated_setting_ignores_case_and_edge_whitespace(monkeypatch, field):
    canonical = _meaning(field, _load(monkeypatch, field, VALID[field]))
    assert _meaning(field, _load(monkeypatch, field, _shouted(VALID[field]))) == canonical


@pytest.mark.parametrize("field", sorted(CASE_SENSITIVE))
def test_a_case_sensitive_setting_refuses_another_case(monkeypatch, field):
    assert _load(monkeypatch, field, VALID[field]) == VALID[field]
    with pytest.raises(ValueError, match=_BAD_SETTINGS[field][0]):
        _load(monkeypatch, field, VALID[field].swapcase())
