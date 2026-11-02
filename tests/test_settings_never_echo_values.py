"""No settings validator echoes the value it rejects.

A value pasted into the wrong variable may be a credential, so a rejected setting's
message names the variable, the requirement and the valid choices, never the value.
The property runs over EVERY field of every settings model (discovered from the model,
not listed by hand), each fed sentinel-bearing malformed values through the environment
-- the real path -- and requires that at least one of them is rejected, so the check can
never pass vacuously for a field. The runtime readers of the same variables (the boolean
switch parser, the tool-family filter, the audit sink) are covered too.
"""

from __future__ import annotations

import json

import pytest
from pydantic_settings import BaseSettings

from unifi_fabric import families, switches
from unifi_fabric.audit import AuditSink
from unifi_fabric.config import MCPTransportSettings, Settings

SENTINEL = "sk-SENTINEL-c0ffee9f3a7c"
#: A digits-only sentinel, for the integer settings (a numeric PIN or key).
DIGITS = "7319024561"

#: Malformed spellings, each carrying a sentinel. Every setting rejects at least one.
CANDIDATES = (
    SENTINEL,
    f"{SENTINEL} x",
    f"\x01{SENTINEL}",
    f"{SENTINEL}/@?#",
    f"-{DIGITS}",
    f"{DIGITS}x",
    f"{DIGITS}.5",
    f"ok,{SENTINEL} x",
    f"https://ok.example.com,{SENTINEL}/@?#",
)

#: Extra JSON candidates for the JSON-decoded settings.
JSON_CANDIDATES = (
    json.dumps([{"key": f"{SENTINEL} x", "label": "a"}]),
    json.dumps([{"key": "bad key", "label": SENTINEL}]),
    json.dumps([{"key": "first", "label": SENTINEL}, {"key": "second", "label": SENTINEL}]),
    json.dumps([{"key": "same", "label": SENTINEL}, {"key": "same", "label": "other"}]),
    json.dumps([{"key": "same", "label": "other"}, {"key": "same", "label": SENTINEL}]),
    json.dumps([{"key": "k", "label": "a", SENTINEL: 1}]),
    json.dumps([{"key": "k", "label": "a", "is_org_key": SENTINEL}]),
    json.dumps({"key": SENTINEL}),
    json.dumps([SENTINEL]),
)

MODELS: tuple[type[BaseSettings], ...] = (Settings, MCPTransportSettings)


def _env_name(model: type[BaseSettings], field: str) -> str:
    info = model.model_fields[field]
    if isinstance(info.validation_alias, str):
        return info.validation_alias
    return f"{model.model_config.get('env_prefix', '')}{field}".upper()


def _leaks(text: str) -> list[str]:
    """The sentinels found in ``text``, in any case (a parser may lower-case a value)."""
    folded = text.casefold()
    return [n for n in (SENTINEL, DIGITS, "SENTINEL") if n.casefold() in folded]


FIELDS = [(model, field) for model in MODELS for field in model.model_fields]


def test_the_property_covers_every_settings_field():
    assert {f for _m, f in FIELDS} >= {
        "allowed_origins",
        "allowed_hosts",
        "oauth_write_scope",
        "tool_families",
        "max_concurrency",
        "audit_log_format",
        "cache_ttl",
    }
    assert len(FIELDS) == sum(len(m.model_fields) for m in MODELS)


@pytest.mark.parametrize(("model", "field"), FIELDS, ids=[f"{m.__name__}.{f}" for m, f in FIELDS])
def test_no_rejected_setting_echoes_its_value(monkeypatch, model, field):
    env = _env_name(model, field)
    rejected = 0
    for value in CANDIDATES + (JSON_CANDIDATES if field == "api_keys" else ()):
        monkeypatch.setenv(env, value)
        try:
            model()
        except Exception as exc:  # noqa: BLE001 - every rejection type is checked
            rejected += 1
            text = f"{exc}\n{exc!r}"
            assert not _leaks(text), f"{env}={value!r} echoed in: {text}"
        monkeypatch.delenv(env)
    assert rejected, f"{env}: no candidate was rejected, the check would be vacuous"


@pytest.mark.parametrize(
    "value", ["0", f"-{DIGITS}", f"{DIGITS}x"], ids=["zero", "negative", "garbled"]
)
def test_integer_bound_message_keeps_name_and_requirement(monkeypatch, value):
    monkeypatch.setenv("UNIFI_MAX_CONCURRENCY", value)
    with pytest.raises(Exception) as exc:
        Settings()
    text = str(exc.value)
    assert "UNIFI_MAX_CONCURRENCY must be" in text
    assert ">= 1" in text
    assert not _leaks(text)


def test_allowlist_messages_keep_the_item_position(monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", f"ok.example.com,{SENTINEL}/x")
    with pytest.raises(Exception) as exc:
        MCPTransportSettings()
    assert "MCP_ALLOWED_HOSTS item 1 is not a host name" in str(exc.value)
    monkeypatch.delenv("MCP_ALLOWED_HOSTS")
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", f"{SENTINEL}")
    with pytest.raises(Exception) as exc:
        MCPTransportSettings()
    assert "MCP_ALLOWED_ORIGINS item 0 is not an origin" in str(exc.value)


def test_unknown_tool_families_are_counted_not_echoed(monkeypatch):
    monkeypatch.setenv("UNIFI_TOOL_FAMILIES", f"network,{SENTINEL}")
    with pytest.raises(Exception) as exc:
        Settings()
    text = str(exc.value)
    assert "UNIFI_TOOL_FAMILIES names unknown families (item 1 of the" in text
    assert "valid families: " in text and "network" in text
    assert not _leaks(text)


async def test_tool_family_filter_never_echoes_an_unknown_family():
    with pytest.raises(ValueError) as exc:
        await families.apply_tool_family_filter(object(), f"network,{SENTINEL}")  # type: ignore[arg-type]
    assert not _leaks(str(exc.value))
    assert "valid families" in str(exc.value)


@pytest.mark.parametrize("value", [SENTINEL, f"{SENTINEL} x", DIGITS])
def test_boolean_switch_parser_never_echoes(monkeypatch, value):
    with pytest.raises(ValueError) as exc:
        switches.parse_bool(value, "UNIFI_DRY_RUN")
    assert "UNIFI_DRY_RUN must be a boolean" in str(exc.value)
    assert not _leaks(str(exc.value))
    monkeypatch.setenv("UNIFI_READ_ONLY", value)
    with pytest.raises(ValueError) as exc:
        switches.env_flag("UNIFI_READ_ONLY", False)
    assert not _leaks(str(exc.value))


def test_audit_sink_format_error_never_echoes():
    with pytest.raises(ValueError) as exc:
        AuditSink(path="audit.log", fmt=SENTINEL)
    assert "UNIFI_AUDIT_LOG_FORMAT must be one of text, json" in str(exc.value)
    assert not _leaks(str(exc.value))


@pytest.mark.parametrize(
    "value",
    JSON_CANDIDATES[1:5],
    ids=["invalid-key", "duplicate-label", "duplicate-key-first", "duplicate-key-last"],
)
@pytest.mark.parametrize("source", ["environment", "direct"])
def test_api_key_label_errors_use_positions(monkeypatch, value, source):
    if source == "environment":
        monkeypatch.setenv("UNIFI_API_KEYS", value)
        kwargs = {}
    else:
        kwargs = {"api_keys": json.loads(value)}
    with pytest.raises(Exception) as exc:
        Settings(**kwargs)
    text = f"{exc.value}\n{exc.value!r}"
    assert not _leaks(text)
    assert "entry 0" in text or "entries 0, 1" in text
