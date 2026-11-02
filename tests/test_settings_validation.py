"""Settings fail fast on values that would hang, raise later, or misroute a key.

Covers duplicate API key labels, the integer lower bounds, and empty-string-as-unset
for every bool/int ``UNIFI_*`` setting (consistent with ``UNIFI_READ_ONLY``).
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from unifi_fabric.config import Settings

_INT_ENV = {
    "UNIFI_MAX_CONCURRENCY": ("max_concurrency", 10),
    "UNIFI_CACHE_MAX_HOSTS": ("cache_max_hosts", 512),
    "UNIFI_CACHE_MAX_SITES": ("cache_max_sites", 2048),
    "UNIFI_PAGINATE_MAX_PAGES": ("paginate_max_pages", None),
    "UNIFI_CACHE_TTL_SECONDS": ("cache_ttl_seconds", 900),
}
_BOOL_ENV = {
    "UNIFI_ENABLE_CONNECTOR_WRITE": ("enable_connector_write", True),
    "UNIFI_DRY_RUN": ("dry_run", False),
    "UNIFI_REDACT_SECRETS": ("redact_secrets", False),
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in [*_INT_ENV, *_BOOL_ENV, "UNIFI_API_KEY", "UNIFI_API_KEYS"]:
        monkeypatch.delenv(name, raising=False)


# --- duplicate API key labels -----------------------------------------------------


def test_duplicate_key_labels_fail_fast_listing_the_positions(monkeypatch):
    keys = [
        {"key": "sk-canary-a", "label": "acme"},
        {"key": "sk-canary-b", "label": "acme"},
        {"key": "sk-canary-c", "label": "globex"},
        {"key": "sk-canary-d", "label": "globex"},
        {"key": "sk-canary-e", "label": "solo"},
    ]
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    with pytest.raises(ValidationError) as exc:
        Settings()
    msg = str(exc.value)
    assert "duplicate key labels at entries 0, 1, 2, 3" in msg
    assert "'solo'" not in msg
    # Neither label nor key values are echoed.
    assert "acme" not in msg and "globex" not in msg
    assert "sk-canary" not in msg


def test_unique_key_labels_construct(monkeypatch):
    keys = [{"key": "sk-a", "label": "acme"}, {"key": "sk-b", "label": "globex"}]
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    assert [c.label for c in Settings().get_key_configs()] == ["acme", "globex"]


def test_duplicate_labels_rejected_on_direct_construction():
    with pytest.raises(ValidationError, match="duplicate key labels at entries 0, 1"):
        Settings(api_keys=[{"key": "k1", "label": "x"}, {"key": "k2", "label": "x"}])


def test_validation_errors_never_echo_key_values(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps([{"key": "sk-canary-z", "label": 7}]))
    with pytest.raises(ValidationError) as exc:
        Settings()
    assert "sk-canary-z" not in str(exc.value)


@pytest.mark.parametrize("legacy", [None, 0, 30, 600, "30", "1.5", "retired-value"])
def test_deprecated_request_deadline_cannot_restore_an_elapsed_cap(monkeypatch, legacy):
    assert Settings().request_timeout_seconds is None
    if legacy is None:
        assert Settings(request_timeout_seconds=None).request_timeout_seconds is None
    else:
        with pytest.raises(ValidationError, match="setting removed; delete it"):
            Settings(request_timeout_seconds=legacy)
        monkeypatch.setenv("UNIFI_REQUEST_TIMEOUT_SECONDS", str(legacy))
        with pytest.raises(ValidationError, match="setting removed; delete it"):
            Settings()


# --- LOW-4: integer lower bounds ------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "value", "needle"),
    [
        ("UNIFI_MAX_CONCURRENCY", "0", "block every upstream request"),
        ("UNIFI_MAX_CONCURRENCY", "-3", "block every upstream request"),
        ("UNIFI_CACHE_MAX_HOSTS", "0", "host-cache write raise"),
        ("UNIFI_CACHE_MAX_SITES", "0", "site-cache write raise"),
        ("UNIFI_PAGINATE_MAX_PAGES", "0", "leave it unset for no page cap"),
        ("UNIFI_PAGINATE_MAX_PAGES", "-1", "leave it unset for no page cap"),
    ],
)
def test_below_one_fails_fast_with_actionable_message(monkeypatch, env, value, needle):
    monkeypatch.setenv(env, value)
    with pytest.raises(ValidationError) as exc:
        Settings()
    msg = str(exc.value)
    assert f"{env} must be >= 1: " in msg
    assert needle in msg


def test_negative_cache_ttl_fails_fast(monkeypatch):
    monkeypatch.setenv("UNIFI_CACHE_TTL_SECONDS", "-1")
    with pytest.raises(ValidationError, match=r"UNIFI_CACHE_TTL_SECONDS must be >= 0"):
        Settings()


def test_zero_cache_ttl_is_allowed(monkeypatch):
    monkeypatch.setenv("UNIFI_CACHE_TTL_SECONDS", "0")
    assert Settings().cache_ttl_seconds == 0


@pytest.mark.parametrize("env", sorted(_INT_ENV))
def test_non_integer_names_the_variable(monkeypatch, env):
    monkeypatch.setenv(env, "lots")
    with pytest.raises(ValidationError, match=rf"{env} must be a whole number"):
        Settings()


def test_bounds_also_apply_to_direct_construction():
    with pytest.raises(ValidationError, match="UNIFI_MAX_CONCURRENCY must be >= 1"):
        Settings(max_concurrency=0)


@pytest.mark.parametrize(
    ("env", "value"),
    [
        ("UNIFI_MAX_CONCURRENCY", "1"),
        ("UNIFI_CACHE_MAX_HOSTS", "1"),
        ("UNIFI_PAGINATE_MAX_PAGES", "1"),
        ("UNIFI_PAGINATE_MAX_PAGES", " 100000 "),
    ],
)
def test_lowest_valid_values_construct(monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    field, _default = _INT_ENV[env]
    assert getattr(Settings(), field) == int(value)


# --- LOW-4: empty string means unset --------------------------------------------------


@pytest.mark.parametrize("value", ["", "   "])
@pytest.mark.parametrize("env", sorted({**_INT_ENV, **_BOOL_ENV}))
def test_empty_value_is_treated_as_unset(monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    field, default = {**_INT_ENV, **_BOOL_ENV}[env]
    assert getattr(Settings(), field) == default


@pytest.mark.parametrize(
    ("env", "value", "expected"),
    [
        ("UNIFI_DRY_RUN", "1", True),
        ("UNIFI_DRY_RUN", " true ", True),
        ("UNIFI_REDACT_SECRETS", "on", True),
        ("UNIFI_ENABLE_CONNECTOR_WRITE", "0", False),
        ("UNIFI_ENABLE_CONNECTOR_WRITE", "off", False),
    ],
)
def test_set_bools_still_parse(monkeypatch, env, value, expected):
    monkeypatch.setenv(env, value)
    field, _default = _BOOL_ENV[env]
    assert getattr(Settings(), field) is expected
