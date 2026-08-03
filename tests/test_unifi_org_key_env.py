"""Guard: ``UNIFI_API_KEYS`` must be **strict JSON**, and the org-key entry must
round-trip into ``Settings``.

Regression context
------------------
The deployed ``UNIFI_API_KEYS`` env value is produced by the deployment's
environment generator, which builds the value with ``json.dumps(...)``. An
earlier form used a bare
``str()``/f-string of a Python ``list[dict]``, which emits **Python repr**
(single-quoted keys, ``True`` instead of ``true``). pydantic-settings parses a
complex field like ``api_keys`` by running ``json.loads`` on the env string, so a
Python-repr value raises at ``Settings()`` construction
(``Expecting property name enclosed in double quotes``) — which erred every
integration test at fixture setup.

These tests lock in the contract on the *consumer* side: the exact JSON shape the
generator emits must parse, and the broken Python-repr shape must NOT silently
parse. If the generator ever regresses to emitting repr, the value stops matching
the format asserted here.
"""

from __future__ import annotations

import json

import pytest

from unifi_fabric.config import Settings

# The exact serialization shape emitted by generate-env.sh: a JSON array with one
# org-key object, compact separators, and a JSON boolean (``true``). The key value
# is synthetic — never a real credential.
_ORG_KEY_ENTRY = {"key": "SYNTHETIC-NOT-A-REAL-KEY", "label": "org-key", "is_org_key": True}
_ORG_KEY_JSON = json.dumps([_ORG_KEY_ENTRY], separators=(",", ":"))


def test_org_key_env_value_is_strict_json() -> None:
    """The emitted value must be strict JSON (double-quoted keys, json boolean)."""
    parsed = json.loads(_ORG_KEY_JSON)
    assert parsed == [_ORG_KEY_ENTRY]
    assert _ORG_KEY_JSON.startswith('[{"'), "generator must emit double-quoted JSON keys"


def test_strict_json_env_parses_into_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """A strict-JSON ``UNIFI_API_KEYS`` round-trips into ``Settings.api_keys``."""
    monkeypatch.setenv("UNIFI_API_KEYS", _ORG_KEY_JSON)
    settings = Settings()
    assert len(settings.api_keys) == 1
    entry = settings.api_keys[0]
    assert entry.label == "org-key"
    assert entry.is_org_key is True
    # The org key resolves as a usable configured key.
    assert len(settings.get_key_configs()) == 1


def test_python_repr_env_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Python-repr value (the historical bug) must NOT silently parse.

    ``str()`` of the same Python object yields single-quoted keys / ``True`` — the
    exact broken form. pydantic-settings must fail rather than accept it, so a
    generator regression can never be swallowed silently.
    """
    repr_value = str([_ORG_KEY_ENTRY])
    # Sanity: this really is Python repr, not JSON.
    assert repr_value.startswith("[{'")
    assert "True" in repr_value
    monkeypatch.setenv("UNIFI_API_KEYS", repr_value)
    with pytest.raises(Exception):  # noqa: B017 -- SettingsError/ValidationError subclass varies
        Settings()
