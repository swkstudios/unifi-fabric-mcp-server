"""Rule 19: private Protect verification failures preserve the actual write response.

The catalog and real UniFiClient/MockTransport harness are shared with the whole-tool
invariants. Verifying tools are discovered through their private-module call graph,
so adding a registered wrapper over a verifying helper automatically adds coverage.
"""

from __future__ import annotations

import functools
import inspect

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests.test_cross_tool_invariants import (
    TOOLS,
    _call,
    _FailedReadAfter,
)
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.tools import protect_private as pp


def _verifies(fn, seen=None):
    seen = set() if seen is None else seen
    fn = inspect.unwrap(fn)
    if not inspect.isfunction(fn) or fn in seen or fn.__module__ != pp.__name__:
        return False
    seen.add(fn)
    if "_verified" in fn.__code__.co_consts:
        return True
    return any(_verifies(fn.__globals__.get(name), seen) for name in fn.__code__.co_names)


@functools.cache
def _lz_VERIFYING_TOOLS():
    return sorted(name for name in cti.WRITE_TOOLS if _verifies(TOOLS[name].fn))


def test_private_verifying_catalog_has_all_existing_updates():
    assert {
        "update_camera_private",
        "update_nvr",
        "update_sensor_private",
        "clear_sensor_tamper",
        "unadopt_protect_device",
    } <= set(_lz_VERIFYING_TOOLS())


@lazy_parametrize("name", lambda: _lz_VERIFYING_TOOLS())
@lazy_parametrize("fault", lambda: (["http", "not_found", "rate_limit", "transport", "shape"]))
@lazy_parametrize("scope", lambda: (["single", "multi", "capped"]))
async def test_private_failed_read_after_preserves_write_evidence(monkeypatch, name, fault, scope):
    up = _FailedReadAfter(mode=f"after_{fault}")
    keys = (
        [
            APIKeyConfig(key="synthetic-alpha", label="alpha"),
            APIKeyConfig(key="synthetic-beta", label="beta"),
        ]
        if scope == "multi"
        else None
    )
    env = {"UNIFI_PAGINATE_MAX_PAGES": "1"} if scope == "capped" else {}
    result = await _call(monkeypatch, name, up, env=env, keys=keys)
    writes = up.writes()
    assert len(writes) == 1, (name, scope, writes)
    expected_method = (
        "DELETE"
        if name == "unadopt_protect_device"
        else "POST"
        if name == "clear_sensor_tamper"
        else "PATCH"
    )
    assert writes[0].method == expected_method
    assert writes[0].status == 200
    payload = uh.result_payload(result)
    assert payload["status"] == 200
    assert payload["body"] == writes[0].body, (name, fault, payload)
    if name == "unadopt_protect_device" and fault == "not_found":
        # A 404 on the read-after of a DELETE is the proof the device is gone.
        assert "readAfterError" not in payload, payload
        assert payload["changed"] is True and payload["noOp"] is False, payload
        assert payload["_verified"] is True and payload["_noOp"] is False, payload
        return
    assert payload["readAfterError"], (name, fault, payload)
    assert payload["_verified"] is None, (name, fault, payload)
    assert payload["_noOp"] is None, (name, fault, payload)
    if "noOp" in payload:
        assert payload["noOp"] is None
    if fault == "rate_limit":
        failed_reads = [r for r in up.served if r.method == "GET" and r.status == 429]
        assert len(failed_reads) == 6, (name, failed_reads)


def _reaches(fn, target, seen=None):
    seen = set() if seen is None else seen
    fn = inspect.unwrap(fn)
    if not inspect.isfunction(fn) or fn in seen or fn.__module__ != pp.__name__:
        return False
    seen.add(fn)
    if fn is target:
        return True
    return any(_reaches(fn.__globals__.get(name), target, seen) for name in fn.__code__.co_names)


@functools.cache
def _lz_SETTINGS_TOOLS():
    return sorted(name for name in cti.WRITE_TOOLS if _reaches(TOOLS[name].fn, pp._update))


def test_requested_leaf_noop_tests_cover_every_settings_update():
    """Every tool over the read-merge-PATCH helper is in the
    requested-leaf no-op / verify tests, so a new sibling cannot ship uncovered."""
    from tests import test_protect_private as tpp

    marks = tpp.test_unrequested_sibling_change_does_not_break_requested_leaf_noop.pytestmark
    covered = {v for mark in marks if mark.name == "parametrize" for v in mark.args[1]}
    assert _lz_SETTINGS_TOOLS(), "no settings update tools discovered"
    assert set(_lz_SETTINGS_TOOLS()) == covered
