"""Catalog-derived Carrier verification fallback must preserve successful write evidence."""

from __future__ import annotations

import functools
import inspect

import httpx

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests.test_cross_tool_invariants import _call, _FailedReadAfter
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.tools import carrier_fabric as cf


@functools.cache
def _lz_CARRIER_VERIFY_TOOLS():
    return sorted(
        name
        for name in cti.WRITE_TOOLS
        if inspect.isfunction(fn := getattr(cf, name, None))
        and "_after_write" in fn.__code__.co_names
    )


WRITE_EVIDENCE = {"syntheticWriteEvidence": {"accepted": True, "opaque": [1, 2, 3]}}


class _CarrierFallback(_FailedReadAfter):
    def __call__(self, request):
        response = super().__call__(request)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and response.is_success:
            # An opaque 200 write body triggers the documented GET fallback. The
            # transport log records the exact response returned to the real client.
            self.served[-1].body = WRITE_EVIDENCE
            return httpx.Response(response.status_code, json=WRITE_EVIDENCE)
        return response


def test_carrier_fallback_catalog_covers_existing_verifiers():
    assert {"assign_carrier_subscriber_plan", "detach_carrier_subscriber_host"} <= set(
        _lz_CARRIER_VERIFY_TOOLS()
    )


@lazy_parametrize("name", lambda: _lz_CARRIER_VERIFY_TOOLS())
@lazy_parametrize("fault", lambda: ["http", "rate_limit", "transport", "shape"])
@lazy_parametrize("scope", lambda: ["single", "multi", "capped"])
async def test_carrier_read_back_failure_keeps_write_evidence(monkeypatch, name, fault, scope):
    up = _CarrierFallback(mode=f"after_{fault}")
    keys = (
        [
            APIKeyConfig(key="synthetic-alpha", label="alpha"),
            APIKeyConfig(key="synthetic-beta", label="beta"),
        ]
        if scope == "multi"
        else None
    )
    env = {"UNIFI_PAGINATE_MAX_PAGES": "1"} if scope == "capped" else {}
    result = uh.result_payload(await _call(monkeypatch, name, up, env=env, keys=keys))
    assert up.writes(), (name, fault, scope)
    assert getattr(up, "failed_read_after_calls", 0), (name, fault, scope)
    assert result["response"] == WRITE_EVIDENCE
    assert result["readAfterError"]
    assert result["verified"] is None
    assert result["subscriber"] is None
