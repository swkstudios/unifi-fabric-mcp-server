"""Every limit a vendored spec states in prose is traced and applied uniformly.

``tests.spec_limits_gen.prose_limit_candidates`` finds every limit-like sentence of a
request-side description (operation parameters and request-body schemas at any depth);
each must have a disposition in ``PROSE_LIMIT_DISPOSITIONS`` that holds:

* ``keyword`` -- the same schema node carries a value keyword (so the generated table has
  it);
* ``described`` -- the limit is in ``DESCRIBED_LIMITS`` (a parameter) or
  ``DESCRIBED_SCHEMA_LIMITS`` (a schema property, applied wherever a body reaches it);
* ``trimmed`` -- in ``TRIMMED_LENGTH_ARGS``;
* ``tool`` -- a named tool function checks it (the Carrier UTF-8 byte limits);
* ``not a limit`` / ``not a static limit`` -- with the reason.

A new prose limit in a spec bump fails here until it is classified.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import spec_limits_gen as gen
from tests import test_cross_tool_invariants as cti
from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import refusals
from unifi_fabric.tools import carrier_fabric

TOOLS = cti.TOOLS
_call = cti._call
_KEYWORDS = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength")


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


CANDIDATES = gen.prose_limit_candidates()


def test_every_prose_limit_has_a_disposition():
    missing = sorted(set(CANDIDATES) - set(gen.PROSE_LIMIT_DISPOSITIONS))
    stale = sorted(set(gen.PROSE_LIMIT_DISPOSITIONS) - set(CANDIDATES))
    assert not missing, f"prose limits with no disposition: {missing}"
    assert not stale, f"dispositions that are no longer prose limits: {stale}"
    assert len(CANDIDATES) >= 30  # the scan is not vacuous


def _node(service: str, location: str) -> dict[str, Any]:
    spec = sc.specs()[service]
    if location.startswith("#/"):
        return gen._pointer_target(spec, location)
    method, path, _param, name = location.split(" ", 3)
    item = spec.doc["paths"][path]
    for raw in [*(item.get("parameters") or []), *(item[method.lower()].get("parameters") or [])]:
        p = sc._resolve(spec, raw)[0]
        if p.get("name") == name:
            return sc._resolve(spec, p.get("schema") or {})[0]
    raise AssertionError(location)


@pytest.mark.parametrize(("service", "location"), sorted(gen.PROSE_LIMIT_DISPOSITIONS))
def test_disposition_holds(service, location):
    disposition = gen.PROSE_LIMIT_DISPOSITIONS[(service, location)]
    kind = disposition.split(":", 1)[0].split(" (", 1)[0]
    if kind.startswith("keyword"):
        node = _node(service, location)
        assert any(k in node for k in _KEYWORDS), (service, location, node)
    elif kind == "described":
        if "DESCRIBED_SCHEMA_LIMITS" in disposition:
            assert (service, location) in gen.DESCRIBED_SCHEMA_LIMITS
        else:
            operation, _sep, name = location.rpartition(" param ")
            path = operation.split(" ", 1)[1]
            assert any(
                src[0] == service and src[1] == path and src[2] == name
                for _limit, src in gen.DESCRIBED_LIMITS.values()
            ), (service, location)
    elif kind == "trimmed":
        assert any(v[0] == service for v in gen.TRIMMED_LENGTH_ARGS.values())
    elif kind == "tool":
        func = disposition.split(":", 1)[1].split("(", 1)[0].strip().split(".")[-1]
        assert callable(getattr(carrier_fabric, func, None)), disposition
    else:
        assert kind in ("not a limit", "not a static limit"), disposition


def test_described_schema_limits_quote_the_spec():
    gen._described_by_id.cache_clear()
    assert len(gen._described_by_id()) == len(gen.DESCRIBED_SCHEMA_LIMITS)


# ---------------------------------------------------------------- applied uniformly
_SENSOR_PROSE = [
    ("humiditySettings", 1, 99),
    ("lightSettings", 1, 503192),
    ("temperatureSettings", -39, 124),
]


@pytest.mark.parametrize(("group", "low", "high"), _SENSOR_PROSE)
async def test_sensor_high_threshold_prose_limit_applies_like_the_low_keyword(
    monkeypatch, group, low, high
):
    """highThreshold states its range only in prose, lowThreshold as keywords: both are
    checked the same way before any request."""
    name = "update_sensor"
    for field in ("lowThreshold", "highThreshold"):
        for bad in (low - 1, high + 1):
            args = {**tool_args.generated_args(TOOLS[name]), "settings": {group: {field: bad}}}
            up = uh.FakeUpstream()
            with pytest.raises(ToolError) as exc:
                await _call(monkeypatch, name, up, args)
            assert refusals.classify(str(exc.value)) is refusals.BY_ID["spec-limits"], exc.value
            assert not up.writes()
        args = {**tool_args.generated_args(TOOLS[name]), "settings": {group: {field: high}}}
        up = uh.FakeUpstream()
        await _call(monkeypatch, name, up, args)
        assert up.writes()


def _metadata_of(size: int) -> dict[str, str]:
    """A metadata object whose compact JSON is exactly ``size`` bytes."""
    skeleton = len(json.dumps({"k": ""}, separators=(",", ":")).encode())
    return {"k": "x" * (size - skeleton)}


@pytest.mark.parametrize("name", ["create_carrier_subscriber", "update_carrier_subscriber"])
async def test_carrier_metadata_byte_limit(monkeypatch, name):
    limit = carrier_fabric.METADATA_MAX_BYTES
    assert limit == 8192
    base = tool_args.generated_args(TOOLS[name])
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, {**base, "metadata": _metadata_of(limit + 1)})
    assert "8192" in str(exc.value) and refusals.classify(str(exc.value)) is not None
    assert not up.writes()
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, {**base, "metadata": _metadata_of(limit)})
    sent = [s.sent_json for s in up.writes()]
    assert sent and any((b or {}).get("metadata") == _metadata_of(limit) for b in sent), sent
