"""Cross-tool invariants (Carrier empties, device wrappers, InnerSpace entries, relay writes).

1. A field the spec OMITS when empty compares equal to its empty value: Carrier
   ``metadata`` absent (or null) == ``{}`` in the no-op, ``changed`` and ``verified``
   checks; SubscriberPatch ``name`` is non-empty after trimming; the suspend ``reason`` is
   at most 1024 characters.
2. A ``/v1/devices`` console wrapper whose ``devices`` is present, non-null and not an
   array raises naming the shape, in every consumer (list_devices, list_all_devices,
   get_fleet_summary, search_device_fleet, the placement snapshot); null / absent stays
   the documented empty console.
3. InnerSpace ``shapes`` / ``plans`` entries that are not objects raise in the summary and
   device tools (their totals would otherwise be short) and are counted under
   ``_unprojected`` by the placement snapshot (``_withheld`` is redaction-only).
4. The connector relay never loses a sent write: every relay write tool, answered with a
   pathological Content-Type (transform codecs, non-text codecs, undecodable bytes),
   returns its status, the complete body (base64) and exactly one audit line; an
   exception anywhere after the write is reported under ``postWriteError``.
"""

from __future__ import annotations

import base64
import codecs
import json as _json
import logging
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError
from httpx import Response

from tests import test_cross_tool_invariants as cti
from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.tools import connector
from unifi_fabric.tools._device_wrappers import wrapper_devices
from unifi_fabric.tools.carrier_fabric import (
    CARRIER_BASE,
    suspend_carrier_subscriber,
    update_carrier_subscriber,
)

TOOLS = cti.TOOLS
_call = cti._call


def _args(name: str, **over: Any) -> dict[str, Any]:
    return {**tool_args.generated_args(TOOLS[name]), **over}


# =========================================================================== 1. carrier
BASE = "https://api.ui.com"
SID = "11111111-1111-4111-8111-111111111111"
SUB = f"{BASE}{CARRIER_BASE}/subscribers/{SID}"


def _subscriber(**over: Any) -> dict[str, Any]:
    record = {"id": SID, "subscriberNumber": "SN-1", "name": "Acme", "suspended": False}
    record.update(over)
    return {"data": record, "traceId": "t-1"}


@pytest.fixture()
def carrier(monkeypatch):
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
    return UniFiClient(Settings(api_key="sk-single"))


@respx.mock
@pytest.mark.parametrize("stored", ["absent", None, {}])
async def test_metadata_empty_object_equals_an_omitted_document(carrier, stored):
    before = _subscriber() if stored == "absent" else _subscriber(metadata=stored)
    respx.get(SUB).mock(return_value=Response(200, json=before))
    patch = respx.patch(SUB)
    result = await update_carrier_subscriber(carrier, SID, metadata={})
    assert result["status"] == "no_op"
    assert not patch.called


@respx.mock
async def test_emptying_metadata_verifies_against_the_omitted_key(carrier):
    respx.get(SUB).mock(return_value=Response(200, json=_subscriber(metadata={"k": 1})))
    # the spec omits metadata once it is empty: the read-after carries no key
    patch = respx.patch(SUB).mock(return_value=Response(200, json=_subscriber()))
    result = await update_carrier_subscriber(carrier, SID, metadata={})
    assert _json.loads(patch.calls[0].request.content) == {"metadata": {}}
    assert result["status"] == "updated"
    assert result["verified"] is True
    assert result["changed"] == {"metadata": {"from": {"k": 1}, "to": {}}}


@respx.mock
async def test_metadata_still_compares_by_value(carrier):
    respx.get(SUB).mock(return_value=Response(200, json=_subscriber()))
    respx.patch(SUB).mock(return_value=Response(200, json=_subscriber()))
    result = await update_carrier_subscriber(carrier, SID, metadata={"k": 1})
    assert result["status"] == "updated"
    assert result["verified"] is False  # the write did not take: never a false verified


@respx.mock
@pytest.mark.parametrize("name", ["", "   ", "\t\n"])
async def test_patch_name_is_non_empty_after_trimming(carrier, name):
    route = respx.route()
    with pytest.raises(ValueError, match="non-empty after trimming"):
        await update_carrier_subscriber(carrier, SID, name=name)
    assert not route.called


@respx.mock
async def test_suspend_reason_is_at_most_1024_characters(carrier):
    route = respx.route()
    with pytest.raises(ValueError, match="0-1024 characters"):
        await suspend_carrier_subscriber(carrier, SID, reason="r" * 1025)
    assert not route.called


@respx.mock
async def test_suspend_reason_at_1024_characters_is_sent(carrier):
    respx.get(SUB).mock(return_value=Response(200, json=_subscriber()))
    post = respx.post(f"{SUB}/suspend").mock(
        return_value=Response(200, json=_subscriber(suspended=True, suspendReason="é" * 1024))
    )
    result = await suspend_carrier_subscriber(carrier, SID, reason="é" * 1024)
    assert post.called and result["verified"] is True  # characters, not bytes


# =========================================================================== 2. wrappers
@pytest.mark.parametrize(
    ("wrapper", "devices"),
    [
        ({"hostId": "h", "devices": None}, []),
        ({"hostId": "h"}, []),
        ({"hostId": "h", "devices": []}, []),
        ({"hostId": "h", "devices": [{"id": "d"}]}, [{"id": "d"}]),
        ({"id": "d", "mac": "m"}, None),
    ],
)
def test_wrapper_documented_shapes(wrapper, devices):
    assert wrapper_devices(wrapper) == devices


@pytest.mark.parametrize("bad", [{"id": "d"}, "devices", 3, True])
def test_wrapper_non_array_devices_raises_naming_the_shape(bad):
    with pytest.raises(UniFiConnectionError, match="expected 'devices' to be an array or null"):
        wrapper_devices({"hostId": "h", "devices": bad})


class _BadWrapperUpstream(uh.FakeUpstream):
    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/devices":
            self._record(req, 200, None, False)
            body = {
                "data": [{"hostId": uh.HOST_ID, "hostName": uh.HOST, "devices": {"id": "x"}}],
                "httpStatusCode": 200,
                "traceId": "t",
            }
            return httpx.Response(200, json=body)
        return super().__call__(req)


@pytest.mark.parametrize(
    "tool",
    [
        "list_devices",
        "list_all_devices",
        "get_fleet_summary",
        "search_device_fleet",
        "get_unifi_placement_snapshot",
    ],
)
async def test_every_wrapper_consumer_raises_on_non_array_devices(monkeypatch, tool):
    logging.disable(logging.CRITICAL)
    try:
        with pytest.raises(ToolError) as exc:
            await _call(monkeypatch, tool, _BadWrapperUpstream(), sc.conformance_args(tool))
    finally:
        logging.disable(logging.NOTSET)
    assert "'devices' to be an array" in str(exc.value), str(exc.value)


# =========================================================================== 3. innerspace
class _ProjectUpstream(uh.FakeUpstream):
    def __init__(self, shapes: list[Any], plans: list[Any]) -> None:
        super().__init__(replay_recordings=False)
        self._shapes, self._plans = shapes, plans

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/proxy/innerspace/integration/v1/project"):
            self._record(req, 200, None, False)
            project = {
                "shapes": self._shapes,
                "plans": self._plans,
                "products": [],
                "wallTypes": [],
            }
            return httpx.Response(200, json={"data": project})
        return super().__call__(req)


_DEVICE = {"type": "device", "id": "s1", "position": [{"x": 1, "y": 2, "z": 0}]}
_PLAN = {"id": "p1", "name": "Ground", "ordering": 0}


@pytest.mark.parametrize(
    ("tool", "shapes", "plans", "where"),
    [
        ("get_innerspace_summary", [_DEVICE, "junk"], [_PLAN], "shapes[1]"),
        ("get_innerspace_summary", [_DEVICE], [_PLAN, None], "plans[1]"),
        ("list_innerspace_devices", [7, _DEVICE], [_PLAN], "shapes[0]"),
    ],
)
async def test_innerspace_totals_never_skip_a_malformed_entry(
    monkeypatch, tool, shapes, plans, where
):
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, tool, _ProjectUpstream(shapes, plans), _args(tool))
    assert where in str(exc.value) and "expected every" in str(exc.value), str(exc.value)


async def test_placement_snapshot_counts_non_object_entries(monkeypatch):
    up = _ProjectUpstream([_DEVICE, "junk", 3], [_PLAN, None])
    tool = "get_unifi_placement_snapshot"
    payload = uh.result_payload(await _call(monkeypatch, tool, up, sc.conformance_args(tool)))
    unprojected = payload["_unprojected"]
    assert unprojected["shapes.record"] == {"not_an_object": 2}
    assert unprojected["floors.record"] == {"not_an_object": 1}
    assert set(payload["_unprojected_how_to_obtain"]) == set(unprojected)
    assert "_withheld" not in payload and "_withheld_how_to_obtain" not in payload
    assert len(payload["placed_devices"]) == 1 and len(payload["floors"]) == 1


# =========================================================================== 4. relay
RELAY_WRITES = [
    "fabric_connector_post",
    "fabric_connector_put",
    "fabric_connector_patch",
    "fabric_connector_delete",
]

#: (Content-Type, body bytes): every charset here names no usable text character set, or
#: the bytes do not decode under it.
PATHOLOGICAL = [
    ("text/plain; charset=idna", b"\x00" + b"a" * 70),
    ("text/plain; charset=punycode", b"\xff\xfe"),
    ("text/plain; charset=unicode_escape", b"\\N{no such name}"),
    ("text/plain; charset=raw_unicode_escape", b"\\u12"),
    ("text/plain; charset=undefined", b"abc"),
    ("text/plain; charset=charmap", b"abc"),
    ("application/json; charset=rot13", b'{"a": 1}'),
    ("application/json; charset=base64", b"eyJhIjogMX0="),
    ("application/json; charset=zlib", b"x\x9c"),
    ("text/plain; charset=utf-16", b"\xff\xfeA"),
    ("text/plain; charset=utf-8", b"\xc3"),
    ("text/plain; charset=\x00", b"abc"),
]


class _RelayUpstream(uh.FakeUpstream):
    def __init__(self, content_type: str, raw: bytes) -> None:
        super().__init__()
        self._ct, self._raw = content_type, raw

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if "/proxy/network/integration/v1/sites/" in req.url.path and not uh.is_resolution(
            req.url.path
        ):
            self._record(req, 200, None, False)
            return httpx.Response(200, content=self._raw, headers={"content-type": self._ct})
        return super().__call__(req)


class _Audit(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if "connector-relay-audit" in record.getMessage():
            self.lines.append(record.getMessage())


async def _relay(monkeypatch, tool: str, up: uh.FakeUpstream) -> tuple[dict[str, Any], list[str]]:
    handler = _Audit()
    log = logging.getLogger(connector.__name__)
    log.addHandler(handler)
    original_level = log.level
    log.setLevel(logging.INFO)
    try:
        payload = uh.result_payload(await _call(monkeypatch, tool, up, sc.conformance_args(tool)))
    finally:
        log.removeHandler(handler)
        log.setLevel(original_level)
    return payload, handler.lines


def _writes(up: uh.FakeUpstream, tool: str) -> list[uh.Served]:
    method = tool.rsplit("_", 1)[1].upper()
    return [s for s in up.served if s.method == method]


@pytest.mark.parametrize("tool", RELAY_WRITES)
@pytest.mark.parametrize(("content_type", "raw"), PATHOLOGICAL)
async def test_relay_write_survives_a_pathological_content_type(
    monkeypatch, tool, content_type, raw
):
    up = _RelayUpstream(content_type, raw)
    payload, audit = await _relay(monkeypatch, tool, up)
    assert payload["status"] == 200
    assert payload["body"] is None
    assert base64.b64decode(payload["bodyBase64"]) == raw
    assert payload["sizeBytes"] == len(raw)
    assert "postWriteError" not in payload
    assert len(_writes(up, tool)) == 1
    assert len(audit) == 1 and "outcome=success" in audit[0], audit


@pytest.mark.parametrize("tool", RELAY_WRITES)
async def test_relay_write_outcome_survives_any_post_write_exception(monkeypatch, tool):
    def boom(_resp: Any) -> dict[str, Any]:
        raise RuntimeError("post-write processing failed")

    monkeypatch.setattr(connector, "_relay_body", boom)
    up = _RelayUpstream("application/json", b'{"ok": true}')
    payload, audit = await _relay(monkeypatch, tool, up)
    assert payload["status"] == 200
    assert payload["postWriteError"] == "RuntimeError: post-write processing failed"
    # confirm is accepted and ignored by policy, so no result reports it.
    assert "confirmed" not in payload
    assert base64.b64decode(payload["bodyBase64"]) == b'{"ok": true}'
    assert len(_writes(up, tool)) == 1
    assert len(audit) == 1 and "status=200" in audit[0], audit


@pytest.mark.parametrize(("content_type", "raw"), PATHOLOGICAL)
async def test_relay_get_survives_a_pathological_content_type(monkeypatch, content_type, raw):
    up = _RelayUpstream(content_type, raw)
    tool = "fabric_connector_get"
    payload = uh.result_payload(await _call(monkeypatch, tool, up, sc.conformance_args(tool)))
    assert payload["body"] is None and base64.b64decode(payload["bodyBase64"]) == raw


@pytest.mark.parametrize(
    ("content_type", "codec"),
    [
        ("text/plain; charset=latin-1", "latin-1"),
        ("text/plain; charset=UTF-8", "utf-8"),
        ("text/plain; charset=utf-7", "utf-7"),
        ("text/plain; charset=idna", connector._UNUSABLE),
        ("text/plain; charset=rot13", connector._UNUSABLE),
        ("text/plain; charset=no-such", connector._UNUSABLE),
        ("text/plain; charset=", None),
        ('text/plain; charset="', None),
        ("text/plain", None),
        (None, None),
    ],
)
def test_declared_codec_accepts_only_text_charsets(content_type, codec):
    if codec not in (None, connector._UNUSABLE):
        codec = codecs.lookup(codec).name
    assert connector._declared_codec(content_type) == codec


@pytest.mark.parametrize("tool", RELAY_WRITES)
async def test_relay_post_write_failure_under_dry_run_says_dry_run(monkeypatch, tool):
    def boom(_resp: Any) -> dict[str, Any]:
        raise RuntimeError("post-write processing failed")

    monkeypatch.setattr(connector, "_relay_body", boom)
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    up = _RelayUpstream("application/json", b"{}")
    payload, audit = await _relay(monkeypatch, tool, up)
    assert payload["status"] == "dry_run"
    assert "postWriteError" in payload
    assert _writes(up, tool) == []
    assert len(audit) == 1 and "outcome=dry_run" in audit[0], audit
