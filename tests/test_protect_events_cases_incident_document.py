"""collect_protect_incident_evidence (protect_events_cases module): normalized Protect evidence.

The private events route is read with the shared offset drain; without cameras there is one
source, with cameras one source per camera. Documents are validated against the closed schema.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import server
from unifi_fabric.client import RateLimitError, UniFiConnectionError, UniFiHTTPError
from unifi_fabric.families.protect import protect_events_cases as pec
from unifi_fabric.shared_shapes import _incident_document as ie

HOST_ID = "host-001"
EVENTS = f"/v1/connector/consoles/{HOST_ID}/proxy/protect/api/events"
CAMERAS = f"/v1/connector/consoles/{HOST_ID}/proxy/protect/integration/v1/cameras"
RECORDED = Path(__file__).resolve().parent / "fixtures" / "recorded" / "protect"
RECORDED_EVENTS = json.loads((RECORDED / "protect_api_events.json").read_text())["body"]
START_S = 1_791_571_915  # the recorded request window
END_S = 1_791_575_515
CAM_A = "000000000000000000fa01b4"
CAM_B = "000000000000000000fa01c0"


@pytest.fixture()
def client():
    c = AsyncMock()
    c.paginate_max_pages = None
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    return r


def _get(events: Any = None, by_camera: dict[str, Any] | None = None, cameras: Any = None):
    """A fake GET: the camera list, and event pages (offset 0 only; later pages empty)."""

    async def get(path: str, *, key: Any = None, params: Any = None, **_: Any) -> Any:
        if path == CAMERAS:
            return cameras if cameras is not None else []
        assert path == EVENTS, path
        if params.get("offset", 0):
            return []
        body = events
        if by_camera is not None:
            body = by_camera[params["cameras"][0]]
        if isinstance(body, Exception):
            raise body
        return copy.deepcopy(body)

    return get


def _wire(client: Any, *args: Any, **kw: Any) -> None:
    """Serve the camera list on ``client.get`` and the events feed on ``client.request`` (the
    collector reads events through the status tap, which calls ``request``)."""
    client.get.side_effect = _get(*args, **kw)
    client.request.side_effect = _as_request(client.get.side_effect)


def _as_request(get: Any):
    async def request(method: str, path: str, **kw: Any) -> Any:
        assert method == "GET"
        return httpx.Response(200, json=await get(path, **kw))

    return request


async def _collect(client: Any, registry: Any, **kw: Any) -> Any:
    args = {"start": START_S, "end": END_S, **kw}
    return await pec._collect_protect_incident_evidence(
        client, registry, "h", args.pop("start"), args.pop("end"), **args
    )


async def test_recorded_protect_fixture_validates_against_the_closed_schema(client, registry):
    _wire(client, RECORDED_EVENTS)
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    assert (doc["product"], doc["status"], doc["causality"]) == (
        "protect",
        "complete",
        "not_assessed",
    )
    assert doc["scope"] == {"host_id": HOST_ID, "site": None}
    params = client.request.await_args_list[0].kwargs["params"]
    assert (params["start"], params["end"]) == (START_S * 1000, END_S * 1000)
    assert "cameras" not in params and "types" not in params
    assert [s["source_id"] for s in doc["sources"]] == ["protect.events"]
    starts = [r["time"]["epoch_ms"] for r in doc["records"]]
    assert starts == sorted(e["start"] for e in RECORDED_EVENTS)
    record = doc["records"][0]
    assert record["time"]["field"] == "start"
    assert record["evidence_id"] == f"protect.events|id|{record['provenance']['record_id']}"
    assert record["identity"]["entities"][0]["kind"] == "camera"
    assert record["attributes"]["product"] == "protect"
    text = json.dumps(doc)
    assert "messageRaw" not in text and "thumbnail" not in text and "description" not in text


async def test_repeated_collection_yields_identical_ids_and_order(client, registry):
    _wire(client, RECORDED_EVENTS)
    first = await _collect(client, registry)
    _wire(client, list(reversed(RECORDED_EVENTS)))
    second = await _collect(client, registry)
    first.pop("collected_at")
    second.pop("collected_at")
    assert first == second


async def test_one_failing_camera_yields_explicit_partial_evidence(client, registry):
    cams = [{"id": CAM_A, "name": "Front"}, {"id": CAM_B, "name": "Back"}]
    error = UniFiHTTPError("HTTP 500 from GET events: upstream failure", status=500)
    _wire(client, by_camera={CAM_A: RECORDED_EVENTS, CAM_B: error}, cameras=cams)
    doc = await _collect(client, registry, cameras=["Front", CAM_B], types=["smartAudioDetect"])
    ie.validate_document(doc)
    assert doc["status"] == "partial"
    good, failed = doc["sources"]
    assert good["source_id"] == f"protect.events.camera.{CAM_A}"
    assert good["scope"]["camera_id"] == CAM_A
    assert good["scope"]["event_types"] == ["smartAudioDetect"]
    assert failed["outcome"] == "unavailable"
    assert failed["failure"] == {
        "kind": "unavailable",
        "http_status": 500,
        "message": f"GET {EVENTS}: {error}",
    }
    event_calls = [c for c in client.request.await_args_list if c.args[1] == EVENTS]
    # Each camera is drained on its own (the bare feed is read until an empty page).
    order = [c.kwargs["params"]["cameras"][0] for c in event_calls]
    assert list(dict.fromkeys(order)) == [CAM_A, CAM_B]
    assert all(c.kwargs["params"]["types"] == ["smartAudioDetect"] for c in event_calls)


async def test_an_unexpected_answer_shape_is_parse_failed_with_the_status_and_the_request(
    client, registry
):
    private = "".join(["priv", "ate-event", "-text"])
    _wire(client, {"unexpectedShape": {"message": private}})
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    source = doc["sources"][0]
    assert (source["outcome"], doc["status"], doc["records"]) == ("parse_failed", "failed", [])
    failure = source["failure"]
    assert failure["http_status"] == 200  # the console answered; the body was unusable
    assert f"GET {EVENTS}" in failure["message"]
    assert "unexpectedShape" in failure["message"] and private not in failure["message"]


async def test_a_read_records_every_failure_including_an_unavailable_one(client, registry):
    # The Protect feed is a plain read: no outcome of it is uncertain, so a 5xx, a 429 and a
    # transport failure are each recorded as that source's failure and never raised.
    for error, kind in (
        (UniFiHTTPError("HTTP 503 from GET events", status=503), "unavailable"),
        (RateLimitError("Rate limited on GET events: HTTP 429"), "unavailable"),
        (UniFiConnectionError("connection reset"), "unavailable"),
    ):
        _wire(client, error)
        doc = await _collect(client, registry)
        assert doc["sources"][0]["outcome"] == kind
        assert f"GET {EVENTS}" in doc["sources"][0]["failure"]["message"]


async def test_non_object_events_are_counted_malformed_never_records(client, registry):
    events = [{"id": "000000000000000000000001", "type": "motion", "start": START_S * 1000}, 7]
    _wire(client, events)
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    counts = doc["sources"][0]["counts"]
    assert (counts["retrieved"], counts["records"], counts["malformed"]) == (2, 1, 1)
    assert "malformed_rows" in doc["sources"][0]["partial_reasons"]


async def test_out_of_window_missing_and_ambiguous_records_stay_uncertain(client, registry):
    events = [
        {
            "id": "000000000000000000000001",
            "type": "motion",
            "start": START_S * 1000 - 5000,
            "camera": CAM_A,
        },
        {"id": "000000000000000000000002", "type": "motion", "camera": CAM_A},
        {
            "id": "000000000000000000000003",
            "type": "motion",
            "start": "2026-10-09T05:00:00",
            "camera": CAM_A,
        },
        {
            "id": "000000000000000000000004",
            "type": "sensorOpened",
            "start": START_S * 1000 + 1,
            "camera": None,
            "sensor": None,
            "metadata": {"sensorId": {"text": "Door"}},
        },
    ]
    _wire(client, events)
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    by_id = {r["provenance"]["record_id"][-1]: r for r in doc["records"]}
    assert by_id["1"]["time"]["status"] == "out_of_window"
    assert by_id["2"]["time"]["status"] == "missing"
    assert by_id["3"]["time"]["status"] == "ambiguous_timezone"
    assert by_id["4"]["identity"]["status"] == "ambiguous"
    source = doc["sources"][0]
    assert source["counts"]["out_of_window"] == 1
    assert source["counts"]["untimed"] == 2
    assert source["outcome"] == "partial"


async def test_page_cap_truncation_is_reported(client, registry):
    client.paginate_max_pages = 1
    page = [
        {"id": f"{i:024x}", "type": "motion", "start": START_S * 1000 + i, "camera": CAM_A}
        for i in range(200)
    ]

    async def get(path: str, *, key: Any = None, params: Any = None, **_: Any) -> Any:
        return copy.deepcopy(page)

    client.request.side_effect = _as_request(get)
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    source = doc["sources"][0]
    assert source["pagination"]["truncated"] == "truncated"
    assert source["pagination"]["page_cap"] == 1
    assert source["coverage"]["window_coverage"] == "unknown"
    assert doc["status"] == "partial"


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"start": END_S, "end": START_S}, "must be after start"),
        ({"start": END_S, "end": START_S}, "nothing was sent"),
        ({"start": END_S, "end": END_S}, "swap start and end"),
        ({"cameras": []}, "names no source"),
        ({"types": []}, "names no source"),
    ],
)
async def test_invalid_input_is_refused_before_any_request(client, registry, kw, match):
    with pytest.raises(ValueError, match=match):
        await _collect(client, registry, **kw)
    registry.resolve_key_for_host.assert_not_awaited()
    client.get.assert_not_awaited()
    client.request.assert_not_awaited()


async def test_unknown_camera_fails_listing_the_cameras_before_any_event_read(client, registry):
    _wire(client, RECORDED_EVENTS, cameras=[{"id": CAM_A, "name": "Front"}])
    with pytest.raises(ValueError, match="Front"):
        await _collect(client, registry, cameras=["Garage"])
    assert [c.args[0] for c in client.get.await_args_list] == [CAMERAS]
    client.request.assert_not_awaited()


EPOCH_CASES = [
    ({"start": -1, "end": START_S}, [("EPOCH_SECONDS_NEGATIVE", "start", -1)]),
    (
        {"start": START_S, "end": 1_700_000_000_000},
        [("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "end", 1_700_000_000_000)],
    ),
    (
        {"start": START_S * 1000, "end": END_S * 1000},
        [
            ("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "start", START_S * 1000),
            ("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "end", END_S * 1000),
        ],
    ),
]


@pytest.mark.parametrize(("kw", "expected"), EPOCH_CASES)
async def test_a_negative_or_millisecond_bound_is_sent_with_a_warning(
    client, registry, kw, expected
):
    _wire(client, RECORDED_EVENTS)
    doc = await _collect(client, registry, **kw)
    ie.validate_document(doc)
    params = client.request.await_args_list[0].kwargs["params"]
    assert (params["start"], params["end"]) == (kw["start"] * 1000, kw["end"] * 1000)
    assert [(w["code"], w["argument"], w["value"]) for w in doc["_warnings"]] == expected


async def test_a_year_55840_bound_is_sent_and_the_document_validates(client, registry):
    _wire(client, RECORDED_EVENTS)
    doc = await _collect(client, registry, end=1_700_000_000_000)
    ie.validate_document(doc)
    window = doc["requested_window"]
    assert window["end"] is None and window["end_epoch_ms"] == 1_700_000_000_000_000
    assert doc["_warnings"][0]["argument"] == "end"


async def test_a_plausible_window_has_no_warnings_key(client, registry):
    _wire(client, RECORDED_EVENTS)
    assert "_warnings" not in await _collect(client, registry)


async def test_routes_to_the_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    keys: list[Any] = []

    async def _request(method: str, path: str, *, key: Any = None, **_: Any) -> Any:
        keys.append(key)
        return httpx.Response(200, json=[])

    multikey_client.request = AsyncMock(side_effect=_request)
    doc = await pec._collect_protect_incident_evidence(
        multikey_client, multikey_registry, "Beta-Branch", START_S, END_S
    )
    assert keys and {k.label for k in keys} == {"beta"}
    assert doc["status"] == "empty"


def _tool(name: str) -> Any:
    tools = asyncio.run(server.mcp.list_tools())
    return {t.name: t for t in tools}[name]


def test_tool_is_registered_read_only_with_described_params():
    tool = _tool("collect_protect_incident_evidence")
    assert tool.annotations.read_only_hint is True
    props = tool.parameters["properties"]
    assert set(props) == {"host", "start", "end", "cameras", "types"}
    assert all(p.get("description") for p in props.values())
    assert tool.parameters["required"] == ["host", "start", "end"]


def test_description_claims_no_causality():
    text = _tool("collect_protect_incident_evidence").description or ""
    assert "claims no cause" in text
    assert "not_assessed" in text
    assert not re.search(r"\b(caused by|root cause|correlat\w*)\b", text, re.IGNORECASE)
