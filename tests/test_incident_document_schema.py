"""The closed, versioned incident-evidence contract (shared_shapes/_incident_document.py).

Covers the committed JSON Schema, time parsing and window placement, identity status, stable
evidence ids and ordering, source outcomes and the document-level rules. The collectors are
tested in test_system_log_incident_document.py and test_protect_events_cases_incident_document.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from unifi_fabric.client import RateLimitError, ResponseShapeError, UniFiHTTPError
from unifi_fabric.secret_scrub import secret_scope
from unifi_fabric.shared_shapes import _incident_document as ie

ROOT = Path(__file__).resolve().parents[1]
RECORDED = ROOT / "tests" / "fixtures" / "recorded"

# 2025-10-11T00:00:00Z .. 01:00:00Z
START_S = 1_760_140_800
END_S = 1_760_144_400
WINDOW = ie.make_window(START_S * 1000, END_S * 1000)
IN_MS = START_S * 1000 + 5_000


def _recorded(name: str) -> Any:
    return json.loads((RECORDED / name).read_text())["body"]


def _scope(**extra: Any) -> ie.SourceScope:
    base: dict[str, Any] = {
        "host_id": "host-001",
        "site": "default",
        "log_class": "all",
        "camera_id": None,
        "event_types": None,
    }
    return ie.SourceScope(**{**base, **extra})


def _read(rows: list[Any], source: str = "all", **kw: Any) -> ie.SourceRead:
    return ie.SourceRead(
        source_id=f"network.system_log.{source}",
        route=f"POST /proxy/network/v2/api/site/{{site}}/system-log/{source}",
        scope=_scope(log_class=source),
        rows=rows,
        **kw,
    )


def _doc(reads: list[ie.SourceRead], rules: ie.ProductRules = ie.NETWORK_RULES) -> dict:
    return ie.build_document(
        rules=rules,
        host_id="host-001",
        site="default" if rules.product == "network" else None,
        window=WINDOW,
        reads=reads,
        page_cap=None,
    )


# --------------------------------------------------------------------------- schema


def test_committed_json_schema_matches_the_models() -> None:
    committed = json.loads((ROOT / ie.SCHEMA_PATH).read_text())
    assert committed == ie.schema_document(), (
        f"{ie.SCHEMA_PATH} is stale; regenerate it with: python -c 'import json; "
        "from unifi_fabric.shared_shapes._incident_document import schema_document as s; "
        f"print(json.dumps(s(), indent=2))' > {ie.SCHEMA_PATH}"
    )


def _objects(node: Any, path: str, out: list[tuple[str, dict]]) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" or "properties" in node:
            out.append((path, node))
        for key, value in node.items():
            _objects(value, f"{path}/{key}", out)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _objects(value, f"{path}/{i}", out)


def test_every_schema_object_is_closed_and_described() -> None:
    schema = ie.schema_document()
    objects: list[tuple[str, dict]] = []
    _objects(schema, "#", objects)
    assert len(objects) >= 15
    open_objects = [p for p, o in objects if o.get("additionalProperties") is not False]
    assert open_objects == []
    undescribed = [
        f"{p}.{name}"
        for p, o in objects
        for name, prop in o.get("properties", {}).items()
        if not prop.get("description")
    ]
    assert undescribed == []
    assert schema["properties"]["schema_version"]["const"] == 1
    assert schema["properties"]["causality"]["const"] == "not_assessed"


def test_unknown_keys_are_rejected_anywhere_in_the_document() -> None:
    doc = _doc(
        [_read(_recorded("network_v2/network_v2_api_site_SITE_system_log_all.json")["data"])]
    )
    ie.validate_document(doc)
    for mutate in (
        lambda d: d.update(extra=1),
        lambda d: d["sources"][0].update(raw={}),
        lambda d: d["records"][0]["attributes"].update(message_raw="x"),
        lambda d: d["records"][0]["time"].update(guess=True),
    ):
        bad = json.loads(json.dumps(doc))
        mutate(bad)
        with pytest.raises(ValidationError):
            ie.validate_document(bad)


# --------------------------------------------------------------------------- time


@pytest.mark.parametrize(
    ("value", "status", "epoch_ms", "precision", "original"),
    [
        (IN_MS, "in_window", IN_MS, "millisecond", "integer"),
        (START_S + 5, "in_window", (START_S + 5) * 1000, "second", "integer"),
        (float(IN_MS), "in_window", IN_MS, "millisecond", "float"),
        (str(IN_MS), "in_window", IN_MS, "millisecond", "string"),
        ("2025-10-11T00:00:05Z", "in_window", IN_MS, "second", "string"),
        ("2025-10-11T00:00:05.000Z", "in_window", IN_MS, "millisecond", "string"),
        ("2025-10-10T19:00:05-05:00", "in_window", IN_MS, "second", "string"),
        ("2025-10-11T00:00:05.000001+00:00", "in_window", IN_MS, "microsecond", "string"),
        (START_S * 1000, "in_window", START_S * 1000, "millisecond", "integer"),
        (END_S * 1000, "out_of_window", END_S * 1000, "millisecond", "integer"),
        (START_S * 1000 - 1, "out_of_window", START_S * 1000 - 1, "millisecond", "integer"),
        ("2025-10-11T00:00:05", "ambiguous_timezone", None, None, "string"),
        (None, "missing", None, None, "null"),
        ("soon", "malformed", None, None, "string"),
        (True, "malformed", None, None, "boolean"),
        (12345, "malformed", None, None, "integer"),
        (-IN_MS, "malformed", None, None, "integer"),
        (float("nan"), "malformed", None, None, "float"),
        ({"ms": IN_MS}, "malformed", None, None, "object"),
        ([IN_MS], "malformed", None, None, "array"),
    ],
)
def test_event_time_never_invents_a_time_or_precision(
    value: Any, status: str, epoch_ms: int | None, precision: str | None, original: str
) -> None:
    time = ie.parse_event_time({"timestamp": value}, "timestamp", WINDOW)
    assert (time.status, time.epoch_ms, time.precision, time.original_type) == (
        status,
        epoch_ms,
        precision,
        original,
    )
    assert (time.utc is None) == (epoch_ms is None)


def test_absent_time_is_missing_and_never_the_collection_time() -> None:
    time = ie.parse_event_time({"id": "x"}, "timestamp", WINDOW)
    assert (time.status, time.original_type, time.epoch_ms) == ("missing", "absent", None)


# --------------------------------------------------------------------------- identity


def test_network_identity_from_recorded_parameters_is_exact() -> None:
    row = _recorded("network_v2/network_v2_api_site_SITE_system_log_all.json")["data"][0]
    identity = ie.network_identity(row)
    assert identity.status == "exact"
    kinds = {(e.role, e.kind, e.id_kind) for e in identity.entities}
    assert ("SRC_CLIENT", "network_client", "mac") in kinds
    assert ("DEVICE", "network_device", "mac") in kinds
    assert ("DST_IP", "ip_address", "ip") in kinds
    # Names and non-MAC/IP ids (console names, initiator uuids) are never identities.
    assert not {e.role for e in identity.entities} & {"CONSOLE_NAME", "INITIATOR_ID"}


@pytest.mark.parametrize(
    ("parameters", "status"),
    [
        ({"NEIGHBOR": {"id": "02:00:5e:00:00:99"}}, "ambiguous"),
        ({"CLIENT": {"name": "laptop-name"}}, "missing"),
        ({"CLIENT": {"id": "laptop-name"}}, "missing"),
        (None, "missing"),
        (
            {"SRC_CLIENT": {"id": "02:00:5e:00:00:01"}, "DST_CLIENT": {"id": "02:00:5e:00:00:02"}},
            "exact",
        ),
    ],
)
def test_network_identity_never_guesses_a_role_or_a_name(parameters: Any, status: str) -> None:
    identity = ie.network_identity({"parameters": parameters})
    assert identity.status == status
    assert (identity.reason is None) == (status == "exact")


def test_protect_identity_camera_and_sensor() -> None:
    cam = "000000000000000000fa01b4"
    sensor = "000000000000000000fa01b9"
    exact = ie.protect_identity({"camera": cam, "metadata": {"sensorId": {"text": sensor}}})
    assert exact.status == "exact"
    assert [(e.kind, e.role) for e in exact.entities] == [
        ("camera", "camera"),
        ("sensor", "metadata.sensorId.text"),
    ]
    assert ie.protect_identity({"camera": "Front Door"}).status == "ambiguous"
    assert ie.protect_identity({"camera": None}).status == "missing"


# --------------------------------------------------------------------------- ids and order


def test_repeated_evidence_yields_stable_ids_and_order() -> None:
    rows = _recorded("network_v2/network_v2_api_site_SITE_system_log_all.json")["data"]
    rows = [dict(r, timestamp=IN_MS + i * 1000) for i, r in enumerate(rows)]
    first = _doc([_read(rows)])
    shuffled = [rows[i] for i in (2, 0, 1)]
    again = _doc([_read(shuffled)])
    assert [r["evidence_id"] for r in first["records"]] == [
        r["evidence_id"] for r in again["records"]
    ]
    assert first["records"] == again["records"]
    assert first["sources"] == again["sources"]
    assert [r["time"]["epoch_ms"] for r in first["records"]] == sorted(
        r["time"]["epoch_ms"] for r in first["records"]
    )
    assert first["records"][0]["evidence_id"] == ("network.system_log.all|id|" + rows[0]["id"])


def test_records_without_a_native_id_get_a_content_digest_id() -> None:
    rows = [{"key": "A", "timestamp": IN_MS}, {"key": "B", "timestamp": IN_MS}]
    ids = [r["evidence_id"] for r in _doc([_read(rows)])["records"]]
    assert ids == [r["evidence_id"] for r in _doc([_read(rows[::-1])])["records"]]
    assert all(i.startswith("network.system_log.all|sha256:") for i in ids)
    assert len(set(ids)) == 2


def test_untimed_records_sort_last_and_make_the_source_partial() -> None:
    rows = [
        {"id": "b", "timestamp": None},
        {"id": "a", "timestamp": "2025-10-11T00:00:05"},
        {"id": "c", "timestamp": IN_MS},
    ]
    doc = _doc([_read(rows)])
    assert [r["provenance"]["record_id"] for r in doc["records"]] == ["c", "a", "b"]
    source = doc["sources"][0]
    assert source["outcome"] == "partial"
    assert source["partial_reasons"] == ["untimed_records"]
    assert source["counts"]["untimed"] == 2
    assert doc["status"] == "partial"


def test_identical_repeats_are_dropped_and_conflicts_kept_and_flagged() -> None:
    rows = [
        {"id": "x", "key": "A", "timestamp": IN_MS},
        {"id": "x", "key": "A", "timestamp": IN_MS},
        {"id": "x", "key": "B", "timestamp": IN_MS},
    ]
    doc = _doc([_read(rows)])
    counts = doc["sources"][0]["counts"]
    assert (counts["retrieved"], counts["records"]) == (3, 2)
    assert (counts["duplicates_dropped"], counts["conflicting"]) == (1, 1)
    assert doc["sources"][0]["partial_reasons"] == ["conflicting_records"]
    ids = [r["evidence_id"] for r in doc["records"]]
    assert ids[0] == "network.system_log.all|id|x"
    assert ids[1].startswith("network.system_log.all|id|x|v:")


# --------------------------------------------------------------------------- sources


def test_window_pagination_and_retention_are_reported_truthfully() -> None:
    rows = [{"id": "a", "timestamp": IN_MS}, {"id": "o", "timestamp": END_S * 1000 + 1}]
    doc = _doc([_read(rows, upstream_total=2)])
    source = doc["sources"][0]
    assert source["outcome"] == "complete"
    assert source["coverage"]["queried_window"] == doc["requested_window"]
    assert source["coverage"]["window_coverage"] == "covered"
    assert source["coverage"]["observed_window"]["earliest_epoch_ms"] == IN_MS
    assert source["coverage"]["observed_window"]["latest_epoch_ms"] == IN_MS
    assert source["coverage"]["retention"] == "unknown"
    assert source["coverage"]["retention_reason"] == ie.RETENTION_REASON
    assert source["pagination"] == {
        "truncated": "not_truncated",
        "reason": None,
        "upstream_total": 2,
        "retrieved": 2,
        "page_cap": None,
    }
    assert (source["counts"]["in_window"], source["counts"]["out_of_window"]) == (1, 1)
    assert doc["requested_window"] == {
        "start": "2025-10-11T00:00:00.000Z",
        "end": "2025-10-11T01:00:00.000Z",
        "start_epoch_ms": START_S * 1000,
        "end_epoch_ms": END_S * 1000,
        "bounds": "half_open",
    }


def test_truncated_drain_is_partial_with_unknown_window_coverage() -> None:
    read = _read([{"id": "a", "timestamp": IN_MS}], incomplete=True, incomplete_reason="cap")
    doc = ie.build_document(
        rules=ie.NETWORK_RULES,
        host_id="host-001",
        site="default",
        window=WINDOW,
        reads=[read],
        page_cap=1,
    )
    source = doc["sources"][0]
    assert source["outcome"] == "partial"
    assert source["partial_reasons"] == ["truncated", "window_coverage_unknown"]
    assert source["coverage"]["window_coverage"] == "unknown"
    assert source["pagination"]["truncated"] == "truncated"
    assert (source["pagination"]["reason"], source["pagination"]["page_cap"]) == ("cap", 1)


def test_one_failing_source_is_explicit_partial_evidence_not_an_empty_success() -> None:
    failure = ie.Failure(kind="unsupported", http_status=404, message="HTTP 404 not found")
    good = _read([{"id": "a", "timestamp": IN_MS}])
    bad = _read([], source="triggers", failure=failure)
    doc = _doc([good, bad])
    assert doc["status"] == "partial"
    failed = doc["sources"][1]
    assert failed["outcome"] == "unsupported"
    assert failed["failure"] == failure.model_dump()
    assert failed["pagination"] is None
    assert failed["coverage"]["window_coverage"] == "not_covered"
    assert len(doc["records"]) == 1
    only_failed = _doc([bad])
    assert only_failed["status"] == "failed"
    assert only_failed["records"] == []


def test_empty_source_is_empty_not_complete() -> None:
    doc = _doc([_read([])])
    assert (doc["status"], doc["sources"][0]["outcome"]) == ("empty", "empty")


@pytest.mark.parametrize(
    ("outcomes", "status"),
    [
        (["complete"], "complete"),
        (["complete", "empty"], "complete"),
        (["empty", "empty"], "empty"),
        (["complete", "partial"], "partial"),
        (["complete", "unsupported"], "partial"),
        (["empty", "unavailable"], "partial"),
        (["unsupported", "permission_denied"], "failed"),
        ([], "partial"),
    ],
)
def test_overall_status(outcomes: list[str], status: str) -> None:
    assert ie.overall_status(outcomes) == status


def test_document_rules_reject_inconsistent_documents() -> None:
    rows = [{"id": "a", "timestamp": IN_MS}, {"id": "b", "timestamp": IN_MS + 1}]
    doc = _doc([_read(rows)])
    for mutate in (
        lambda d: d["records"].reverse(),
        lambda d: d.update(status="complete" if d["status"] != "complete" else "empty"),
        lambda d: d["sources"][0]["counts"].update(records=5),
        lambda d: d["records"][0].update(source_id="network.system_log.other"),
        lambda d: d["sources"][0].update(outcome="unsupported"),
        lambda d: d.update(causality="assessed"),
    ):
        bad = json.loads(json.dumps(doc))
        mutate(bad)
        with pytest.raises(ValidationError):
            ie.validate_document(bad)


# --------------------------------------------------------------------------- inputs


@pytest.mark.parametrize(
    ("start", "end", "match"),
    [
        (START_S, START_S, "must be after start"),
        (END_S, START_S, "must be after start"),
        (END_S, START_S, "nothing was sent"),
        (END_S, START_S, "swap start and end"),
        (True, END_S, "must be an integer"),
        ("1760140800", END_S, "must be an integer"),
        (START_S, None, "must be an integer"),
    ],
)
def test_evidence_window_refusals(start: Any, end: Any, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        ie.evidence_window("tool_x", start, end)


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, START_S), (START_S, END_S * 1000), (START_S * 1000, END_S * 1000), (-(10**12), -1)],
)
def test_evidence_window_sends_a_negative_or_millisecond_bound_unchanged(
    start: int, end: int
) -> None:
    window = ie.evidence_window("tool_x", start, end)
    assert (window.start_epoch_ms, window.end_epoch_ms) == (start * 1000, end * 1000)
    assert ie.Window.model_validate(window.model_dump()) == window


def test_window_iso_is_null_exactly_outside_years_1_to_9999() -> None:
    far = ie.evidence_window("t", START_S, 1_700_000_000_000)
    assert far.end is None and far.start is not None
    assert far.end_epoch_ms == 1_700_000_000_000_000
    early = ie.evidence_window("t", -(10**12), 0)
    assert early.start is None and early.end == "1970-01-01T00:00:00.000Z"
    assert ie.format_utc(-1) == "1969-12-31T23:59:59.999Z"
    assert ie.format_utc(ie.MIN_ISO_EPOCH_MS) == "0001-01-01T00:00:00.000Z"
    assert ie.format_utc(ie.MAX_ISO_EPOCH_MS) == "9999-12-31T23:59:59.999Z"
    assert ie.window_iso(ie.MAX_ISO_EPOCH_MS + 1) is None
    assert ie.window_iso(ie.MIN_ISO_EPOCH_MS - 1) is None
    with pytest.raises(ValidationError):
        ie.Window(start="2026-01-01T00:00:00.000Z", end=None, start_epoch_ms=0, end_epoch_ms=10**15)


def test_evidence_selectors() -> None:
    assert ie.evidence_selectors("t", "log_classes", None) is None
    assert ie.evidence_selectors("t", "log_classes", ["a", "b", "a"]) == ["a", "b"]
    with pytest.raises(ValueError, match="names no source"):
        ie.evidence_selectors("t", "log_classes", [])
    with pytest.raises(ValueError, match="must be a list of strings"):
        ie.evidence_selectors("t", "log_classes", ["a", 1])


@pytest.mark.parametrize(
    ("exc", "kind", "status"),
    [
        (UniFiHTTPError("HTTP 404 api.err.NotFound", status=404), "unsupported", 404),
        (UniFiHTTPError("HTTP 405", status=405), "unsupported", 405),
        (UniFiHTTPError("HTTP 403 forbidden", status=403), "permission_denied", 403),
        (UniFiHTTPError("HTTP 401", status=401), "auth_failed", 401),
        (UniFiHTTPError("HTTP 400 api.err.InvalidObject", status=400), "rejected", 400),
        (UniFiHTTPError("HTTP 502", status=502), "unavailable", 502),
        (RateLimitError("rate limited"), "unavailable", 429),
        (ResponseShapeError("bad field"), "parse_failed", None),
    ],
)
def test_capture_failure_classifies_and_keeps_the_upstream_text(
    exc: Exception, kind: str, status: int | None
) -> None:
    failure = ie.capture_failure(exc, None, method="POST", path="/x/y")
    assert (failure.kind, failure.http_status) == (kind, status)
    # The upstream text is kept whole; a message that does not name the request is prefixed.
    assert failure.message.endswith(str(exc))
    assert "POST /x/y" in failure.message


def test_capture_failure_does_not_repeat_a_request_the_message_already_names() -> None:
    exc = UniFiHTTPError("HTTP 404 from POST /x/y: gone", status=404)
    assert ie.capture_failure(exc, None, method="POST", path="/x/y").message == str(exc)


def test_capture_failure_reports_the_2xx_status_of_an_unusable_answer() -> None:
    shape = ResponseShapeError("Unexpected response shape from POST /x/y: got str")
    failure = ie.capture_failure(shape, None, method="POST", path="/x/y", answered=200)
    assert (failure.kind, failure.http_status) == ("parse_failed", 200)
    # A transport error carries no status even when an earlier page was answered.
    transport = UniFiHTTPError("connection reset", status=None)
    assert (
        ie.capture_failure(transport, None, method="POST", path="/x", answered=200).http_status
        is None
    )


def test_capture_failure_masks_configured_secrets() -> None:
    secret = "".join(["s3", "cr3t", "-valu", "e-for-scrub", "-test-0001"])
    with secret_scope([secret]):
        failure = ie.capture_failure(
            UniFiHTTPError(f"HTTP 500 {secret}", status=500), None, method="GET", path="/p"
        )
    assert secret not in failure.message
    assert failure.message.startswith("GET /p: HTTP 500 ")


@pytest.mark.parametrize(
    ("exc", "raises"),
    [
        (UniFiHTTPError("HTTP 500", status=500), True),
        (UniFiHTTPError("HTTP 502", status=502), True),
        (UniFiHTTPError("HTTP 503", status=503), True),
        (UniFiHTTPError("HTTP 504", status=504), True),
        (UniFiHTTPError("HTTP 599", status=599), True),
        (RateLimitError("HTTP 429"), True),
        (UniFiHTTPError("transport error", status=None), True),
        (UniFiHTTPError("HTTP 501", status=501), False),
        (UniFiHTTPError("HTTP 400", status=400), False),
        (UniFiHTTPError("HTTP 401", status=401), False),
        (UniFiHTTPError("HTTP 403", status=403), False),
        (UniFiHTTPError("HTTP 404", status=404), False),
        (UniFiHTTPError("HTTP 405", status=405), False),
        (UniFiHTTPError("HTTP 422", status=422), False),
        (ResponseShapeError("bad field"), False),
    ],
)
def test_a_write_collector_raises_on_an_uncertain_outcome_and_records_a_definite_one(
    exc: Exception, raises: bool
) -> None:
    assert ie.must_raise(exc, write=True) is raises
    # A read has no uncertain outcome: every failure is recorded.
    assert ie.must_raise(exc, write=False) is False


def test_an_unusable_2xx_answer_is_parse_failed_with_the_scrubbed_body_verbatim() -> None:
    secret = "".join(["s3", "cr3t", "-valu", "e-for-scrub", "-test-0002"])
    with secret_scope([secret]):
        scalar = ie.unusable_answer(
            f"accepted {secret}", None, method="POST", path="/p", status=200
        )
    assert (scalar.kind, scalar.http_status) == ("parse_failed", 200)
    assert "accepted " in scalar.message and secret not in scalar.message
    assert "POST /p" in scalar.message
    assert (
        "empty body" in ie.unusable_answer(None, None, method="POST", path="/p", status=204).message
    )
    assert (
        "JSON scalar: 42"
        in ie.unusable_answer(42, None, method="POST", path="/p", status=200).message
    )
    # An object is described by shape only: its values may be event data.
    drift = ie.unusable_answer(
        {"events": [{"message": "private text"}]}, None, method="POST", path="/p", status=200
    )
    assert "events" in drift.message and "private text" not in drift.message


# ---------------------------------------------------------------------------- native rows


def test_distinct_id_less_rows_with_equal_safe_fields_are_never_merged() -> None:
    rows = [
        {"key": "A", "timestamp": IN_MS, "message_raw": "first"},
        {"key": "A", "timestamp": IN_MS, "message_raw": "second"},
        {"key": "A", "timestamp": IN_MS, "message_raw": "second"},
    ]
    doc = _doc([_read(rows)])
    counts = doc["sources"][0]["counts"]
    # Two raw-distinct rows are two records; the exact repeat of the second is the one duplicate.
    assert (counts["retrieved"], counts["records"], counts["duplicates_dropped"]) == (3, 2, 1)
    ids = [r["evidence_id"] for r in doc["records"]]
    assert len(set(ids)) == 2
    assert sum(1 for i in ids if "|n:" in i) == 1
    # Stable across reads of the same drain.
    assert ids == [r["evidence_id"] for r in _doc([_read(rows)])["records"]]


def test_same_id_rows_differing_only_in_an_unkept_field_are_conflicting_not_duplicates() -> None:
    rows = [
        {"id": "x", "key": "A", "timestamp": IN_MS, "message_raw": "one"},
        {"id": "x", "key": "A", "timestamp": IN_MS, "message_raw": "two"},
        {"id": "x", "key": "A", "timestamp": IN_MS, "message_raw": "three"},
        {"id": "x", "key": "A", "timestamp": IN_MS, "message_raw": "three"},
    ]
    counts = _doc([_read(rows)])["sources"][0]["counts"]
    assert (counts["records"], counts["conflicting"], counts["duplicates_dropped"]) == (3, 2, 1)


def test_non_object_rows_are_counted_malformed_and_never_made_into_records() -> None:
    rows = [{"id": "a", "timestamp": IN_MS}, "text", 7, None, ["x"]]
    doc = _doc([_read(rows)])
    source = doc["sources"][0]
    counts = source["counts"]
    assert (counts["retrieved"], counts["records"], counts["malformed"]) == (5, 1, 4)
    assert (
        counts["records"] + counts["duplicates_dropped"] + counts["malformed"]
        == counts["retrieved"]
    )
    assert source["outcome"] == "partial" and "malformed_rows" in source["partial_reasons"]
    assert [r["provenance"]["record_id"] for r in doc["records"]] == ["a"]


# --------------------------------------------------------------------------- incomplete flag


def test_the_document_carries_the_repo_wide_incomplete_flag() -> None:
    whole = _doc([_read([{"id": "a", "timestamp": IN_MS}])])
    assert whole["incomplete"] is False and "incompleteReason" not in whole
    cut = ie.build_document(
        rules=ie.NETWORK_RULES,
        host_id="host-001",
        site="default",
        window=WINDOW,
        reads=[_read([{"id": "a", "timestamp": IN_MS}], incomplete=True, incomplete_reason="cap")],
        page_cap=1,
    )
    assert cut["incomplete"] is True
    assert cut["incompleteReason"] == "network.system_log.all: cap"
    # A failed source is not truncated: it is a failure, reported as one.
    failed = _doc([_read([], failure=ie.Failure(kind="rejected", http_status=400, message="m"))])
    assert failed["incomplete"] is False
    for mutate in (
        lambda d: d.update(incomplete=True),
        lambda d: d.update(incompleteReason="x"),
    ):
        bad = json.loads(json.dumps(whole))
        mutate(bad)
        with pytest.raises(ValidationError):
            ie.validate_document(bad)


# --------------------------------------------------------------------------- wrong type


def test_a_present_wrongly_typed_field_is_distinct_from_an_absent_one() -> None:
    rows = [
        {"id": "absent", "timestamp": IN_MS},
        {"id": "null", "timestamp": IN_MS + 1, "key": None},
        {"id": "wrong", "timestamp": IN_MS + 2, "key": 7, "severity": ["HIGH"], "type": "T"},
    ]
    by_id = {r["provenance"]["record_id"]: r["attributes"] for r in _doc([_read(rows)])["records"]}
    assert by_id["absent"]["wrong_typed_fields"] == []
    assert by_id["null"]["wrong_typed_fields"] == []
    assert by_id["wrong"]["wrong_typed_fields"] == ["key", "severity"]
    assert by_id["wrong"]["key"] is None and by_id["wrong"]["type"] == "T"


def test_protect_wrongly_typed_fields_are_listed_not_silently_nulled() -> None:
    rows = [
        {"id": "ok", "start": IN_MS, "score": 80, "smartDetectTypes": ["person"], "end": IN_MS + 1},
        {"id": "bad1", "start": IN_MS + 1, "score": "80", "smartDetectTypes": "person", "end": 1.5},
        {"id": "bad2", "start": IN_MS + 2, "score": float("inf"), "smartDetectTypes": ["a", 3]},
        {"id": "none", "start": IN_MS + 3, "score": None, "smartDetectTypes": None},
    ]
    doc = _doc([_read(rows, source="events")], ie.PROTECT_RULES)
    by_id = {r["provenance"]["record_id"]: r["attributes"] for r in doc["records"]}
    assert by_id["ok"]["wrong_typed_fields"] == []
    assert by_id["bad1"]["wrong_typed_fields"] == ["smartDetectTypes", "score", "end"]
    assert by_id["bad1"]["score"] is None and by_id["bad1"]["smart_detect_types"] is None
    assert by_id["bad2"]["wrong_typed_fields"] == ["smartDetectTypes", "score"]
    assert by_id["bad2"]["smart_detect_types"] == ["a"]
    assert by_id["none"]["wrong_typed_fields"] == []
