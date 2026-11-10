"""Normalized incident evidence: a closed, versioned document built from native event reads.

This module performs no I/O. The two collectors (``collect_network_incident_evidence`` in
:mod:`.system_log` and ``collect_protect_incident_evidence`` in :mod:`.protect_events_cases`)
read the native Network system-log and Protect event routes with the shared drain helpers and
hand each source's rows (or its failure) to :func:`build_document`, which returns the document
as plain JSON data validated against :class:`IncidentEvidence`.

The native event tools are unchanged and stay the verbatim view of each record; this document
is a derived view that keeps a small, explicit set of safe fields, the native record id and the
source it came from, so a caller can go back to the native record.

Contract (``schema_name`` ``unifi-fabric-incident-evidence``, ``schema_version`` 1):

* Windows are half-open, ``start <= t < end``, in UTC epoch milliseconds.
* Collection time never stands in for event time. A missing, malformed or timezone-less
  timestamp is an explicit time status, and such a record sorts after every timed record.
* Identity comes only from exact identifiers in known fields (a MAC, an IP address, a Protect
  camera or device id). Names and nearby timestamps never establish an identity, and nothing
  is matched across products.
* Each source reports its own outcome. A failed source is a failure state with its HTTP
  status, never an empty result, and it makes the document ``partial`` (``failed`` when every
  source failed). A drain stopped by the opt-in page cap is ``truncated`` and partial.
* Retention is never claimed: neither product reports its oldest retained event, so every
  source's retention coverage is ``unknown``.
* Records are ordered by event time, then product, source, native record id and evidence id.
  Order is chronology only; the document makes no causal claim (``causality`` is always
  ``not_assessed``).
* Evidence ids are stable: the same native record read from the same source always gets the
  same id (the native id when the record has one, else a digest of its normalized fields).

Design credit: the normalized incident-evidence reference of sirkirby/unifi-mcp (Chris Kirby
and contributors, MIT licence). This is an independent implementation; no code was copied.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final, Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..client import ResponseShapeError, decode_body, describe_shape, upstream_error_value
from ..macs import colon_mac, is_mac
from ..read_post_routes import is_read_post, read_post
from ..secret_scrub import scrub

SCHEMA_NAME: Final = "unifi-fabric-incident-evidence"
SCHEMA_VERSION: Final = 1

#: The committed JSON Schema of :class:`IncidentEvidence` (repo-relative).
SCHEMA_PATH = "schemas/incident-document.v1.schema.json"

#: Why no source can claim retention coverage (the same text on every source).
RETENTION_REASON = (
    "The controller does not report its oldest retained event, so an event that occurred in "
    "the window but was already discarded cannot be detected."
)

Product = Literal["network", "protect"]
TimeStatus = Literal["in_window", "out_of_window", "missing", "malformed", "ambiguous_timezone"]
OriginalType = Literal["absent", "null", "string", "integer", "float", "boolean", "object", "array"]
Precision = Literal["second", "millisecond", "microsecond"]
EntityKind = Literal[
    "network_client", "network_device", "network_station", "ip_address", "camera", "sensor"
]
IdKind = Literal["mac", "ip", "protect_camera_id", "protect_device_id"]
IdentityStatus = Literal["exact", "ambiguous", "missing"]
FailureKind = Literal[
    "unsupported", "permission_denied", "auth_failed", "rejected", "unavailable", "parse_failed"
]
SourceOutcome = Literal[
    "complete",
    "empty",
    "partial",
    "unsupported",
    "permission_denied",
    "auth_failed",
    "rejected",
    "unavailable",
    "parse_failed",
]
PartialReason = Literal[
    "truncated",
    "untimed_records",
    "conflicting_records",
    "malformed_rows",
    "window_coverage_unknown",
]
Truncation = Literal["not_truncated", "truncated"]
WindowCoverage = Literal["covered", "not_covered", "unknown"]
OverallStatus = Literal["complete", "empty", "partial", "failed"]

_FAILED_OUTCOMES = frozenset(
    {"unsupported", "permission_denied", "auth_failed", "rejected", "unavailable", "parse_failed"}
)

_PROTECT_ID_RE = re.compile(r"\A[0-9A-Fa-f]{24}\Z")
_ISO_RE = re.compile(
    r"\A(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"(Z|z|[+-]\d{2}:?\d{2})?\Z"
)
_DIGITS_RE = re.compile(r"\A\d+(?:\.\d+)?\Z")
#: Magnitudes that identify an epoch unit without guessing (1973 to 5138 either way).
_SECONDS_RANGE = (10**8, 10**11)
_MILLIS_RANGE = (10**11, 10**14)


class _Closed(BaseModel):
    """Every object in the document is closed: an unknown key is a validation error."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Window(_Closed):
    """A half-open UTC window: ``start`` inclusive, ``end`` exclusive.

    The ``*_epoch_ms`` fields are authoritative. An ISO bound is null exactly when its epoch
    value lies outside 0001-01-01T00:00:00.000Z to 9999-12-31T23:59:59.999Z (a value a
    caller passed in the wrong unit is still sent and reported, never refused)."""

    start: str | None = Field(
        description="Window start, UTC ISO 8601 with milliseconds (inclusive); null when "
        "start_epoch_ms is outside years 1 to 9999."
    )
    end: str | None = Field(
        description="Window end, UTC ISO 8601 with milliseconds (exclusive); null when "
        "end_epoch_ms is outside years 1 to 9999."
    )
    start_epoch_ms: int = Field(
        description="Window start, epoch milliseconds (inclusive); authoritative."
    )
    end_epoch_ms: int = Field(
        description="Window end, epoch milliseconds (exclusive); authoritative."
    )
    bounds: Literal["half_open"] = Field(
        default="half_open", description="Always half_open: start <= t < end."
    )

    @model_validator(mode="after")
    def _ordered(self) -> Window:
        if self.end_epoch_ms <= self.start_epoch_ms:
            raise ValueError("window end must be after its start")
        if self.start != window_iso(self.start_epoch_ms) or self.end != window_iso(
            self.end_epoch_ms
        ):
            raise ValueError(
                "window ISO bounds must equal the epoch bounds (null when unrepresentable)"
            )
        return self


class EpochWarning(_Closed):
    """A warning about a window bound that is negative or looks like epoch milliseconds."""

    code: Literal["EPOCH_SECONDS_NEGATIVE", "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"] = Field(
        description="Which heuristic fired."
    )
    argument: Literal["start", "end"] = Field(description="The argument that looks wrong.")
    value: int = Field(description="The value as given (epoch seconds); it was sent unchanged.")
    message: str = Field(description="What was sent and what to pass instead.")


class ObservedWindow(_Closed):
    """The earliest and latest in-window event times a source returned (null when none)."""

    earliest: str | None = Field(description="Earliest in-window event time, UTC ISO 8601.")
    latest: str | None = Field(description="Latest in-window event time, UTC ISO 8601.")
    earliest_epoch_ms: int | None = Field(description="Earliest in-window event time, epoch ms.")
    latest_epoch_ms: int | None = Field(description="Latest in-window event time, epoch ms.")


class EventTime(_Closed):
    """When the event happened, as the record states it, and where it falls in the window."""

    status: TimeStatus = Field(
        description="in_window / out_of_window for a usable time; missing, malformed or "
        "ambiguous_timezone (no UTC offset) when the record gives no usable time."
    )
    field: str = Field(description="The native field the time was read from.")
    original_type: OriginalType = Field(description="JSON type of the native value.")
    utc: str | None = Field(description="UTC ISO 8601 time; null without a usable time.")
    epoch_ms: int | None = Field(description="Epoch milliseconds; null without a usable time.")
    precision: Precision | None = Field(
        description="Precision the native value carries; null without a usable time."
    )

    @model_validator(mode="after")
    def _consistent(self) -> EventTime:
        timed = self.status in ("in_window", "out_of_window")
        if timed != (self.epoch_ms is not None) or timed != (self.utc is not None):
            raise ValueError("epoch_ms and utc are set exactly when the time is usable")
        if timed != (self.precision is not None):
            raise ValueError("precision is set exactly when the time is usable")
        return self


class Entity(_Closed):
    """One exact identifier the record names."""

    kind: EntityKind = Field(
        description="What the identifier names. network_station is a MAC whose client or "
        "device role the record does not state."
    )
    id_kind: IdKind = Field(description="The identifier's form.")
    id: str = Field(description="The identifier exactly as the record gives it.")
    role: str = Field(description="The native field or parameter that holds it.")


class Identity(_Closed):
    """Which entities the record names, and how certain that is."""

    status: IdentityStatus = Field(
        description="exact: every identifier has a known role and form; ambiguous: a role or "
        "form is unstated or two identifiers conflict; missing: no identifier in known fields."
    )
    reason: str | None = Field(description="Why the status is ambiguous or missing; else null.")
    entities: tuple[Entity, ...] = Field(description="The identifiers, ordered by role and id.")


class NetworkAttributes(_Closed):
    """The safe Network system-log fields kept for a record (free text is never kept)."""

    product: Literal["network"] = Field(description="Always network.")
    key: str | None = Field(description="Event key, e.g. THREAT_DETECTED_KNOWN_SOURCE_CLIENT.")
    event: str | None = Field(description="Event name.")
    category: str | None = Field(description="Category, e.g. SECURITY.")
    subcategory: str | None = Field(description="Subcategory.")
    severity: str | None = Field(description="Severity as the controller states it.")
    type: str | None = Field(description="Event type.")
    status: str | None = Field(description="Alert status, e.g. NEW.")
    target: str | None = Field(description="What the event targets, e.g. DEVICE.")
    wrong_typed_fields: tuple[str, ...] = Field(
        description="Native fields that are present with a value of the wrong JSON type and so "
        "are null here. A field that is simply absent (or null) is not listed."
    )


class ProtectAttributes(_Closed):
    """The safe Protect event fields kept for a record (descriptions and media are never kept)."""

    product: Literal["protect"] = Field(description="Always protect.")
    type: str | None = Field(description="Event type, e.g. motion or smartDetectZone.")
    category: str | None = Field(description="Event category, e.g. smart.")
    smart_detect_types: tuple[str, ...] | None = Field(
        description="Smart-detect subtypes, e.g. person; null when the event has none."
    )
    score: int | float | None = Field(description="Detection score as the event states it.")
    end_epoch_ms: int | None = Field(
        description="Event end, epoch milliseconds, when the event gives an integer end."
    )
    wrong_typed_fields: tuple[str, ...] = Field(
        description="Native fields that are present with a value of the wrong JSON type (or, "
        "for smartDetectTypes, with a non-string entry that was left out) and so are null or "
        "reduced here. A field that is simply absent (or null) is not listed."
    )


class Provenance(_Closed):
    """Where a record came from."""

    product: Product = Field(description="The product that served the record.")
    source_id: str = Field(description="The source (see sources[].source_id).")
    route: str = Field(description="HTTP method and route template that was read.")
    record_id: str | None = Field(description="The native record id; null when it has none.")
    record_id_field: str = Field(description="The native field the record id is read from.")


class EvidenceRecord(_Closed):
    """One normalized event."""

    evidence_id: str = Field(
        description="Stable id: SOURCE_ID|id|NATIVE_ID, or SOURCE_ID|sha256:DIGEST for a "
        "record without a native id; a conflicting repeat adds |v:DIGEST."
    )
    product: Product = Field(description="The product that served the record.")
    source_id: str = Field(description="The source the record came from.")
    time: EventTime = Field(description="The event time and its window placement.")
    attributes: Annotated[NetworkAttributes | ProtectAttributes, Field(discriminator="product")] = (
        Field(description="Safe native fields, by product.")
    )
    identity: Identity = Field(description="Identifiers the record names.")
    provenance: Provenance = Field(description="Where the record came from.")


class Failure(_Closed):
    """Why a source produced no evidence."""

    kind: FailureKind = Field(
        description="unsupported (HTTP 404/405/501), permission_denied (403), auth_failed "
        "(401), rejected (another 4xx), unavailable (5xx, 429 or no answer), parse_failed "
        "(an answer of an unexpected shape)."
    )
    http_status: int | None = Field(description="Upstream HTTP status; null without one.")
    message: str = Field(description="The upstream error text, with configured secrets masked.")


class Pagination(_Closed):
    """How much of the source's listing was read."""

    truncated: Truncation = Field(
        description="truncated when the drain stopped early (the opt-in page cap, a repeated "
        "or early-empty page, or a short declared total); else not_truncated."
    )
    reason: str | None = Field(description="Why the drain stopped early; else null.")
    upstream_total: int | None = Field(
        description="The total the API declared, when it declared one."
    )
    retrieved: int = Field(description="Rows read from the source.")
    page_cap: int | None = Field(
        description="UNIFI_PAGINATE_MAX_PAGES when the operator set it; else null (no cap)."
    )


class Counts(_Closed):
    """Record counts for a source."""

    retrieved: int = Field(description="Rows read.")
    records: int = Field(description="Records kept in the document for this source.")
    in_window: int = Field(description="Kept records whose time is in the window.")
    out_of_window: int = Field(description="Kept records whose time is outside the window.")
    untimed: int = Field(description="Kept records with a missing, malformed or zoneless time.")
    duplicates_dropped: int = Field(
        description="Rows identical, field for field, to a row already read: not kept twice."
    )
    conflicting: int = Field(
        description="Repeats of a record id whose native row differs from the first one read."
    )
    malformed: int = Field(
        description="Rows that are not JSON objects: counted, never made into records."
    )


class Coverage(_Closed):
    """What part of the requested window the source covered."""

    queried_window: Window | None = Field(
        description="The window sent upstream; null when no request was sent."
    )
    observed_window: ObservedWindow = Field(description="In-window event times returned.")
    window_coverage: WindowCoverage = Field(
        description="covered: the whole requested window was queried and every page read; "
        "unknown: the drain stopped early; not_covered: the source failed."
    )
    retention: Literal["unknown"] = Field(description="Always unknown (see retention_reason).")
    retention_reason: str = Field(description="Why retention coverage is unknown.")


class SourceScope(_Closed):
    """What one source read."""

    host_id: str = Field(description="The console id the source read.")
    site: str | None = Field(description="Network site slug; null for Protect.")
    log_class: str | None = Field(description="Network system-log class; null for Protect.")
    camera_id: str | None = Field(description="Protect camera filter; null for all cameras.")
    event_types: tuple[str, ...] | None = Field(
        description="Protect event types sent as a filter; null when not filtered."
    )


class SourceResult(_Closed):
    """One source's outcome, coverage and counts."""

    source_id: str = Field(description="Stable source id, e.g. network.system_log.all.")
    product: Product = Field(description="The product the source reads.")
    route: str = Field(description="HTTP method and route template.")
    scope: SourceScope = Field(description="What the source read.")
    outcome: SourceOutcome = Field(
        description="complete, empty (no in-window record), partial (see partial_reasons), "
        "or a failure kind (see failure)."
    )
    partial_reasons: tuple[PartialReason, ...] = Field(
        description="Why the outcome is partial; empty otherwise."
    )
    failure: Failure | None = Field(description="The failure; null unless the source failed.")
    coverage: Coverage = Field(description="Window and retention coverage.")
    pagination: Pagination | None = Field(description="Drain state; null when the source failed.")
    counts: Counts = Field(description="Record counts.")

    @model_validator(mode="after")
    def _outcome_rules(self) -> SourceResult:
        failed = self.outcome in _FAILED_OUTCOMES
        if failed != (self.failure is not None):
            raise ValueError("a failure is set exactly when the outcome is a failure kind")
        if self.failure is not None and self.failure.kind != self.outcome:
            raise ValueError("a failed source's outcome must equal its failure kind")
        if failed and (self.pagination is not None or self.counts.records):
            raise ValueError("a failed source carries no pagination and no records")
        if self.counts.records + self.counts.duplicates_dropped + self.counts.malformed != (
            self.counts.retrieved
        ):
            raise ValueError("records + duplicates_dropped + malformed must equal retrieved")
        if (self.outcome == "partial") != bool(self.partial_reasons):
            raise ValueError("partial_reasons are set exactly when the outcome is partial")
        if self.outcome == "empty" and self.counts.in_window:
            raise ValueError("an empty source has no in-window record")
        if self.outcome == "complete" and not self.counts.in_window:
            raise ValueError("a complete source has at least one in-window record")
        if failed and self.coverage.window_coverage != "not_covered":
            raise ValueError("a failed source does not cover its window")
        return self


class Scope(_Closed):
    """The console (and site) the document covers."""

    host_id: str = Field(description="The console id.")
    site: str | None = Field(description="Network site slug; null for Protect.")


class IncidentEvidence(_Closed):
    """Normalized incident evidence from one product on one console."""

    schema_name: Literal["unifi-fabric-incident-evidence"] = Field(
        description="Always unifi-fabric-incident-evidence."
    )
    schema_version: Literal[1] = Field(description="Schema version; 1.")
    product: Product = Field(description="The product every source reads.")
    status: OverallStatus = Field(
        description="complete: every source complete or empty with at least one complete; "
        "empty: every source empty; failed: every source failed; partial: anything else."
    )
    causality: Literal["not_assessed"] = Field(
        description="Always not_assessed: records are ordered by time only and no record is "
        "claimed to cause another."
    )
    ordering: Literal["event_time_then_source"] = Field(
        description="Records sort by event time, product, source id, native record id and "
        "evidence id; records without a usable time sort last."
    )
    scope: Scope = Field(description="The console (and site) read.")
    requested_window: Window = Field(description="The window the caller asked for.")
    collected_at: str = Field(
        description="When the collection ran, UTC ISO 8601; never used as an event time."
    )
    incomplete: bool = Field(
        description="True exactly when some source is truncated (its drain stopped early); the "
        "repo-wide signal that this is not everything the console holds."
    )
    incompleteReason: str | None = Field(  # noqa: N815 - the repo-wide key name
        default=None,
        description="Why the document is incomplete, naming each truncated source. Present "
        "only when incomplete is true (like every other result that carries the flag).",
    )
    sources: tuple[SourceResult, ...] = Field(description="Every source, in request order.")
    records: tuple[EvidenceRecord, ...] = Field(description="Every record, in order.")
    epoch_warnings: tuple[EpochWarning, ...] | None = Field(
        default=None,
        alias="_warnings",
        description="One entry per window bound that is negative or looks like epoch "
        "milliseconds (the repo-wide epoch warning); the bound was sent unchanged. Present "
        "only when there is one.",
    )

    @model_validator(mode="after")
    def _document_rules(self) -> IncidentEvidence:
        ids = [r.evidence_id for r in self.records]
        if len(set(ids)) != len(ids):
            raise ValueError("evidence ids must be unique")
        if list(self.records) != sorted(self.records, key=record_sort_key):
            raise ValueError("records must be in event-time order")
        by_source = {s.source_id: s for s in self.sources}
        if len(by_source) != len(self.sources):
            raise ValueError("source ids must be unique")
        for position, record in enumerate(self.records):
            source = by_source.get(record.source_id)
            if source is None or source.product != record.product:
                raise ValueError(
                    f"records[{position}].source_id must name an entry of sources with the "
                    "same product as the record (the record's evidence_id is not echoed: it "
                    "embeds an upstream native id)"
                )
        for source in self.sources:
            if source.product != self.product:
                raise ValueError("every source must read the document's product")
            kept = sum(1 for r in self.records if r.source_id == source.source_id)
            if kept != source.counts.records:
                raise ValueError(f"source {source.source_id} record count disagrees")
        if self.status != overall_status(s.outcome for s in self.sources):
            raise ValueError("status disagrees with the source outcomes")
        truncated = [
            s for s in self.sources if s.pagination and s.pagination.truncated == "truncated"
        ]
        if self.incomplete != bool(truncated):
            raise ValueError("incomplete is true exactly when some source is truncated")
        if (self.incompleteReason is not None) != self.incomplete:
            raise ValueError("incompleteReason is set exactly when the document is incomplete")
        return self


def schema_document() -> dict[str, Any]:
    """The JSON Schema of :class:`IncidentEvidence` (the committed :data:`SCHEMA_PATH`)."""
    schema = IncidentEvidence.model_json_schema()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{SCHEMA_NAME}/v{SCHEMA_VERSION}",
        **schema,
    }


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
#: Epoch milliseconds of 0001-01-01T00:00:00.000Z and 9999-12-31T23:59:59.999Z.
MIN_ISO_EPOCH_MS = -62_135_596_800_000
MAX_ISO_EPOCH_MS = 253_402_300_799_999


def format_utc(epoch_ms: int) -> str:
    """Epoch milliseconds as UTC ISO 8601 with milliseconds and a ``Z`` suffix.

    Portable: no ``fromtimestamp`` (it raises for negatives on Windows) and no ``%Y`` (it does
    not pad years below 1000). Raises ``OverflowError`` outside years 1 to 9999."""
    m = _EPOCH + timedelta(milliseconds=epoch_ms)
    return (
        f"{m.year:04d}-{m.month:02d}-{m.day:02d}T{m.hour:02d}:{m.minute:02d}:{m.second:02d}"
        f".{m.microsecond // 1000:03d}Z"
    )


def window_iso(epoch_ms: int) -> str | None:
    """:func:`format_utc` when ``epoch_ms`` is within years 1 to 9999, else None."""
    if not MIN_ISO_EPOCH_MS <= epoch_ms <= MAX_ISO_EPOCH_MS:
        return None
    return format_utc(epoch_ms)


def make_window(start_ms: int, end_ms: int) -> Window:
    return Window(
        start=window_iso(start_ms),
        end=window_iso(end_ms),
        start_epoch_ms=start_ms,
        end_epoch_ms=end_ms,
    )


_ABSENT = object()


def _original_type(value: Any) -> OriginalType:
    if value is _ABSENT:
        return "absent"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    return "array"


def _epoch_number(number: int | float) -> tuple[int, Precision] | None:
    """Epoch milliseconds and precision for a number whose magnitude proves its unit."""
    if not math.isfinite(number) or number < 0:
        return None
    if _MILLIS_RANGE[0] <= number < _MILLIS_RANGE[1]:
        return math.floor(number), "millisecond"
    if _SECONDS_RANGE[0] <= number < _SECONDS_RANGE[1]:
        if number != math.floor(number):
            return math.floor(number * 1000), "millisecond"
        return int(number) * 1000, "second"
    return None


def _iso_time(text: str) -> tuple[int, Precision] | Literal["ambiguous_timezone"] | None:
    match = _ISO_RE.match(text.strip())
    if match is None:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    if zone is None:
        return "ambiguous_timezone"
    try:
        moment = datetime.fromisoformat(
            f"{year}-{month}-{day}T{hour}:{minute}:{second}"
            + ("+00:00" if zone in ("Z", "z") else zone)
        )
    except ValueError:
        return None
    fraction = fraction or ""
    millis = int((fraction + "000")[:3])
    precision: Precision = (
        "second" if not fraction else "millisecond" if len(fraction) <= 3 else "microsecond"
    )
    return int(moment.timestamp()) * 1000 + millis, precision


def parse_event_time(record: Mapping[str, Any], field_name: str, window: Window) -> EventTime:
    """The record's ``field_name`` as an :class:`EventTime` placed against ``window``.

    Integer and numeric-string values are epoch seconds or milliseconds, told apart by
    magnitude only; an ISO 8601 string needs a UTC offset (without one it is
    ``ambiguous_timezone``, never assumed to be UTC). Anything else is ``malformed``.
    """
    value = record.get(field_name, _ABSENT)
    original = _original_type(value)
    parsed: tuple[int, Precision] | Literal["ambiguous_timezone"] | None = None
    if value is _ABSENT or value is None:
        return EventTime(
            status="missing",
            field=field_name,
            original_type=original,
            utc=None,
            epoch_ms=None,
            precision=None,
        )
    if isinstance(value, int | float) and not isinstance(value, bool):
        parsed = _epoch_number(value)
    elif isinstance(value, str):
        text = value.strip()
        if _DIGITS_RE.match(text):
            parsed = _epoch_number(float(text) if "." in text else int(text))
        else:
            parsed = _iso_time(text)
    if parsed == "ambiguous_timezone":
        return EventTime(
            status="ambiguous_timezone",
            field=field_name,
            original_type=original,
            utc=None,
            epoch_ms=None,
            precision=None,
        )
    if parsed is None:
        return EventTime(
            status="malformed",
            field=field_name,
            original_type=original,
            utc=None,
            epoch_ms=None,
            precision=None,
        )
    epoch_ms, precision = parsed
    inside = window.start_epoch_ms <= epoch_ms < window.end_epoch_ms
    return EventTime(
        status="in_window" if inside else "out_of_window",
        field=field_name,
        original_type=original,
        utc=format_utc(epoch_ms),
        epoch_ms=epoch_ms,
        precision=precision,
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def _is_colon_mac(value: str) -> bool:
    """A MAC in the controller's colon form, any case (the one MAC rule, unifi_fabric.macs)."""
    return is_mac(value) and colon_mac(value) == value.lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _identity(entities: list[Entity], ambiguous: list[str]) -> Identity:
    ordered = tuple(sorted(set(entities), key=lambda e: (e.role, e.kind, e.id)))
    roles: dict[tuple[str, str], set[str]] = {}
    for entity in ordered:
        roles.setdefault((entity.role, entity.kind), set()).add(entity.id.lower())
    reasons = list(ambiguous)
    reasons += [
        f"{role} names more than one {kind}" for (role, kind), ids in roles.items() if len(ids) > 1
    ]
    reasons += [
        f"{e.role} holds a MAC whose client or device role is not stated"
        for e in ordered
        if e.kind == "network_station"
    ]
    if reasons:
        return Identity(
            status="ambiguous", reason="; ".join(sorted(set(reasons))), entities=ordered
        )
    if not ordered:
        return Identity(
            status="missing", reason="no exact identifier in the known fields", entities=()
        )
    return Identity(status="exact", reason=None, entities=ordered)


def network_identity(row: Mapping[str, Any]) -> Identity:
    """Identifiers in a system-log entry's ``parameters``: a MAC under a ``*CLIENT*`` role is
    a client, under ``DEVICE`` / ``*_DEVICE`` a device, under any other role a station (role
    unstated, so ambiguous); an IP address is an ip_address. Names and other ids are skipped."""
    params = row.get("parameters")
    entities: list[Entity] = []
    if not isinstance(params, dict):
        return _identity(entities, [])
    for role in sorted(str(k) for k in params):
        item = params[role]
        ident = item.get("id") if isinstance(item, dict) else None
        if not isinstance(ident, str):
            continue
        if _is_colon_mac(ident):
            upper = role.upper()
            kind: EntityKind = (
                "network_client"
                if "CLIENT" in upper
                else "network_device"
                if upper == "DEVICE" or upper.endswith("_DEVICE")
                else "network_station"
            )
            entities.append(Entity(kind=kind, id_kind="mac", id=ident, role=role))
        elif _is_ip(ident):
            entities.append(Entity(kind="ip_address", id_kind="ip", id=ident, role=role))
    return _identity(entities, [])


def protect_identity(row: Mapping[str, Any]) -> Identity:
    """The Protect event's ``camera`` id and sensor id (``sensor`` or
    ``metadata.sensorId.text``). A value that is not a 24-hex Protect id is ambiguous."""
    entities: list[Entity] = []
    ambiguous: list[str] = []
    camera = row.get("camera")
    if isinstance(camera, str) and camera:
        if _PROTECT_ID_RE.match(camera):
            entities.append(
                Entity(kind="camera", id_kind="protect_camera_id", id=camera, role="camera")
            )
        else:
            ambiguous.append("camera is not a Protect id")
    sensor = row.get("sensor")
    role = "sensor"
    if sensor is None:
        metadata = row.get("metadata")
        sensor_ref = metadata.get("sensorId") if isinstance(metadata, dict) else None
        sensor = sensor_ref.get("text") if isinstance(sensor_ref, dict) else None
        role = "metadata.sensorId.text"
    if isinstance(sensor, str) and sensor:
        if _PROTECT_ID_RE.match(sensor):
            entities.append(
                Entity(kind="sensor", id_kind="protect_device_id", id=sensor, role=role)
            )
        else:
            ambiguous.append(f"{role} is not a Protect id")
    return _identity(entities, ambiguous)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def _text(row: Mapping[str, Any], key: str, wrong: list[str]) -> str | None:
    """A string field; a present non-null value of another type is listed in ``wrong``
    (absent and null are both just null, and are not listed)."""
    value = row.get(key)
    if isinstance(value, str):
        return value
    if value is not None:
        wrong.append(key)
    return None


def network_attributes(row: Mapping[str, Any]) -> NetworkAttributes:
    wrong: list[str] = []
    return NetworkAttributes(
        product="network",
        key=_text(row, "key", wrong),
        event=_text(row, "event", wrong),
        category=_text(row, "category", wrong),
        subcategory=_text(row, "subcategory", wrong),
        severity=_text(row, "severity", wrong),
        type=_text(row, "type", wrong),
        status=_text(row, "status", wrong),
        target=_text(row, "target", wrong),
        wrong_typed_fields=tuple(wrong),
    )


def protect_attributes(row: Mapping[str, Any]) -> ProtectAttributes:
    wrong: list[str] = []
    type_ = _text(row, "type", wrong)
    category = _text(row, "category", wrong)
    types = row.get("smartDetectTypes")
    detect: tuple[str, ...] | None = None
    if isinstance(types, list):
        detect = tuple(t for t in types if isinstance(t, str))
        if len(detect) != len(types):
            wrong.append("smartDetectTypes")
    elif types is not None:
        wrong.append("smartDetectTypes")
    score = row.get("score")
    if isinstance(score, int | float) and not isinstance(score, bool) and math.isfinite(score):
        kept_score: int | float | None = score
    else:
        kept_score = None
        if score is not None:
            wrong.append("score")
    end = row.get("end")
    if isinstance(end, int) and not isinstance(end, bool):
        kept_end: int | None = end
    else:
        kept_end = None
        if end is not None:
            wrong.append("end")
    return ProtectAttributes(
        product="protect",
        type=type_,
        category=category,
        smart_detect_types=detect,
        score=kept_score,
        end_epoch_ms=kept_end,
        wrong_typed_fields=tuple(wrong),
    )


@dataclass(frozen=True)
class ProductRules:
    """How one product's native rows become records."""

    product: Product
    time_field: str
    id_field: str
    attributes: Any
    identity: Any


NETWORK_RULES = ProductRules("network", "timestamp", "id", network_attributes, network_identity)
PROTECT_RULES = ProductRules("protect", "start", "id", protect_attributes, protect_identity)


def _digest(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:24]


def record_sort_key(record: EvidenceRecord) -> tuple[Any, ...]:
    epoch = record.time.epoch_ms
    return (
        epoch is None,
        epoch if epoch is not None else 0,
        record.product,
        record.source_id,
        record.provenance.record_id or "",
        record.evidence_id,
    )


# ---------------------------------------------------------------------------
# Sources and the document
# ---------------------------------------------------------------------------


@dataclass
class SourceRead:
    """One source's read: its rows and drain state, or the failure that stopped it."""

    source_id: str
    route: str
    scope: SourceScope
    queried: bool = True
    rows: list[Any] = field(default_factory=list)
    upstream_total: int | None = None
    incomplete: bool = False
    incomplete_reason: str | None = None
    failure: Failure | None = None


def failure_kind(status: int | None, shape_error: bool) -> FailureKind:
    """The failure kind for an upstream error with HTTP ``status`` (None: no answer)."""
    if shape_error:
        return "parse_failed"
    if status in (404, 405, 501):
        return "unsupported"
    if status == 403:
        return "permission_denied"
    if status == 401:
        return "auth_failed"
    if status is not None and 400 <= status < 500 and status != 429:
        return "rejected"
    return "unavailable"


def _records_for(
    read: SourceRead, rules: ProductRules, window: Window
) -> tuple[list[EvidenceRecord], int, int, int, int]:
    """Records of one source's rows: (records, retrieved, duplicates_dropped, conflicting,
    malformed).

    Repeat decisions use a digest of the full native row (internal only, never emitted), so
    two rows that differ anywhere are never merged, however alike their safe fields. A row
    that is not a JSON object is counted as malformed and never becomes a record."""
    kept: dict[str, EvidenceRecord] = {}
    first_native: dict[str, str] = {}  # base evidence id -> native digest of the first row
    seen: set[tuple[str, str]] = set()  # (base evidence id, native digest) already kept
    idless_seen: dict[str, int] = {}  # base evidence id -> raw-distinct rows kept so far
    duplicates = conflicting = malformed = 0
    for row in read.rows:
        if not isinstance(row, dict):
            malformed += 1
            continue
        native = row.get(rules.id_field)
        record_id = native if isinstance(native, str) and native else None
        if isinstance(native, int) and not isinstance(native, bool):
            record_id = str(native)
        native_digest = _digest(row)
        time = parse_event_time(row, rules.time_field, window)
        attributes = rules.attributes(row)
        identity = rules.identity(row)
        if record_id is not None:
            base = f"{read.source_id}|id|{quote(record_id, safe='')}"
        else:
            projection = _digest(
                {
                    "time": time.model_dump(mode="json"),
                    "attributes": attributes.model_dump(mode="json"),
                    "identity": identity.model_dump(mode="json"),
                }
            )
            base = f"{read.source_id}|sha256:{projection}"
        if (base, native_digest) in seen:
            duplicates += 1
            continue
        seen.add((base, native_digest))
        evidence_id = base
        if record_id is not None:
            if base in first_native:
                conflicting += 1
                evidence_id = f"{base}|v:{native_digest}"
            else:
                first_native[base] = native_digest
        else:
            # Raw-distinct id-less rows are distinct records: the occurrence number, in drain
            # order, keeps their ids apart when their safe fields agree.
            idless_seen[base] = idless_seen.get(base, 0) + 1
            if idless_seen[base] > 1:
                evidence_id = f"{base}|n:{idless_seen[base]}"
        kept[evidence_id] = EvidenceRecord(
            evidence_id=evidence_id,
            product=rules.product,
            source_id=read.source_id,
            time=time,
            attributes=attributes,
            identity=identity,
            provenance=Provenance(
                product=rules.product,
                source_id=read.source_id,
                route=read.route,
                record_id=record_id,
                record_id_field=rules.id_field,
            ),
        )
    return list(kept.values()), len(read.rows), duplicates, conflicting, malformed


def _source_result(
    read: SourceRead,
    rules: ProductRules,
    window: Window,
    page_cap: int | None,
) -> tuple[SourceResult, list[EvidenceRecord]]:
    queried = window if read.queried else None
    if read.failure is not None:
        empty_counts = Counts(
            retrieved=0,
            records=0,
            in_window=0,
            out_of_window=0,
            untimed=0,
            duplicates_dropped=0,
            conflicting=0,
            malformed=0,
        )
        return (
            SourceResult(
                source_id=read.source_id,
                product=rules.product,
                route=read.route,
                scope=read.scope,
                outcome=read.failure.kind,
                partial_reasons=(),
                failure=read.failure,
                coverage=Coverage(
                    queried_window=queried,
                    observed_window=ObservedWindow(
                        earliest=None, latest=None, earliest_epoch_ms=None, latest_epoch_ms=None
                    ),
                    window_coverage="not_covered",
                    retention="unknown",
                    retention_reason=RETENTION_REASON,
                ),
                pagination=None,
                counts=empty_counts,
            ),
            [],
        )
    records, retrieved, duplicates, conflicting, malformed = _records_for(read, rules, window)
    in_window = [r.time.epoch_ms for r in records if r.time.status == "in_window"]
    times = [t for t in in_window if t is not None]
    untimed = sum(1 for r in records if r.time.epoch_ms is None)
    reasons: list[PartialReason] = []
    if read.incomplete:
        reasons += ["truncated", "window_coverage_unknown"]
    if untimed:
        reasons.append("untimed_records")
    if conflicting:
        reasons.append("conflicting_records")
    if malformed:
        reasons.append("malformed_rows")
    outcome: SourceOutcome = "partial" if reasons else "complete" if times else "empty"
    result = SourceResult(
        source_id=read.source_id,
        product=rules.product,
        route=read.route,
        scope=read.scope,
        outcome=outcome,
        partial_reasons=tuple(reasons),
        failure=None,
        coverage=Coverage(
            queried_window=queried,
            observed_window=ObservedWindow(
                earliest=format_utc(min(times)) if times else None,
                latest=format_utc(max(times)) if times else None,
                earliest_epoch_ms=min(times) if times else None,
                latest_epoch_ms=max(times) if times else None,
            ),
            window_coverage="unknown" if read.incomplete else "covered",
            retention="unknown",
            retention_reason=RETENTION_REASON,
        ),
        pagination=Pagination(
            truncated="truncated" if read.incomplete else "not_truncated",
            reason=read.incomplete_reason if read.incomplete else None,
            upstream_total=read.upstream_total,
            retrieved=retrieved,
            page_cap=page_cap,
        ),
        counts=Counts(
            retrieved=retrieved,
            records=len(records),
            in_window=len(times),
            out_of_window=sum(1 for r in records if r.time.status == "out_of_window"),
            untimed=untimed,
            duplicates_dropped=duplicates,
            conflicting=conflicting,
            malformed=malformed,
        ),
    )
    return result, records


def overall_status(outcomes: Iterable[str]) -> OverallStatus:
    """complete / empty / partial / failed from the source outcomes (see IncidentEvidence)."""
    values = list(outcomes)
    if values and all(o in _FAILED_OUTCOMES for o in values):
        return "failed"
    if not values or any(o == "partial" or o in _FAILED_OUTCOMES for o in values):
        return "partial"
    if all(o == "empty" for o in values):
        return "empty"
    return "complete"


def build_document(
    *,
    rules: ProductRules,
    host_id: str,
    site: str | None,
    window: Window,
    reads: Sequence[SourceRead],
    page_cap: int | None,
    collected_at: datetime | None = None,
    warnings: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """The validated evidence document for ``reads`` as JSON data.

    ``warnings`` is the collector's ``epoch_warnings(start=..., end=...)``; it becomes the
    declared ``_warnings`` field, present only when there is one."""
    sources: list[SourceResult] = []
    records: list[EvidenceRecord] = []
    for read in reads:
        source, kept = _source_result(read, rules, window, page_cap)
        sources.append(source)
        records.extend(kept)
    records.sort(key=record_sort_key)
    moment = collected_at or datetime.now(UTC)
    truncated = [
        f"{s.source_id}: {(s.pagination.reason if s.pagination else None) or 'drain stopped early'}"
        for s in sources
        if s.pagination is not None and s.pagination.truncated == "truncated"
    ]
    declared_warnings: dict[str, Any] = {"_warnings": tuple(warnings)} if warnings else {}
    document = IncidentEvidence(
        schema_name=SCHEMA_NAME,
        schema_version=SCHEMA_VERSION,
        product=rules.product,
        status=overall_status(s.outcome for s in sources),
        causality="not_assessed",
        ordering="event_time_then_source",
        scope=Scope(host_id=host_id, site=site),
        requested_window=window,
        collected_at=format_utc(int(moment.timestamp() * 1000)),
        incomplete=bool(truncated),
        incompleteReason="; ".join(truncated) if truncated else None,
        sources=tuple(sources),
        records=tuple(records),
        **declared_warnings,
    )
    data = document.model_dump(mode="json", by_alias=True)
    if data["incompleteReason"] is None:
        del data["incompleteReason"]  # the repo-wide flag's reason appears only when it applies
    if data["_warnings"] is None:
        del data["_warnings"]
    return data


def validate_document(document: Mapping[str, Any]) -> IncidentEvidence:
    """Validate ``document`` against the closed schema (raises pydantic ValidationError)."""
    return IncidentEvidence.model_validate(dict(document))


# ---------------------------------------------------------------------------
# Collector helpers (validation and failure capture; still no I/O)
# ---------------------------------------------------------------------------


def evidence_window(tool: str, start: Any, end: Any) -> Window:
    """The requested half-open window from integer epoch-second ``start`` / ``end``.

    Refused before any request only for a value that is not an integer and for an ``end`` that
    is not after ``start`` (an empty window names nothing). A negative value or a millisecond
    magnitude is not refused: it is sent unchanged (times 1000) and the collector reports it in
    the document's ``_warnings``, like every other epoch argument.
    """
    bounds: dict[str, int] = {}
    for name, value in (("start", start), ("end", end)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"{tool} window: {name} must be an integer epoch-seconds timestamp, got {value!r}"
            )
        bounds[name] = value
    if bounds["end"] <= bounds["start"]:
        raise ValueError(
            f"{tool} window: end ({bounds['end']}) must be after start ({bounds['start']}); "
            "nothing was sent. The window is half-open (start inclusive, end exclusive); "
            "swap start and end if they are reversed."
        )
    return make_window(bounds["start"] * 1000, bounds["end"] * 1000)


def evidence_selectors(tool: str, name: str, values: Any) -> list[str] | None:
    """``values`` (a list of non-blank strings) without repeats, in the given order.

    None is "not given". An empty list names no source and is refused before any request.
    """
    if values is None:
        return None
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ValueError(f"{tool} {name} must be a list of strings, got {values!r}")
    if not values:
        raise ValueError(
            f"{tool} {name} names no source: omit {name} for the default or name at least one"
        )
    return list(dict.fromkeys(values))


def _is_shape_error(exc: BaseException, status: int | None) -> bool:
    """True for an answer of an unusable shape (the upstream did answer, with a 2xx)."""
    lowered = str(exc).lower()
    return isinstance(exc, ResponseShapeError) or (
        status is None and ("response shape" in lowered or "pagination" in lowered)
    )


def _scrubbed(text: str, client: Any) -> str:
    message = upstream_error_value(scrub(text), client)
    return message if isinstance(message, str) else str(message)


def capture_failure(
    exc: BaseException,
    client: Any,
    *,
    method: str,
    path: str,
    answered: int | None = None,
) -> Failure:
    """The :class:`Failure` for an upstream error, its text scrubbed of configured secrets
    (and credential fields masked when UNIFI_REDACT_SECRETS is on).

    The message always names the request (``method`` and ``path``): the client's own error
    text already does; any other text (an unusable 2xx shape, a transport error) is prefixed
    with it. ``answered`` is the 2xx status of an answer that was then unusable; it is the
    ``http_status`` when the error itself carries none."""
    status = getattr(exc, "status", None)
    status = status if isinstance(status, int) and not isinstance(status, bool) else None
    shape = _is_shape_error(exc, status)
    text = str(exc)
    request = f"{method} {path}"
    if request not in text:
        text = f"{request}: {text}"
    return Failure(
        kind=failure_kind(status, shape),
        http_status=status if status is not None else (answered if shape else None),
        message=_scrubbed(text, client),
    )


def unusable_answer(
    body: Any, client: Any, *, method: str, path: str, status: int | None
) -> Failure:
    """The ``parse_failed`` :class:`Failure` for a 2xx answer that carries no usable listing.

    A scalar, empty or text body is carried verbatim (after the secret scrubber): it is
    the controller's own answer and the caller's only evidence of what happened. A JSON
    object of another shape is described by shape only, never dumped: it may be event data
    in a drifted envelope."""
    if body is None:
        said = "an empty body"
    elif isinstance(body, dict):
        said = f"a JSON object without a 'data' array ({describe_shape(body)})"
    elif isinstance(body, str):
        said = f"a text answer (not JSON, or a JSON string): {body}"
    else:
        said = f"a JSON scalar: {json.dumps(body)}"
    code = f"HTTP {status} " if status is not None else ""
    return Failure(
        kind="parse_failed",
        http_status=status,
        message=_scrubbed(
            f"Unexpected response shape from {method} {path}: {code}answered {said}; expected "
            "an object with a 'data' array or an array",
            client,
        ),
    )


def definite_write_status(status: int | None) -> bool:
    """True for a status that is a definite answer of a write (nothing was applied): a 4xx
    other than 429, and 501 (not implemented). Every other failure of a write is uncertain."""
    return status is not None and (status == 501 or (400 <= status < 500 and status != 429))


def must_raise(exc: BaseException, *, write: bool) -> bool:
    """True when a failed request must stop the collection and surface as the client's own
    error rather than become a source failure.

    Only a write-classified route (``is_write_request``) can have an uncertain outcome, and an
    uncertain outcome is never absorbed: a 5xx other than 501, a 429 and a transport error
    raise. A definite 4xx or 501 and an unusable 2xx answer (the upstream did answer) are
    recorded. A read never has an uncertain outcome, so every read failure is recorded."""
    if not write:
        return False
    status = getattr(exc, "status", None)
    status = status if isinstance(status, int) and not isinstance(status, bool) else None
    if status is None and _is_shape_error(exc, None):
        return False
    return not definite_write_status(status)


class _StatusRecorder:
    """Base of the client stand-ins that record the HTTP status of every answered request.

    The collectors drain through the shared helpers, which see only the decoded body; the tap
    delegates each call to ``client.request`` (what ``client.get`` / ``client.post`` do) and
    keeps the status, so a 2xx answer that turns out unusable can report the status it carried.
    Every other attribute is the wrapped client's."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.statuses: list[int] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    @property
    def last_status(self) -> int | None:
        return self.statuses[-1] if self.statuses else None


class GetStatusTap(_StatusRecorder):
    """A read-only tap: only ``get`` is offered (the Protect collector is a plain read)."""

    async def get(self, path: str, *, key: Any = None, params: Any = None) -> Any:
        resp = await self._client.request("GET", path, key=key, params=params)
        self.statuses.append(resp.status_code)
        return decode_body(resp)


@read_post
class PostStatusTap(_StatusRecorder):
    """A tap for the read-allowlisted system-log POST: only ``post`` is offered, and only for
    a route on the read-POST allowlist (refused before any request otherwise), so the
    collector that uses it sends nothing but allowlisted reads."""

    async def post(
        self, path: str, *, key: Any = None, json: Any = None, params: Any = None
    ) -> Any:
        if not is_read_post("POST", path, json):
            raise ValueError(f"POST {path} is not on the read-POST allowlist")
        resp = await self._client.request("POST", path, key=key, json=json, params=params)
        self.statuses.append(resp.status_code)
        return decode_body(resp)


def page_cap(client: Any) -> int | None:
    """The operator's opt-in UNIFI_PAGINATE_MAX_PAGES, else None (no cap)."""
    value = getattr(client, "paginate_max_pages", None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
