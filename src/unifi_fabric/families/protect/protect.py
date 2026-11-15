"""UniFi Protect tools — cameras, sensors, lights, chimes, viewers via connector proxy."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import io
import json
import math
import re
import time
from collections.abc import Iterator
from typing import Any, cast

from ... import switches
from ...client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    path_segment,
    upstream_error_value,
    validate_id,
    validate_spec_id,
)
from ...config import APIKeyConfig
from ...matching import id_key, name_keys, same_id, with_upstream_id
from ...read_only import mark_write_denied
from ...redaction import note_dropped_fields
from ...registry import Registry, _require_native_id
from ...route_secrets import mask_response_body
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
    with_warnings,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._pagination import (
    bare_page,
    collect_offset,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)
from ...shared_shapes._payload import upstream_hint
from ...shared_shapes._protect_shared import (  # noqa: F401  (shared)
    PROTECT_PROXY_BASE as PROTECT_PROXY_BASE,
)
from ...shared_shapes._protect_shared import (
    _as_list as _as_list,
)
from ...shared_shapes._protect_shared import (
    _list_body as _list_body,
)
from ...shared_shapes._protect_shared import (
    _proxy as _proxy,
)
from ...shared_shapes._protect_shared import (
    list_cameras as list_cameras,
)
from ...shared_shapes._protect_shared import (
    list_sensors as list_sensors,
)
from ...shared_shapes._results import (
    deletion_result,
    leaf_equal,
    read_after_verdict,
    requested_leaves_match,
    requested_leaves_verdict,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
from ...spec_limits import check_arguments
from ...write_body import IDENTITY_FIELDS, update_problem
from .schemas import (  # the family's shapes (family-owned layout)
    _ARM_DISABLED_STATES,
    _ARM_ENABLED_STATES,
    _EXTERNAL_ARM_PROFILES,
    _POS_TXN_TYPES,
    _TS_UNIT_WARNING,
    _VOLATILE_DEVICE_FIELDS,
    DEVICE_FAMILIES,
    GLOBAL_ALARM_MANAGER_HINT,
    GLOBAL_ALARM_MANAGER_REFUSAL,
    PROTECT_PRIVATE_BASE,
    RESOLVED_SENSOR_KEY,
    SMART_DETECT_WITHOUT_TYPES_WARNING,
    UPLOAD_CONTENT_TYPES,
)

# Protect camera IDs are 24-char hex (Mongo ObjectId style). Used to tell an ID
# from a human-readable camera name when resolving the ``cameras`` filter.
_CAMERA_ID_RE = re.compile(r"^[A-Fa-f0-9]{24}\Z")


def _route_result(client: UniFiClient, method: str, path: str, result: Any) -> Any:
    """Apply the shared registry to a terminal result, after internal comparisons."""
    redact = getattr(getattr(client, "_settings", None), "redact_secrets", False) is True
    return mask_response_body(method, path, result, redact_secrets=redact)


def _private(host_id: str, path: str) -> str:
    return PROTECT_PRIVATE_BASE.format(host_id=host_id) + path


# --- Historical Events (private REST path) ---


def _normalize_sensor_reference(event: Any) -> Any:
    """Report a sensor event's sensor id under the additive ``_resolved_sensor`` key.

    Sensor events set the top-level ``sensor`` field to null; the actual sensor
    reference lives at ``metadata.sensorId.text``. Callers filter and join on the
    sensor, so it is surfaced in one predictable place — added next to the
    controller's fields, which (``sensor`` and ``metadata`` included) stay verbatim.
    """
    if not isinstance(event, dict) or event.get("sensor") is not None:
        return event
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        sensor_id = metadata.get("sensorId")
        if isinstance(sensor_id, dict) and sensor_id.get("text"):
            return with_context(event, {RESOLVED_SENSOR_KEY: sensor_id["text"]})
    return event


#: The match keys of a camera name: the server's one name-tier rule
#: (:func:`unifi_fabric.matching.name_keys`).
_name_tiers = name_keys


async def _resolve_camera_refs(
    client: UniFiClient, host_id: str, refs: str | list[str], *, key: APIKeyConfig | None = None
) -> list[str]:
    """Resolve camera name(s) to ID(s) for the ``cameras`` filter; pass IDs through.

    Mirrors the name-or-ID convention used by ``resolve_host_id``/``resolve_site_id``.
    A reference that matches a known camera ID (or is 24-hex ID-shaped) passes through
    unchanged. A name is matched in tiers, the first tier with a match wins: the exact
    name; then the NFC-normalized, casefolded name (so ``Café`` typed composed matches a
    decomposed upstream ``Café``, and case does not matter); then with surrounding
    whitespace stripped, case kept before casefolded (``Garage`` matches an upstream
    ``Garage ``; `` Garage`` prefers ``Garage`` over ``garage``). Two
    cameras matching in the winning tier is an ambiguity error listing both; no match
    raises ValueError listing the camera names exactly as the upstream has them, rather
    than silently filtering to a non-existent camera.
    """
    ref_list = [refs] if isinstance(refs, str) else list(refs)
    data = await client.get(_proxy(host_id, "/cameras"), key=key)
    from ...client import object_records

    cams = object_records(_as_list(data, "cams"), "Protect camera resolution")
    # Camera ids by their case-insensitive key: an upper-case ObjectId resolves to the
    # upstream spelling.
    by_id = {id_key(c["id"]): c["id"] for c in cams if isinstance(c.get("id"), str) and c.get("id")}
    named_cams = [c for c in cams if isinstance(c.get("name"), str)]
    tiers: list[dict[str, list[dict[str, Any]]]] = [{}, {}, {}, {}]
    for c in named_cams:
        for tier, match_key in zip(tiers, _name_tiers(c["name"]), strict=True):
            tier.setdefault(match_key, []).append(c)
    resolved: list[str] = []
    for ref in ref_list:
        if id_key(ref) in by_id:
            resolved.append(by_id[id_key(ref)])
            continue
        if _CAMERA_ID_RE.match(ref):
            resolved.append(ref)
            continue
        named: list[dict[str, Any]] = []
        for tier, match_key in zip(tiers, _name_tiers(ref), strict=True):
            named = tier.get(match_key, [])
            if named:
                break
        named = list({id_key(_require_native_id(c, "id")): c for c in named}.values())
        if len(named) > 1:
            choices = "; ".join(
                f"{upstream_error_value(c['name'], client)!r} "
                f"({upstream_error_value(c['id'], client)})"
                for c in named
            )
            raise ValueError(
                f"ambiguous camera {ref!r}: {len(named)} cameras share that name "
                f"({choices}). Pass the camera id instead."
            )
        if not named:
            available = sorted(
                str(upstream_error_value(c["name"], client))
                for c in cams
                if isinstance(c, dict) and isinstance(c.get("name"), str)
            )
            raise ValueError(
                f"Camera {ref!r} not found on host {host_id!r}. "
                f"Pass a camera ID or one of these names: {upstream_error_value(available, client)}"
            )
        resolved.append(named[0]["id"])
    return resolved


async def list_protect_events(
    client: UniFiClient,
    registry: Registry,
    host: str,
    start: int,
    end: int,
    types: str | list[str] | None = None,
    cameras: str | list[str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    order_direction: str | None = None,
    smart_detect_types: str | list[str] | None = None,
    categories: str | list[str] | None = None,
    without_descriptions: bool | None = None,
) -> Any:
    """Query historical Protect events via the private /proxy/protect/api/events REST path.

    start/end: REQUIRED epoch SECONDS (UTC) as integers; converted to milliseconds
    internally. Bounds are exact millisecond instants; end excludes the remainder of its
    second. ``order_direction`` is sent as
    ``orderDirection`` only when given ("ASC" oldest-first, "DESC" newest-first); omitted,
    the upstream's own order applies (this private endpoint has no spec, so no default is
    sent on the caller's behalf). (These are epoch seconds, not the ISO 8601 strings
    query_isp_metrics expects.)

    Filters (all verified live to actually narrow the result set server-side):
    * ``types`` — event TYPE; single value or list. Verified-present values:
      ``motion``, ``smartDetectZone``, ``smartAudioDetect``, ``sensorOpened``,
      ``sensorClosed``, ``access``. An unrecognised value returns zero events.
    * ``smart_detect_types`` — the smart-detect SUBTYPE within smart events
      (``person``/``vehicle``/``animal``/``package``/``face``/``licensePlate`` on
      ``smartDetectZone``; ``alrmSpeak``/``alrmSiren``/``alrmBark``/``alrmCarHorn`` on
      ``smartAudioDetect``). This is a DIFFERENT upstream parameter from ``types`` —
      these values are NOT accepted by ``types``. The API only honours
      ``smart_detect_types`` when ``types`` is also set (passing it alone is a silent
      no-op upstream); the call is still sent and the result carries a ``_warnings``
      entry (``SMART_DETECT_TYPES_WITHOUT_TYPES``).
    * ``cameras`` — camera name(s) OR ID(s); single value or list. Names resolve to
      IDs (case-insensitive); an unknown name raises rather than filtering to nothing.
    * ``categories`` — event category; single value or list. Verified values:
      ``motion``, ``smart``, ``iot``, ``admin``. Unknown values are silently ignored
      by the upstream API (it validates against its own enum).
    * ``without_descriptions`` — when True, ask the API to omit the per-event
      ``description`` block (~16% smaller payload). Opt-in only; full fidelity is the
      default and this is never applied automatically.

    Pagination is offset-based (verified live: the endpoint returns a bare JSON array
    and honours offset/limit; a wide window holds tens of thousands of events and an
    unpaginated fetch times out on the device). By default every page is drained (in
    pages of 200) and the complete, time-ordered event set is returned; a large
    window therefore returns *all* matching events rather than only the first page.
    Pass offset or limit to fetch a single explicit page instead; its result follows the
    upstream page's shape. A bare-list page is returned as that list: each event verbatim
    except that a sensor event gains ``_resolved_sensor``, and no ``_warnings`` (a list has
    no place for them). An object page preserves every upstream top-level field verbatim;
    its ``data`` events gain only ``_resolved_sensor`` and the page gains ``_count`` and
    the epoch-unit and smart-detect ``_warnings``, as a drained result does. A drain
    of object pages retains the
    ``data`` array key and the first page's envelope fields; a drain of bare arrays uses
    ``result`` for the gathered events. There is no page cap by default; only when the operator
    opts in to ``UNIFI_PAGINATE_MAX_PAGES`` can a drain stop early, and then the events
    gathered so far are returned with ``incomplete=true`` rather than truncated silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    warnings = epoch_warnings(start=start, end=end)
    if smart_detect_types is not None and types is None:
        warnings.append(dict(SMART_DETECT_WITHOUT_TYPES_WARNING))
    smart_hint = _smart_detect_hint(smart_detect_types, types)
    start_ms = seconds_to_millis(require_epoch_seconds(start, "start"))
    end_ms = seconds_to_millis(require_epoch_seconds(end, "end"))
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    params: dict[str, Any] = {"start": start_ms, "end": end_ms}
    if types is not None:
        params["types"] = types
    if cameras is not None:
        params["cameras"] = await _resolve_camera_refs(client, host_id, cameras, key=key)
    if smart_detect_types is not None:
        params["smartDetectTypes"] = smart_detect_types
    if categories is not None:
        params["categories"] = categories
    if without_descriptions:
        params["withoutDescriptions"] = "true"
    if order_direction is not None:
        params["orderDirection"] = order_direction
    try:
        collected = await collect_offset(
            client, _private(host_id, "/events"), key=key, params=params, offset=offset, limit=limit
        )
    except UniFiConnectionError as exc:
        error = upstream_hint(translate_host_not_found(exc, host), smart_hint)
        if error is exc:
            raise
        raise error from exc
    events = collected["items"]
    normalized = [_normalize_sensor_reference(event) for event in events]
    if bare_page(collected) is not None:
        # An explicit page the upstream sent as a bare array is returned as that array
        # (each event verbatim, plus the additive _resolved_sensor key).
        return normalized
    raw = collected.get("raw")
    if isinstance(raw, dict):
        result: dict[str, Any] = with_context(
            {**raw, "data": normalized}, {"_count": len(normalized)}
        )
    else:
        # The drain retains the first page's array key even when its envelope is empty.
        # Bare-array drains keep the historical result wrapper.
        array_key = "data" if collected.get("array_key") == "data" else "result"
        result = with_envelope({array_key: normalized, "_count": len(normalized)}, collected)
    return with_warnings(mark_incomplete(result, collected), warnings)


def _smart_detect_hint(smart_detect_types: Any, types: Any) -> str | None:
    """The hint an upstream error gets when ``smart_detect_types`` was sent without
    ``types`` (None otherwise)."""
    if smart_detect_types is None or types is not None:
        return None
    return str(SMART_DETECT_WITHOUT_TYPES_WARNING["message"])


# --- Live-stream collectors (poll-count REST poll) ---
#
# The Protect WebSocket subscriptions are not reachable over the Fabric cloud
# connector (see the DELIBERATELY EXCLUDED note further down). These two tools
# surface the same data — new events, and device add/remove/modify — by polling
# the REST surface for a caller-selected number of polls and assembling one result.
# They are read-only and stateless: each call starts fresh, holds no cursor
# between calls, and issues no writes.

# Pacing sleep is indirected so tests can complete each poll without real delays.
_sleep = asyncio.sleep


def _validate_collector_controls(poll_count: int, poll_interval_seconds: float) -> None:
    """Reject invalid work counts and pacing before host resolution or I/O."""
    if isinstance(poll_count, bool) or not isinstance(poll_count, int) or poll_count < 1:
        raise ValueError("poll_count must be a positive integer")
    if (
        isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not math.isfinite(poll_interval_seconds)
    ):
        raise ValueError("poll_interval_seconds must be a finite number")
    if poll_interval_seconds < 0:
        raise ValueError("poll_interval_seconds must be at least 0 seconds")


def _validate_collector_limit(value: int | None, name: str) -> None:
    """Reject invalid optional collection limits before host resolution or I/O."""
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
        raise ValueError(f"{name} must be a positive integer or None")


#: A family whose list route answers one of these is not served by this console's
#: Protect version (the newer families need a newer Protect application).
_FAMILY_UNAVAILABLE_RE = re.compile(r"^HTTP (404|501) from GET ")


def _device_change_basis(device: dict[str, Any]) -> dict[str, Any]:
    """Modified-comparison basis: the upstream device object minus the volatile
    heartbeat fields in ``_VOLATILE_DEVICE_FIELDS``. Never returned to the caller —
    the verbatim object is what ships in the change record."""
    return {k: v for k, v in device.items() if k not in _VOLATILE_DEVICE_FIELDS}


def _record_key(record: Any) -> str:
    """Stable identity for a record with no ``id``: its canonical full-record JSON.

    Key order does not matter (``sort_keys``); every field participates, so two
    records that differ anywhere get different keys. Non-JSON values fall back to
    ``repr`` so the key is always computable.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=repr)


def _collector_id(record: Any, path: str) -> Any:
    """Read an optional scalar identity before indexing an upstream poll record."""
    value = record.get("id") if isinstance(record, dict) else None
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: record id must be a JSON "
            f"scalar or null, got {describe_shape(value)}"
        )
    return value


async def collect_protect_events(
    client: UniFiClient,
    registry: Registry,
    host: str,
    poll_count: int = 6,
    max_events: int | None = None,
    since: int | None = None,
    types: str | list[str] | None = None,
    cameras: str | list[str] | None = None,
    smart_detect_types: str | list[str] | None = None,
    poll_interval_seconds: float = 2.0,
    order_direction: str | None = None,
) -> dict[str, Any]:
    """Collect Protect events with an explicit poll-count boundary (WebSocket-feed parity).

    Queries the historical-events REST path for ``poll_count`` completed polls
    and returns every distinct event seen. This is the REST
    stand-in for the ``/v1/subscribe/events`` WebSocket feed, which is not
    reachable over the Fabric cloud connector.

    poll_count: positive integer number of complete polls (default 6). An active
      poll is never interrupted by elapsed time; cancellation remains available.
    max_events: optional early stop — once this many distinct events have been
      collected, stop and flag ``_truncated=true``. Default None: no limit, the requested
      polls are completed. A single poll is never truncated mid-page, so the returned
      count may slightly exceed it. Full event fidelity is preserved.
    since: optional epoch SECONDS lower bound for the query window; defaults to the
      wall-clock moment the call starts, so only events at/after the call are seen.
    types / cameras / smart_detect_types: same filters as ``list_protect_events``
      (camera names resolve to IDs; ``smart_detect_types`` without ``types`` is
      forwarded unchanged with the same ``_warnings`` entry).
    poll_interval_seconds: pacing delay between completed polls (default 2). This
      does not bound request duration or cancel an active poll.
      0 means no timed delay; the event loop still yields between polls. Small values poll
      harder and may hit the shared 429 backoff, which the client already handles.
    order_direction: optional; sent as ``orderDirection`` on every poll only when given
      (no default is sent: the private events endpoint has no spec to back one).

    Each poll drains every page of each poll. There is no page cap by default; only
    when the operator opts in to ``UNIFI_PAGINATE_MAX_PAGES`` can a poll stop early, and
    then the result carries ``incomplete=true`` with the reason. When a poll fails after
    at least one poll succeeded (any error: an HTTP error, a 429 that outlasted the
    retries, a transport or shape error), polling stops and the events already gathered
    are returned with ``incomplete=true`` and an ``incompleteReason`` carrying the failed
    poll's complete error; a failing FIRST poll raises that error.

    Returns ``{result, _poll_count, _polls, _truncated}`` where ``result`` holds the
    verbatim upstream event objects. Events are de-duplicated by event ``id`` only;
    when the same id is seen across polls the LATEST object for that id is kept
    (events without an ``id`` are de-duplicated by their full record: an identical
    id-less event returned by several overlapping polls is kept once, verbatim, and
    counts once toward ``max_events``; id-less events that differ in any field are
    each kept). ``since`` must be an integer (checked before any host resolution or
    upstream call); a negative or millisecond-magnitude value is sent with a ``_warnings``
    entry.
    An upstream 404/501 (Protect absent on this console/version) is passed straight
    through.
    """
    _validate_collector_controls(poll_count, poll_interval_seconds)
    _validate_collector_limit(max_events, "max_events")
    warnings = epoch_warnings(since=since)
    if smart_detect_types is not None and types is None:
        warnings.append(dict(SMART_DETECT_WITHOUT_TYPES_WARNING))
    smart_hint = _smart_detect_hint(smart_detect_types, types)
    # ``since`` must be an integer (checked before any key/host resolution or request).
    since_ms = (
        seconds_to_millis(require_epoch_seconds(since, "since")) if since is not None else None
    )
    key, host_id = await _resolve(registry, host)
    resolved_cameras: list[str] | None = None
    if cameras is not None:
        resolved_cameras = await _resolve_camera_refs(client, host_id, cameras, key=key)
    start_ms = since_ms if since_ms is not None else int(time.time() * 1000)

    events_by_id: dict[Any, Any] = {}
    # Events without an ``id`` are keyed by their full canonical record, so the same
    # id-less event re-returned by every overlapping poll is kept once (and counted
    # once toward max_events) instead of being re-appended on each poll.
    anonymous: dict[str, Any] = {}
    polls = 0
    truncated = False
    incomplete_reasons: list[str] = []
    while True:
        params: dict[str, Any] = {"start": start_ms, "end": int(time.time() * 1000)}
        if order_direction is not None:
            params["orderDirection"] = order_direction
        if types is not None:
            params["types"] = types
        if resolved_cameras is not None:
            params["cameras"] = resolved_cameras
        if smart_detect_types is not None:
            params["smartDetectTypes"] = smart_detect_types
        try:
            # Each poll drains every page of each poll (same offset paging as
            # list_protect_events), so a busy window is never cut at one page.
            collected = await collect_offset(
                client, _private(host_id, "/events"), key=key, params=params
            )
            # Validate the whole poll before accepting it, so a malformed later poll
            # leaves earlier polls intact and uses the same incomplete-error path.
            event_ids = [
                _collector_id(event, _private(host_id, "/events")) for event in collected["items"]
            ]
        except Exception as exc:  # noqa: BLE001 - any failed poll ends this collection run
            error = (
                upstream_hint(translate_host_not_found(exc, host), smart_hint)
                if isinstance(exc, UniFiConnectionError)
                else exc
            )
            if polls == 0:
                if error is exc:
                    raise
                raise error from exc
            # Events already gathered are real: keep them, say why the polling run ended
            # (an HTTP error, a 429 that outlasted the retries, a transport or shape error).
            incomplete_reasons.append(_poll_failed_reason(polls + 1, error))
            break
        polls += 1
        if collected["incomplete"]:
            incomplete_reasons.append(f"poll {polls}: {collected['incompleteReason']}")
        for event, event_id in zip(collected["items"], event_ids, strict=True):
            normalized = _normalize_sensor_reference(event)
            if event_id is not None:
                events_by_id[event_id] = normalized
            else:
                anonymous.setdefault(_record_key(event), normalized)
        if max_events is not None and len(events_by_id) + len(anonymous) >= max_events:
            truncated = True
            break
        if polls >= poll_count:
            break
        await _sleep(poll_interval_seconds)

    events = list(events_by_id.values()) + list(anonymous.values())
    result: dict[str, Any] = {
        "result": events,
        "_poll_count": poll_count,
        "_polls": polls,
        "_truncated": truncated,
    }
    if incomplete_reasons:
        result["incomplete"] = True
        result["incompleteReason"] = "; ".join(incomplete_reasons)
    return with_warnings(result, warnings)


def _poll_failed_reason(poll: int, error: Exception) -> str:
    """The ``incompleteReason`` part for a collector poll that failed after a completed poll."""
    return (
        f"poll {poll} failed, so polling stopped and only the earlier polls' results are "
        f"returned: {error}"
    )


def _unidentified_key(entry: dict[str, Any]) -> str:
    """Identity of an id-less ``{family, device}`` observation across polls: the family
    plus the device object minus the volatile heartbeat fields
    (``_VOLATILE_DEVICE_FIELDS``)."""
    device = entry.get("device")
    basis = _device_change_basis(device) if isinstance(device, dict) else device
    return _record_key({"family": entry.get("family"), "device": basis})


async def _poll_device_snapshot(
    client: UniFiClient,
    host: str,
    host_id: str,
    key: APIKeyConfig | None,
) -> tuple[dict[Any, Any], list[dict[str, Any]], dict[str, str], dict[Any, str]]:
    """One snapshot: the union of the Protect device families keyed by device id.

    Returns ``(snapshot, unidentified, unavailable, family_of)``; ``family_of`` maps each
    device id in ``snapshot`` to the family list it came from. A device object without an ``id``
    cannot be tracked across polls, so it is not diffed; it is returned verbatim in
    ``unidentified`` as ``{"family", "device"}`` (never silently skipped). A family whose
    list route answers 404/501 (a family this console's Protect version does not serve)
    is reported in ``unavailable`` ({family: upstream error}) and the other families
    still count; when EVERY family answers that way (Protect absent on this console) the
    first error propagates verbatim via ``translate_host_not_found``. Any other error
    propagates at once.
    """
    snapshot: dict[Any, Any] = {}
    family_of: dict[Any, str] = {}
    unidentified: list[dict[str, Any]] = []
    unavailable: dict[str, str] = {}
    first_error: UniFiConnectionError | None = None
    for family in DEVICE_FAMILIES:
        try:
            data = await client.get(_proxy(host_id, f"/{family}"), key=key)
        except UniFiConnectionError as exc:
            if not _FAMILY_UNAVAILABLE_RE.match(str(exc)):
                raise translate_host_not_found(exc, host) from exc
            first_error = first_error or exc
            unavailable[family] = str(exc)
            continue
        for device in _as_list(data):
            device_id = _collector_id(device, _proxy(host_id, f"/{family}"))
            if device_id is not None:
                snapshot[device_id] = device
                family_of[device_id] = family
            else:
                unidentified.append({"family": family, "device": device})
    if first_error is not None and len(unavailable) == len(DEVICE_FAMILIES):
        raise translate_host_not_found(first_error, host) from first_error
    return snapshot, unidentified, unavailable, family_of


def _diff_device_snapshots(
    previous: dict[Any, Any], current: dict[Any, Any]
) -> list[dict[str, Any]]:
    """Diff two device snapshots into added / modified / removed change records.

    ``added`` / ``modified`` carry the current verbatim object; ``removed`` carries
    the last-seen verbatim object. ``modified`` uses ``_device_change_basis`` so a
    routine heartbeat (``lastSeen`` / ``uptime`` / ``upSince`` only) is not a change.
    """
    changes: list[dict[str, Any]] = []
    for device_id, device in current.items():
        if device_id not in previous:
            changes.append({"change": "added", "device": device})
        elif _device_change_basis(device) != _device_change_basis(previous[device_id]):
            changes.append({"change": "modified", "device": device})
    for device_id, device in previous.items():
        if device_id not in current:
            changes.append({"change": "removed", "device": device})
    return changes


async def collect_protect_device_changes(
    client: UniFiClient,
    registry: Registry,
    host: str,
    poll_count: int = 6,
    max_changes: int | None = None,
    poll_interval_seconds: float = 2.0,
) -> dict[str, Any]:
    """Collect Protect device add/remove/modify changes for an explicit number of polls.

    Polls the union of the Protect device families ``poll_count`` times and reports
    what changed between consecutive snapshots. This
    is the REST stand-in for the ``/v1/subscribe/devices`` WebSocket feed, which is
    not reachable over the Fabric cloud connector.

    poll_count: positive integer number of complete snapshots (default 6).
      At least two polls are needed to detect a change. An active snapshot is never
      interrupted by elapsed time; cancellation remains available.
    max_changes: optional early stop — once this many change records have accumulated,
      stop and flag ``_truncated=true``. Default None: no limit, all requested polls are
      completed.
    poll_interval_seconds: pacing delay between completed polls (default 2). This
      does not bound request duration or cancel an active poll.
      0 means no timed delay; the event loop still yields between polls. Small values may
      hit the shared 429 backoff, which the client already handles.

    Returns ``{_poll_count, _polls, _truncated, changes}`` (the same ``_``-prefixed run
    keys as ``collect_protect_events``); when a device object carries
    no ``id`` it cannot be diffed, and the result adds ``unidentified`` (``[{family,
    device}]`` verbatim, every distinct one seen in any poll of the run, even one a
    later poll no longer returns), ``incomplete: true`` and ``incompleteReason``.
    Each change is
    ``{"change": "added"|"removed"|"modified", "device": <verbatim upstream
    object>}``: the ``change`` label is derived by this tool; the device object is
    never altered. MODIFIED EQUALITY BASIS: two snapshots of the same device id are
    "modified" when their upstream objects differ by equality after removing the
    volatile heartbeat fields ``lastSeen`` / ``uptime`` / ``upSince``, so a status
    beacon that only bumps those does not surface as a change. An upstream 404/501
    (Protect absent on this console/version) is passed straight through. A family that
    answers 404/501 in either of two consecutive polls is left out of their diff (named
    under ``unavailableFamilies``): a family that stops answering never reports its
    devices "removed", one that starts answering never reports them "added". When a
    poll fails after at least one poll succeeded (any error: an HTTP error, a 429 that
    outlasted the retries, a transport or shape error), polling stops and the changes
    already gathered are returned with ``incomplete: true`` and an ``incompleteReason``
    carrying the failed poll's complete error; a failing FIRST poll raises that error.
    """
    _validate_collector_controls(poll_count, poll_interval_seconds)
    _validate_collector_limit(max_changes, "max_changes")
    key, host_id = await _resolve(registry, host)
    polls = 0
    truncated = False
    changes: list[dict[str, Any]] = []
    previous: dict[Any, Any] | None = None
    previous_family_of: dict[Any, str] = {}
    previous_unavailable: set[str] = set()
    # Id-less device objects seen in ANY poll of the run: one that a later poll no
    # longer returns is still reported, so the collection run stays incomplete for it. Each is
    # keyed by its family and record minus the volatile heartbeat fields (the same basis
    # as "modified"), so a heartbeat (a rising uptime) is the same device, never a new
    # entry; the latest verbatim object is kept, in first-seen order.
    unidentified: dict[str, dict[str, Any]] = {}
    unavailable: dict[str, str] = {}
    poll_failure: str | None = None
    while True:
        try:
            (
                snapshot,
                polled_unidentified,
                polled_unavailable,
                family_of,
            ) = await _poll_device_snapshot(client, host, host_id, key)
        except Exception as exc:  # noqa: BLE001 - any failed poll ends this collection run
            if polls == 0:
                raise
            # Changes already gathered are real: keep them, say why the polling run ended
            # (an HTTP error, a 429 that outlasted the retries, a transport or shape error).
            poll_failure = _poll_failed_reason(polls + 1, exc)
            break
        unavailable.update(polled_unavailable)
        for entry in polled_unidentified:
            unidentified[_unidentified_key(entry)] = entry
        polls += 1
        if previous is not None:
            # A family unavailable (404/501) in either poll is left out of the diff: its
            # devices did not vanish or appear, the family list did.
            skip = previous_unavailable | set(polled_unavailable)
            before = {i: d for i, d in previous.items() if previous_family_of.get(i) not in skip}
            after = {i: d for i, d in snapshot.items() if family_of.get(i) not in skip}
            for change in _diff_device_snapshots(before, after):
                changes.append(change)
                if max_changes is not None and len(changes) >= max_changes:
                    truncated = True
                    break
        previous = snapshot
        previous_family_of = family_of
        previous_unavailable = set(polled_unavailable)
        if truncated or polls >= poll_count:
            break
        await _sleep(poll_interval_seconds)
    # The derived run metadata uses the same additive keys as collect_protect_events.
    result: dict[str, Any] = {
        "_poll_count": poll_count,
        "_polls": polls,
        "_truncated": truncated,
        "changes": changes,
    }
    reasons: list[str] = []
    if unidentified:
        # Never a silent skip: id-less device objects (from every poll of the run) are
        # returned verbatim and the change set is flagged incomplete for them.
        result["unidentified"] = list(unidentified.values())
        reasons.append(
            f"{len(unidentified)} device object(s) carry no id, so their add/remove/modify "
            "changes cannot be tracked; they are listed verbatim under unidentified"
        )
    if unavailable:
        # A family this console does not serve is named with its upstream error, never
        # dropped silently.
        result["unavailableFamilies"] = unavailable
        reasons.append(
            f"{len(unavailable)} device famil{'y' if len(unavailable) == 1 else 'ies'} "
            f"({', '.join(sorted(unavailable))}) answered 404/501, so their changes are not "
            "tracked; the upstream errors are under unavailableFamilies"
        )
    if poll_failure is not None:
        reasons.append(poll_failure)
    if reasons:
        result["incomplete"] = True
        result["incompleteReason"] = "; ".join(reasons)
    return result


# --- Camera Info and Settings ---


async def get_camera(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect camera by ID."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/cameras/{camera_id_seg}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


async def update_camera(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    /,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect camera (name, recording mode, etc.)."""
    return await _update_item_verified(
        client, registry, host, "cameras", camera_id, "camera_id", fields
    )


# --- Camera share links (private REST, cloud connector only) ---


async def get_camera_share_link(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> Any:
    """Read the upstream share-link body verbatim through the cloud connector."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_id_seg}/sharedStream")
    return _route_result(client, "GET", path, await client.get(path, key=key))


async def enable_camera_share_link(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> Any:
    """Enable public camera sharing; no request body and no automatic retry."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_id_seg}/sharedStream")
    response = await client.request("POST", path, key=key)
    return _route_result(client, "POST", path, decode_body(response))


async def disable_camera_share_link(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> Any:
    """Revoke public camera sharing; return the DELETE body verbatim, without retry."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_id_seg}/sharedStream")
    return _route_result(client, "DELETE", path, await client.delete(path, key=key))


# --- Camera Streams and Media ---


async def get_camera_snapshot(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    channel: str | None = None,
    high_quality: bool | None = None,
    ts: int | None = None,
) -> dict[str, Any]:
    """Request a snapshot from a Protect camera. Returns base64 image data and the
    upstream Content-Type (typically image/jpeg).

    ``channel`` and ``high_quality`` are the spec's optional ``channel`` and
    ``highQuality`` query parameters, sent only when given: ``channel`` verbatim
    (``"main"``, or ``"package"`` for the package camera of a camera with
    ``hasPackageCamera: true``), ``high_quality`` as ``"true"``/``"false"`` (force a
    1080p-or-higher snapshot). The upstream validates the values.

    ``ts`` selects a past moment instead of the live frame: the request then goes to the
    private Protect route ``cameras/{id}/recording-snapshot`` (Protect 5.3.18 web app; not
    in the published Integration API) with ``ts`` as its query parameter, sent as given.
    Provenance of ``ts``: the route's query keys are built dynamically in the web app, so
    the name was found by probing a live console on 2026-10-17 (Protect 5.3.18): the route
    answered HTTP 400 without it and HTTP 404 ``Recording not found`` with it, so the key
    is accepted. Its unit is INFERRED to be epoch milliseconds and is UNVERIFIED (a 404 does
    not prove a unit), and a successful image response has not been observed. When ``ts`` is
    given the result also carries a ``_warnings`` entry saying so.
    """
    camera_id_seg = path_segment(camera_id, "camera_id")
    params: dict[str, Any] = {}
    if channel is not None:
        params["channel"] = channel
    if high_quality is not None:
        params["highQuality"] = "true" if high_quality else "false"
    if ts is not None:
        params["ts"] = ts
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    route = (
        _private(host_id, f"/cameras/{camera_id_seg}/recording-snapshot")
        if ts is not None
        else _proxy(host_id, f"/cameras/{camera_id_seg}/snapshot")
    )
    raw, content_type = await client.get_binary(
        route,
        key=key,
        **({"params": params} if params else {}),
    )
    snapshot = {
        "image_base64": base64.b64encode(raw).decode(),
        "content_type": content_type,  # the upstream Content-Type, not assumed
        "size_bytes": len(raw),
    }
    if ts is None:
        return snapshot
    return with_warnings(snapshot, [_TS_UNIT_WARNING | {"value": ts}])


async def get_rtsps_stream(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get existing RTSPS stream URLs for a Protect camera."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/cameras/{camera_id_seg}/rtsps-stream")
    return _route_result(
        client, "GET", path, _require_object(await client.get(path, key=key), f"GET {path}")
    )


def require_nonempty_qualities(qualities: Any, *, where: str) -> list[str]:
    """Validate a required ``qualities`` array (spec ``minItems: 1``) before any request.

    ``where`` names the spec location (``"query"`` for DELETE, ``"body"`` for POST) for the
    message. An empty list would otherwise be sent as no ``qualities`` at all (an empty
    array serializes to no query parameter), which the spec forbids and which could be
    reported as a successful delete. Returns the lowercased list that is sent upstream.
    """
    if not isinstance(qualities, list) or not qualities:
        raise ValueError(
            f"'qualities' must be a non-empty list (got {qualities!r}): the {where} parameter "
            "is required with minItems 1 (Protect 7.3.74). Pass at least one of 'high', "
            "'medium', 'low', 'package'."
        )
    if not all(isinstance(q, str) and q.strip() for q in qualities):
        raise ValueError(f"'qualities' entries must be non-empty strings (got {qualities!r})")
    return [q.lower() for q in qualities]


async def create_rtsps_stream(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    qualities: list[str],
) -> dict[str, Any]:
    """Create an RTSPS stream for a Protect camera."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    normalized = require_nonempty_qualities(qualities, where="body")
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/cameras/{camera_id_seg}/rtsps-stream")
    response = await _post(
        client,
        path,
        key=key,
        json={"qualities": normalized},
    )
    return _route_result(client, "POST", path, _write_result("created", response))


async def delete_rtsps_stream(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    qualities: str | list[str],
) -> Any:
    """Delete an RTSPS stream for a Protect camera; returns the upstream body verbatim.

    ``qualities`` is one channel name or a list of them (spec ``removedQualities``:
    ``anyOf`` a ``channelQuality`` scalar or a non-empty array); both send the same
    ``qualities`` query parameter(s).
    """
    camera_id_seg = path_segment(camera_id, "camera_id")
    items = [qualities] if isinstance(qualities, str) else qualities
    normalized = require_nonempty_qualities(items, where="query")
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/cameras/{camera_id_seg}/rtsps-stream")
    response = await client.delete(
        path,
        key=key,
        params={"qualities": normalized},
    )

    return _route_result(client, "DELETE", path, response)


# --- Camera Audio ---


async def talkback_start(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Start a talkback audio session on a Protect camera (opens live two-way audio).

    429 auto-retry is disabled: a retry could open a second session."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    # A physical action: never auto-retried on 429, since a retry can repeat it
    # (same rule as trigger_alarm_webhook and the siren/relay/arm actions).
    response = await _post(
        client,
        _proxy(host_id, f"/cameras/{camera_id_seg}/talkback-session"),
        key=key,
    )
    return _write_result("sent", response)


async def disable_mic_permanently(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Permanently disable the microphone on a Protect camera (irreversible).

    429 auto-retry is disabled (a physical action is never repeated by a retry)."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    # A physical action: never auto-retried on 429, since a retry can repeat it
    # (same rule as trigger_alarm_webhook and the siren/relay/arm actions).
    response = await _post(
        client,
        _proxy(host_id, f"/cameras/{camera_id_seg}/disable-mic-permanently"),
        key=key,
    )
    return _write_result("sent", response)


# --- Camera PTZ Control ---


async def ptz_goto(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    slot: int,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Move a PTZ camera to a preset slot (-1 = the home preset, >= 0 other presets).

    429 auto-retry is disabled (physical action)."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    check_arguments("ptz_goto_preset", {"slot": slot})
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    # A physical action: never auto-retried on 429, since a retry can repeat it
    # (same rule as trigger_alarm_webhook and the siren/relay/arm actions).
    response = await _post(
        client, _proxy(host_id, f"/cameras/{camera_id_seg}/ptz/goto/{slot}"), key=key
    )
    return _write_result("sent", response)


async def ptz_patrol_start(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    slot: int,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Start a PTZ patrol on a patrol slot 0-4. 429 auto-retry is disabled (physical action)."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    check_arguments("ptz_patrol_start", {"slot": slot})
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    # A physical action: never auto-retried on 429, since a retry can repeat it
    # (same rule as trigger_alarm_webhook and the siren/relay/arm actions).
    response = await _post(
        client,
        _proxy(host_id, f"/cameras/{camera_id_seg}/ptz/patrol/start/{slot}"),
        key=key,
    )
    return _write_result("sent", response)


async def ptz_patrol_stop(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Stop the current PTZ patrol on a camera. 429 auto-retry is disabled (physical action)."""
    camera_id_seg = path_segment(camera_id, "camera_id")
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    # A physical action: never auto-retried on 429, since a retry can repeat it
    # (same rule as trigger_alarm_webhook and the siren/relay/arm actions).
    response = await _post(
        client, _proxy(host_id, f"/cameras/{camera_id_seg}/ptz/patrol/stop"), key=key
    )
    return _write_result("sent", response)


# --- Sensors ---


async def get_sensor(
    client: UniFiClient,
    registry: Registry,
    host: str,
    sensor_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect sensor by ID."""
    sensor_id_seg = path_segment(sensor_id, "sensor_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/sensors/{sensor_id_seg}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


async def update_sensor(
    client: UniFiClient,
    registry: Registry,
    host: str,
    sensor_id: str,
    /,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect sensor."""
    return await _update_item_verified(
        client, registry, host, "sensors", sensor_id, "sensor_id", fields
    )


# --- Lights ---


async def list_lights(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all lights on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/lights"), key=key)
    return _list_body(data, "lights")


async def get_light(
    client: UniFiClient,
    registry: Registry,
    host: str,
    light_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect light by ID."""
    light_id_seg = path_segment(light_id, "light_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/lights/{light_id_seg}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


async def update_light(
    client: UniFiClient,
    registry: Registry,
    host: str,
    light_id: str,
    /,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect light."""
    return await _update_item_verified(
        client, registry, host, "lights", light_id, "light_id", fields
    )


# --- Chimes ---


async def list_chimes(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all chimes on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/chimes"), key=key)
    return _list_body(data, "chimes")


async def get_chime(
    client: UniFiClient,
    registry: Registry,
    host: str,
    chime_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect chime by ID."""
    chime_id_seg = path_segment(chime_id, "chime_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/chimes/{chime_id_seg}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


async def update_chime(
    client: UniFiClient,
    registry: Registry,
    host: str,
    chime_id: str,
    /,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect chime."""
    return await _update_item_verified(
        client, registry, host, "chimes", chime_id, "chime_id", fields
    )


# --- Viewers ---


async def list_viewers(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all viewers on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/viewers"), key=key)
    return _list_body(data, "viewers")


async def get_viewer(
    client: UniFiClient,
    registry: Registry,
    host: str,
    viewer_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect viewer by ID."""
    viewer_id_seg = path_segment(viewer_id, "viewer_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/viewers/{viewer_id_seg}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


async def update_viewer(
    client: UniFiClient,
    registry: Registry,
    host: str,
    viewer_id: str,
    /,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect viewer."""
    return await _update_item_verified(
        client, registry, host, "viewers", viewer_id, "viewer_id", fields
    )


# --- Liveviews ---


async def list_liveviews(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all liveviews on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/liveviews"), key=key)
    return _list_body(data, "liveviews")


async def get_liveview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    liveview_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect liveview by ID."""
    liveview_id_seg = path_segment(liveview_id, "liveview_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, f"/liveviews/{liveview_id_seg}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


def _body_with_name(tool: str, name: str, fields: dict[str, Any]) -> dict[str, Any]:
    """Merge the explicit ``name`` argument into a create body.

    ``name`` is its own tool argument and may also appear inside the settings dict. An
    identical repeat is accepted; a conflicting one is rejected before any request with
    an error that says which value to keep.
    """
    extra = dict(fields)
    if "name" in extra:
        repeated = extra.pop("name")
        if not leaf_equal(repeated, name):
            raise ValueError(
                f"{tool}: 'name' was given twice with different values (the name argument "
                "and settings['name']); pass it once, in the name argument"
            )
    return {"name": name, **extra}


async def create_liveview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    name: str,
    /,
    **fields: Any,
) -> dict[str, Any]:
    """Create a liveview on a Protect console."""
    _require_mutations()
    payload = _body_with_name("create_liveview", name, fields)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    response = await _post(client, _proxy(host_id, "/liveviews"), key=key, json=payload)
    return _write_result("created", response)


async def update_liveview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    liveview_id: str,
    /,
    **fields: Any,
) -> dict[str, Any]:
    """Update a liveview on a Protect console."""
    return await _update_item_verified(
        client, registry, host, "liveviews", liveview_id, "liveview_id", fields
    )


# --- NVR ---


async def get_nvr(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Get NVR details from a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, "/nvrs")
    return _require_object(await client.get(path, key=key), f"GET {path}")


# --- Protect Files ---


async def list_protect_files(
    client: UniFiClient,
    registry: Registry,
    host: str,
    file_type: str,
) -> dict[str, Any]:
    """List Protect device asset files of a given type (Protect 7.3.74: 'animations')."""
    validate_id(file_type, "file_type")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/files/{file_type}"), key=key)
    return with_context(_list_body(data, "files"), {"_file_type": file_type})


#: A MIME type ``type/subtype`` (RFC 6838 token characters, optional parameters).
_MIME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*(;[ -~]*)?\Z"
)


def upload_content_type(filename: str, content_type: str | None) -> str:
    """The Content-Type of the uploaded file part, or raise before any request.

    An explicit ``content_type`` is passed through as given (checked only to be a
    well-formed ``type/subtype``). Otherwise the filename extension is mapped to the
    spec-accepted type (:data:`UPLOAD_CONTENT_TYPES`); an unmapped extension fails,
    listing the accepted types.
    """
    if content_type is not None:
        if not isinstance(content_type, str) or not _MIME_RE.fullmatch(content_type.strip()):
            raise ValueError(
                f"content_type must be a MIME type such as 'audio/wave'; got {content_type!r}."
            )
        return content_type.strip()
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    mapped = UPLOAD_CONTENT_TYPES.get(ext)
    if mapped is None:
        accepted = ", ".join(f"{e} ({t})" for e, t in UPLOAD_CONTENT_TYPES.items())
        raise ValueError(
            f"Cannot tell the upload's MIME type from filename {filename!r} "
            f"(extension {ext or '(none)'!r}). Protect accepts: {accepted}. Rename the file "
            "with one of these extensions, or pass content_type explicitly."
        )
    return mapped


async def upload_protect_file(
    client: UniFiClient,
    registry: Registry,
    host: str,
    file_type: str,
    filename: str,
    file_content_base64: str,
    content_type: str | None = None,
) -> dict[str, Any]:
    """Upload a Protect device asset file (base64-encoded content) to /v1/files/{fileType}.

    ``file_content_base64`` is standard-alphabet, padded base64. Wrapped base64 is
    accepted: MIME / PEM-style line breaks and other whitespace are removed before a
    strict decode. Anything else that is not valid base64 (including a ``data:`` URL
    prefix) is rejected before any upload. The file part's Content-Type is
    ``content_type`` when given, else the spec type of the filename extension
    (:func:`upload_content_type`); an unmapped extension is rejected before any request.
    """
    _require_mutations()
    validate_id(file_type, "file_type")
    part_type = upload_content_type(filename, content_type)
    compact = "".join(file_content_base64.split())
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"file_content_base64 is not valid base64 ({exc}); pass the file's bytes "
            "base64-encoded (standard alphabet, padded; line breaks are allowed, a data: "
            "prefix is not)."
        ) from exc
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    # The part's Content-Type is stated explicitly, so the dry-run policy preview (field,
    # filename, content type, size) shows exactly what is sent.
    files = {"file": (filename, io.BytesIO(raw), part_type)}
    response = await _post(client, _proxy(host_id, f"/files/{file_type}"), key=key, files=files)
    return _write_result("uploaded", response)


# --- Alarm Manager ---


async def trigger_alarm_webhook(
    client: UniFiClient,
    registry: Registry,
    host: str,
    webhook_id: str,
) -> dict[str, Any]:
    """Trigger an alarm manager webhook by ID."""
    webhook_id_seg = path_segment(webhook_id, "webhook_id")
    _require_mutations()
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    response = await _post(
        client,
        _proxy(host_id, f"/alarm-manager/webhook/{webhook_id_seg}"),
        key=key,
    )
    return _write_result("sent", response)


# ===========================================================================
# Extended Protect resource families (UniFi Protect Integration API)
# ===========================================================================
#
# Every resource below is an officially documented UniFi Protect *Integration
# API* operation reached over the SAME Fabric-only connector base as the camera
# tools above (``PROTECT_PROXY_BASE`` →
# ``/v1/connector/consoles/{host_id}/proxy/protect/integration/v1``). There is
# no UI, SSH, or direct-controller route and no private/undocumented endpoint is
# used — the paths map 1:1 onto the published OpenAPI document
# (developer.ui.com/protect; the published Protect Integration API, including the
# meta/ULP/POS additions).
#
# Availability is firmware / application-version dependent. The alarm, arm,
# siren, relay, speaker, fob, bridge, link-station, alarm-hub, and POS resources
# require a Protect application new enough to expose them, and the arm/siren/
# relay/alarm-hub/POS actions require a local Alarm Manager / feature support. A
# console that does not support a family answers the proxied request with an
# upstream 404/501 which is passed straight through — treat that as "not
# available on this console/version", not a client bug.
#
# DELIBERATELY EXCLUDED: a persistent Protect WebSocket subscription. The Protect
# Integration API documents three subscription endpoints, ``GET /v1/subscribe/devices``,
# ``GET /v1/subscribe/events`` and (Protect 7.4.96) ``GET /v1/subscribe/updates``, but a
# persistent subscription is not available
# over the Fabric cloud connector this server uses: a GET carrying the WebSocket
# upgrade headers through
# ``…/proxy/protect/integration/v1/subscribe/events`` returns an upstream HTTP 404
# (``Entity 'endpoint' not found``), never a ``101 Switching Protocols`` — the
# cloud connector is a unary request/response relay and does not carry the Upgrade.
# A true persistent subscription needs local console (wss://) access this server
# does not have. The poll-count REST-poll collectors ``collect_protect_events``
# and ``collect_protect_device_changes`` (above) surface the same event and
# device-change data instead. Do not add a one-shot WebSocket wrapper here — it
# cannot connect. The per-product evidence lives in ``stream_buffers.COMPATIBILITY``,
# which ``get_event_stream_status`` and ``read_recent_events`` report.

PROTECT_MUTATIONS_ENV = switches.PROTECT_WRITES.env


def protect_mutations_enabled() -> bool:
    """Whether the Protect mutation family (extended write/action tools) may run.

    It governs every Protect *create / update / delete / upload / physical-action /
    POS-ingestion* tool, legacy camera-era families included. Pure read tools
    (list/get/meta) are never gated.

    DEFAULT ON: writes are allowed unless ``UNIFI_WRITE_EXCEPTIONS`` holds
    ``family:protect=deny`` (every Protect mutation refused at the deployment level). A
    ``confirm`` argument, where a tool has one, is ignored.
    """
    return switches.PROTECT_WRITES.enabled()


MUTATIONS_DISABLED_REASON = switches.area_deny_text("Protect", PROTECT_MUTATIONS_ENV)


def _require_mutations() -> None:
    """Raise ``ValueError`` with the actionable reason when Protect writes are opted out.

    Returns normally when writes are on (the default). Checked before any host
    resolution or HTTP call, so an opted-out deployment makes zero network requests.
    Raises like the connector write relay does, so every opted-out write area reports
    the refusal the same way.
    """
    if not protect_mutations_enabled():
        raise mark_write_denied(
            ValueError(
                MUTATIONS_DISABLED_REASON + switches.current_value_note(PROTECT_MUTATIONS_ENV)
            )
        )


def _require_object(data: Any, what: str) -> dict[str, Any]:
    """Return an upstream body that must be a JSON object, verbatim.

    Any other shape raises naming the shape received; it is never wrapped in an
    invented key or read as an empty object.
    """
    if isinstance(data, dict):
        return data
    raise UniFiConnectionError(
        f"Unexpected Protect response shape for {what}: expected an object, got "
        f"{describe_shape(data)}"
    )


async def _post(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None,
    json: dict[str, Any] | None = None,
    files: dict[str, Any] | None = None,
) -> Any:
    """POST a Protect write or action and return the upstream body verbatim.

    The body is decoded by ``client.decode_body`` (the server's single pass-through rule):
    decoded JSON, the text of a non-JSON body, or ``None`` for an empty/204 body. The
    write has already happened when the body arrives, so it is reported, never raised.
    """
    resp = await client.request("POST", path, key=key, json=json, files=files)
    return decode_body(resp)


async def _patch(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None,
    json: dict[str, Any],
) -> Any:
    """PATCH a Protect resource and return the upstream body verbatim (see ``_post``)."""
    resp = await client.request("PATCH", path, key=key, json=json, files=None)
    return decode_body(resp)


def _write_result(status: str, response: Any) -> dict[str, Any]:
    """The result of a Protect write or action: a status plus the upstream body verbatim.

    Under ``dry-run policy`` the write was never sent and ``response`` is the preview: the
    status is then ``"dry_run"``, never the would-be ``status`` ("created", "triggered").
    """
    if is_dry_run_preview(response):
        return {"status": "dry_run", "response": response}
    return {"status": status, "response": response}


async def _resolve(registry: Registry, host: str) -> tuple[APIKeyConfig | None, str]:
    """Resolve the owning key ONCE and the host id, threading key through both.

    Every extended-family tool routes through here so the owning Fabric API key is
    resolved a single time and passed to ``resolve_host_id`` and each client call —
    the multi-key routing contract the rest of the Protect module already follows.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return key, host_id


async def _list_family(
    client: UniFiClient, registry: Registry, host: str, family: str, plural: str
) -> dict[str, Any]:
    """GET /{family} and return the list body (see ``_list_body``).

    These Integration-API list endpoints return a bare JSON array (no pagination
    envelope), like ``list_cameras`` / ``list_sensors``.
    """
    key, host_id = await _resolve(registry, host)
    data = await client.get(_proxy(host_id, f"/{family}"), key=key)
    return _list_body(data, plural)


async def _get_item(
    client: UniFiClient, registry: Registry, host: str, family: str, item_id: str, id_name: str
) -> dict[str, Any]:
    """GET /{family}/{id} and pass the upstream object through unchanged."""
    item_id_seg = path_segment(item_id, id_name)
    key, host_id = await _resolve(registry, host)
    path = _proxy(host_id, f"/{family}/{item_id_seg}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


def _fields_to_send(fields: dict[str, Any], what: str) -> dict[str, Any]:
    """The PATCH body after dropping additive ``_`` keys and redaction-masked values.

    Runs before any upstream call, through the server's one empty-update guard
    (``write_body.update_problem``): a body with no field to change (empty, only ``_``
    keys, only masked values, only empty objects such as ``{"osdSettings": {}}``) raises
    "No fields provided" and no request is sent. The masked fields dropped are reported
    on the result (``_redactedFieldsNotSent``).
    """
    clean, dropped, reason = update_problem(fields, f"{what} 'settings'", identity=IDENTITY_FIELDS)
    if reason is not None:
        raise ValueError(reason)
    if dropped:
        note_dropped_fields(dropped)
    return cast(dict[str, Any], clean)


def _dry_run_result(before: Any, response: Any) -> dict[str, Any]:
    """Result of a verified update under ``dry-run policy``: the preview, no read-after.

    No write was sent, so a read-after would only show the unchanged state and report
    the update as unverified; the read-before is kept for context.
    """
    return {"status": "dry_run", "before": before, "response": response}


def _updated(
    fields: dict[str, Any], before: Any, after: Any, response: Any, error: str | None
) -> dict[str, Any]:
    """The result of an applied verified update (:func:`requested_leaves_verdict`).

    ``verified`` is true only when the read-after confirms every requested leaf; it is
    null when the read-after failed, returned no object or an unexpected shape
    (``readAfterError`` says why), and false when a requested leaf is missing or holds
    another value. The PATCH response is kept verbatim as ``response``."""
    verified, error = requested_leaves_verdict(fields, after, error, spec="protect-7.4.96.json")
    result = {
        "status": "updated",
        "verified": verified,
        "before": before,
        "after": after,
        "response": response,
    }
    return with_read_after_error(result, error)


async def _update_item_verified(
    client: UniFiClient,
    registry: Registry,
    host: str,
    family: str,
    item_id: str,
    id_name: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """PATCH /{family}/{id} with read-before / no-op-detect / read-after verification.

    Reads the current object, and if every requested leaf already equals its current
    value returns ``status='noop'`` WITHOUT issuing the PATCH. Otherwise it PATCHes
    (with 429 auto-retry disabled — a settings write is side-effecting), re-reads, and
    reports whether the read-after confirms each requested leaf. Nested objects are
    compared leaf by leaf (:func:`requested_leaves_match`): a partial nested update such
    as ``osdSettings={"isDateEnabled": True}`` is verified by that one leaf, and sibling
    keys the request does not name are ignored. The read-before and
    read-after must both be objects (any other shape raises); they are preserved
    verbatim in ``before``/``after`` (unknown/future fields survive), and the PATCH
    response body is returned verbatim as ``response``.
    """
    item_id_seg = path_segment(item_id, id_name)
    _require_mutations()
    fields = _fields_to_send(fields, family.rstrip("s"))
    key, host_id = await _resolve(registry, host)
    item_path = _proxy(host_id, f"/{family}/{item_id_seg}")
    before = _require_object(await client.get(item_path, key=key), f"GET {item_path}")
    fields = with_upstream_id(fields, "id", before.get("id"))
    upstream_id = before.get("id")
    if isinstance(upstream_id, str) and same_id(item_id, upstream_id):
        item_path = _proxy(host_id, f"/{family}/{path_segment(upstream_id, id_name)}")
    if short_circuit_no_op(
        client, requested_leaves_match(fields, before, spec="protect-7.4.96.json")
    ):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    response = await _patch(client, item_path, key=key, json=fields)
    if is_dry_run_preview(response):
        return _dry_run_result(before, response)

    async def _read() -> dict[str, Any]:
        return _require_object(await client.get(item_path, key=key), f"GET {item_path}")

    after, error = await safe_read_after(_read)
    comparison = with_upstream_id(fields, "id", after.get("id")) if after is not None else fields
    return _updated(comparison, before, after, response, error)


# --- Protect application metadata ----------------------------------------------------


async def get_protect_application_info(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    """Get Protect application metadata (``GET /v1/meta/info``). Read-only.

    Reports the Protect application version and Integration-API capabilities of the
    console — the authoritative way to check which extended families are available.
    """
    key, host_id = await _resolve(registry, host)
    path = _proxy(host_id, "/meta/info")
    return _require_object(await client.get(path, key=key), f"GET {path}")


# --- Arm profiles + alarm enablement -------------------------------------------------
#
# ``/v1/arm-profiles`` list/create/update/delete plus the current arm-profile selection
# (``PATCH /v1/arm-profiles/settings``) and the global arm-alarm enable/disable actions
# (``POST /v1/arm-profiles/enable`` | ``/disable``). Selection, enable, and disable are
# three DISTINCT operations from settings CRUD. Enable/disable act on the currently
# selected profile and require a local Alarm Manager. The arm-profile *collection* has
# no ``GET /{id}`` in the API, so single-profile reads (and update verification) are done
# by filtering the list — the documented read path for an individual profile.
#
# Every arm-profile tool (list/get/create/update/delete, settings, enable/disable)
# returns HTTP 400 ('This operation is not available when global alarm manager is
# enabled') when the console's global Alarm Manager is enabled; that console state
# blocks the arm-profile API.


@contextlib.contextmanager
def _global_alarm_manager_hint() -> Iterator[None]:
    """Append :data:`GLOBAL_ALARM_MANAGER_HINT` to the console's global-mode 400.

    Only that exact refusal (HTTP 400 carrying :data:`GLOBAL_ALARM_MANAGER_REFUSAL`) gets
    the hint; the upstream text stays first and unchanged. A permission (401/403), any
    other 400 or a transport failure passes through untouched, so it is never presented
    as a mode.
    """
    try:
        yield
    except UniFiConnectionError as exc:
        if exc.status == 400 and GLOBAL_ALARM_MANAGER_REFUSAL in str(exc).lower():
            raise upstream_hint(exc, GLOBAL_ALARM_MANAGER_HINT) from exc.__cause__
        raise


async def list_arm_profiles(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List arm profiles (``GET /v1/arm-profiles``).

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.
    """
    with _global_alarm_manager_hint():
        return await _list_family(client, registry, host, "arm-profiles", "arm_profiles")


async def _find_arm_profile(
    client: UniFiClient, host_id: str, arm_profile_id: str, *, key: APIKeyConfig | None
) -> tuple[dict[str, Any] | None, list[Any]]:
    """Return ``(profile, valid_ids)`` for one arm profile id from the list endpoint.

    There is no GET-by-id, so the whole list is read; ``valid_ids`` is every profile id
    the list carries, for an unknown-id error that names the real choices.
    """
    data = await client.get(_proxy(host_id, "/arm-profiles"), key=key)
    from ...client import object_records

    profiles = object_records(_as_list(data), "Protect arm profile resolution")
    valid_ids = [p.get("id") for p in profiles]
    for profile in profiles:
        if same_id(arm_profile_id, profile.get("id")):
            return profile, valid_ids
    return None, valid_ids


def _unknown_arm_profile(
    arm_profile_id: str, host: str, valid_ids: list[Any], client: UniFiClient | None = None
) -> ValueError:
    """Unknown-id error naming every arm profile id the console's list carries."""
    choices = (
        ", ".join(repr(upstream_error_value(i, client)) for i in valid_ids)
        if valid_ids
        else "none (the list is empty)"
    )
    return ValueError(
        f"Arm profile {arm_profile_id!r} not found on host {host!r}. "
        f"Valid arm_profile_id values (list_arm_profiles id): {choices}"
    )


async def get_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Get one arm profile by id.

    The Integration API exposes no ``GET /v1/arm-profiles/{id}``; this reads the
    documented ``GET /v1/arm-profiles`` collection and returns the matching entry
    (raising when the id is absent, listing every valid id, so a typo id is a loud
    error, not a silent empty result).

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.
    """
    with _global_alarm_manager_hint():
        path_segment(arm_profile_id, "arm_profile_id")  # the path twins' rule (spec: string)
        key, host_id = await _resolve(registry, host)
        profile, valid_ids = await _find_arm_profile(client, host_id, arm_profile_id, key=key)
        if profile is None:
            raise _unknown_arm_profile(arm_profile_id, host, valid_ids, client)
        return profile


async def create_arm_profile(
    client: UniFiClient, registry: Registry, host: str, name: str, /, **fields: Any
) -> dict[str, Any]:
    """Create an arm profile (``POST /v1/arm-profiles``).

    The API additionally requires ``automations``, ``schedules``, ``recordEverything``,
    and ``activationDelay`` in the body; pass them through ``fields``. Server-side
    validation enforces the full schema. 429 auto-retry is disabled (a create is a
    non-idempotent side effect).

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.
    """
    with _global_alarm_manager_hint():
        _require_mutations()
        if not name:
            raise ValueError("'name' must not be empty")
        payload = _body_with_name("create_arm_profile", name, fields)
        key, host_id = await _resolve(registry, host)
        response = await _post(client, _proxy(host_id, "/arm-profiles"), key=key, json=payload)
        return _write_result("created", response)


async def update_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update an arm profile (``PATCH /v1/arm-profiles/{id}``) with read/no-op/read-after.

    Because the collection has no ``GET /{id}``, the read-before and read-after are done
    against the list endpoint; if every requested leaf already matches (nested objects
    compared leaf by leaf, see :func:`requested_leaves_match`), no PATCH is sent. An id
    the list does not carry fails before any PATCH, listing the valid ids. 429
    auto-retry is disabled on the write; the PATCH body is returned verbatim as
    ``response``.

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.
    """
    with _global_alarm_manager_hint():
        path_segment(arm_profile_id, "arm_profile_id")
        _require_mutations()
        fields = _fields_to_send(fields, "arm profile")
        key, host_id = await _resolve(registry, host)
        before, valid_ids = await _find_arm_profile(client, host_id, arm_profile_id, key=key)
        if before is None:
            # Unknown id: fail before any PATCH, naming every id the console has.
            raise _unknown_arm_profile(arm_profile_id, host, valid_ids, client)
        # The PATCH addresses the profile the list matched by ITS id (an upper-case hex id
        # sends the upstream spelling), in the URL and in a body ``id`` naming it.
        upstream_id = str(before["id"])
        arm_profile_id_seg = path_segment(upstream_id, "arm_profile_id")
        fields = with_upstream_id(fields, "id", upstream_id)
        if short_circuit_no_op(
            client, requested_leaves_match(fields, before, spec="protect-7.4.96.json")
        ):
            return {
                "status": "noop",
                "reason": "all requested fields already match the current values; no write sent",
                "resource": before,
            }
        response = await _patch(
            client,
            _proxy(host_id, f"/arm-profiles/{arm_profile_id_seg}"),
            key=key,
            json=fields,
        )
        if is_dry_run_preview(response):
            return _dry_run_result(before, response)

        async def _read() -> Any:
            found, _ids = await _find_arm_profile(client, host_id, upstream_id, key=key)
            if found is None:
                raise UniFiConnectionError(
                    "Read-after Protect arm profile "
                    f"{upstream_error_value(upstream_id)!r} was not found in the collection"
                )
            return found

        after, error = await safe_read_after(_read)
        return _updated(fields, before, after, response, error)


async def delete_arm_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    arm_profile_id: str,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete an arm profile (``DELETE /v1/arm-profiles/{id}``). Irreversible.

    429 auto-retry is disabled on the write.

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.

    Like ``update_arm_profile``, the id is found in the arm-profile list first: an
    unknown id fails before any DELETE, naming every valid id, and the DELETE addresses
    the profile by the id the console listed (an upper-case hex id sends the upstream
    spelling).
    """
    with _global_alarm_manager_hint():
        path_segment(arm_profile_id, "arm_profile_id")
        _require_mutations()
        key, host_id = await _resolve(registry, host)
        profile, valid_ids = await _find_arm_profile(client, host_id, arm_profile_id, key=key)
        if profile is None:
            raise _unknown_arm_profile(arm_profile_id, host, valid_ids, client)
        upstream_id = str(profile["id"])
        arm_profile_id_seg = path_segment(upstream_id, "arm_profile_id")
        response = await client.delete(
            _proxy(host_id, f"/arm-profiles/{arm_profile_id_seg}"), key=key
        )
        return deletion_result(f"Arm profile {upstream_id} deleted.", response)


async def update_arm_profile_settings(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Select the active arm profile (``PATCH /v1/arm-profiles/settings``).

    A DISTINCT operation from arm-profile CRUD and from enable/disable: it chooses which
    profile is current. Body is ``{"armProfileId": <id>}``. The id is first resolved
    against ``GET /v1/arm-profiles`` (hex ids match case-insensitively): an id the list
    does not carry fails before any PATCH, listing the valid ids, and the body sends the
    id as the list spells it. The current selection is read from the NVR's
    ``armMode.armProfileId`` (documented ``nvrArmMode`` field) for the read-before /
    no-op / read-after flow: if already selected, no PATCH is sent. Both NVR reads must
    be objects (any other shape raises). 429 auto-retry is disabled on the write; the
    PATCH body is returned verbatim as ``response``.

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.
    """
    with _global_alarm_manager_hint():
        # Body-only (armProfileId: string): validated per the spec, not by path rules.
        validate_spec_id(arm_profile_id, "arm_profile_id")
        _require_mutations()
        key, host_id = await _resolve(registry, host)
        profile, valid_ids = await _find_arm_profile(client, host_id, arm_profile_id, key=key)
        if profile is None:
            # Unknown id: fail before any PATCH, naming every id the console has.
            raise _unknown_arm_profile(arm_profile_id, host, valid_ids, client)
        # Select the profile the list matched by ITS id (an upper-case hex id sends the
        # upstream spelling); the NVR selection is compared with the same id rule.
        upstream_id = str(profile["id"])
        nvr_path = _proxy(host_id, "/nvrs")
        before_nvr = _require_object(await client.get(nvr_path, key=key), f"GET {nvr_path}")
        before = before_nvr.get("armMode")
        selected = isinstance(before, dict) and same_id(before.get("armProfileId"), upstream_id)
        if short_circuit_no_op(client, selected):
            return {
                "status": "noop",
                "reason": "arm profile already selected; no write sent",
                "resource": before,
            }
        response = await _patch(
            client,
            _proxy(host_id, "/arm-profiles/settings"),
            key=key,
            json={"armProfileId": upstream_id},
        )
        if is_dry_run_preview(response):
            return _dry_run_result(before, response)

        async def _read() -> Any:
            nvr = _require_object(await client.get(nvr_path, key=key), f"GET {nvr_path}")
            return _require_object(nvr.get("armMode"), f"Read-after GET {nvr_path} armMode")

        after, error = await safe_read_after(_read)
        verified, error = read_after_verdict(
            after,
            error,
            lambda mode: "armProfileId" in mode and same_id(mode["armProfileId"], upstream_id),
        )
        result = {
            "status": "updated",
            "verified": verified,
            "before": before,
            "after": after,
            "response": response,
        }
        return with_read_after_error(result, error)


async def _arm_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    route: str,
    expected: frozenset[str],
) -> dict[str, Any]:
    """POST an arm enable or disable, then read ``armMode`` back from ``GET /v1/nvrs``.

    The POST answers an empty 204, so the sent response proves nothing about the alarm
    state. The read-after reports ``verified`` true only when ``armMode.status`` is one of
    ``expected`` (type-strict string compare). A failed read, or an answer with no ``armMode``
    object, leaves ``verified`` null with the reason under ``readAfterError``; an ``armMode``
    whose status is not an expected string gives false. The write is never retried and a failing
    read-after never turns the sent write into an error. Under dry-run policy nothing was
    sent, so no read is made.
    """
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    response = await _post(client, _proxy(host_id, route), key=key)
    if is_dry_run_preview(response):
        return _write_result("sent", response)
    nvr_path = _proxy(host_id, "/nvrs")

    async def _read() -> Any:
        nvr = await client.get(nvr_path, key=key)
        mode = nvr.get("armMode") if isinstance(nvr, dict) else None
        if not isinstance(mode, dict):
            raise UniFiConnectionError(
                f"Read-after GET {nvr_path} armMode: expected an object, got {describe_shape(mode)}"
            )
        return mode

    after, error = await safe_read_after(_read)
    verified, error = read_after_verdict(
        after,
        error,
        lambda mode: isinstance(mode.get("status"), str) and mode["status"] in expected,
    )
    result = {"status": "sent", "verified": verified, "after": after, "response": response}
    return with_read_after_error(result, error)


async def enable_arm(
    client: UniFiClient, registry: Registry, host: str, *, confirm: bool = False
) -> dict[str, Any]:
    """Enable the arm alarm (``POST /v1/arm-profiles/enable``). Physical side effects.

    A DISTINCT operation from profile selection: arms the system using the currently
    selected arm profile; requires a local Alarm Manager. 429 auto-retry is disabled.
    The NVR's ``armMode`` is read back (``GET /v1/nvrs``) and ``verified`` is true only
    when its ``status`` is ``arming``, ``armed`` or ``breach``.

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.
    """
    with _global_alarm_manager_hint():
        return await _arm_action(
            client, registry, host, "/arm-profiles/enable", _ARM_ENABLED_STATES
        )


async def disable_arm(
    client: UniFiClient, registry: Registry, host: str, *, confirm: bool = False
) -> dict[str, Any]:
    """Disable the arm alarm (``POST /v1/arm-profiles/disable``). Physical side effects.

    Disarms the system; requires a local Alarm Manager. 429 auto-retry is disabled. The
    NVR's ``armMode`` is read back (``GET /v1/nvrs``) and ``verified`` is true only when
    its ``status`` is ``disabled``.

    Returns HTTP 400 ('This operation is not available when global alarm manager
    is enabled') when the console's global Alarm Manager is enabled; that console
    state blocks the arm-profile API.
    """
    with _global_alarm_manager_hint():
        return await _arm_action(
            client, registry, host, "/arm-profiles/disable", _ARM_DISABLED_STATES
        )


# --- Sirens --------------------------------------------------------------------------


# --- External arm profiles + speaker siren (Protect 7.4.96) ---------------------------
#
# ``/v1/external/arm-profiles`` is the Integration API for the arm profiles of an EXTERNAL
# (global) alarm manager: list, get, create, update, delete and the arm / disarm actions.
# It is separate from ``/v1/arm-profiles`` (the local Alarm Manager, above). The spec
# states these routes are only available when the console uses the external alarm manager
# (``nvr.featureFlags.useExternalAlarmManager``; see get_protect_alarm_manager_mode).


async def list_external_arm_profiles(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    """List the arm profiles of the external alarm manager (GET /v1/external/arm-profiles).

    Only available when the console uses the external alarm manager (check
    get_protect_alarm_manager_mode); other consoles answer with an upstream error.
    Returns {result, _count}: result is the upstream array verbatim and _count its length.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect. The console whose
            external alarm manager arm profiles are listed.
    """
    return await _list_family(
        client, registry, host, _EXTERNAL_ARM_PROFILES, "external_arm_profiles"
    )


async def get_external_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Get one external arm profile (``GET /v1/external/arm-profiles/{id}``)."""
    return await _get_item(
        client, registry, host, _EXTERNAL_ARM_PROFILES, arm_profile_id, "arm_profile_id"
    )


async def create_external_arm_profile(
    client: UniFiClient, registry: Registry, host: str, title: str, /, **fields: Any
) -> dict[str, Any]:
    """Create an external arm profile (``POST /v1/external/arm-profiles``).

    ``title`` is the one required body key; the rest of the body comes through ``fields``
    (activation_delay, deactivation_delay, schedule). A ``title`` repeated in ``fields``
    must equal the argument. 429 auto-retry is disabled (a create is not idempotent).
    """
    _require_mutations()
    if not title:
        raise ValueError("'title' must not be empty")
    extra = dict(fields)
    repeated = extra.pop("title", title)
    if not leaf_equal(repeated, title):
        raise ValueError(
            "create_external_arm_profile: 'title' was given twice with different values (the "
            "title argument and settings['title']); pass it once, in the title argument"
        )
    key, host_id = await _resolve(registry, host)
    response = await _post(
        client,
        _proxy(host_id, f"/{_EXTERNAL_ARM_PROFILES}"),
        key=key,
        json={"title": title, **extra},
    )
    return _write_result("created", response)


def _readable_leaves(fields: dict[str, Any]) -> dict[str, Any]:
    """The leaves of an external arm profile write that a read-after can confirm.

    The PIN is write-only: the profile never reports ``pin_code``, only ``has_pin`` (a
    boolean). Comparing a sent ``pin_code`` with the read-after would always find it missing
    and report ``verified: false`` for a PIN that saved. So a ``pin_code`` is verified by
    ``has_pin`` reading ``true``, and ``pin_code: null`` (the spec's way to clear the PIN) by
    ``has_pin`` reading ``false``; every other leaf is compared as sent. That proves whether a
    PIN is set, not which digits: replacing one PIN with another cannot be seen in the
    read-after.
    """
    if "pin_code" not in fields:
        return fields
    rest = {k: v for k, v in fields.items() if k != "pin_code"}
    return {**rest, "has_pin": fields["pin_code"] is not None}


async def update_external_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update an external arm profile (PATCH /v1/external/arm-profiles/{id}).

    Consequence: changes how the external alarm manager arms that profile (the console must
    use it). Reads the profile first, PATCHes only
    the given keys and reads it again. Returns {status: "updated", verified, before, after,
    response (the PATCH body verbatim)}; verified is true only when every requested leaf
    reads back equal, null with readAfterError when the read-back failed, or {status: "noop",
    reason, resource} when every requested leaf already matches (a pin_code is never compared
    for the no-op: the profile reports has_pin only). A pin_code is verified by
    has_pin reading true in the read-back, and pin_code null (clears the PIN) by has_pin
    reading false: that proves whether a PIN is set, not its digits, so replacing one PIN
    with another cannot be confirmed. At least one property is required (minProperties 1);
    an empty settings fails before any request. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the
    preview: method, path, params, body)}.

    Request body (Protect 7.4.96, schema "externalArmProfilePatch") is passed in `settings`;
    omitted keys stay unchanged.
    - title: string, minLength 1 (cannot be cleared)
    - activation_delay: integer 0-3600 (seconds), or null to clear it
    - deactivation_delay: integer 0-3600 (seconds), or null to clear it
    - schedule: object with optional keys sun, mon, tue, wed, thu, fri, sat; each day is
      {type: "all_day"} or {type: "intervals", entries: [{start: {hour: integer 0-23,
      minute: integer 0-59}, end: {hour: integer 0-23, minute: integer 0-59}, or 24:00}]}
      (entries minItems 1; end of day: 24:00 or 23:59)
    - alarm_ids: array of string
    - pin_code: string, or null to clear the PIN (write-only; the profile reports has_pin)

    Example call (update_external_arm_profile):
        {
          "host": "my-console",
          "arm_profile_id": "00000000000000000000010b",
          "settings": {"title": "Night"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        arm_profile_id: External arm profile id from list_external_arm_profiles (id).
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.4.96 PATCH
            /v1/external/arm-profiles/{id} body. Keys: title, activation_delay,
            deactivation_delay, schedule, alarm_ids, pin_code.
    """
    arm_profile_id_seg = path_segment(arm_profile_id, "arm_profile_id")
    _require_mutations()
    fields = _fields_to_send(fields, "external arm profile")
    key, host_id = await _resolve(registry, host)
    path = _proxy(host_id, f"/{_EXTERNAL_ARM_PROFILES}/{arm_profile_id_seg}")
    before = _require_object(await client.get(path, key=key), f"GET {path}")
    if short_circuit_no_op(
        client, requested_leaves_match(fields, before, spec="protect-7.4.96.json")
    ):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    response = await _patch(client, path, key=key, json=fields)
    if is_dry_run_preview(response):
        return _dry_run_result(before, response)

    async def _read() -> Any:
        return _require_object(await client.get(path, key=key), f"Read-after GET {path}")

    after, error = await safe_read_after(_read)
    return _updated(_readable_leaves(fields), before, after, response, error)


async def delete_external_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Delete an external arm profile (``DELETE /v1/external/arm-profiles/{id}``)."""
    arm_profile_id_seg = path_segment(arm_profile_id, "arm_profile_id")
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    response = await client.delete(
        _proxy(host_id, f"/{_EXTERNAL_ARM_PROFILES}/{arm_profile_id_seg}"), key=key
    )
    return deletion_result(f"External arm profile {arm_profile_id} deleted.", response)


async def _external_arm_action(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str, action: str
) -> dict[str, Any]:
    arm_profile_id_seg = path_segment(arm_profile_id, "arm_profile_id")
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    response = await _post(
        client,
        _proxy(host_id, f"/{_EXTERNAL_ARM_PROFILES}/{arm_profile_id_seg}/actions/{action}"),
        key=key,
    )
    return _write_result("sent", response)


async def arm_external_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Arm one external arm profile (``POST /v1/external/arm-profiles/{id}/actions/arm``)."""
    return await _external_arm_action(client, registry, host, arm_profile_id, "arm")


async def disarm_external_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Disarm one external arm profile (``POST /v1/external/arm-profiles/{id}/actions/disarm``)."""
    return await _external_arm_action(client, registry, host, arm_profile_id, "disarm")


async def stop_speaker_siren(
    client: UniFiClient, registry: Registry, host: str, speaker_id: str
) -> dict[str, Any]:
    """Stop a siren playing on a speaker (``POST /v1/speakers/{id}/stop-siren``)."""
    speaker_id_seg = path_segment(speaker_id, "speaker_id")
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    response = await _post(
        client, _proxy(host_id, f"/speakers/{speaker_id_seg}/stop-siren"), key=key
    )
    return _write_result("sent", response)


async def list_sirens(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List sirens (``GET /v1/sirens``)."""
    return await _list_family(client, registry, host, "sirens", "sirens")


async def get_siren(
    client: UniFiClient, registry: Registry, host: str, siren_id: str
) -> dict[str, Any]:
    """Get one siren by id (``GET /v1/sirens/{id}``)."""
    return await _get_item(client, registry, host, "sirens", siren_id, "siren_id")


async def update_siren(
    client: UniFiClient, registry: Registry, host: str, siren_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update siren settings (``PATCH /v1/sirens/{id}``) with read/no-op/read-after.

    Documented settable fields include ``name``, ``volume`` (1-100), and ``ledSettings``.
    """
    return await _update_item_verified(
        client, registry, host, "sirens", siren_id, "siren_id", fields
    )


async def siren_play(
    client: UniFiClient,
    registry: Registry,
    host: str,
    siren_id: str,
    *,
    confirm: bool = False,
    duration: int | None = None,
) -> dict[str, Any]:
    """Sound a siren (``POST /v1/sirens/{id}/play``). Physical side effects.

    ``duration`` (seconds) accepts the documented values 5/10/20/30 and defaults to 5
    upstream when omitted. 429 auto-retry is disabled.
    """
    siren_id_seg = path_segment(siren_id, "siren_id")
    check_arguments("siren_play", {"duration": duration})  # sirenDurationSeconds: 5|10|20|30
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if duration is not None:
        body["duration"] = duration
    response = await _post(
        client,
        _proxy(host_id, f"/sirens/{siren_id_seg}/play"),
        key=key,
        json=body,
    )
    return _write_result("sent", response)


async def siren_stop(
    client: UniFiClient,
    registry: Registry,
    host: str,
    siren_id: str,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Stop a sounding siren (``POST /v1/sirens/{id}/stop``). Physical side effects.

    429 auto-retry is disabled.
    """
    siren_id_seg = path_segment(siren_id, "siren_id")
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    response = await _post(client, _proxy(host_id, f"/sirens/{siren_id_seg}/stop"), key=key)
    return _write_result("sent", response)


async def siren_test_sound(
    client: UniFiClient,
    registry: Registry,
    host: str,
    siren_id: str,
    *,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a siren's sound (``POST /v1/sirens/{id}/test-sound``). Physical side effects.

    ``volume`` (1-100) defaults to the configured device volume upstream when omitted.
    429 auto-retry is disabled.
    """
    siren_id_seg = path_segment(siren_id, "siren_id")
    check_arguments("siren_test_sound", {"volume": volume})  # sirenVolume: 1-100
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if volume is not None:
        body["volume"] = volume
    response = await _post(
        client,
        _proxy(host_id, f"/sirens/{siren_id_seg}/test-sound"),
        key=key,
        json=body,
    )
    return _write_result("sent", response)


# --- Fobs ----------------------------------------------------------------------------


async def list_fobs(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List fobs (``GET /v1/fobs``)."""
    return await _list_family(client, registry, host, "fobs", "fobs")


async def get_fob(
    client: UniFiClient, registry: Registry, host: str, fob_id: str
) -> dict[str, Any]:
    """Get one fob by id (``GET /v1/fobs/{id}``)."""
    return await _get_item(client, registry, host, "fobs", fob_id, "fob_id")


async def update_fob(
    client: UniFiClient, registry: Registry, host: str, fob_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update fob settings (``PATCH /v1/fobs/{id}``) with read/no-op/read-after."""
    return await _update_item_verified(client, registry, host, "fobs", fob_id, "fob_id", fields)


# --- Relays --------------------------------------------------------------------------


async def list_relays(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List relays (``GET /v1/relays``)."""
    return await _list_family(client, registry, host, "relays", "relays")


async def get_relay(
    client: UniFiClient, registry: Registry, host: str, relay_id: str
) -> dict[str, Any]:
    """Get one relay by id (``GET /v1/relays/{id}``)."""
    return await _get_item(client, registry, host, "relays", relay_id, "relay_id")


async def update_relay(
    client: UniFiClient, registry: Registry, host: str, relay_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update relay settings (``PATCH /v1/relays/{id}``) with read/no-op/read-after."""
    return await _update_item_verified(
        client, registry, host, "relays", relay_id, "relay_id", fields
    )


def _output_channel(output_id: Any) -> int:
    """The ``{outputId}`` path integer (spec: integer) from an integer or a decimal-integer
    string; the range (0 or 1) is checked by the spec limits before this runs."""
    if isinstance(output_id, int) and not isinstance(output_id, bool):
        return output_id
    if not isinstance(output_id, str):
        raise ValueError(f"'output_id' must be an integer (0 or 1), got {output_id!r}")
    validate_id(output_id, "output_id")
    return int(output_id)


async def relay_activate_output(
    client: UniFiClient,
    registry: Registry,
    host: str,
    relay_id: str,
    output_id: int | str,
    *,
    confirm: bool = False,
    state: str | None = None,
    pulse_duration: int | None = None,
) -> dict[str, Any]:
    """Switch a relay output (``POST /v1/relays/{id}/outputs/{outputId}/activate``).

    Physical side effects. ``state`` is ``"on"`` or ``"off"`` (omit to toggle);
    ``pulse_duration`` is an auto-off delay in milliseconds that only applies when
    ``state="on"``. 429 auto-retry is disabled.
    """
    relay_id_seg = path_segment(relay_id, "relay_id")
    # outputId: integer >= 0, "Output channel ID (0 or 1)" (spec); state / pulseDuration
    # per the body schema. Checked before any request (also for direct callers).
    check_arguments(
        "relay_activate_output",
        {"output_id": output_id, "state": state, "pulse_duration": pulse_duration},
    )
    output = _output_channel(output_id)
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if state is not None:
        body["state"] = state
    if pulse_duration is not None:
        body["pulseDuration"] = pulse_duration
    response = await _post(
        client,
        _proxy(host_id, f"/relays/{relay_id_seg}/outputs/{output}/activate"),
        key=key,
        json=body,
    )
    return _write_result("sent", response)


# --- Speakers ------------------------------------------------------------------------


async def list_speakers(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List speakers on a Protect console (GET /v1/speakers via Fabric proxy).

    Returns {result, _count}: result is the upstream array of speakers verbatim and _count its
    length (an upstream object with a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect. The Protect console
            whose speakers are listed.
    """
    return await _list_family(client, registry, host, "speakers", "speakers")


async def get_speaker(
    client: UniFiClient, registry: Registry, host: str, speaker_id: str
) -> dict[str, Any]:
    """Get one speaker by id (``GET /v1/speakers/{id}``)."""
    return await _get_item(client, registry, host, "speakers", speaker_id, "speaker_id")


async def update_speaker(
    client: UniFiClient, registry: Registry, host: str, speaker_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update speaker settings (``PATCH /v1/speakers/{id}``) with read/no-op/read-after."""
    return await _update_item_verified(
        client, registry, host, "speakers", speaker_id, "speaker_id", fields
    )


async def speaker_test_sound(
    client: UniFiClient,
    registry: Registry,
    host: str,
    speaker_id: str,
    *,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a speaker's sound (``POST /v1/speakers/{id}/test-sound``). Physical side effects.

    ``volume`` (0-100) defaults to the configured device volume upstream when omitted.
    429 auto-retry is disabled.
    """
    speaker_id_seg = path_segment(speaker_id, "speaker_id")
    check_arguments("speaker_test_sound", {"volume": volume})  # speakerVolume: 0-100
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if volume is not None:
        body["volume"] = volume
    response = await _post(
        client,
        _proxy(host_id, f"/speakers/{speaker_id_seg}/test-sound"),
        key=key,
        json=body,
    )
    return _write_result("sent", response)


# --- Bridges -------------------------------------------------------------------------


async def list_bridges(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List bridges (``GET /v1/bridges``)."""
    return await _list_family(client, registry, host, "bridges", "bridges")


async def get_bridge(
    client: UniFiClient, registry: Registry, host: str, bridge_id: str
) -> dict[str, Any]:
    """Get one bridge by id (``GET /v1/bridges/{id}``)."""
    return await _get_item(client, registry, host, "bridges", bridge_id, "bridge_id")


async def update_bridge(
    client: UniFiClient, registry: Registry, host: str, bridge_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update bridge settings (``PATCH /v1/bridges/{id}``) with read/no-op/read-after."""
    return await _update_item_verified(
        client, registry, host, "bridges", bridge_id, "bridge_id", fields
    )


# --- Link stations -------------------------------------------------------------------


async def list_link_stations(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List link stations (``GET /v1/link-stations``)."""
    return await _list_family(client, registry, host, "link-stations", "link_stations")


async def get_link_station(
    client: UniFiClient, registry: Registry, host: str, link_station_id: str
) -> dict[str, Any]:
    """Get one link station by id (``GET /v1/link-stations/{id}``)."""
    return await _get_item(
        client, registry, host, "link-stations", link_station_id, "link_station_id"
    )


async def update_link_station(
    client: UniFiClient, registry: Registry, host: str, link_station_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update link-station settings (``PATCH /v1/link-stations/{id}``), read/no-op/read-after."""
    return await _update_item_verified(
        client, registry, host, "link-stations", link_station_id, "link_station_id", fields
    )


# --- Alarm hubs ----------------------------------------------------------------------


async def list_alarm_hubs(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List alarm hubs (``GET /v1/alarm-hubs``)."""
    return await _list_family(client, registry, host, "alarm-hubs", "alarm_hubs")


async def get_alarm_hub(
    client: UniFiClient, registry: Registry, host: str, alarm_hub_id: str
) -> dict[str, Any]:
    """Get one alarm hub by id (``GET /v1/alarm-hubs/{id}``)."""
    return await _get_item(client, registry, host, "alarm-hubs", alarm_hub_id, "alarm_hub_id")


async def update_alarm_hub(
    client: UniFiClient, registry: Registry, host: str, alarm_hub_id: str, /, **fields: Any
) -> dict[str, Any]:
    """Update alarm-hub settings (``PATCH /v1/alarm-hubs/{id}``) with read/no-op/read-after."""
    return await _update_item_verified(
        client, registry, host, "alarm-hubs", alarm_hub_id, "alarm_hub_id", fields
    )


async def alarm_hub_trigger_output(
    client: UniFiClient,
    registry: Registry,
    host: str,
    alarm_hub_id: str,
    output_id: int | str,
    *,
    confirm: bool = False,
    enable: bool | None = None,
    delay: int | None = None,
    duration: int | None = None,
) -> dict[str, Any]:
    """Trigger an alarm-hub output (``POST /v1/alarm-hubs/{id}/outputs/{outputId}/trigger``).

    Physical side effects. ``enable`` true turns the output on, false off (omit to
    toggle); ``delay`` (ms) waits before activating; ``duration`` (ms) keeps it active
    (0 = indefinite until manually turned off). 429 auto-retry is disabled.
    """
    alarm_hub_id_seg = path_segment(alarm_hub_id, "alarm_hub_id")
    # outputId: integer >= 0, "Output channel ID (0 or 1)" (spec); delay / duration >= 0.
    # Checked before any request (also for direct callers).
    check_arguments(
        "alarm_hub_trigger_output",
        {"output_id": output_id, "delay": delay, "duration": duration},
    )
    output = _output_channel(output_id)
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if enable is not None:
        body["enable"] = enable
    if delay is not None:
        body["delay"] = delay
    if duration is not None:
        body["duration"] = duration
    response = await _post(
        client,
        _proxy(host_id, f"/alarm-hubs/{alarm_hub_id_seg}/outputs/{output}/trigger"),
        key=key,
        json=body,
    )
    return _write_result("sent", response)


# --- Protect users (read-only) -------------------------------------------------------


async def list_protect_users(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List Protect users (``GET /v1/users``). Read-only in the Integration API.

    Distinct from ULP users (``list_ulp_users`` / ``/v1/ulp-users``): this is the
    Protect application's own user list.
    """
    return await _list_family(client, registry, host, "users", "users")


async def get_protect_user(
    client: UniFiClient, registry: Registry, host: str, user_id: str
) -> dict[str, Any]:
    """Get one Protect user by id (``GET /v1/users/{id}``). Read-only."""
    return await _get_item(client, registry, host, "users", user_id, "user_id")


# --- ULP users (read-only) -----------------------------------------------------------
#
# The Unifi-account (ULP) user directory — DISTINCT from the Protect users above. These
# are the UI-account identities (``/v1/ulp-users``), not Protect's local user list.


async def list_ulp_users(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List ULP (UniFi account) users (``GET /v1/ulp-users``). Read-only.

    Distinct from Protect users (``list_protect_users`` / ``/v1/users``).
    """
    return await _list_family(client, registry, host, "ulp-users", "ulp_users")


async def get_ulp_user(
    client: UniFiClient, registry: Registry, host: str, ulp_user_id: str
) -> dict[str, Any]:
    """Get one ULP (UniFi account) user by id (``GET /v1/ulp-users/{id}``). Read-only."""
    return await _get_item(client, registry, host, "ulp-users", ulp_user_id, "ulp_user_id")


# --- POS transaction ingestion -------------------------------------------------------


async def pos_ingest_transaction(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    transaction: dict[str, Any],
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Ingest a POS transaction to overlay on camera footage.

    ``POST /v1/pos/cameras/{id}/transactions`` with the documented ``posTransactionRequest``
    body. This is a SIDE-EFFECTING write that creates a footage overlay event with NO
    documented rollback, so it has its own validation and idempotency guard:
    * ``transaction`` must carry the required fields ``type`` ('sale'|'refund', validated
      against a strict allowlist), ``externalId`` (caller-supplied, unique per camera —
      the idempotency/deduplication key the API uses for best-effort in-window dedup), and
      ``amount``. Optional documented fields (``currency``, ``lineItems``, ``location``,
      ``paymentTypes``, ``timestamp``) pass through verbatim.
    * 429 auto-retry is DISABLED (no non-GET request is retried). Because dedup is best-effort and
      in-memory upstream, an automatic retry could create a duplicate overlay; the tool
      never retries a POS write. A retry, if needed, is the caller's explicit decision and
      must reuse the same ``externalId``.
    """
    camera_id_seg = path_segment(camera_id, "camera_id")
    if not isinstance(transaction, dict):
        raise ValueError("'transaction' must be a posTransactionRequest object")
    txn_type = transaction.get("type")
    if txn_type not in _POS_TXN_TYPES:
        raise ValueError(f"transaction 'type' must be one of {_POS_TXN_TYPES} (got {txn_type!r})")
    external_id = transaction.get("externalId")
    if not isinstance(external_id, str) or not external_id:
        raise ValueError(
            "transaction 'externalId' is required (a string of at least 1 character, per "
            "the spec's minLength 1): it is the per-camera "
            "idempotency/deduplication key for POS ingestion"
        )
    if "amount" not in transaction:
        raise ValueError("transaction 'amount' is required")
    amount = transaction["amount"]
    # posTransactionRequest.amount is a required, non-nullable number with minimum 0
    # (Protect 7.3.74): null, a string, a boolean or a negative value fails fast.
    if (
        isinstance(amount, bool)
        or not isinstance(amount, (int, float))
        or not math.isfinite(amount)
        or amount < 0
    ):
        raise ValueError(
            f"transaction 'amount' must be a number >= 0 and finite (got {amount!r}); the spec's "
            "posTransactionRequest.amount is a required, non-nullable number with minimum 0 "
            "(NaN and Infinity are not JSON numbers)"
        )
    # Every other posTransactionRequest limit (externalId 1-255 characters, currency
    # ^[A-Z]{3}$, lineItems <= 200, paymentTypes <= 20 of 1-255 characters, timestamp >= 1,
    # ...), before any request.
    check_arguments("pos_ingest_transaction", {"transaction": transaction})
    _require_mutations()
    key, host_id = await _resolve(registry, host)
    response = await _post(
        client,
        _proxy(host_id, f"/pos/cameras/{camera_id_seg}/transactions"),
        key=key,
        json=transaction,
    )
    return _write_result("sent", response)
