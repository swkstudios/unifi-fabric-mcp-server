"""UniFi Protect events, event media, favorites, cases (investigations) and stream URLs.

Route choice (the official published API when it can do the job, else
the newer private API, else the older one). The official Protect Integration API pinned in
``tests/fixtures/spec_drift/baseline_snapshot.json`` (protect 7.3.70) has no REST route for
any capability in this module: events are WebSocket-only there (``/v1/subscribe/events``),
and it has no event media, favorites, cases or stream-URL routes. Its only stream route,
``/v1/cameras/{id}/rtsps-stream``, is already served by ``get_rtsps_stream`` /
``create_rtsps_stream``, and its camera snapshot by ``get_camera_snapshot``. Every tool here
therefore uses the private ``/proxy/protect/api`` routes the Protect web app calls (UI
bundle 5.3.18), each proven live on Protect 7.x through the cloud connector unless its
docstring says it is a hermetic view.

Every response body is passed through verbatim (server pass-through invariant). Binary
media is returned base64-encoded with the upstream Content-Type, never decoded as text.

Validation before any request uses only the server's registered refusals (path-safe ids,
integer epoch seconds, the empty-update guard, the Protect write opt-out and read-only
mode, and pydantic validation of the closed ``kind``/``action`` choices); every other value
is the upstream's to judge.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Annotated, Any, Literal, NoReturn, TypedDict

from fastmcp import FastMCP
from pydantic import Field, StrictBool, TypeAdapter

from ..client import UniFiClient, is_dry_run_preview, validate_id
from ..matching import same_id, with_upstream_id
from ..read_only import guard_action
from ..registry import Registry
from ..tool_annotations import READ_ONLY, WRITE
from ._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    with_warnings,
)
from ._pagination import (
    bare_page,
    collect_links,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)
from ._results import (
    deletion_result,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
from .protect import (
    _as_list,
    _body_with_name,
    _dry_run_result,
    _fields_to_send,
    _list_body,
    _private,
    _require_mutations,
    _require_object,
    _resolve,
    _write_result,
)

#: Event media kinds and the private route each one reads (``/events/{id}/<suffix>``).
MediaKind = Literal[
    "thumbnail", "animated_thumbnail", "heatmap", "smart_detect_track", "transcriptions"
]
_MEDIA_SUFFIX: dict[str, str] = {
    "thumbnail": "thumbnail",
    "animated_thumbnail": "animated-thumbnail",
    "heatmap": "heatmap",
    "smart_detect_track": "smartDetectTrack",
    "transcriptions": "transcriptions",
}
#: Kinds whose body is an image (returned base64 + content_type); the others are JSON.
_BINARY_MEDIA = frozenset({"thumbnail", "animated_thumbnail", "heatmap"})

#: Stream URL kinds and the private route each one reads.
StreamKind = Literal[
    "livestream",
    "playback",
    "timelapse",
    "heatmap",
    "live_detect_track",
    "live_alias",
    "video_prepare",
]
_STREAM_PATH: dict[str, str] = {
    "livestream": "/ws/livestream",
    "playback": "/ws/playback",
    "timelapse": "/ws/timelapse",
    "heatmap": "/ws/heatmap",
    "live_detect_track": "/ws/liveDetectTrack",
    "live_alias": "/video/live",
    "video_prepare": "/tcp/video/prepare",
}

ExportAction = Literal["prepare", "download"]


class FavoriteObject(TypedDict):
    """One per-object favorite mark for the batch route (``idsWithObject``)."""

    eventId: Annotated[str, Field(description="Id of the event to mark; one of event_ids.")]
    objectId: Annotated[
        str,
        Field(
            description="Detected object of that event (metadata.detectedThumbnails[].objectId)."
        ),
    ]


_MEDIA_KIND = TypeAdapter(MediaKind)
_STREAM_KIND = TypeAdapter(StreamKind)
_EXPORT_ACTION = TypeAdapter(ExportAction)
_STRICT_BOOL = TypeAdapter(StrictBool)

#: Secret-registry entries for this module (GS3 W0). Successful fields are masked only
#: under ``UNIFI_REDACT_SECRETS``, like error text; logs always scrub them. The stream-URL tool
#: returns short-lived, tokenised stream addresses: ``url`` and ``directUrl`` carry a
#: per-request ``uniqid`` / path token and ``alias`` is the live-stream alias. Keys are
#: the response field names, matched only on the registered stream routes (a global ``url`` key
#: would mask every URL in the catalog). Route entries live in route_secrets (GS3 W0).
SECRET_RESPONSE_FIELDS: dict[str, frozenset[str]] = {
    "get_protect_stream_url": frozenset({"url", "directUrl", "alias"}),
}


def _b64(raw: bytes, content_type: str | None, field: str) -> dict[str, Any]:
    """A binary body for transport: base64 text plus the upstream Content-Type as sent."""
    return {
        field: base64.b64encode(raw).decode(),
        "content_type": content_type,
        "size_bytes": len(raw),
    }


def _epoch_ms(value: int | None, name: str) -> int | None:
    """An optional epoch-seconds argument as epoch milliseconds (type-checked first)."""
    if value is None:
        return None
    return seconds_to_millis(require_epoch_seconds(value, name))


def _given(**params: Any) -> dict[str, Any]:
    """Only the query parameters the caller actually gave (no invented defaults)."""
    return {k: v for k, v in params.items() if v is not None}


def _find(records: list[Any], record_id: str, what: str) -> dict[str, Any] | None:
    """The record whose ``id`` is ``record_id``, or None.

    A row that is not an object raises with the shape received: skipping it would turn a
    collection of the wrong shape into "record not found" (a ``verified: false`` verdict
    after a write) instead of an unreadable read.
    """
    for index, row in enumerate(records):
        record = _require_object(row, f"{what} row {index}")
        if same_id(record_id, record.get("id")):
            return record
    return None


# --- Events -------------------------------------------------------------------------


async def get_protect_event(
    client: UniFiClient, registry: Registry, host: str, event_id: str
) -> dict[str, Any]:
    """GET one Protect event by id (private ``/events/{id}``), verbatim."""
    validate_id(event_id, "event_id")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/events/{event_id}")
    return _require_object(await client.get(path, key=key), f"GET {path}")


async def get_protect_event_media(
    client: UniFiClient,
    registry: Registry,
    host: str,
    event_id: str,
    kind: str,
    width: int | None = None,
    height: int | None = None,
    full_fov: bool | None = None,
    key_frame_only: bool | None = None,
    speedup: int | None = None,
    start: int | None = None,
    end: int | None = None,
    camera_id: str | None = None,
) -> Any:
    """Read one media view of a Protect event (thumbnail, GIF, heatmap, track, transcript)."""
    kind = _MEDIA_KIND.validate_python(kind)
    validate_id(event_id, "event_id")
    params = _given(
        w=width,
        h=height,
        isFullfov=full_fov,
        keyFrameOnly=key_frame_only,
        speedup=speedup,
        start=_epoch_ms(start, "start"),
        end=_epoch_ms(end, "end"),
        camera=camera_id,
    )
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/events/{event_id}/{_MEDIA_SUFFIX[kind]}")
    if kind in _BINARY_MEDIA:
        raw, content_type = await client.get_binary(path, key=key, params=params or None)
        result: Any = _b64(raw, content_type, "image_base64")
    else:
        result = await client.get(path, key=key, params=params or None)
    return with_warnings(result, epoch_warnings(start=start, end=end))


def _argument_grammar(message: str) -> NoReturn:
    """Refuse an argument combination of this module (registered in refusals.py)."""
    raise ValueError(f"Protect events and cases arguments: {message} Nothing was sent.")


def _no_typed_override(fields: dict[str, Any] | None, typed: dict[str, str]) -> None:
    """Refuse a free-form ``fields`` key that a typed argument sets (``{body key: argument}``).

    The typed value is the one sent, so the ``fields`` key would be silently replaced.
    """
    clash = [key for key in typed if fields and key in fields]
    if clash:
        _argument_grammar(
            f"fields must not contain {', '.join(repr(k) for k in clash)}: the typed argument "
            f"{', '.join(typed[k] for k in clash)} sets that key and would silently replace it."
        )


async def set_protect_event_favorite(
    client: UniFiClient,
    registry: Registry,
    host: str,
    event_ids: str | list[str],
    favorite: bool,
    object_id: str | None = None,
    objects: list[FavoriteObject] | None = None,
) -> dict[str, Any]:
    """Favorite or unfavorite one event (str) or several (list) on a Protect console."""
    favorite = _STRICT_BOOL.validate_python(favorite)
    verb = "favorite" if favorite else "unfavorite"
    status = "favorited" if favorite else "unfavorited"
    single = isinstance(event_ids, str)
    if isinstance(event_ids, list) and not event_ids:
        _argument_grammar("event_ids is an empty list, so it names no event to mark.")
    if single and objects is not None:
        _argument_grammar(
            "objects is for a list of event_ids (the batch route); with one event id pass "
            "object_id."
        )
    if not single and object_id is not None:
        _argument_grammar(
            "object_id is for one event id (the per-event route); with a list of event_ids "
            "pass objects."
        )
    ids: list[str] = [event_ids] if isinstance(event_ids, str) else list(event_ids)
    if single:
        validate_id(ids[0], "event_ids")
    _require_mutations()
    guard_action("POST")
    key, host_id = await _resolve(registry, host)
    if single:
        event_id = ids[0]
        response = await client.post(
            _private(host_id, f"/{verb}-events/{event_id}"),
            key=key,
            params=_given(objectId=object_id) or None,
        )
        if is_dry_run_preview(response):
            return _write_result(status, response)

        async def _read() -> dict[str, Any]:
            path = _private(host_id, f"/events/{event_id}")
            return _require_object(await client.get(path, key=key), f"GET {path}")

        after, error = await safe_read_after(_read)
        result = _write_result(status, response)
        if after is not None:
            if object_id is None:
                result["verified"] = after.get("isFavorite") is favorite
            else:
                favs = after.get("favoriteObjectIds") or []
                result["verified"] = any(same_id(object_id, value) for value in favs) is favorite
            result["event"] = after
        else:
            result["verified"] = None
        return with_read_after_error(result, error)
    body = {"ids": ids, "idsWithObject": list(objects) if objects is not None else []}
    response = await client.post(_private(host_id, f"/{verb}-events"), key=key, json=body)
    return _write_result(status, response)


# --- Cases ----------------------------------------------------------------------------


async def list_protect_cases(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List every Protect case (investigation) on a console (private ``/cases``)."""
    key, host_id = await _resolve(registry, host)
    return _list_body(await client.get(_private(host_id, "/cases"), key=key), "Protect cases")


async def create_protect_case(
    client: UniFiClient,
    registry: Registry,
    host: str,
    name: str,
    summary: str | None = None,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a Protect case (``POST /cases``) and return the created case verbatim."""
    _require_mutations()
    guard_action("POST")
    _no_typed_override(fields, {"summary": "summary"} if summary is not None else {})
    extra = dict(fields or {})
    if summary is not None:
        extra["summary"] = summary
    body = _body_with_name("create_protect_case", name, extra)
    key, host_id = await _resolve(registry, host)
    response = await client.post(_private(host_id, "/cases"), key=key, json=body)
    return _write_result("created", response)


def _merge_patch_value(current: Any, requested: Any) -> Any:
    """Deep-merge object updates; arrays, null and scalars replace atomically."""
    if isinstance(current, dict) and isinstance(requested, dict):
        return {
            **current,
            **{
                key: _merge_patch_value(current.get(key), value) for key, value in requested.items()
            },
        }
    return requested


def _patch_leaves_match(requested: Any, actual: Any, *, exact: bool = False) -> bool:
    """Compare every sent leaf with exact types and distinguish missing from null."""
    if type(requested) is not type(actual):
        return False
    if isinstance(requested, dict):
        if exact and requested.keys() != actual.keys():
            return False
        return all(
            key in actual and _patch_leaves_match(value, actual[key], exact=exact)
            for key, value in requested.items()
        )
    if isinstance(requested, list):
        return len(requested) == len(actual) and all(
            _patch_leaves_match(left, right, exact=True)
            for left, right in zip(requested, actual, strict=True)
        )
    return bool(requested == actual)


async def _verified_patch(
    client: UniFiClient,
    key: Any,
    list_path: str,
    item_path: str,
    item_id: str,
    body: dict[str, Any],
    what: str,
    fill: Callable[[dict[str, Any] | None, dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """PATCH an item that has no GET-by-id route, verified through its collection.

    The item is read from the collection before and after the PATCH. Every requested leaf
    already equal skips the write (``status: "noop"``). An id missing from the collection is
    not refused: the PATCH is sent and the upstream answers. Nested object updates
    preserve current siblings in the PATCH. The read-after reports
    ``verified`` against every sent leaf, including preserved siblings (type-strict).
    A failed read-after leaves ``verified`` null
    with ``readAfterError``.
    """
    before = _find(_as_list(await client.get(list_path, key=key), what), item_id, what)
    if before is not None:
        item_id = before["id"]
        item_path = f"{item_path.rsplit('/', 1)[0]}/{item_id}"
    if fill is not None:
        body = fill(before, body)
    if before is not None:
        body = with_upstream_id(body, "id", before.get("id"))
        upstream_id = before.get("id")
        if isinstance(upstream_id, str) and same_id(item_id, upstream_id):
            item_path = f"{list_path}/{upstream_id}"
    if before is not None and short_circuit_no_op(client, _patch_leaves_match(body, before)):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    if before is not None:
        body = {
            field: _merge_patch_value(before.get(field), value) for field, value in body.items()
        }
    response = await client.patch(item_path, key=key, json=body)
    if is_dry_run_preview(response):
        return _dry_run_result(before, response)

    async def _read() -> dict[str, Any] | None:
        return _find(_as_list(await client.get(list_path, key=key), what), item_id, what)

    after, error = await safe_read_after(_read)
    verified = (
        _patch_leaves_match(with_upstream_id(body, "id", after.get("id")), after)
        if after is not None
        else None
    )
    if error is None and after is None:
        verified = False
    result = {
        "status": "updated",
        "verified": verified,
        "before": before,
        "after": after,
        "response": response,
    }
    return with_read_after_error(result, error)


async def update_protect_case(
    client: UniFiClient,
    registry: Registry,
    host: str,
    case_id: str,
    name: str | None = None,
    summary: str | None = None,
    active: bool | None = None,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Update a Protect case (``PATCH /cases/{id}``) with read-before/after verification."""
    validate_id(case_id, "case_id")
    _require_mutations()
    guard_action("PATCH")
    _no_typed_override(
        fields,
        {
            key: arg
            for key, arg, value in (
                ("name", "name", name),
                ("summary", "summary", summary),
                ("active", "active", active),
            )
            if value is not None
        },
    )
    body = dict(fields or {})
    body.update(_given(name=name, summary=summary, active=active))
    body = _fields_to_send(body, "protect case")
    key, host_id = await _resolve(registry, host)
    return await _verified_patch(
        client,
        key,
        _private(host_id, "/cases"),
        _private(host_id, f"/cases/{case_id}"),
        case_id,
        body,
        "Protect cases",
    )


async def delete_protect_case(
    client: UniFiClient, registry: Registry, host: str, case_id: str
) -> dict[str, Any]:
    """Delete a Protect case (``DELETE /cases/{id}``); its assets go with it."""
    validate_id(case_id, "case_id")
    _require_mutations()
    guard_action("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(_private(host_id, f"/cases/{case_id}"), key=key)
    return deletion_result(f"Protect case {case_id} deleted.", response)


async def get_protect_case_activity(
    client: UniFiClient,
    registry: Registry,
    host: str,
    case_id: str,
    page: int | None = None,
    page_size: int | None = None,
) -> Any:
    """Read a case's activity log, draining every links.next page by default.

    The default drain uses batches up to 100. page_size=N returns records
    [(page-1)*N, page*N): exactly N when that many exist, fewer only at the end,
    never more. page is the 1-based window number counted in units of page_size
    (default 1); without page_size, returns one native console page.
    To continue, resume from _nextPage with the same page_size. ``_pageSize`` reports
    requested, sent, effective and returned sizes."""
    validate_pagination(
        page=page, page_size=page_size, names={"page": "page", "page_size": "page_size"}
    )
    validate_id(case_id, "case_id")
    key, host_id = await _resolve(registry, host)
    collected = await collect_links(
        client,
        _private(host_id, f"/cases/{case_id}/activity-log"),
        "activities",
        key=key,
        page=page,
        page_size=page_size,
    )
    if (bare := bare_page(collected)) is not None:
        return bare
    activities = collected["items"]
    result: dict[str, Any] = {"activities": activities, "_count": len(activities)}
    if collected.get("nextPage") is not None:
        result["_nextPage"] = collected["nextPage"]
    return mark_incomplete(with_envelope(result, collected), collected)


async def list_protect_case_assets(
    client: UniFiClient, registry: Registry, host: str, case_id: str
) -> dict[str, Any]:
    """List every asset of a Protect case (``GET /cases/{id}/assets``)."""
    validate_id(case_id, "case_id")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cases/{case_id}/assets")
    return _list_body(await client.get(path, key=key), "Protect case assets")


async def add_protect_case_asset(
    client: UniFiClient,
    registry: Registry,
    host: str,
    case_id: str,
    camera_id: str,
    start: int,
    end: int,
    note: str | None = None,
    lens: list[str] | None = None,
    asset_type: str = "clip",
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Add a recording clip to a Protect case (``POST /cases/{id}/assets``)."""
    validate_id(case_id, "case_id")
    start_ms = _epoch_ms(start, "start")
    end_ms = _epoch_ms(end, "end")
    _require_mutations()
    guard_action("POST")
    _no_typed_override(
        fields,
        {
            "camera": "camera_id",
            "type": "asset_type",
            "start": "start",
            "end": "end",
            **({"note": "note"} if note is not None else {}),
            **({"lens": "lens"} if lens is not None else {}),
        },
    )
    body: dict[str, Any] = dict(fields or {})
    body.update({"camera": camera_id, "type": asset_type, "start": start_ms, "end": end_ms})
    body.update(_given(note=note, lens=lens))
    key, host_id = await _resolve(registry, host)
    response = await client.post(_private(host_id, f"/cases/{case_id}/assets"), key=key, json=body)
    return with_warnings(_write_result("created", response), epoch_warnings(start=start, end=end))


def _echo_asset_type(before: dict[str, Any] | None, body: dict[str, Any]) -> dict[str, Any]:
    """Send the asset's current ``type`` when the caller gave none (the PATCH schema's
    discriminator, as the Protect web app does); an explicit type is sent as given."""
    if "type" in body or before is None or "type" not in before:
        return body
    return {"type": before["type"], **body}


async def update_protect_case_asset(
    client: UniFiClient,
    registry: Registry,
    host: str,
    case_id: str,
    asset_id: str,
    note: str | None = None,
    title: str | None = None,
    include_in_export: bool | None = None,
    asset_type: str | None = None,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Update a case asset (``PATCH /cases/{id}/assets/{assetId}``), verified via the list."""
    validate_id(case_id, "case_id")
    validate_id(asset_id, "asset_id")
    _require_mutations()
    guard_action("PATCH")
    _no_typed_override(
        fields,
        {
            key: arg
            for key, arg, value in (
                ("note", "note", note),
                ("title", "title", title),
                ("includeInExport", "include_in_export", include_in_export),
                ("type", "asset_type", asset_type),
            )
            if value is not None
        },
    )
    body = dict(fields or {})
    body.update(_given(note=note, title=title, includeInExport=include_in_export, type=asset_type))
    body = _fields_to_send(body, "protect case asset")
    key, host_id = await _resolve(registry, host)

    async def _read_parent() -> dict[str, Any] | None:
        cases = _as_list(await client.get(_private(host_id, "/cases"), key=key), "Protect cases")
        return _find(cases, case_id, "Protect cases")

    # Parent canonicalization is best-effort: an ancillary lookup must not prevent
    # the existing asset write when the collection is unavailable or unreadable.
    parent, _ = await safe_read_after(_read_parent)
    if parent is not None:
        case_id = parent["id"]
    return await _verified_patch(
        client,
        key,
        _private(host_id, f"/cases/{case_id}/assets"),
        _private(host_id, f"/cases/{case_id}/assets/{asset_id}"),
        asset_id,
        body,
        "Protect case assets",
        fill=_echo_asset_type,
    )


async def remove_protect_case_asset(
    client: UniFiClient, registry: Registry, host: str, case_id: str, asset_id: str
) -> dict[str, Any]:
    """Remove one asset from a Protect case (``DELETE /cases/{id}/assets/{assetId}``)."""
    validate_id(case_id, "case_id")
    validate_id(asset_id, "asset_id")
    _require_mutations()
    guard_action("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(
        _private(host_id, f"/cases/{case_id}/assets/{asset_id}"), key=key
    )
    return deletion_result(f"Asset {asset_id} removed from Protect case {case_id}.", response)


async def export_protect_case(
    client: UniFiClient,
    registry: Registry,
    host: str,
    action: str,
    case_id: str | None = None,
    export_id: str | None = None,
) -> Any:
    """Prepare a case export archive, or download a prepared one (base64 zip)."""
    action = _EXPORT_ACTION.validate_python(action)
    if action == "prepare" and export_id is not None:
        _argument_grammar(
            "export_id is for action 'download' only; action 'prepare' takes case_id."
        )
    if action == "download" and case_id is not None:
        _argument_grammar(
            "case_id is for action 'prepare' only; action 'download' takes export_id."
        )
    if action == "prepare":
        validate_id(case_id or "", "case_id")
        key, host_id = await _resolve(registry, host)
        path = _private(host_id, f"/cases/{case_id}/export/prepare")
        return _require_object(await client.get(path, key=key), f"GET {path}")
    validate_id(export_id or "", "export_id")
    key, host_id = await _resolve(registry, host)
    raw, content_type = await client.get_binary(
        _private(host_id, f"/cases/export/download/{export_id}"), key=key
    )
    return _b64(raw, content_type, "content_base64")


async def get_protect_case_asset_snapshot(
    client: UniFiClient, registry: Registry, host: str, case_id: str, asset_id: str
) -> dict[str, Any]:
    """GET a case asset's snapshot image (hermetic: not served on the estate controller)."""
    validate_id(case_id, "case_id")
    validate_id(asset_id, "asset_id")
    key, host_id = await _resolve(registry, host)
    raw, content_type = await client.get_binary(
        _private(host_id, f"/cases/{case_id}/assets/{asset_id}/snapshot"), key=key
    )
    return _b64(raw, content_type, "image_base64")


# --- Stream URLs ------------------------------------------------------------------------


async def get_protect_stream_url(
    client: UniFiClient,
    registry: Registry,
    host: str,
    kind: str,
    camera_id: str,
    channel: int | None = None,
    start: int | None = None,
    end: int | None = None,
    lens: int | None = None,
    stream_type: str | None = None,
    stream_format: str | None = None,
    frame_duration_ms: int | None = None,
    label: str | None = None,
    filename: str | None = None,
    fps: int | None = None,
) -> Any:
    """Get a short-lived stream address for a camera (WebSocket URL or live alias)."""
    kind = _STREAM_KIND.validate_python(kind)
    if kind == "livestream" and channel is None:
        # Protect answers 400 "Channel is not defined" without one; 0 is the web app's
        # default (the highest-quality stream).
        channel = 0
    params = _given(
        camera=camera_id,
        channel=channel,
        start=_epoch_ms(start, "start"),
        end=_epoch_ms(end, "end"),
        lens=lens,
        type=stream_type,
        format=stream_format,
        frameDurationMs=frame_duration_ms,
        label=label,
        filename=filename,
        fps=fps,
    )
    key, host_id = await _resolve(registry, host)
    body = await client.get(_private(host_id, _STREAM_PATH[kind]), key=key, params=params)
    return with_warnings(body, epoch_warnings(start=start, end=end))


# Module-level aliases: the registered tools below shadow these names inside register().
_get_protect_event = get_protect_event
_get_protect_event_media = get_protect_event_media
_set_protect_event_favorite = set_protect_event_favorite
_list_protect_cases = list_protect_cases
_create_protect_case = create_protect_case
_update_protect_case = update_protect_case
_delete_protect_case = delete_protect_case
_get_protect_case_activity = get_protect_case_activity
_list_protect_case_assets = list_protect_case_assets
_add_protect_case_asset = add_protect_case_asset
_update_protect_case_asset = update_protect_case_asset
_remove_protect_case_asset = remove_protect_case_asset
_export_protect_case = export_protect_case
_get_protect_case_asset_snapshot = get_protect_case_asset_snapshot
_get_protect_stream_url = get_protect_stream_url


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_event(host: str, event_id: str) -> dict[str, Any]:
        """Get one Protect event by id, with its full metadata.

        Returns the event object verbatim (id, type, start/end in epoch ms, camera,
        smartDetectTypes, isFavorite, favoriteObjectIds, metadata.detectedThumbnails with
        objectId values, thumbnail and heatmap ids). An unknown id answers HTTP 404 from
        the console. Find event ids with list_protect_events.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            event_id: Event id from list_protect_events (24-hex or UUID); for example
                "6acc281301811e03e42beafc".
        """
        client, registry = deps_fn()
        return await _get_protect_event(client, registry, host, event_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_event_media(
        host: str,
        event_id: str,
        kind: MediaKind,
        width: int | None = None,
        height: int | None = None,
        full_fov: bool | None = None,
        key_frame_only: bool | None = None,
        speedup: int | None = None,
        start: int | None = None,
        end: int | None = None,
        camera_id: str | None = None,
    ) -> Any:
        """Get one media view of a Protect event.

        Use kind thumbnail (JPEG), animated_thumbnail (GIF) and heatmap (PNG, motion events)
        for binary media. Returns {image_base64, content_type, size_bytes} with the
        upstream Content-Type. Smart_detect_track (object tracks) and transcriptions (which
        need camera_id) return the upstream JSON verbatim. Only the optional arguments you
        pass are sent.
        The console answers 404 when an event has no such media (for example a heatmap
        for a smart-detect event, or an animated thumbnail for a UUID-id event).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            event_id: Event id from list_protect_events; for example "6acc281301811e03e42beafc".
            kind: Media view: thumbnail, animated_thumbnail, heatmap, smart_detect_track or
                transcriptions; for example "thumbnail".
            width: Thumbnail or GIF width in pixels, sent as w; for example 640.
            height: Thumbnail or GIF height in pixels, sent as h; for example 360.
            full_fov: Thumbnail of the full field of view, sent as isFullfov; for example true.
            key_frame_only: GIF built from key frames only, sent as keyFrameOnly; for example true.
            speedup: GIF playback speed factor; for example 10.
            start: GIF window start, epoch SECONDS (sent as ms); for example 1760227200.
            end: GIF window end, epoch SECONDS (sent as ms); for example 1760227260.
            camera_id: Camera id of the event, required by transcriptions; for example
                "65d4f1e2a1b2c3d4e5f60718".
        """
        client, registry = deps_fn()
        return await _get_protect_event_media(
            client,
            registry,
            host,
            event_id,
            kind,
            width=width,
            height=height,
            full_fov=full_fov,
            key_frame_only=key_frame_only,
            speedup=speedup,
            start=start,
            end=end,
            camera_id=camera_id,
        )

    @mcp.tool(annotations=WRITE)
    async def set_protect_event_favorite(
        host: str,
        event_ids: str | list[str],
        favorite: bool,
        object_id: str | None = None,
        objects: list[FavoriteObject] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Mark Protect events as favorite (favorite=true) or remove the mark (false).

        Consequence: only the events' favorite mark changes, as every user of the console
        sees it; no recording changes.

        One id (a string) uses the per-event route and returns {status, response,
        verified, event}: the event is read back and verified is whether isFavorite (or,
        with object_id, favoriteObjectIds) now matches. A list of ids uses the batch route.
        Returns {status, response}, where response maps each id to the console's result.
        Both forms answer status: "favorited" for favorite=true and status: "unfavorited"
        for false. The Protect write opt-out and read-only mode apply before any request.
        With UNIFI_DRY_RUN, returns {status: "dry_run", response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            event_ids: One event id, or a non-empty list of ids for the batch route (an empty
                list fails before any request); for example
                "6acc281301811e03e42beafc".
                Shape: string|string[]
            favorite: true to favorite, false to unfavorite; for example true.
            object_id: Single-id form only (with a list it fails before any request): favorite
                one detected object of the event
                (metadata.detectedThumbnails[].objectId); for example
                "1d4432d2-7eb8-47e4-acb0-3f3e62b01d8f".
            objects: List form only (with one event id it fails before any request): per-object
                marks sent as idsWithObject, each
                {eventId, objectId}; for example [{"eventId": "6acc...", "objectId": "1d44..."}].
                Shape: {eventId:string,objectId:string}[]
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _set_protect_event_favorite(
            client, registry, host, event_ids, favorite, object_id=object_id, objects=objects
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_cases(host: str) -> dict[str, Any]:
        """List every Protect case (investigation) on a console.

        Returns {result: [case, ...], _count}; each case is verbatim (id, name, summary,
        active, assetCount, incident fields, createdAt/updatedAt in epoch ms). The console
        returns the complete list in one response; there is no per-case GET route, so use
        this list to read one case.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
        """
        client, registry = deps_fn()
        return await _list_protect_cases(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def create_protect_case(
        host: str,
        name: str,
        summary: str | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a Protect case (investigation) and return it.

        Sends {name, summary?, ...fields} to POST /cases. Returns {status: "created",
        response: CASE}, where CASE is the created case with its id. Add recordings with
        add_protect_case_asset. With UNIFI_DRY_RUN, returns {status: "dry_run", response:
        PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            name: Case name; for example "Garage break-in 2026-10-11".
            summary: Case summary text; for example "Side door forced at 02:10".
            fields: Other case fields sent as given (free-form object), such as location,
                incidentType, incidentSeverity, incidentTimestamp; for example
                {"location": "Garage"}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _create_protect_case(
            client, registry, host, name, summary=summary, fields=fields
        )

    @mcp.tool(annotations=WRITE)
    async def update_protect_case(
        host: str,
        case_id: str,
        name: str | None = None,
        summary: str | None = None,
        active: bool | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Update a Protect case: rename, edit the summary, close (active=false) or reopen.

        Requested top-level fields are sent (PATCH /cases/{case_id}), preserving current
        nested siblings; named arguments win. Read-back verifies all merged leaves
        type-strictly. The case is read from
        list_protect_cases before and after. Returns {status: "updated", verified, before,
        after, response}, or {status: "noop", resource} when every field already matches.
        Passing no field fails before any request. With UNIFI_DRY_RUN, returns {status:
        "dry_run", before, response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
            name: New case name; for example "Garage break-in (closed)".
            summary: New summary; for example "Suspect identified".
            active: false closes the case, true reopens it; for example false.
            fields: Other case fields sent as given (free-form object); for example
                {"incidentSeverity": "high"}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _update_protect_case(
            client,
            registry,
            host,
            case_id,
            name=name,
            summary=summary,
            active=active,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def delete_protect_case(host: str, case_id: str, confirm: bool = False) -> dict[str, Any]:
        """Delete a Protect case permanently, with all of its assets.

        Consequence: the case and every asset in it are removed for all users and cannot be
        restored; the recordings themselves stay on the NVR.

        Sends DELETE /cases/{case_id}. Returns {deleted: true, message, response}. With
        UNIFI_DRY_RUN, returns {status: "dry_run", deleted: false, message, response:
        PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _delete_protect_case(client, registry, host, case_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_case_activity(
        host: str, case_id: str, page: int | None = None, page_size: int | None = None
    ) -> Any:
        """Get the activity (audit) log of a Protect case.

        Returns {activities: [...], _count} with each entry unchanged (timestamp in epoch
        ms, sequenceId, description.messageRaw, ipAddress). Every links.next page is
        drained by default in batches up to 100. page_size=N returns records
        [(page-1)*N, page*N): exactly N when that many exist, fewer only at the end,
        never more. page is the 1-based window number counted in units of page_size
        (default 1); without page_size, returns one native console page.
        To continue, resume from _nextPage with the same page_size. _pageSize reports requested,
        sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
            page: 1-based window number counted in units of page_size (default 1); without
                page_size, returns one native console page; resume from _nextPage with the same
                page_size. Example: `2`.
            page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
                fewer only at the end, never more; resume from _nextPage with the same page_size.
                Example: `50`.
        """
        client, registry = deps_fn()
        return await _get_protect_case_activity(
            client, registry, host, case_id, page=page, page_size=page_size
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_case_assets(host: str, case_id: str) -> dict[str, Any]:
        """List every asset of a Protect case (clips plus the generated PDF report).

        Returns {result: [asset, ...], _count}; each asset is verbatim (id, type such as
        clip or pdfReport, camera, start/end in epoch ms, note, title, includeInExport).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
        """
        client, registry = deps_fn()
        return await _list_protect_case_assets(client, registry, host, case_id)

    @mcp.tool(annotations=WRITE)
    async def add_protect_case_asset(
        host: str,
        case_id: str,
        camera_id: str,
        start: int,
        end: int,
        note: str | None = None,
        lens: list[str] | None = None,
        asset_type: str = "clip",
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add a recording clip from one camera to a Protect case.

        Consequence: the clip is attached to the case for everyone with access to it; the
        recording itself is unchanged.

        Sends {camera, type, start, end, note?, lens?, ...fields} to POST
        /cases/{case_id}/assets, start and end converted from epoch SECONDS to ms. To add
        an event, pass its camera and start/end (event times are ms; divide by 1000).
        Returns {status: "created", response: {main: {success, data: ASSET}}}. The
        console accepts asset_type "clip" only (live-probed). With UNIFI_DRY_RUN, returns
        {status: "dry_run", response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
            camera_id: Camera id (an event's camera field); for example "65d4f1e2a1b2c3d4e5f60718".
            start: Clip start, epoch SECONDS; for example 1760227200.
            end: Clip end, epoch SECONDS; for example 1760227230.
            note: Note shown on the asset; for example "Person at side door".
            lens: Lenses of a package-camera doorbell, "main" and/or "secondary"; for
                example ["main"].
                Shape: ('main'|'secondary')[]
            asset_type: Asset type discriminator; for example "clip".
            fields: Other asset fields sent as given (free-form object); for example
                {"title": "Side door"}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _add_protect_case_asset(
            client,
            registry,
            host,
            case_id,
            camera_id,
            start,
            end,
            note=note,
            lens=lens,
            asset_type=asset_type,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def update_protect_case_asset(
        host: str,
        case_id: str,
        asset_id: str,
        note: str | None = None,
        title: str | None = None,
        include_in_export: bool | None = None,
        asset_type: str | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Update a Protect case asset: note, title or whether it is included in exports.

        Sends PATCH /cases/{case_id}/assets/{asset_id}, preserving current nested siblings.
        Read-back verifies all merged leaves type-strictly. The
        console requires the asset type in every PATCH, so the asset's current type is sent
        when asset_type is omitted (as the Protect web app does). The asset is read from
        list_protect_case_assets before and after. Returns {status: "updated", verified,
        before, after, response} or {status: "noop", resource}. No field fails before any
        request. With UNIFI_DRY_RUN, returns {status: "dry_run", before, response: PREVIEW}.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
            asset_id: Asset id from list_protect_case_assets; for example
                "6acc2a9500461e03e42bf50d".
            note: New note; for example "Confirmed: courier".
            title: New title; for example "Front door".
            include_in_export: Include the asset in case exports, sent as includeInExport;
                for example false.
            asset_type: Type discriminator to send (clip, externalFile, pdfReport,
                presentation); for example "clip".
            fields: Other asset fields sent as given (free-form object); for example
                {"isMuted": true}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _update_protect_case_asset(
            client,
            registry,
            host,
            case_id,
            asset_id,
            note=note,
            title=title,
            include_in_export=include_in_export,
            asset_type=asset_type,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def remove_protect_case_asset(
        host: str, case_id: str, asset_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove one asset from a Protect case (the recording stays on the NVR).

        Consequence: the asset leaves the case for every user; add it again with
        add_protect_case_asset. The recording itself stays on the NVR.

        Sends DELETE /cases/{case_id}/assets/{asset_id}. Returns {deleted: true, message,
        response}. With UNIFI_DRY_RUN, returns {status: "dry_run", deleted: false,
        message, response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
            asset_id: Asset id from list_protect_case_assets; for example
                "6acc2a9500461e03e42bf50d".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _remove_protect_case_asset(client, registry, host, case_id, asset_id)

    @mcp.tool(annotations=READ_ONLY)
    async def export_protect_case(
        host: str,
        action: ExportAction,
        case_id: str | None = None,
        export_id: str | None = None,
    ) -> Any:
        """Export a Protect case as a zip archive, in two steps.

        With action "prepare" (which needs case_id), the console creates an export job and
        builds the archive without changing configuration. This read is allowed in read-only
        mode and executes under UNIFI_DRY_RUN.
        Returns: for prepare, the export job verbatim ({id, type: "CaseExport", status,
        progressRatio, archiveFileName, ...}); for action "download" (needs export_id, the
        job id), {content_base64, content_type, size_bytes} for the finished zip. A download before
        the archive is ready, or of a large archive, can time out at the cloud connector
        (HTTP 408 DeviceTimeout); try again later.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            action: "prepare" or "download"; for example "prepare".
            case_id: Case id from list_protect_cases, for prepare only (with download it fails
                before any request); for example
                "6acc2a9002b21e03e42bf4ce".
            export_id: Export job id returned by prepare, for download only (with prepare it
                fails before any request); for example
                "6acc2a97013c1e03e42bf532".
        """
        client, registry = deps_fn()
        return await _export_protect_case(
            client, registry, host, action, case_id=case_id, export_id=export_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_case_asset_snapshot(
        host: str, case_id: str, asset_id: str
    ) -> dict[str, Any]:
        """Get the snapshot image of a Protect case asset.

        Returns {image_base64, content_type, size_bytes}. Not served by every Protect
        version: on Protect 7.x through the cloud connector the route answers HTTP 404
        (route not found), which is returned as the upstream error.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "6acc2a9002b21e03e42bf4ce".
            asset_id: Asset id from list_protect_case_assets; for example
                "6acc2a9500461e03e42bf50d".
        """
        client, registry = deps_fn()
        return await _get_protect_case_asset_snapshot(client, registry, host, case_id, asset_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_stream_url(
        host: str,
        kind: StreamKind,
        camera_id: str,
        channel: int | None = None,
        start: int | None = None,
        end: int | None = None,
        lens: int | None = None,
        stream_type: str | None = None,
        stream_format: str | None = None,
        frame_duration_ms: int | None = None,
        label: str | None = None,
        filename: str | None = None,
        fps: int | None = None,
    ) -> Any:
        """Get a short-lived stream address for a Protect camera, as the web app does.

        Returns the upstream body verbatim: {url} for livestream, playback, timelapse, heatmap
        and live_detect_track (WebSocket addresses with a per-request token); for live_alias
        the body is {alias}. livestream sends channel (default 0) and adds directUrl;
        playback and timelapse need start, end. An upstream array is returned as {result:
        [...]}. When start or end is negative or looks like epoch milliseconds, an object
        result gains an additive _warnings list and an array result is returned as
        {result, _warnings}.
        video_prepare
        (tcp/video/prepare) is not served on Protect 7.x via the connector (HTTP 404).
        Otherwise only the arguments you pass are sent; the console reports a missing one. These
        values are registered credentials: success fields and error text are masked only
        when UNIFI_REDACT_SECRETS is on, otherwise verbatim. Logs always scrub them.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            kind: livestream, playback, timelapse, heatmap, live_detect_track, live_alias or
                video_prepare; for example "livestream".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            channel: Camera channel index (0 is the highest quality; livestream defaults
                to 0); for example 0.
            start: Window start, epoch SECONDS (sent as ms); for example 1760227200.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227260.
            lens: Lens index of a multi-lens camera; for example 0.
            stream_type: Sent as type, for example "fmp4" (livestream) or "rotating"
                (video_prepare); for example "fmp4".
            stream_format: Sent as format; for example "FMP4".
            frame_duration_ms: Heatmap frame duration, sent as frameDurationMs; for example 1000.
            label: Heatmap object label; for example "person".
            filename: video_prepare output file name; for example "clip.mp4".
            fps: video_prepare frame rate; for example 0.
        """
        client, registry = deps_fn()
        return await _get_protect_stream_url(
            client,
            registry,
            host,
            kind,
            camera_id,
            channel=channel,
            start=start,
            end=end,
            lens=lens,
            stream_type=stream_type,
            stream_format=stream_format,
            frame_duration_ms=frame_duration_ms,
            label=label,
            filename=filename,
            fps=fps,
        )
