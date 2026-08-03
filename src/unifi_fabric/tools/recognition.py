"""UniFi Protect face/vehicle recognition tools (private, undocumented REST API).

The recognition resource lives at ``/proxy/protect/api/recognition/{type}/groups`` and
its siblings — NOT the Protect Integration API, which has no recognition surface. These
paths were verified live (GET only): named recognition groups, aggregate counts, the
per-group reference crop, per-group detections, and per-detection thumbnails.

Pass-through, not redaction
---------------------------
The server is a faithful pass-through. Group records carry ``name`` / ``matchedName``
label fields and the image endpoints return the actual reference crops; everything
upstream returns is returned unchanged. This matches the whole-server pass-through
invariant (see ``CLAUDE.md``): the tool does not withhold data from its caller, and a
deployment that wants to restrict output layers that policy on top of the response.

Pagination
----------
``/recognition/{type}/groups`` and ``.../{id}/detections`` return a
``{<array_field>, links:{prev,next}}`` envelope and page via an explicit ``page=N`` query
parameter (``links.next`` carries the next page URL, or null on the last page). Both list
tools drain every page by default through ``collect_links``; pass ``page`` to fetch a
single page manually.

Type validation is path-safety only (``validate_id``): ``face``, ``vehicle``, ``person``,
``license-plate`` all pass our check and are forwarded as-is. The server never narrows the
accepted ``type`` set below what the upstream API accepts — if upstream rejects a type it
answers with its own 400/404 rather than us pre-rejecting it.
"""

from __future__ import annotations

import base64
from typing import Any

from ..client import UniFiClient, UniFiConnectionError, validate_id
from ..registry import Registry
from ._history_common import require_epoch_seconds, seconds_to_millis, translate_host_not_found
from ._pagination import DRAIN_PAGE_SIZE, collect_links, mark_incomplete

RECOGNITION_PRIVATE_BASE = "/v1/connector/consoles/{host_id}/proxy/protect/api"


def _private(host_id: str, path: str) -> str:
    return RECOGNITION_PRIVATE_BASE.format(host_id=host_id) + path


async def list_recognition_groups(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    has_name: bool | None = None,
    page_size: int | None = None,
    order_by: str | None = None,
    order_direction: str | None = None,
    page: int | None = None,
) -> dict[str, Any]:
    """List recognition groups (e.g. enrolled faces) on a Protect console.

    Each group is a recognised subject with a stable, monotonic ``id`` (``face_1``,
    ``face_90``, …), a ``name`` / ``matchedName`` label, a ``detectionsCount``, and
    ``createdAt`` / ``firstDetectedAt`` / ``lastDetectedAt`` timestamps usable as sync
    and change-detection keys. Nothing is redacted — the ``name`` label is returned as-is.

    Response shape: ``{"groups": [...], "count": N}`` (plus ``nextPage`` / ``incomplete``
    when applicable). The array is under ``groups``, not ``data`` — this follows the
    codebase convention of naming a list's array after its resource (as in
    ``list_recognition_detections`` → ``detections``, ``list_hotspot_operators`` →
    ``operators``). Only the Network Integration offset-paginated proxy lists use the
    ``{"data": [...], "totalCount": N}`` shape; a consumer must key off ``groups`` here.

    type: recognition type. Use ``face`` or ``vehicle`` (singular). Plural forms
      (``faces``, ``vehicles``) are NOT valid and return HTTP 400 from the upstream
      API — two separate agents have guessed plural and hit this error. The value is
      forwarded as-is, so any other type the console accepts also works, and any it
      rejects is answered by the API's own error.
    has_name: when true, return only named groups (unnamed groups are filtered out).
    page_size: API page size; also the drain page size. Defaults to 200.
    order_by / order_direction: server-side sort, e.g. order_by='name',
      order_direction='asc'.
    page: fetch a single page (1-based) instead of draining. Response envelope pages via
      ``links.next``; by default every page is drained and the complete group set is
      returned. Pass ``page`` to fetch one page manually — ``nextPage`` is then surfaced.
    """
    validate_id(type, "type")
    host_id = await registry.resolve_host_id(host)
    params: dict[str, Any] = {}
    if has_name is not None:
        params["hasName"] = has_name
    if order_by is not None:
        params["orderBy"] = order_by
    if order_direction is not None:
        params["orderDirection"] = order_direction
    try:
        collected = await collect_links(
            client,
            _private(host_id, f"/recognition/{type}/groups"),
            "groups",
            params=params,
            page=page,
            page_size=page_size if page_size is not None else DRAIN_PAGE_SIZE,
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    groups = collected["items"]
    result: dict[str, Any] = {"groups": groups, "count": len(groups)}
    if collected.get("nextPage") is not None:
        result["nextPage"] = collected["nextPage"]
    return mark_incomplete(result, collected)


async def get_recognition_group_counts(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
) -> dict[str, Any]:
    """Get aggregate recognition-group counts for a Protect console.

    Returns totals such as ``totalCount``, ``nameNotNullCount`` (named groups),
    ``nameIsNullCount``, ``notificationEnabledCount``, and ``degradedCount``.

    type: recognition type. Use ``face`` or ``vehicle`` (singular — plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.
    """
    validate_id(type, "type")
    host_id = await registry.resolve_host_id(host)
    try:
        data = await client.get(_private(host_id, f"/recognition/{type}/groups/counts"))
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return data if isinstance(data, dict) else {"data": data}


async def get_recognition_group_image(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    group_id: str,
) -> dict[str, Any]:
    """Get a recognition group's reference crop. Returns base64-encoded JPEG image data.

    The endpoint returns raw ``image/jpeg`` bytes (a ~360x360 reference crop); they are
    base64-encoded for transport, mirroring ``get_camera_snapshot``.

    type: recognition type. Use ``face`` or ``vehicle`` (singular — plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.
    group_id: the group's stable id, e.g. ``face_90``.
    """
    validate_id(type, "type")
    validate_id(group_id, "group_id")
    host_id = await registry.resolve_host_id(host)
    try:
        raw = await client.get_bytes(
            _private(host_id, f"/recognition/{type}/groups/{group_id}/image")
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return {
        "image_base64": base64.b64encode(raw).decode(),
        "content_type": "image/jpeg",
        "size_bytes": len(raw),
    }


async def list_recognition_detections(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    group_id: str,
    page_size: int | None = None,
    start: int | None = None,
    end: int | None = None,
    page: int | None = None,
) -> dict[str, Any]:
    """List a recognition group's detections (individual sightings) on a Protect console.

    Each detection record carries ``id``, ``eventId`` (joinable against
    ``list_protect_events``), ``thumbnailId`` (fetch the crop with ``get_thumbnail``),
    ``detectedAt`` (epoch ms), ``cameraId``, and ``matchedGroupConfidence`` (0-100).

    type: recognition type. Use ``face`` or ``vehicle`` (singular — plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.
    group_id: the group's stable id, e.g. ``face_90``.
    page_size: API page size; also the drain page size. Defaults to 200.
    start/end: optional time window in epoch SECONDS (UTC), converted to milliseconds
      internally. Verified live: the endpoint filters detections server-side by
      ``detectedAt`` against this window, so a caller can request an arbitrary range
      (e.g. the last hour, 30 days, or 90 days) directly. Omit both for all detections.
    page: fetch a single page (1-based) instead of draining. The response envelope pages
      via ``links.next``; by default every page is drained so the complete detection set
      for the group (and window, if given) is returned. Pass ``page`` to fetch one page
      manually — ``nextPage`` is then surfaced.
    """
    validate_id(type, "type")
    validate_id(group_id, "group_id")
    host_id = await registry.resolve_host_id(host)
    params: dict[str, Any] = {}
    if start is not None:
        params["start"] = seconds_to_millis(require_epoch_seconds(start, "start"))
    if end is not None:
        params["end"] = seconds_to_millis(require_epoch_seconds(end, "end"))
    try:
        collected = await collect_links(
            client,
            _private(host_id, f"/recognition/{type}/groups/{group_id}/detections"),
            "detections",
            params=params,
            page=page,
            page_size=page_size if page_size is not None else DRAIN_PAGE_SIZE,
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    detections = collected["items"]
    result: dict[str, Any] = {"detections": detections, "count": len(detections)}
    if collected.get("nextPage") is not None:
        result["nextPage"] = collected["nextPage"]
    return mark_incomplete(result, collected)


async def get_thumbnail(
    client: UniFiClient,
    registry: Registry,
    host: str,
    thumbnail_id: str,
) -> dict[str, Any]:
    """Get a detection thumbnail crop. Returns base64-encoded JPEG image data.

    The endpoint returns raw ``image/jpeg`` bytes (a ~360x360 per-detection crop, distinct
    from the group reference crop); they are base64-encoded for transport, mirroring
    ``get_camera_snapshot``.

    thumbnail_id: the ``thumbnailId`` from a detection record.
    """
    validate_id(thumbnail_id, "thumbnail_id")
    host_id = await registry.resolve_host_id(host)
    try:
        raw = await client.get_bytes(_private(host_id, f"/thumbnails/{thumbnail_id}"))
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return {
        "image_base64": base64.b64encode(raw).decode(),
        "content_type": "image/jpeg",
        "size_bytes": len(raw),
    }
