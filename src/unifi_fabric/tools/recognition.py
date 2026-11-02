"""UniFi Protect face/vehicle recognition tools (private, undocumented REST API).

The recognition resource lives at ``/proxy/protect/api/recognition/{type}/groups`` and
its siblings — NOT the Protect Integration API, which has no recognition surface. These
tools issue GETs only: named recognition groups, aggregate counts, the per-group
reference crop, per-group detections, and per-detection thumbnails.

Pass-through, not redaction
---------------------------
The server is a faithful pass-through. Group records carry ``name`` / ``matchedName``
label fields and the image endpoints return the actual reference crops; everything
upstream returns is returned unchanged. The tool does not withhold data from its
caller; a deployment that wants to restrict output layers that policy on top of the
response.

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

from ..client import UniFiClient, UniFiConnectionError, describe_shape, validate_id
from ..registry import Registry
from ._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
    with_warnings,
)
from ._pagination import (
    bare_page,
    collect_links,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)

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
) -> Any:
    """List recognition groups (enrolled subjects) on a Protect console.

    Each group carries a stable id (for example ``face_90``), name/matchedName,
    detectionsCount and createdAt/firstDetectedAt/lastDetectedAt timestamps. Names
    are returned unchanged. The result contains ``groups`` and ``_count``.

    By default every ``links.next`` page is drained in batches of at most 100.
    page_size=N returns records [(page-1)*N, page*N): exactly N when that many
    exist, fewer only at the end, never more. page is the 1-based window number
    counted in units of page_size (default 1); without page_size, returns one
    native console page. To continue, resume from _nextPage with the same page_size.
    ``_pageSize`` reports requested, sent, effective and returned sizes.
    An incomplete drain carries incomplete/incompleteReason.

    type: recognition type, normally ``face`` or ``vehicle`` (singular); forwarded
      unchanged. Plural forms return HTTP 400 from upstream.
    has_name: when true, return only named groups.
    page_size: N returns records [(page-1)*N, page*N): exactly N when that many
      exist, fewer only at the end, never more; resume from _nextPage with the same page_size.
    order_by / order_direction: server-side sort, for example ``name`` / ``asc``.
    page: 1-based window number counted in units of page_size (default 1); without
      page_size, returns one native console page; resume from _nextPage with the same page_size."""
    validate_pagination(
        page=page, page_size=page_size, names={"page": "page", "page_size": "page_size"}
    )
    validate_id(type, "type")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
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
            key=key,
            params=params,
            page=page,
            page_size=page_size,
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    if (bare := bare_page(collected)) is not None:
        return bare
    groups = collected["items"]
    result: dict[str, Any] = {"groups": groups, "_count": len(groups)}
    if collected.get("nextPage") is not None:
        result["_nextPage"] = collected["nextPage"]
    return mark_incomplete(with_envelope(result, collected), collected)


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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _private(host_id, f"/recognition/{type}/groups/counts")
    try:
        data = await client.get(path, key=key)
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    if not isinstance(data, dict):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object of counts, "
            f"got {describe_shape(data)}"
        )
    return data


async def get_recognition_group_image(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    group_id: str,
) -> dict[str, Any]:
    """Get a recognition group's reference crop. Returns base64-encoded image data.

    The endpoint returns raw image bytes (a ~360x360 reference crop); they are
    base64-encoded for transport, mirroring ``get_camera_snapshot``. ``content_type`` is
    the upstream Content-Type header as sent (typically image/jpeg), or None when the
    upstream sends none; it is never assumed.

    type: recognition type. Use ``face`` or ``vehicle`` (singular — plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.
    group_id: the group's stable id, e.g. ``face_90``.
    """
    validate_id(type, "type")
    validate_id(group_id, "group_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    try:
        raw, content_type = await client.get_binary(
            _private(host_id, f"/recognition/{type}/groups/{group_id}/image"), key=key
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return {
        "image_base64": base64.b64encode(raw).decode(),
        "content_type": content_type,
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
) -> Any:
    """List one recognition group's detections (sightings) on a Protect console.

    Both ``type`` and ``group_id`` are required. Obtain ``group_id`` from
    ``list_recognition_groups`` (for example ``face_90``); there is no all-groups
    mode and a nonexistent group returns HTTP 404. Each detection carries id,
    eventId (join to list_protect_events), thumbnailId (get_thumbnail), detectedAt
    (epoch milliseconds), cameraId and matchedGroupConfidence (0-100).

    By default every ``links.next`` page is drained in batches of at most 100.
    page_size=N returns records [(page-1)*N, page*N): exactly N when that many
    exist, fewer only at the end, never more. page is the 1-based window number
    counted in units of page_size (default 1); without page_size, returns one
    native console page. To continue, resume from _nextPage with the same page_size.
    ``_pageSize`` reports requested, sent, effective and returned sizes.
    An incomplete drain carries incomplete/incompleteReason.

    A manual page follows the upstream page's shape. A bare-list page is returned
    unchanged without warnings. An object page is returned as detections/_count
    with upstream fields and epoch warnings, as a drained result does, and _nextPage
    when manual paging has more.

    type: recognition type, normally ``face`` or ``vehicle`` (singular); forwarded
      unchanged. Plural forms return HTTP 400 from upstream.
    group_id: The group's stable id from list_recognition_groups.
    page_size: N returns records [(page-1)*N, page*N): exactly N when that many
      exist, fewer only at the end, never more; resume from _nextPage with the same page_size.
    start/end: Optional UTC epoch-second window, converted to milliseconds for
      detectedAt filtering; omit both for all detections.
    page: 1-based window number counted in units of page_size (default 1); without
      page_size, returns one native console page; resume from _nextPage with the same page_size."""
    validate_pagination(
        page=page, page_size=page_size, names={"page": "page", "page_size": "page_size"}
    )
    validate_id(type, "type")
    validate_id(group_id, "group_id")
    # The time window is validated before any request (no resolution for a bad window).
    params: dict[str, Any] = {}
    if start is not None:
        params["start"] = seconds_to_millis(require_epoch_seconds(start, "start"))
    if end is not None:
        params["end"] = seconds_to_millis(require_epoch_seconds(end, "end"))
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    try:
        collected = await collect_links(
            client,
            _private(host_id, f"/recognition/{type}/groups/{group_id}/detections"),
            "detections",
            key=key,
            params=params,
            page=page,
            page_size=page_size,
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    if (bare := bare_page(collected)) is not None:
        return bare
    detections = collected["items"]
    result: dict[str, Any] = {"detections": detections, "_count": len(detections)}
    if collected.get("nextPage") is not None:
        result["_nextPage"] = collected["nextPage"]
    return with_warnings(
        mark_incomplete(with_envelope(result, collected), collected),
        epoch_warnings(start=start, end=end),
    )


async def get_thumbnail(
    client: UniFiClient,
    registry: Registry,
    host: str,
    thumbnail_id: str,
) -> dict[str, Any]:
    """Get a detection thumbnail crop. Returns base64-encoded image data.

    The endpoint returns raw image bytes (a ~360x360 per-detection crop, distinct from
    the group reference crop); they are base64-encoded for transport, mirroring
    ``get_camera_snapshot``. ``content_type`` is the upstream Content-Type header as sent
    (typically image/jpeg), or None when the upstream sends none; it is never assumed.

    thumbnail_id: the ``thumbnailId`` from a detection record.
    """
    validate_id(thumbnail_id, "thumbnail_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    try:
        raw, content_type = await client.get_binary(
            _private(host_id, f"/thumbnails/{thumbnail_id}"), key=key
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    return {
        "image_base64": base64.b64encode(raw).decode(),
        "content_type": content_type,
        "size_bytes": len(raw),
    }
