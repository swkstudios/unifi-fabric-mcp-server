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
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ...client import UniFiClient, UniFiConnectionError, describe_shape, validate_id
from ...registry import Registry
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
    with_warnings,
)
from ...shared_shapes._pagination import (
    bare_page,
    collect_links,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)
from ...shared_shapes._shared import _image_result
from ...tool_annotations import READ_ONLY

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


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import recognition  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the recognition tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_recognition_groups(
        host: str,
        type: str,
        has_name: bool | None = None,
        page_size: int | None = None,
        order_by: str | None = None,
        order_direction: str | None = None,
        page: int | None = None,
    ) -> dict[str, Any]:
        """List recognition groups (enrolled faces or vehicles) on a Protect console.

        Returns {groups, _count} plus upstream envelope fields. Each group has a stable
        monotonic id (for example face_90), name/matchedName, detectionsCount, and
        createdAt/firstDetectedAt/lastDetectedAt timestamps. Names remain unchanged.
        The private recognition API returns groups under groups, rather than data.

        Default drains all links.next pages in batches up to 100. page_size=N returns
        records [(page-1)*N, page*N): exactly N when that many exist, fewer only at the
        end, never more. page is the 1-based window number counted in units of page_size
        (default 1); without page_size, returns one native console page.
        To continue, resume from _nextPage with the same page_size. _pageSize reports requested,
        sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

        Args:
            host: Console reportedState.hostname or data[].id from list_hosts, for example "my-console";
                names match reportedState.hostname/name case-insensitively.
            type: Recognition type, normally 'face' or 'vehicle' (singular). Forwarded
                unchanged; plural forms return HTTP 400 from upstream.
            has_name: When true, return named groups only. Example: true.
            page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
                fewer only at the end, never more; resume from _nextPage with the same page_size.
                Example: `100`.
            order_by: Sort field: name, createdAt, lastDetectedAt or detectionsCount.
                Example: 'name'. With no order_direction, upstream defaults to descending.
            order_direction: 'asc' or 'desc', case-insensitive; effective only with
                order_by. Unknown values return upstream HTTP 400. Example: 'asc'.
            page: 1-based window number counted in units of page_size (default 1); without
                page_size, returns one native console page; resume from _nextPage with the same
                page_size. Example: `2`.
        """
        client, registry = deps_fn()
        return await recognition.list_recognition_groups(
            client, registry, host, type, has_name, page_size, order_by, order_direction, page
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_recognition_group_counts(
        host: str,
        type: str,
    ) -> dict[str, Any]:
        """Get aggregate recognition-group counts for a Protect console.

        Returns totals such as totalCount, nameNotNullCount (named groups), nameIsNullCount,
        notificationEnabledCount, and degradedCount.

        Required arguments: host, type (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            type: recognition type. Use 'face' or 'vehicle' (singular — plural forms return HTTP 400
                from upstream). Forwarded to the API as-is.
        """
        client, registry = deps_fn()
        return await recognition.get_recognition_group_counts(client, registry, host, type)

    @mcp.tool(annotations=READ_ONLY)
    async def get_recognition_group_image(
        host: str,
        type: str,
        group_id: str,
    ) -> Any:
        """Get a recognition group's reference crop. Returns MCP ImageContent plus image metadata.

        Returns MCP ImageContent plus text and structured metadata
        {image_base64, content_type, size_bytes}; content_type is the upstream
        Content-Type header (typically image/jpeg), not assumed, and null when the upstream
        sends none.

        `type`: recognition type. Use 'face' or 'vehicle' (singular -- plural forms
          return HTTP 400 from upstream). Forwarded to the API as-is.

        Example call (get_recognition_group_image):
            {"host": "my-console", "type": "face", "group_id": "face_90"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            type: 'face' or 'vehicle' (singular; plural returns HTTP 400).
            group_id: Recognition group id, e.g. 'face_90'. Get it from list_recognition_groups (id).
                Protect recognition id.
        """
        client, registry = deps_fn()
        return _image_result(
            await recognition.get_recognition_group_image(client, registry, host, type, group_id)
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_recognition_detections(
        host: str,
        type: str,
        group_id: str,
        page_size: int | None = None,
        start: int | None = None,
        end: int | None = None,
        page: int | None = None,
    ) -> dict[str, Any]:
        """List one enrolled recognition group's detections (sightings) on Protect.

        Returns {detections, _count} plus upstream envelope fields and epoch warnings.
        Required group_id comes from list_recognition_groups, for example face_90. There
        is no all-groups mode; a nonexistent group returns HTTP 404. Each detection has
        id, eventId (list_protect_events), thumbnailId (get_thumbnail), detectedAt (epoch
        milliseconds), cameraId and matchedGroupConfidence (0-100).

        Default drains all links.next pages in batches up to 100. page_size=N returns
        records [(page-1)*N, page*N): exactly N when that many exist, fewer only at the
        end, never more. page is the 1-based window number counted in units of page_size
        (default 1); without page_size, returns one native console page.
        To continue, resume from _nextPage with the same page_size. _pageSize reports requested,
        sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

        page without page_size fetches one native page, with _nextPage when more exist.
        An explicit page keeps a bare list verbatim (no _warnings) when page_size is absent,
        and preserves every field of an object page verbatim with epoch-unit _warnings.
        A bare-list manual page is unchanged without _warnings; object pages preserve
        upstream fields and add epoch warnings.
        Examples are in docs/TOOL-USAGE.md#list_recognition_detections.

        Args:
            host: Console reportedState.hostname or data[].id from list_hosts, for example "my-console";
                names match reportedState.hostname/name case-insensitively.
            type: 'face' or 'vehicle' (singular); plural forms return HTTP 400 upstream.
            group_id: Group id from list_recognition_groups, for example 'face_90'.
            page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
                fewer only at the end, never more; resume from _nextPage with the same page_size.
                Example: `100`.
            start: Optional UTC epoch seconds start, converted to milliseconds. Negative
                or millisecond-magnitude values add _warnings. Example: 1792972800.
            end: Optional UTC epoch seconds end, converted to milliseconds; omit both for
                all detections. The same magnitude warnings apply. Example: 1793059200.
            page: 1-based window number counted in units of page_size (default 1); without
                page_size, returns one native console page; resume from _nextPage with the same
                page_size. Example: `2`.
        """
        client, registry = deps_fn()
        return await recognition.list_recognition_detections(
            client, registry, host, type, group_id, page_size, start, end, page
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_thumbnail(
        host: str,
        thumbnail_id: str,
    ) -> Any:
        """Get a detection thumbnail crop. Returns MCP ImageContent plus image metadata.

        Returns MCP ImageContent plus text and structured metadata
        {image_base64, content_type, size_bytes}; content_type is the upstream
        Content-Type header (typically image/jpeg), not assumed, and null when the upstream
        sends none.

        Example call (get_thumbnail):
            {"host": "my-console", "thumbnail_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            thumbnail_id: Detection thumbnail id. Get it from list_recognition_detections
                (detections[].thumbnailId).
        """
        client, registry = deps_fn()
        return _image_result(await recognition.get_thumbnail(client, registry, host, thumbnail_id))

    return {
        "list_recognition_groups": list_recognition_groups,
        "get_recognition_group_counts": get_recognition_group_counts,
        "get_recognition_group_image": get_recognition_group_image,
        "list_recognition_detections": list_recognition_detections,
        "get_thumbnail": get_thumbnail,
    }
