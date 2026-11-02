"""Private Protect recognition-group writes, image recognition and detection search (GS3 P07).

The published Protect Integration API has no recognition or detection-search surface, so
these tools call the Protect web application's private API through the connector proxy
(``/proxy/protect/api``). Every route is inventoried from the Protect 5.3.18 frontend
bundle (``tests/fixtures/private_api/inventory_protect_5.3.18.json``).

The read side of recognition (group lists, counts, reference crops, per-group detections
and detection thumbnails) already lives in :mod:`.recognition`; this module reuses it
(the group list drives every id lookup) and does not duplicate it.

Pass-through: upstream bodies are returned verbatim; anything this server adds is a
``_``-prefixed key. Request bodies the frontend builds dynamically (no literal key set in
the bundle) are free-form objects sent exactly as given: no key is invented. Binary bodies
go both ways as base64 plus a content type: uploads take ``file_content_base64`` and send
a multipart file part; binary responses come back as base64 with the upstream
Content-Type, never decoded as text.

Every write is bound by ``UNIFI_READ_ONLY`` and the Protect write opt-out
(``UNIFI_PROTECT_MUTATIONS_ENABLED=0``) before any request, and returns the client's
``UNIFI_DRY_RUN`` preview ``{status, dryRun, sent: false, message, preview}`` (method, path, query,
body; nothing sent) when dry-run is on. Writes are sent once (no automatic retry).
"""

from __future__ import annotations

import base64
import binascii
import io
from collections.abc import Callable
from typing import Any, Literal

import httpx
from fastmcp import FastMCP
from pydantic import Field

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    validate_id,
    validate_selector,
)
from ..config import APIKeyConfig
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
from ._keys import context_value, with_context
from ._pagination import (
    bare_page,
    collect_offset,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)
from ._payload import upstream_hint
from ._results import (
    deletion_result,
    requested_leaves_match,
    requested_leaves_verdict,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
from .protect import (
    _fields_to_send,
    _private,
    _require_mutations,
    _resolve,
    _resolve_camera_refs,
    upload_content_type,
)
from .recognition import list_recognition_groups

#: The three GET routes under ``detection-search`` (Protect 5.3.18 inventory), by section.
METADATA_ROUTES: dict[str, str] = {
    "search": "/detection-search",
    "labels": "/detection-search/labels",
    "progress": "/detection-search/progress",
}

#: The multipart field name the published Protect upload uses (protect-7.3.70
#: ``POST /v1/files/{fileType}``); the private routes' field name is not in the inventory.
DEFAULT_FORM_FIELD = "file"

#: Spec of the read-after comparison (no published schema: the private Protect API).
_SPEC = "protect-private-5.3.18"


# --------------------------------------------------------------------------- helpers


def _object(value: Any, what: str) -> dict[str, Any]:
    """A free-form argument object, refused only when it is not a JSON object."""
    if not isinstance(value, dict):
        raise ValueError(f"{what!r} must be a JSON object; got {type(value).__name__}.")
    return dict(value)


def _selector(value: Any, name: str) -> None:
    """``validate_selector`` that names the shape received for a non-string value
    (instead of reporting a number or object as "empty"). Makes no request."""
    if not isinstance(value, str):
        raise ValueError(
            f"{name!r} must be a string; got {describe_shape(value)} ({value!r}). Nothing was sent."
        )
    validate_selector(value, name)


def _body(value: Any, what: str) -> dict[str, Any]:
    """A free-form request body, refused only when it is not an object or carries no
    field (the server's empty-update guard); the fields are sent as given."""
    return _fields_to_send(_object(value, what), what)


def _upload_files(
    filename: str, file_content_base64: str, content_type: str | None, form_field: str
) -> dict[str, Any]:
    """The multipart ``files`` mapping of one base64 upload, checked before any request.

    The part's Content-Type is ``content_type`` when given, else the type of the filename
    extension (``protect.upload_content_type``). Whitespace (wrapped base64) is removed
    before a strict decode.
    """
    part_type = upload_content_type(filename, content_type)
    compact = "".join(str(file_content_base64).split())
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"file_content_base64 is not valid base64 ({exc}); pass the file's bytes "
            "base64-encoded (standard alphabet, padded; line breaks are allowed, a data: "
            "prefix is not)."
        ) from exc
    return {form_field: (filename, io.BytesIO(raw), part_type)}


def _media(raw: bytes, content_type: str | None, field: str) -> dict[str, Any]:
    """A binary body for transport: base64 text plus the upstream Content-Type as sent."""
    return {
        field: base64.b64encode(raw).decode("ascii"),
        "content_type": content_type,
        "size_bytes": len(raw),
    }


def _is_text(content_type: str | None, content: bytes) -> bool:
    """Whether a response body is text (JSON or ``text/*``) rather than binary media."""
    if content_type:
        media = content_type.split(";", 1)[0].strip().lower()
        return media.startswith("text/") or media == "application/json" or media.endswith("+json")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _media_or_body(resp: httpx.Response) -> Any:
    """A response that may be an image: base64 media when binary, else the decoded body."""
    content_type = resp.headers.get("content-type")
    if resp.status_code != 204 and resp.content and not _is_text(content_type, resp.content):
        return _media(bytes(resp.content), content_type, "image_base64")
    return decode_body(resp)


async def _post_files(
    client: UniFiClient, path: str, *, key: APIKeyConfig | None, files: dict[str, Any]
) -> Any:
    """POST a multipart upload once; a binary answer comes back as base64 media."""
    return _media_or_body(await client.request("POST", path, key=key, files=files))


async def _find_group(
    client: UniFiClient, registry: Registry, host: str, type: str, group_id: str
) -> dict[str, Any]:
    """The listed recognition group whose ``id`` is ``group_id``.

    Drains the group list with :func:`recognition.list_recognition_groups`. An unknown id
    fails listing the valid ids; when the drain was incomplete the reason is named.
    """
    listed = await list_recognition_groups(client, registry, host, type)
    groups = listed.get("groups") if isinstance(listed, dict) else None
    if not isinstance(groups, list):
        raise UniFiConnectionError(
            f"Unexpected response shape for the {type} recognition groups of {host!r}: "
            f"expected an object with a 'groups' array, got {describe_shape(listed)}"
        )
    for group in groups:
        if isinstance(group, dict) and same_id(group_id, group.get("id")):
            return group
    ids = [g.get("id") for g in groups if isinstance(g, dict) and isinstance(g.get("id"), str)]
    partial = ""
    if context_value(listed, "incomplete"):
        partial = f" The group list was incomplete ({context_value(listed, 'incompleteReason')})."
    raise ValueError(
        f"Recognition group {group_id!r} not found among the {type} groups of {host!r}; "
        f"valid: {ids}.{partial} No write was sent."
    )


# --------------------------------------------------------------------------- groups


async def _create_recognition_group(
    client: UniFiClient, registry: Registry, host: str, type: str, group: dict[str, Any]
) -> Any:
    validate_id(type, "type")
    body = _body(group, "group")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(_private(hid, f"/recognition/{type}/groups"), key=key, json=body)


async def _update_recognition_group(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    group_id: str,
    changes: dict[str, Any],
) -> Any:
    validate_id(type, "type")
    validate_id(group_id, "group_id")
    fields = _body(changes, "changes")
    _require_mutations()
    guard_action("PATCH")
    key, hid = await _resolve(registry, host)
    before = await _find_group(client, registry, host, type, group_id)
    target = before["id"]
    fields = with_upstream_id(fields, "id", target)
    if short_circuit_no_op(client, requested_leaves_match(fields, before, spec=_SPEC)):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    response = await client.patch(
        _private(hid, f"/recognition/{type}/groups/{target}"), key=key, json=fields
    )
    if is_dry_run_preview(response):
        return response

    async def read() -> dict[str, Any]:
        return await _find_group(client, registry, host, type, target)

    after, error = await safe_read_after(read)
    verified, error = requested_leaves_verdict(fields, after, error, spec=_SPEC)
    base: dict[str, Any] = dict(response) if isinstance(response, dict) else {"response": response}
    result = with_context(base, {"_before": before, "_after": after, "_verified": verified})
    return with_read_after_error(result, error, additive=True)


async def _delete_recognition_group(
    client: UniFiClient, registry: Registry, host: str, type: str, group_id: str
) -> Any:
    validate_id(type, "type")
    validate_id(group_id, "group_id")
    _require_mutations()
    guard_action("DELETE")
    key, hid = await _resolve(registry, host)
    target = (await _find_group(client, registry, host, type, group_id))["id"]
    response = await client.delete(_private(hid, f"/recognition/{type}/groups/{target}"), key=key)
    return deletion_result(f"Recognition group {group_id} deleted.", response)


def _id_list(value: Any, name: str, what: str) -> list[str]:
    """A non-empty list of id strings, each checked as a selector; makes no request."""
    if not isinstance(value, list):
        raise ValueError(
            f"{name!r} must be a list of {what} id strings; got {describe_shape(value)}. "
            "Nothing was sent."
        )
    if not value:
        raise ValueError(
            f"{name} must be a non-empty list: an empty list names no {what}; nothing was sent."
        )
    for index, ident in enumerate(value):
        _selector(ident, f"{name}[{index}]")
    return list(value)


async def _assign_detections_to_recognition_group(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    detection_ids: list[str] | None,
    group_id: str | None,
) -> Any:
    validate_id(type, "type")
    ids = _id_list(detection_ids, "detection_ids", "detection")
    _selector(group_id, "group_id")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    # The Protect web app (unifi-protect 5.3.48 package, UI 5.3.18 bundle) posts
    # {objectIds, groupId} from assignObjectsToSmartDetectObjectGroup.
    body = {"objectIds": ids, "groupId": group_id}
    return await client.post(_private(hid, f"/recognition/{type}/assign-group"), key=key, json=body)


async def _merge_recognition_groups(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    to_group_id: str | None,
    from_group_ids: list[str] | None,
) -> Any:
    validate_id(type, "type")
    _selector(to_group_id, "to_group_id")
    sources = _id_list(from_group_ids, "from_group_ids", "group to merge")
    if to_group_id in sources:
        raise ValueError(
            f"from_group_ids must not contain to_group_id {to_group_id!r}: a group cannot be "
            "merged into itself; nothing was sent."
        )
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    # The Protect web app (UI 5.3.18 bundle) merge dialog calls
    # mergeSmartDetectObjectGroups(type, {fromGroupIds, toGroupId}).
    body = {"fromGroupIds": sources, "toGroupId": to_group_id}
    return await client.post(_private(hid, f"/recognition/{type}/merge-group"), key=key, json=body)


async def _search_recognition_group_candidates(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    query_params: dict[str, Any] | None = None,
) -> Any:
    validate_id(type, "type")
    params = None if query_params is None else (_object(query_params, "query_params") or None)
    key, hid = await _resolve(registry, host)
    return await client.get(
        _private(hid, f"/recognition/{type}/groups/search-candidates"), key=key, params=params
    )


# --------------------------------------------------------------------------- images


async def _enhance_face_detection_image(
    client: UniFiClient, registry: Registry, host: str, detection_id: str
) -> Any:
    validate_id(detection_id, "detection_id")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    resp = await client.request(
        "POST", _private(hid, f"/recognition/face/detections/{detection_id}/image/enhance"), key=key
    )
    return _media_or_body(resp)


async def _set_recognition_group_image(
    client: UniFiClient,
    registry: Registry,
    host: str,
    type: str,
    group_id: str,
    filename: str,
    file_content_base64: str,
    content_type: str | None = None,
    form_field: str = DEFAULT_FORM_FIELD,
) -> Any:
    validate_id(type, "type")
    validate_id(group_id, "group_id")
    files = _upload_files(filename, file_content_base64, content_type, form_field)
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    target = (await _find_group(client, registry, host, type, group_id))["id"]
    return await _post_files(
        client, _private(hid, f"/recognition/{type}/groups/{target}/image"), key=key, files=files
    )


async def _recognize_image(
    client: UniFiClient,
    registry: Registry,
    host: str,
    filename: str,
    file_content_base64: str,
    content_type: str | None = None,
    form_field: str = DEFAULT_FORM_FIELD,
) -> Any:
    files = _upload_files(filename, file_content_base64, content_type, form_field)
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await _post_files(
        client, _private(hid, "/recognition/recognize-image"), key=key, files=files
    )


async def _bulk_upload_vehicle_groups(
    client: UniFiClient,
    registry: Registry,
    host: str,
    filename: str,
    file_content_base64: str,
    content_type: str | None = None,
    form_field: str = DEFAULT_FORM_FIELD,
) -> Any:
    files = _upload_files(filename, file_content_base64, content_type, form_field)
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await _post_files(
        client, _private(hid, "/recognition/vehicle/groups/batch-upload"), key=key, files=files
    )


async def _get_vehicle_group_upload_template(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    key, hid = await _resolve(registry, host)
    raw, content_type = await client.get_binary(
        _private(hid, "/recognition/vehicle/groups/template"), key=key
    )
    return _media(raw, content_type, "content_base64")


# --------------------------------------------------------------------------- detections


async def _search_detections(
    client: UniFiClient,
    registry: Registry,
    host: str,
    search_text: str,
    start: int | None = None,
    end: int | None = None,
    cameras: list[str] | None = None,
    min_similarity: float | None = None,
    order_by: str | None = None,
    ignore_time_filter_from_text: bool | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> Any:
    """GET /detection-nls; epoch-second windows become milliseconds with ``_warnings``."""
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    params: dict[str, Any] = {"searchText": search_text}
    if start is not None:
        params["start"] = seconds_to_millis(require_epoch_seconds(start, "start"))
    if end is not None:
        params["end"] = seconds_to_millis(require_epoch_seconds(end, "end"))
    if min_similarity is not None:
        params["minSimilarity"] = min_similarity
    if order_by is not None:
        params["orderBy"] = order_by
    if ignore_time_filter_from_text is not None:
        params["ignoreTimeFilterFromText"] = ignore_time_filter_from_text
    key, hid = await _resolve(registry, host)
    if cameras is not None:
        params["cameras"] = await _resolve_camera_refs(client, hid, cameras, key=key)
    try:
        collected = await collect_offset(
            client,
            _private(hid, "/detection-nls"),
            key=key,
            params=params,
            offset=offset,
            limit=limit,
            preserve_bare=True,
        )
    except UniFiConnectionError as exc:
        if exc.status != 404 or "searchHost" not in str(exc):
            raise
        upstream_hint(
            exc,
            "Check detection search service availability and configuration in Protect.",
        )
        raise
    if (bare := bare_page(collected)) is not None:
        return bare
    items = collected["items"]
    raw = collected.get("raw")
    if isinstance(raw, dict):
        result: dict[str, Any] = with_context(dict(raw), {"_count": len(items)})
    else:
        array_key = "data" if collected.get("array_key") == "data" else "result"
        result = with_envelope({array_key: items, "_count": len(items)}, collected)
    return with_warnings(mark_incomplete(result, collected), epoch_warnings(start=start, end=end))


async def _get_detection_search_metadata(
    client: UniFiClient, registry: Registry, host: str, section: str = "labels"
) -> Any:
    route = METADATA_ROUTES.get(section) if isinstance(section, str) else None
    if route is None:
        raise ValueError(
            f"Invalid section {section!r} for detection search metadata; "
            f"expected one of {sorted(METADATA_ROUTES)}."
        )
    key, hid = await _resolve(registry, host)
    return await client.get(_private(hid, route), key=key)


async def _get_detection_statistics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    start: int | None = None,
    end: int | None = None,
    period: int | str | None = None,
    group_id: str | None = None,
) -> Any:
    """GET /statistics/detections; epoch-second windows become milliseconds."""
    params: dict[str, Any] = {}
    if start is not None:
        params["start"] = seconds_to_millis(require_epoch_seconds(start, "start"))
    if end is not None:
        params["end"] = seconds_to_millis(require_epoch_seconds(end, "end"))
    if period is not None:
        if isinstance(period, bool) or not isinstance(period, (int, str)):
            raise ValueError(f"period must be an integer or string, got {period!r}")
        params["period"] = seconds_to_millis(period) if isinstance(period, int) else period
    if group_id is not None:
        _selector(group_id, "group_id")
        params["groupId"] = group_id
    key, hid = await _resolve(registry, host)
    try:
        body = await client.get(
            _private(hid, "/statistics/detections"), key=key, params=params or None
        )
    except UniFiConnectionError as exc:
        if exc.status != 400 or all(x is not None for x in (start, end, period)):
            raise
        upstream_hint(
            exc,
            "Statistics requires start, end and period; supply missing arguments.",
        )
        raise
    return with_warnings(body, epoch_warnings(start=start, end=end))


async def _report_ai_false_positive(
    client: UniFiClient,
    registry: Registry,
    host: str,
    event_id: str,
    reported_thumbnails: list[str | dict[str, Any]],
) -> Any:
    _selector(event_id, "event_id")
    if isinstance(reported_thumbnails, list) and not reported_thumbnails:
        raise ValueError(
            "reported_thumbnails must be a non-empty list: an empty list names no thumbnail "
            "to report as a false positive; nothing was sent."
        )
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    body = {"eventId": event_id, "reportedThumbnails": list(reported_thumbnails)}
    return await client.post(_private(hid, "/report/ai-false-positive"), key=key, json=body)


async def _hide_face_detection_enhanced_image(
    client: UniFiClient, registry: Registry, host: str, detection_id: str, hide: bool
) -> Any:
    validate_id(detection_id, "detection_id")
    if not isinstance(hide, bool):
        raise ValueError(
            f"'hide' must be a boolean (true to hide, false to show); got {describe_shape(hide)}. "
            "Nothing was sent."
        )
    _require_mutations()
    guard_action("PATCH")
    key, hid = await _resolve(registry, host)
    return await client.patch(
        _private(hid, f"/recognition/face/detections/{detection_id}/enhanced-image"),
        key=key,
        json={"hide": hide},
    )


async def _apply_recognized_image(
    client: UniFiClient, registry: Registry, host: str, apply: dict[str, Any]
) -> Any:
    body = _body(apply, "apply")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(
        _private(hid, "/recognition/recognize-image/apply"), key=key, json=body
    )


async def _create_recognition_object_group(
    client: UniFiClient, registry: Registry, host: str, object_ids: list[str]
) -> Any:
    if not isinstance(object_ids, list):
        raise ValueError(
            f"'object_ids' must be a list of object id strings; got {describe_shape(object_ids)}. "
            "Nothing was sent."
        )
    if not object_ids:
        raise ValueError(
            "object_ids must be a non-empty list: an empty list names no recognized object "
            "to group; nothing was sent."
        )
    for index, object_id in enumerate(object_ids):
        _selector(object_id, f"object_ids[{index}]")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(
        _private(hid, "/recognition/objects/groups"), key=key, json={"objectIds": list(object_ids)}
    )


# --------------------------------------------------------------------------- registration


_NATIVE_BODY_UNSET = object()
# A factory omits a JSON default and preserves the legacy non-null object schema.
_NATIVE_BODY_DEFAULT: Any = Field(default_factory=lambda: _NATIVE_BODY_UNSET)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 18 P07 and NL-1 tools."""

    @mcp.tool(annotations=WRITE)
    async def create_recognition_group(host: str, type: str, group: dict[str, Any]) -> Any:
        """Create a Protect recognition group (an enrolled face or vehicle).

        POST protect/api/recognition/{type}/groups (private Protect API) with group sent
        verbatim; the upstream response is returned unchanged. The frontend builds this
        body dynamically, so no key is required here; the upstream judges it. An empty
        object is refused before any request. Under UNIFI_DRY_RUN it returns a dry-run
        preview. Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Returns the upstream response unchanged (an object, an array or null); under
        UNIFI_DRY_RUN the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular, e.g. "face" or "vehicle".
            group: Native group object, e.g. {"name": "Delivery van"}. Free-form object.
        """
        client, registry = deps_fn()
        return await _create_recognition_group(client, registry, host, type, group)

    @mcp.tool(annotations=WRITE)
    async def update_recognition_group(
        host: str, type: str, group_id: str, changes: dict[str, Any]
    ) -> Any:
        """Change fields of one Protect recognition group (read, write, then verify).

        Drains list_recognition_groups to find group_id (an unknown id fails listing the
        valid ids, before any write). If every requested leaf already matches it returns
        {status: "noop"} without writing; otherwise sends changes with PATCH
        protect/api/recognition/{type}/groups/{group_id}. The upstream response is
        returned unchanged plus _before, _after and _verified (each requested leaf re-read,
        type strict; _readAfterError when the re-read failed). An empty changes object is
        refused before any request. Under UNIFI_DRY_RUN it returns a dry-run preview.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Returns the upstream response plus _before, _after, _verified and
        _readAfterError (a non-object response sits under response); {status: "noop",
        reason, resource} when nothing changes; under UNIFI_DRY_RUN the preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular, e.g. "face" or "vehicle".
            group_id: Group id from list_recognition_groups, e.g. "face_90".
            changes: Fields to change as on the group record, e.g. {"name": "Visitors"}.
                Free-form object.
        """
        client, registry = deps_fn()
        return await _update_recognition_group(client, registry, host, type, group_id, changes)

    @mcp.tool(annotations=WRITE)
    async def delete_recognition_group(host: str, type: str, group_id: str) -> Any:
        """Delete one Protect recognition group.

        Drains list_recognition_groups to confirm group_id (an unknown id fails listing the valid
        ids, before any write), then sends DELETE protect/api/recognition/{type}/groups/{group_id}.
        Under UNIFI_DRY_RUN it returns {status: "dry_run", deleted: false, message, response} where
        response is the dry-run preview. Honours UNIFI_READ_ONLY and
        UNIFI_PROTECT_MUTATIONS_ENABLED=0. Consequence: the enrolled face or vehicle and its name
        are removed from the console; there is no undo. Returns {deleted, message, response}:
        deleted is true, message summarizes the delete, and response is the upstream body verbatim
        (decoded JSON, raw text, or null when the body is empty). The dry-run preview under response
        is {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular, e.g. "face" or "vehicle".
            group_id: Group id from list_recognition_groups, e.g. "face_90".
        """
        client, registry = deps_fn()
        return await _delete_recognition_group(client, registry, host, type, group_id)

    @mcp.tool(annotations=WRITE)
    async def assign_detections_to_recognition_group(
        host: str,
        type: str,
        detection_ids: list[str] | None = None,
        group_id: str | None = None,
        assignment: dict[str, Any] = _NATIVE_BODY_DEFAULT,
    ) -> Any:
        """Assign recognition detections to a recognition group.

        POST protect/api/recognition/{type}/assign-group with the body the Protect web app
        sends, {"objectIds": detection_ids, "groupId": group_id}; the upstream response is
        returned unchanged. An empty or non-list detection_ids, or an empty group_id, is
        refused before any request. Under UNIFI_DRY_RUN it returns a dry-run preview.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the detections move out of the group that held them and are
        re-labelled as the target group on the console.
        Returns the upstream response unchanged (an object, an array or null); under
        UNIFI_DRY_RUN the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular, e.g. "face" or "vehicle".
            detection_ids: Shape: string[]. Ids of the detections to move, from
                list_recognition_detections, e.g. ["66f1a2b3c4d5e6f7a8b9c0d5"].
            group_id: Id of the group that receives them, from list_recognition_groups,
                e.g. "face_90".
            assignment: Legacy native body sent verbatim when supplied instead of the typed
                arguments; it takes precedence, so detection_ids and group_id are then ignored.
                Free-form object. Shape: {objectIds:string[],groupId:string}.
        """
        client, registry = deps_fn()
        if assignment is not _NATIVE_BODY_UNSET:
            validate_id(type, "type")
            body = _body(assignment, "assignment")
            _require_mutations()
            guard_action("POST")
            key, hid = await _resolve(registry, host)
            return await client.post(
                _private(hid, f"/recognition/{type}/assign-group"), key=key, json=body
            )
        return await _assign_detections_to_recognition_group(
            client, registry, host, type, detection_ids, group_id
        )

    @mcp.tool(annotations=WRITE)
    async def enhance_face_detection_image(host: str, detection_id: str) -> Any:
        """Ask Protect to enhance the image of one face detection.

        POST protect/api/recognition/face/detections/{detection_id}/image/enhance with no
        body. A JSON or text response is returned unchanged; an image response is returned
        as {image_base64, content_type, size_bytes} with the upstream Content-Type. Under
        UNIFI_DRY_RUN it returns a dry-run preview. Honours UNIFI_READ_ONLY and
        UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the console processes the detection image and stores the enhanced
        image for that detection.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under UNIFI_DRY_RUN the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            detection_id: Detection id from list_recognition_detections,
                e.g. "66f1a2b3c4d5e6f7a8b9c0d5".
        """
        client, registry = deps_fn()
        return await _enhance_face_detection_image(client, registry, host, detection_id)

    @mcp.tool(annotations=READ_ONLY)
    async def search_recognition_group_candidates(
        host: str, type: str, query_params: dict[str, Any] | None = None
    ) -> Any:
        """Search for recognition groups that are candidates for a match or merge.

        GET protect/api/recognition/{type}/groups/search-candidates. The inventory records
        no fixed query keys, so query_params is a free-form object forwarded as query parameters
        exactly as given (omit it to send none). The upstream body is returned unchanged.
        Returns the upstream body unchanged (an object or an array).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular, e.g. "face" or "vehicle".
            query_params: Free-form query parameters, e.g. {"groupId": "face_90"}. Omit for none.
        """
        client, registry = deps_fn()
        return await _search_recognition_group_candidates(
            client, registry, host, type, query_params
        )

    @mcp.tool(annotations=WRITE)
    async def set_recognition_group_image(
        host: str,
        type: str,
        group_id: str,
        filename: str,
        file_content_base64: str,
        content_type: str | None = None,
        form_field: str = DEFAULT_FORM_FIELD,
    ) -> Any:
        """Upload a new reference image for one Protect recognition group.

        Drains list_recognition_groups to confirm group_id (an unknown id fails listing
        the valid ids, before any write), then sends the decoded image as a multipart file
        part with POST protect/api/recognition/{type}/groups/{group_id}/image. The upstream
        response is returned unchanged. Invalid base64 is refused before any request. Under
        UNIFI_DRY_RUN it returns a dry-run preview (part name, filename, type and size).
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the group's reference image on the console is replaced.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under UNIFI_DRY_RUN the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular, e.g. "face" or "vehicle".
            group_id: Group id from list_recognition_groups, e.g. "face_90".
            filename: File name sent with the part, e.g. "reference.jpg".
            file_content_base64: The image bytes, base64-encoded, e.g. "iVBORw0KGgo=".
            content_type: Part MIME type, e.g. "image/jpeg". Omit to derive it from the
                filename extension.
            form_field: Multipart field name, default "file" (the published Protect
                upload's name), e.g. "file".
        """
        client, registry = deps_fn()
        return await _set_recognition_group_image(
            client,
            registry,
            host,
            type,
            group_id,
            filename,
            file_content_base64,
            content_type,
            form_field,
        )

    @mcp.tool(annotations=WRITE)
    async def merge_recognition_groups(
        host: str,
        type: str,
        to_group_id: str | None = None,
        from_group_ids: list[str] | None = None,
        merge: dict[str, Any] = _NATIVE_BODY_DEFAULT,
    ) -> Any:
        """Merge Protect recognition groups into one.

        POST protect/api/recognition/{type}/merge-group with the body the Protect web app
        sends, {"fromGroupIds": from_group_ids, "toGroupId": to_group_id}; the upstream
        response is returned unchanged. An empty or non-list from_group_ids, an empty
        to_group_id, or a from_group_ids list that names to_group_id is refused before any
        request. Under UNIFI_DRY_RUN it returns a dry-run preview.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the groups in from_group_ids are folded into to_group_id with their
        detections; there is no unmerge.
        Returns the upstream response unchanged (an object, an array or null); under
        UNIFI_DRY_RUN the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular, e.g. "face".
            to_group_id: Id of the group that is kept, from list_recognition_groups,
                e.g. "face_90".
            from_group_ids: Shape: string[]. Ids of the groups merged into it, e.g. ["face_91"].
            merge: Legacy native body sent verbatim when supplied instead of the typed
                arguments; it takes precedence, so to_group_id and from_group_ids are then ignored.
                Free-form object. Shape: {fromGroupIds:string[],toGroupId:string}.
        """
        client, registry = deps_fn()
        if merge is not _NATIVE_BODY_UNSET:
            validate_id(type, "type")
            body = _body(merge, "merge")
            _require_mutations()
            guard_action("POST")
            key, hid = await _resolve(registry, host)
            return await client.post(
                _private(hid, f"/recognition/{type}/merge-group"), key=key, json=body
            )
        return await _merge_recognition_groups(
            client, registry, host, type, to_group_id, from_group_ids
        )

    @mcp.tool(annotations=WRITE)
    async def recognize_image(
        host: str,
        filename: str,
        file_content_base64: str,
        content_type: str | None = None,
        form_field: str = DEFAULT_FORM_FIELD,
    ) -> Any:
        """Run Protect recognition on an uploaded image.

        Sends the decoded image as a multipart file part with POST
        protect/api/recognition/recognize-image; the upstream response (what Protect
        recognised) is returned unchanged. This is a POST, so it is classed as a write.
        Invalid base64 is refused before any request. Under UNIFI_DRY_RUN it returns a
        dry-run preview (part name, filename, type and size).
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the image is uploaded to and processed by the console.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under UNIFI_DRY_RUN the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            filename: File name sent with the part, e.g. "photo.jpg".
            file_content_base64: The image bytes, base64-encoded, e.g. "iVBORw0KGgo=".
            content_type: Part MIME type, e.g. "image/jpeg". Omit to derive it from the
                filename extension.
            form_field: Multipart field name, default "file" (the published Protect
                upload's name), e.g. "file".
        """
        client, registry = deps_fn()
        return await _recognize_image(
            client, registry, host, filename, file_content_base64, content_type, form_field
        )

    @mcp.tool(annotations=WRITE)
    async def bulk_upload_vehicle_groups(
        host: str,
        filename: str,
        file_content_base64: str,
        content_type: str | None = None,
        form_field: str = DEFAULT_FORM_FIELD,
    ) -> Any:
        """Create vehicle recognition groups in bulk from a filled-in upload file.

        Sends the decoded file (the template from get_vehicle_group_upload_template, filled
        in) as a multipart file part with POST
        protect/api/recognition/vehicle/groups/batch-upload; the upstream response is
        returned unchanged. Invalid base64 is refused before any request. Under
        UNIFI_DRY_RUN it returns a dry-run preview (part name, filename, type and size).
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: every vehicle row in the file is created as a recognition group.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under UNIFI_DRY_RUN the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            filename: File name sent with the part, e.g. "vehicles.csv".
            file_content_base64: The file bytes, base64-encoded, e.g. "cGxhdGUsbmFtZQo=".
            content_type: Part MIME type, e.g. "text/csv". Required when the filename
                extension is not an image or audio type.
            form_field: Multipart field name, default "file" (the published Protect
                upload's name), e.g. "file".
        """
        client, registry = deps_fn()
        return await _bulk_upload_vehicle_groups(
            client, registry, host, filename, file_content_base64, content_type, form_field
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_vehicle_group_upload_template(host: str) -> Any:
        """Download the vehicle recognition group bulk-upload template.

        GET protect/api/recognition/vehicle/groups/template (the link the Protect web
        application offers for download). The complete file is returned as
        {content_base64, content_type, size_bytes} with the upstream Content-Type; fill it
        in and pass it to bulk_upload_vehicle_groups.
        Returns {content_base64, content_type, size_bytes}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await _get_vehicle_group_upload_template(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def search_detections(
        host: str,
        search_text: str,
        start: int | None = None,
        end: int | None = None,
        cameras: list[str] | None = None,
        min_similarity: float | None = None,
        order_by: str | None = None,
        ignore_time_filter_from_text: bool | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Any:
        """Search Protect detections with a natural-language description.

        GET protect/api/detection-nls with searchText and only the filters given. start and
        end are epoch SECONDS, sent as milliseconds (_warnings flags values that look like
        milliseconds or are negative). cameras takes camera ids or names (names resolve to
        ids; an unknown name fails listing the cameras). Without limit/offset every page is
        drained (incomplete=true with the reason if a drain stops short); with either, that
        one page is returned in the upstream shape.
        Returns a drained list as {data or result, _count} plus the first page's other
        fields, incomplete and incompleteReason when it stopped short, and _warnings; an
        explicit page as the upstream page plus _count and _warnings (a bare-array page
        as that array).

        A searchHost 404 indicates detection search service availability or configuration;
        check Protect.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            search_text: What to look for, e.g. "white van in the driveway".
            start: Window start, epoch seconds, e.g. 1718000000.
            end: Window end, epoch seconds, e.g. 1718003600.
            cameras: Camera ids or names, e.g. ["66f1a2b3c4d5e6f7a8b9c0d3"].
                Shape: string[]
            min_similarity: minSimilarity threshold sent as given, e.g. 0.25.
            order_by: orderBy value sent as given, e.g. "similarity".
            ignore_time_filter_from_text: Sent as ignoreTimeFilterFromText, e.g. true.
            limit: Page size for one explicit page. Example: `50`.
            offset: Start position for one explicit page. Example: `25`.
        """
        client, registry = deps_fn()
        return await _search_detections(
            client,
            registry,
            host,
            search_text,
            start,
            end,
            cameras,
            min_similarity,
            order_by,
            ignore_time_filter_from_text,
            limit,
            offset,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_detection_search_metadata(
        host: str, section: Literal["search", "labels", "progress"] = "labels"
    ) -> Any:
        """Read Protect detection-search metadata.

        The section selects the GET route: "search" -> protect/api/detection-search, "labels" ->
        protect/api/detection-search/labels (the searchable labels), "progress" ->
        protect/api/detection-search/progress (indexing progress). The upstream body is
        returned unchanged.
        Returns the upstream body unchanged (an object or an array).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            section: Which detection-search route to read, e.g. "progress".
        """
        client, registry = deps_fn()
        return await _get_detection_search_metadata(client, registry, host, section)

    @mcp.tool(annotations=READ_ONLY)
    async def get_detection_statistics(
        host: str,
        start: int | None = None,
        end: int | None = None,
        period: int | str | None = None,
        group_id: str | None = None,
    ) -> Any:
        """Read Protect detection statistics, per camera, in time buckets.

        Protect 7.3 requires start, end and period; an upstream rejection adds a hint.
        GET protect/api/statistics/detections. start and end are epoch SECONDS and period
        is an integer bucket width in SECONDS (sent as milliseconds) or a string sent
        unchanged (_warnings flags start/end values that look like milliseconds or are negative).
        group_id is forwarded as given; the upstream judges it. The upstream body is
        returned unchanged.
        Returns the upstream body unchanged (an object or an array) plus _warnings for
        suspect epoch values on an object.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            start: Window start, epoch seconds, e.g. 1718000000.
            end: Window end, epoch seconds, e.g. 1718086400.
            period: Integer bucket width in seconds, or a string forwarded unchanged; e.g. 900.
            group_id: Recognition group id sent as groupId, e.g. "face_90".
        """
        client, registry = deps_fn()
        return await _get_detection_statistics(client, registry, host, start, end, period, group_id)

    @mcp.tool(annotations=WRITE)
    async def report_ai_false_positive(
        host: str, event_id: str, reported_thumbnails: list[str | dict[str, Any]]
    ) -> Any:
        """Report a Protect AI detection as a false positive.

        POST protect/api/report/ai-false-positive with {"eventId": event_id,
        "reportedThumbnails": reported_thumbnails} (the keys the frontend sends); the
        upstream response is returned unchanged. Under UNIFI_DRY_RUN it returns a dry-run
        preview. Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the report and the named thumbnails are submitted from the console.
        Returns the upstream response unchanged (an object, an array or null); under
        UNIFI_DRY_RUN the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            event_id: Event id from list_protect_events, e.g. "66f1a2b3c4d5e6f7a8b9c0d6".
            reported_thumbnails: Non-empty list of thumbnails of the event being reported, sent
                as given (an empty list fails before any request), for example
                ["e-66f1a2b3c4d5e6f7a8b9c0d6"].
                Shape: (string|object)[]; keys the server reads: none, each entry is sent as given
        """
        client, registry = deps_fn()
        return await _report_ai_false_positive(
            client, registry, host, event_id, reported_thumbnails
        )

    @mcp.tool(annotations=WRITE)
    async def hide_face_detection_enhanced_image(host: str, detection_id: str, hide: bool) -> Any:
        """Hide or show the enhanced image of one face detection in Protect.

        PATCH protect/api/recognition/face/detections/{detection_id}/enhanced-image
        (private Protect API) with the body {"hide": hide}. The upstream response is
        returned unchanged. hide is required (no default); pass hide=false to show the
        enhanced image again. Under
        UNIFI_DRY_RUN it returns a dry-run preview. Honours UNIFI_READ_ONLY and
        UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the console stops (or resumes) displaying the enhanced image of that
        detection in the Protect app; the detection itself is kept.
        Returns the upstream response unchanged (an object, an array or null); under
        UNIFI_DRY_RUN the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            detection_id: Face detection id from list_recognition_detections,
                e.g. "66f1a2b3c4d5e6f7a8b9c0d5".
            hide: Required. true to hide the enhanced image, false to show it again,
                e.g. true.
        """
        client, registry = deps_fn()
        return await _hide_face_detection_enhanced_image(client, registry, host, detection_id, hide)

    @mcp.tool(annotations=WRITE)
    async def apply_recognized_image(host: str, apply: dict[str, Any]) -> Any:
        """Apply the result of a recognize_image run to Protect's recognition data.

        POST protect/api/recognition/recognize-image/apply (private Protect API) with
        apply as the JSON body; the upstream response is returned unchanged. The
        frontend builds this body dynamically and the key set is not documented, so no
        key is required here and the upstream judges it. Build it from the answer of
        recognize_image. Fields are sent as given except: keys starting with "_" and
        values the server masks as redacted are dropped (reported on the result), and a
        body left with no field to send (empty, or only empty objects) is refused
        before any request with "No fields provided" (the message
        reads "apply 'settings'"). Nothing else is added, removed or rewritten. Under
        UNIFI_DRY_RUN it returns a dry-run preview. Honours UNIFI_READ_ONLY and
        UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the console stores the recognition outcome of the uploaded image
        (for example adding it to a recognition group).
        Returns the upstream response unchanged (an object, an array or null); under
        UNIFI_DRY_RUN the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            apply: Free-form JSON object built from the recognize_image response; its
                keys are not documented, so none are prescribed here. Sent as given
                apart from the dropped fields described above,
                e.g. `{"recognize_image response key": "value"}`.
        """
        client, registry = deps_fn()
        return await _apply_recognized_image(client, registry, host, apply)

    @mcp.tool(annotations=WRITE)
    async def create_recognition_object_group(host: str, object_ids: list[str]) -> Any:
        """Create a Protect object recognition group from recognized object ids.

        POST protect/api/recognition/objects/groups (private Protect API) with the body
        {"objectIds": object_ids}. The upstream response (the new group) is returned
        unchanged. An empty list is refused before any request. Under UNIFI_DRY_RUN it
        returns a dry-run preview. Honours UNIFI_READ_ONLY and
        UNIFI_PROTECT_MUTATIONS_ENABLED=0.
        Consequence: the console creates a new object recognition group holding those
        recognized objects.
        Returns the upstream response unchanged (an object, an array or null); under
        UNIFI_DRY_RUN the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            object_ids: Ids of the recognized objects to group, as the console reports
                them, e.g. ["66f1a2b3c4d5e6f7a8b9c0d5", "66f1a2b3c4d5e6f7a8b9c0d6"].
        """
        client, registry = deps_fn()
        return await _create_recognition_object_group(client, registry, host, object_ids)
