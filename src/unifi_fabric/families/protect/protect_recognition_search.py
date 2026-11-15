"""Private Protect recognition-group writes, image recognition and detection search.

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

Every write is bound by ``UNIFI_WRITE_POLICY=deny`` and the Protect write opt-out
(``family:protect=deny``) before any request, and returns the client's
``dry-run policy`` preview ``{status, dryRun, sent: false, message, preview}`` (method, path, query,
body; nothing sent) when dry-run is on. Writes are sent once (no automatic retry).
"""

from __future__ import annotations

import base64
import binascii
import io
from typing import Any

import httpx
from pydantic import Field

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    upstream_error_value,
    validate_id,
    validate_selector,
)
from ...config import APIKeyConfig
from ...matching import same_id, with_upstream_id
from ...read_only import guard_action
from ...registry import Registry
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    with_warnings,
)
from ...shared_shapes._keys import context_value, with_context
from ...shared_shapes._pagination import (
    bare_page,
    collect_offset,
    mark_incomplete,
    validate_pagination,
    with_envelope,
)
from ...shared_shapes._payload import upstream_hint
from ...shared_shapes._results import (
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
from .schemas import (  # the family's shapes (family-owned layout)
    _SPEC,
    DEFAULT_FORM_FIELD,
    METADATA_ROUTES,
)

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
    ids = [
        upstream_error_value(g.get("id"))
        for g in groups
        if isinstance(g, dict) and isinstance(g.get("id"), str)
    ]
    partial = ""
    if context_value(listed, "incomplete"):
        partial = (
            " The group list was incomplete "
            f"({upstream_error_value(context_value(listed, 'incompleteReason'))})."
        )
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
            "this console has no search host for natural-language detection search, so "
            "search_detections cannot run here; list_recognition_detections reads a recognition "
            "group's detections without it.",
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
