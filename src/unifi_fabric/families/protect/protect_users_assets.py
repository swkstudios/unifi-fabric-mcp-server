# ruff: noqa: E501, E702
"""Private Protect user, asset, device-tag and ringtone tools.

Route choice: Protect's published Integration API does not offer these operations;
these use the newer Protect web application's ``/protect/api`` routes.  Bodies are
returned unchanged.  Password fields are registered in ``route_secrets`` and are
only redacted when the operator enables ``UNIFI_REDACT_SECRETS``.
"""

from __future__ import annotations

import base64
import binascii
import sys
from typing import Any

from ...client import (
    UniFiClient,
    is_dry_run_preview,
    path_segment,
    upstream_error_value,
    validate_id,
)
from ...matching import same_id, with_upstream_id
from ...read_only import guard_action
from ...registry import Registry
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import (
    deletion_result,
    requested_leaves_match,
    safe_read_after,
)
from .protect import (
    _as_list,
    _fields_to_send,
    _private,
    _require_mutations,
    _require_object,
    _resolve,
)

_impl = sys.modules[__name__]


def _merge(before: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Merge requested leaves without dropping unrequested siblings."""
    merged = dict(before)
    for name, value in changes.items():
        previous = before.get(name)
        merged[name] = (
            _merge(previous, value)
            if isinstance(previous, dict) and isinstance(value, dict)
            else value
        )
    return merged


def _result(response: Any, **metadata: Any) -> Any:
    """Preserve upstream responses while keeping verification metadata available.

    The metadata goes beside the upstream body through :func:`with_context`: an upstream
    key of the same name (``_verified``, ``_before`` ...) keeps its value, and the server's
    value goes in the ``_wrapperFields`` collision bucket.
    """
    if is_dry_run_preview(response):
        return response
    result = response if isinstance(response, dict) else {"response": response}
    return with_context(result, {f"_{k}": v for k, v in metadata.items()})


def _verified_result(
    response: Any, requested: dict[str, Any], before: Any, after: Any, error: str | None
) -> Any:
    if after is not None and not isinstance(after, dict):
        error = "Unexpected read-after shape: expected an object"
        after = None
    return _result(
        response,
        before=before,
        after=after,
        verified=requested_leaves_match(requested, after) if after is not None else None,
        readAfterError=error,
    )


def _segment(value: str, name: str) -> str:
    """Validate a private-route identifier before resolving a host or sending a request."""
    validate_id(value, name)
    return path_segment(value, name)


def _body(body: dict[str, Any] | None, tool: str) -> dict[str, Any]:
    """Reject empty and redacted write bodies before an upstream request."""
    if body is not None and not isinstance(body, dict):
        raise ValueError("body must be a JSON object")
    return _fields_to_send(dict(body or {}), tool)


async def _private_object(client: UniFiClient, key: Any, host_id: str, path: str) -> dict[str, Any]:
    return _require_object(await client.get(_private(host_id, path), key=key), f"GET {path}")


def _complete(body: Any) -> Any:
    if isinstance(body, dict) and (
        body.get("incomplete") is True or body.get("_incomplete") is True
    ):
        raise ValueError("Cannot select a Protect write target from an incomplete collection")
    return body


async def _bootstrap_record(
    client: UniFiClient, key: Any, host_id: str, family: str, item_id: str
) -> dict[str, Any]:
    bootstrap = _complete(await _private_object(client, key, host_id, "/bootstrap"))
    return _find(_as_list(bootstrap.get(family), f"Protect {family}"), item_id, f"Protect {family}")


async def _device_tags(client: UniFiClient, key: Any, host_id: str) -> list[Any]:
    return _as_list(
        _complete(await client.get(_private(host_id, "/device-tags"), key=key)),
        "Protect device tags",
    )


def _find(records: list[Any], item_id: str, kind: str) -> dict[str, Any]:
    """Resolve an id from a collection by the shared matching rule (:func:`same_id`),
    preserving the upstream spelling."""
    candidates = [r for r in records if isinstance(r, dict) and isinstance(r.get("id"), str)]
    found = next((r for r in candidates if same_id(item_id, r["id"])), None)
    if found is None:
        choices = sorted(str(upstream_error_value(r["id"])) for r in candidates)
        raise ValueError(f"Unknown {kind} {item_id!r}; valid choices: {choices}")
    return found


async def list_protect_device_tags(client: UniFiClient, registry: Registry, host: str) -> Any:
    """List Protect device tags (private ``GET /device-tags``)."""
    key, host_id = await _resolve(registry, host)
    return await client.get(_private(host_id, "/device-tags"), key=key)


async def create_protect_device_tag(
    client: UniFiClient, registry: Registry, host: str, tag: dict[str, Any]
) -> dict[str, Any]:
    """Create one Protect device tag with the web-app JSON body."""
    body = _body(tag, "create_protect_device_tag")
    _require_mutations()
    guard_action("POST")
    key, host_id = await _resolve(registry, host)
    return await client.post(_private(host_id, "/device-tags"), key=key, json=body)


async def update_protect_device_tag(
    client: UniFiClient, registry: Registry, host: str, tag_id: str, changes: dict[str, Any]
) -> dict[str, Any]:
    """Patch a known device tag and verify requested leaves by a collection read-back."""
    _segment(tag_id, "tag_id")
    body = _body(changes, "update_protect_device_tag")
    _require_mutations()
    guard_action("PATCH")
    key, host_id = await _resolve(registry, host)
    before = _find(await _device_tags(client, key, host_id), tag_id, "Protect device tag")
    body = with_upstream_id(body, "id", before["id"])
    if not client.dry_run and requested_leaves_match(body, before):
        return _result(before, status="noop", verified=True)
    response = await client.patch(
        _private(host_id, f"/device-tags/{_segment(str(before['id']), 'tag_id')}"),
        key=key,
        json=_merge(before, body),
    )
    if is_dry_run_preview(response):
        return response

    async def read_tag() -> dict[str, Any]:
        return _find(
            await _device_tags(client, key, host_id), str(before["id"]), "Protect device tag"
        )

    after, error = await safe_read_after(read_tag)
    return _verified_result(response, body, before, after, error)


async def delete_protect_device_tag(
    client: UniFiClient, registry: Registry, host: str, tag_id: str
) -> dict[str, Any]:
    """Delete a known Protect device tag. Consequence: tag assignments are removed."""
    _segment(tag_id, "tag_id")
    _require_mutations()
    guard_action("DELETE")
    key, host_id = await _resolve(registry, host)
    tag = _find(await _device_tags(client, key, host_id), tag_id, "Protect device tag")
    response = await client.delete(
        _private(host_id, f"/device-tags/{_segment(str(tag['id']), 'tag_id')}"), key=key
    )
    return deletion_result(f"Protect device tag {tag_id} deleted.", response)


async def create_protect_user_group(
    client: UniFiClient, registry: Registry, host: str, group: dict[str, Any]
) -> dict[str, Any]:
    body = _body(group, "create_protect_user_group")
    _require_mutations()
    guard_action("POST")
    key, host_id = await _resolve(registry, host)
    return await client.post(_private(host_id, "/groups"), key=key, json=body)


async def update_protect_user_group(
    client: UniFiClient, registry: Registry, host: str, group_id: str, changes: dict[str, Any]
) -> dict[str, Any]:
    group_id = _segment(group_id, "group_id")
    body = _body(changes, "update_protect_user_group")
    _require_mutations()
    guard_action("PATCH")
    key, host_id = await _resolve(registry, host)
    return await _patch_record(client, key, host_id, "groups", group_id, body)


async def delete_protect_user_group(
    client: UniFiClient, registry: Registry, host: str, group_id: str
) -> dict[str, Any]:
    group_id = _segment(group_id, "group_id")
    _require_mutations()
    guard_action("DELETE")
    key, host_id = await _resolve(registry, host)
    before = await _bootstrap_record(client, key, host_id, "groups", group_id)
    response = await client.delete(
        _private(host_id, f"/groups/{_segment(before['id'], 'group_id')}"), key=key
    )
    return deletion_result(f"Protect user group {group_id} deleted.", response)


async def _patch_record(
    client: UniFiClient,
    key: Any,
    host_id: str,
    family: str,
    item_id: str,
    body: dict[str, Any],
) -> Any:
    record = await _bootstrap_record(client, key, host_id, family, item_id)
    body = with_upstream_id(body, "id", record["id"])
    path = f"/{family}/{_segment(record['id'], 'id')}"
    before = record
    if not client.dry_run and requested_leaves_match(body, before):
        return _result(before, status="noop", verified=True)
    response = await client.patch(_private(host_id, path), key=key, json=body)
    if is_dry_run_preview(response):
        return response

    async def read_record() -> dict[str, Any]:
        return await _bootstrap_record(client, key, host_id, family, record["id"])

    after, error = await safe_read_after(read_record)
    return _verified_result(response, body, before, after, error)


async def _patch_user(
    client: UniFiClient,
    registry: Registry,
    host: str,
    user_id: str,
    changes: dict[str, Any],
) -> dict[str, Any]:
    user_id = _segment(user_id, "user_id")
    body = _body(changes, "update_protect_user")
    _require_mutations()
    guard_action("PATCH")
    key, host_id = await _resolve(registry, host)
    return await _patch_record(client, key, host_id, "users", user_id, body)


async def update_protect_user(
    client: UniFiClient, registry: Registry, host: str, user_id: str, changes: dict[str, Any]
) -> Any:
    return await _patch_user(client, registry, host, user_id, changes)


async def set_protect_notifications_muted(
    client: UniFiClient,
    registry: Registry,
    host: str,
    user_id: str,
    muted: bool,
    valid_until: int | None = None,
) -> dict[str, Any]:
    """Mute/unmute a user's Protect notifications; ``valid_until`` is the upstream epoch-ms value."""
    user_id = _segment(user_id, "user_id")
    if not isinstance(muted, bool):
        raise ValueError("muted must be a boolean")
    if valid_until is not None and (
        isinstance(valid_until, bool) or not isinstance(valid_until, int)
    ):
        raise ValueError("valid_until must be an epoch-milliseconds integer")
    _require_mutations()
    guard_action("POST" if muted else "DELETE")
    key, host_id = await _resolve(registry, host)
    user = await _bootstrap_record(client, key, host_id, "users", user_id)
    path = _private(host_id, f"/users/{_segment(user['id'], 'user_id')}/notifications/mute")
    before = user.get("notificationSnoozeSettings")
    body = {"validUntil": valid_until} if muted else {}
    response = await (
        client.post(path, key=key, json=_merge(before if isinstance(before, dict) else {}, body))
        if muted
        else client.delete(path, key=key)
    )
    if is_dry_run_preview(response):
        return response
    after_user, error = await safe_read_after(
        lambda: _bootstrap_record(client, key, host_id, "users", user["id"])
    )
    after = after_user.get("notificationSnoozeSettings") if after_user is not None else None
    if muted and valid_until is None:
        result = _result(
            response,
            before=before,
            after=after,
            verified=isinstance(after, dict) if error is None else None,
            readAfterError=error,
        )
    elif muted:
        result = _verified_result(response, body, before, after, error)
    else:
        result = _result(
            response,
            before=before,
            after=after,
            verified=after is None if after_user is not None else None,
            readAfterError=error,
        )
    return _result(
        result, warnings=["valid_until uses epoch milliseconds (for example 1893456000000)."]
    )


async def get_protect_device_password(client: UniFiClient, registry: Registry, host: str) -> Any:
    """Get the Protect device password; response is redacted only with the opt-in setting."""
    key, host_id = await _resolve(registry, host)
    return await client.get(_private(host_id, "/nvr/device-password"), key=key)


async def update_protect_device_password(
    client: UniFiClient, registry: Registry, host: str, device_password: str
) -> dict[str, Any]:
    """Set the NVR's device password. Consequence: device integrations may need updating."""
    if not isinstance(device_password, str):
        raise ValueError("device_password must be a string")
    _require_mutations()
    guard_action("PATCH")
    key, host_id = await _resolve(registry, host)
    return await client.patch(
        _private(host_id, "/nvr/device-password"),
        key=key,
        json={"devicePassword": device_password},
    )


async def get_protect_file(
    client: UniFiClient, registry: Registry, host: str, file_id: str, asset_id: str
) -> dict[str, Any]:
    """Download a Protect file as base64, preserving the upstream content type."""
    file_id = _segment(file_id, "file_id")
    asset_id = _segment(asset_id, "asset_id")
    key, host_id = await _resolve(registry, host)
    raw, content_type = await client.get_binary(
        _private(host_id, f"/files/{file_id}/{asset_id}"), key=key
    )
    return {
        "content_base64": base64.b64encode(raw).decode("ascii"),
        "content_type": content_type,
        "size_bytes": len(raw),
    }


async def delete_protect_file(
    client: UniFiClient,
    registry: Registry,
    host: str,
    file_id: str,
    asset_id: str,
    ignore_file_extension: bool = False,
) -> dict[str, Any]:
    """Delete a Protect file. Consequence: the selected uploaded asset is permanently removed."""
    file_id = _segment(file_id, "file_id")
    asset_id = _segment(asset_id, "asset_id")
    if not isinstance(ignore_file_extension, bool):
        raise ValueError("ignore_file_extension must be a boolean")
    _require_mutations()
    guard_action("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(
        _private(host_id, f"/files/{file_id}/{asset_id}"),
        key=key,
        params={"ignoreFileExtension": ignore_file_extension},
    )
    return deletion_result(f"Protect file {file_id} deleted.", response)


async def upload_ringtone(
    client: UniFiClient,
    registry: Registry,
    host: str,
    filename: str,
    content_base64: str,
    content_type: str = "audio/mpeg",
) -> dict[str, Any]:
    """Upload one ringtone using multipart form data."""
    if not isinstance(filename, str):
        raise ValueError("filename must be a string")
    if not isinstance(content_base64, str):
        raise ValueError("content_base64 must be a base64 string")
    try:
        raw = base64.b64decode(content_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("content_base64 must be valid base64") from exc
    if not isinstance(content_type, str):
        raise ValueError("content_type must be a string")
    _require_mutations()
    guard_action("POST")
    key, host_id = await _resolve(registry, host)
    return await client.post_multipart(
        _private(host_id, "/ringtones"), key=key, files={"file": (filename, raw, content_type)}
    )


async def get_ringtone(client: UniFiClient, registry: Registry, host: str, ringtone_id: str) -> Any:
    ringtone_id = _segment(ringtone_id, "ringtone_id")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/ringtones/{ringtone_id}")
    return await client.get(path, key=key)


async def delete_ringtone(
    client: UniFiClient, registry: Registry, host: str, ringtone_id: str
) -> Any:
    ringtone_id = _segment(ringtone_id, "ringtone_id")
    _require_mutations()
    guard_action("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(_private(host_id, f"/ringtones/{ringtone_id}"), key=key)
    return deletion_result(f"Ringtone {ringtone_id} deleted.", response)


async def delete_liveview(
    client: UniFiClient, registry: Registry, host: str, liveview_id: str
) -> dict[str, Any]:
    """Delete a Protect liveview. Consequence: its layout is permanently removed."""
    liveview_id = _segment(liveview_id, "liveview_id")
    _require_mutations()
    guard_action("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(_private(host_id, f"/liveviews/{liveview_id}"), key=key)
    return deletion_result(f"Liveview {liveview_id} deleted.", response)
