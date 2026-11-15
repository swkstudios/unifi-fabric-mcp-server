"""Private Protect automation, backup and cloud archive tools.

The published Integration API lacks these routes, so this module calls the Protect web
application's private API (routes inventoried from the Protect 5.3.18 frontend) through
the connector proxy. Upstream bodies pass through verbatim; additions are ``_``-prefixed.

Every write is bound by ``UNIFI_WRITE_POLICY=deny`` and the Protect write opt-out
(``family:protect=deny``) before any request, and returns the client's
``dry-run policy`` preview ``{status: "dry_run", dryRun, sent: false, message, preview: {method,
path, params, body}}`` (nothing sent) when dry-run is on.
Restores are never refused or gated by this module: the upstream judges them.
"""

from __future__ import annotations

from typing import Any

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    is_dry_run_preview,
    keep_stored_secrets,
    masked_read,
    unmasked_read,
    upstream_error_value,
    validate_id,
    validate_selector,
)
from ...matching import same_id, with_upstream_id
from ...read_only import guard_action
from ...registry import Registry
from ...shared_shapes._keys import with_context
from ...shared_shapes._payload import upstream_hint
from ...shared_shapes._results import (
    deletion_readback_ids,
    deletion_result,
    requested_leaves_verdict,
    safe_read_after,
    with_read_after_error,
)
from .protect import (
    _fields_to_send,
    _private,
    _require_mutations,
    _resolve,
)


def _body(value: dict[str, Any], what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object.")
    return _fields_to_send(dict(value), what)


def _merge(current: Any, update: Any) -> Any:
    if isinstance(current, dict) and isinstance(update, dict):
        return {
            **current,
            **{key: _merge(current.get(key), value) for key, value in update.items()},
        }
    return update


def _text(*values: str) -> None:
    if not all(isinstance(value, str) for value in values):
        raise ValueError("Text arguments must be strings.")


async def _list(client: UniFiClient, key: Any, host_id: str, route: str) -> Any:
    """One GET of a Protect list route, returned verbatim.

    The Protect 5.3.18 frontend calls ``/automations`` and ``/backups`` with no query
    parameters, so there is no page parameter to drain with and none is invented.
    """
    return await client.get(_private(host_id, route), key=key)


def _rows(response: Any, kind: str) -> list[Any]:
    """The records of a list response: a bare array, or a ``data``/``result`` array."""
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        if response.get("incomplete") or response.get("_incomplete"):
            raise ValueError(f"Incomplete Protect {kind} list; no write target can be resolved.")
        for field in ("data", "result"):
            if isinstance(response.get(field), list):
                return list(response[field])
    raise ValueError(
        f"Unexpected response shape: expected an array or an object with a data array "
        f"for Protect {kind}s, got {type(response).__name__}."
    )


async def _known(
    client: UniFiClient, key: Any, host_id: str, route: str, ident: str, kind: str
) -> dict[str, Any]:
    """The listed record whose ``id`` is ``ident``; an unknown id lists the valid ids."""
    rows = _rows(await _list(client, key, host_id, route), kind)
    matches = [row for row in rows if isinstance(row, dict) and same_id(ident, row.get("id"))]
    if len(matches) != 1:
        choices = [
            upstream_error_value(row.get("id"))
            for row in rows
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        ]
        raise ValueError(f"Unknown {kind} {ident!r}; valid choices: {choices}. No write was sent.")
    return matches[0]


# --------------------------------------------------------------------------- automations


async def _list_protect_automations(client: UniFiClient, registry: Registry, host: str) -> Any:
    key, hid = await _resolve(registry, host)
    return await _list(client, key, hid, "/automations")


async def _create_protect_automation(
    client: UniFiClient, registry: Registry, host: str, automation: dict[str, Any]
) -> Any:
    body = _body(automation, "automation")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(_private(hid, "/automations"), key=key, json=body)


async def _update_protect_automation(
    client: UniFiClient, registry: Registry, host: str, automation_id: str, changes: dict[str, Any]
) -> Any:
    patch = _body(changes, "automation changes")
    validate_id(automation_id, "automation_id")
    _require_mutations()
    guard_action("PATCH")
    key, hid = await _resolve(registry, host)
    with unmasked_read():  # webhook headers/auth are written back as stored
        before = await _known(client, key, hid, "/automations", automation_id, "automation")
    automation_id = before["id"]
    patch = with_upstream_id(patch, "id", automation_id)
    response = await client.patch(
        _private(hid, f"/automations/{automation_id}"),
        key=key,
        json=keep_stored_secrets(client, _merge(before, patch), before, changes),
    )
    if is_dry_run_preview(response):
        return response
    if not isinstance(response, dict):
        # Keep a non-object write body whole so the verdict keys are never dropped.
        response = {"response": response}

    async def read() -> dict[str, Any]:
        return await _known(client, key, hid, "/automations", automation_id, "automation")

    after, error = await safe_read_after(read)
    verified, error = requested_leaves_verdict(patch, after, error, spec="protect-private")
    # Beside the upstream body, never over it: a colliding upstream key keeps its value.
    # Unmasked for the write only; the caller sees it as a read shows it.
    shown = masked_read(client, _private(hid, "/automations"), before)
    result = with_context(response, {"_before": shown, "_after": after, "_verified": verified})
    return with_read_after_error(result, error, additive=True)


async def _delete_protect_automation(
    client: UniFiClient, registry: Registry, host: str, automation_id: str
) -> Any:
    validate_id(automation_id, "automation_id")
    _require_mutations()
    guard_action("DELETE")
    key, hid = await _resolve(registry, host)
    before = await _known(client, key, hid, "/automations", automation_id, "automation")
    automation_id = before["id"]
    response = await client.delete(_private(hid, f"/automations/{automation_id}"), key=key)
    return deletion_result(f"Automation {automation_id} deleted.", response)


async def _get_protect_automation_history(
    client: UniFiClient, registry: Registry, host: str, automation_id: str, limit: int | None = None
) -> Any:
    validate_id(automation_id, "automation_id")
    key, hid = await _resolve(registry, host)
    return await client.get(
        _private(hid, f"/automations/{automation_id}/history"),
        key=key,
        params=None if limit is None else {"limit": limit},
    )


async def _reset_protect_automations(client: UniFiClient, registry: Registry, host: str) -> Any:
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(_private(hid, "/automations/reset"), key=key)


async def _set_protect_notification_receivers(
    client: UniFiClient, registry: Registry, host: str, receivers: dict[str, Any]
) -> Any:
    body = _body(receivers, "notification receivers")
    _require_mutations()
    guard_action("PATCH")
    key, hid = await _resolve(registry, host)
    return await client.patch(
        _private(hid, "/automations/system-notifications/receivers"), key=key, json=body
    )


# --------------------------------------------------------------------------- backups


async def _list_protect_backups(client: UniFiClient, registry: Registry, host: str) -> Any:
    key, hid = await _resolve(registry, host)
    return await _list(client, key, hid, "/backups")


async def _create_protect_backup(client: UniFiClient, registry: Registry, host: str) -> Any:
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(_private(hid, "/backups"), key=key)


async def _delete_protect_backup(
    client: UniFiClient, registry: Registry, host: str, backup_id: str
) -> Any:
    validate_id(backup_id, "backup_id")
    _require_mutations()
    guard_action("DELETE")
    key, hid = await _resolve(registry, host)
    before = await _known(client, key, hid, "/backups", backup_id, "backup")
    backup_id = before["id"]
    # Protect 7.3 serves the per-backup routes as /backup{s}/:id, and only the singular
    # form reaches the delete handler: DELETE /backups/{id} answers 404 for every backup.
    response = await client.delete(_private(hid, f"/backup/{backup_id}"), key=key)
    result = deletion_result(f"Backup {backup_id} deleted.", response)
    if result.get("status") == "dry_run":
        return result

    async def read() -> set[str]:
        return deletion_readback_ids(
            _rows(await _list(client, key, hid, "/backups"), "backup"), "id"
        )

    rows, error = await safe_read_after(read)
    if error is not None:
        result["deleted"] = None
        result["message"] = (
            f"Backup {backup_id}: the DELETE was answered but the read-back failed, so the "
            "delete is unconfirmed; check list_protect_backups before retrying."
        )
    elif any(same_id(backup_id, identity) for identity in rows or []):
        result["deleted"] = False
        result["message"] = (
            f"Backup {backup_id} is still listed by list_protect_backups after the DELETE; "
            "it was not deleted."
        )
    return with_read_after_error(result, error)


async def _import_protect_backup(
    client: UniFiClient, registry: Registry, host: str, backup: dict[str, Any]
) -> Any:
    body = _body(backup, "backup import")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(_private(hid, "/backups/import"), key=key, json=body)


async def _restore_protect_backup(
    client: UniFiClient, registry: Registry, host: str, backup_id: str
) -> Any:
    # No pre-lookup refusal: the upstream judges the backup id (restores are never gated).
    validate_id(backup_id, "backup_id")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    # The singular route, as for delete: Protect 7.3 answers 404 on /backups/{id}/...
    return await client.post(_private(hid, f"/backup/{backup_id}/restore"), key=key)


async def _restore_protect_database(client: UniFiClient, registry: Registry, host: str) -> Any:
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    # Protect 7.x serves the 5.x nvr/restore-pg-dump handler unchanged at this route.
    return await client.post(_private(hid, "/nvr/restore-database-backup"), key=key)


# --------------------------------------------------------------------------- cloud archive


async def _get_cloud_archive_status(
    client: UniFiClient, registry: Registry, host: str, provider: str
) -> Any:
    _text(provider)
    key, hid = await _resolve(registry, host)
    try:
        return await client.get(
            _private(hid, "/cloud-provider/authenticate"), key=key, params={"provider": provider}
        )
    except UniFiConnectionError as exc:
        if exc.status != 500:
            raise
        upstream_hint(
            exc,
            "Check the cloud provider identifier and configuration in Protect.",
        )
        raise


async def _start_cloud_video_archive(
    client: UniFiClient, registry: Registry, host: str, archive: dict[str, Any]
) -> Any:
    body = _body(archive, "cloud archive")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(_private(hid, "/cloud-provider/video-archive"), key=key, json=body)


async def _connect_cloud_archive_provider(
    client: UniFiClient, registry: Registry, host: str, code: str
) -> Any:
    _text(code)
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(
        _private(hid, "/cloud-provider/authenticate-device-code"), key=key, json={"code": code}
    )


async def _cancel_cloud_archive_task(
    client: UniFiClient, registry: Registry, host: str, archive_id: str
) -> Any:
    validate_selector(archive_id, "archive_id")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(
        _private(hid, "/cloud-provider/cancel-archive-task"),
        key=key,
        json={"archiveId": archive_id},
    )


async def _disconnect_cloud_archive_provider(
    client: UniFiClient, registry: Registry, host: str, provider: str
) -> Any:
    _text(provider)
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(
        _private(hid, "/cloud-provider/revoke"), key=key, json={"provider": provider}
    )


async def _connect_unifi_video_server(
    client: UniFiClient, registry: Registry, host: str, server: dict[str, Any]
) -> Any:
    body = _body(server, "UniFi Video server")
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(_private(hid, "/cloud-provider/authenticate-nas"), key=key, json=body)


async def _import_unifi_video_cameras(
    client: UniFiClient, registry: Registry, host: str, server_host: str
) -> Any:
    _text(server_host)
    key, hid = await _resolve(registry, host)
    try:
        return await client.get(
            _private(hid, "/cloud-provider/shared-drives"), key=key, params={"host": server_host}
        )
    except UniFiConnectionError as exc:
        if exc.status != 500:
            raise
        upstream_hint(
            exc,
            "Check the shared drives server connection and provider configuration.",
        )
        raise


async def _accept_ironclad_terms(
    client: UniFiClient,
    registry: Registry,
    host: str,
    cid: str,
    vid: str,
    status: str,
    agreement_type: str,
) -> Any:
    _text(cid, vid, status, agreement_type)
    _require_mutations()
    guard_action("POST")
    key, hid = await _resolve(registry, host)
    return await client.post(
        _private(hid, "/ironclad/sendAcceptance"),
        key=key,
        json={"cid": cid, "vid": vid, "status": status, "type": agreement_type},
    )


# --------------------------------------------------------------------------- registration
