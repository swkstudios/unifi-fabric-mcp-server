"""Private Protect automation, backup and cloud archive tools (GS3 P05).

The published Integration API lacks these routes, so this module calls the Protect web
application's private API (routes inventoried from the Protect 5.3.18 frontend) through
the connector proxy. Upstream bodies pass through verbatim; additions are ``_``-prefixed.

Every write is bound by ``UNIFI_READ_ONLY`` and the Protect write opt-out
(``UNIFI_PROTECT_MUTATIONS_ENABLED=0``) before any request, and returns the client's
``UNIFI_DRY_RUN`` preview ``{status: "dry_run", dryRun, sent: false, message, preview: {method,
path, params, body}}`` (nothing sent) when dry-run is on.
Restores are never refused or gated by this module: the upstream judges them.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    is_dry_run_preview,
    validate_id,
    validate_selector,
)
from ..matching import same_id, with_upstream_id
from ..read_only import guard_action
from ..registry import Registry
from ..tool_annotations import READ_ONLY, WRITE
from ._keys import with_context
from ._payload import upstream_hint
from ._results import (
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
            row.get("id")
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
    before = await _known(client, key, hid, "/automations", automation_id, "automation")
    automation_id = before["id"]
    patch = with_upstream_id(patch, "id", automation_id)
    response = await client.patch(
        _private(hid, f"/automations/{automation_id}"), key=key, json=_merge(before, patch)
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
    result = with_context(response, {"_before": before, "_after": after, "_verified": verified})
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
    return await client.post(_private(hid, "/nvr/restore-pg-dump"), key=key)


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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 21 P05 tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_automations(host: str) -> Any:
        """List the Protect automations on a console.

        GET protect/api/automations (private Protect API); the route takes no paging
        parameters. Returns: the upstream body unchanged (an array arrives as {result: [...]}).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await _list_protect_automations(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def create_protect_automation(
        host: str, automation: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a Protect automation.

        POST protect/api/automations with the automation object sent verbatim. Returns: the
        upstream response unchanged. An empty object is refused before any request.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation: Native Protect automation object, e.g.
                {"name": "Night lights", "enabled": true, "triggers": [], "actions": []}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _create_protect_automation(client, registry, host, automation)

    @mcp.tool(annotations=WRITE)
    async def update_protect_automation(
        host: str, automation_id: str, changes: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Change fields of one Protect automation (read, merge, write, then verify).

        Lists automations to find automation_id (an unknown id fails listing the valid
        ids, before any write), deep-merges changes into the listed record and sends it with
        PATCH protect/api/automations/{automation_id}. Returns: the upstream response
        unchanged plus _before, _after and _verified (every requested leaf re-read, type
        strict), and _readAfterError when the re-read failed; a non-object response is
        returned whole under response with those keys beside it. An empty changes object is
        refused before any request.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation_id: Automation id from list_protect_automations,
                e.g. "66f1a2b3c4d5e6f7a8b9c0d1".
            changes: Fields to change, nested as on the record, e.g. {"enabled": false}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _update_protect_automation(client, registry, host, automation_id, changes)

    @mcp.tool(annotations=WRITE)
    async def delete_protect_automation(
        host: str, automation_id: str, confirm: bool = False
    ) -> Any:
        """Delete one Protect automation permanently.

        Lists automations to check automation_id exists (an unknown id fails listing the valid ids,
        before any write), then sends DELETE protect/api/automations/{id}.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty).

        Consequence: the automation is removed permanently and its triggers stop running
        its actions; there is no undo.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        {status: "dry_run", deleted: false, message, response} when UNIFI_DRY_RUN is set,
        where response is the dry-run preview {status, dryRun, sent: false, message, preview:
        {method, path, params, body}} (nothing sent).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation_id: Automation id from list_protect_automations,
                e.g. "66f1a2b3c4d5e6f7a8b9c0d1".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _delete_protect_automation(client, registry, host, automation_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_automation_history(
        host: str, automation_id: str, limit: int | None = None
    ) -> Any:
        """Read the run history of one Protect automation.

        GET protect/api/automations/{automation_id}/history. limit is forwarded unchanged
        when given and omitted otherwise (no default cap). Returns: the upstream body
        unchanged (an array arrives as {result: [...]}).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation_id: Automation id from list_protect_automations,
                e.g. "66f1a2b3c4d5e6f7a8b9c0d1".
            limit: Upstream history limit query parameter. Omit for the upstream default.
                Example: `50`.
        """
        client, registry = deps_fn()
        return await _get_protect_automation_history(client, registry, host, automation_id, limit)

    @mcp.tool(annotations=WRITE)
    async def reset_protect_automations(host: str, confirm: bool = False) -> Any:
        """Reset the console's Protect automations to the upstream defaults.

        POST protect/api/automations/reset with no body. Returns: the upstream response
        unchanged.

        Consequence: the current configuration is replaced by the upstream defaults, and
        custom entries are lost unless recreated.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _reset_protect_automations(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def set_protect_notification_receivers(
        host: str, receivers: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Set who receives Protect system notifications.

        PATCH protect/api/automations/system-notifications/receivers with receivers sent
        verbatim. Returns: the upstream response unchanged. An empty object is refused
        before any request.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            receivers: Native receivers object, e.g.
                {"userIds": ["66f1a2b3c4d5e6f7a8b9c0d2"]}. Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _set_protect_notification_receivers(client, registry, host, receivers)

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_backups(host: str) -> Any:
        """List the Protect configuration backups stored on a console.

        GET protect/api/backups (private Protect API); the route takes no paging
        parameters. Returns: the upstream body unchanged (an array arrives as {result: [...]}).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await _list_protect_backups(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def create_protect_backup(host: str, confirm: bool = False) -> Any:
        """Create a Protect configuration backup now.

        POST protect/api/backups with no body; uses console storage. Returns: the upstream
        response unchanged.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _create_protect_backup(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def delete_protect_backup(host: str, backup_id: str, confirm: bool = False) -> Any:
        """Delete one stored Protect backup permanently.

        Lists backups to check backup_id exists (an unknown id fails listing the valid ids, before
        any write), sends DELETE protect/api/backup/{backup_id} (the singular route; Protect 7.3
        answers 404 on the plural one), then lists backups again.
        Returns {deleted, message, response}: deleted is true only when the read-back no longer
        lists the backup, false when it is still listed, and null with readAfterError when the
        read-back failed; message summarizes the outcome, and response is the upstream body
        verbatim (decoded JSON, raw text, or null when the body is empty).

        Consequence: the backup is removed from console storage and can no longer be
        restored with restore_protect_backup; there is no undo.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        {status: "dry_run", deleted: false, message, response} when UNIFI_DRY_RUN is set,
        where response is the dry-run preview {status, dryRun, sent: false, message, preview:
        {method, path, params, body}} (nothing sent).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            backup_id: Backup id from list_protect_backups, e.g. "backup-1718000000000".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _delete_protect_backup(client, registry, host, backup_id)

    @mcp.tool(annotations=WRITE)
    async def import_protect_backup(
        host: str, backup: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Import a Protect backup onto a console.

        POST protect/api/backups/import with backup sent verbatim. Returns: the upstream
        response unchanged. An empty object is refused before any request.

        Consequence: the console imports the backup named in the body, using console
        storage; check list_protect_backups afterwards, since what else the import changes
        is decided upstream.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            backup: Native backup import object, e.g. {"name": "backup-1718000000000"}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _import_protect_backup(client, registry, host, backup)

    @mcp.tool(annotations=WRITE)
    async def restore_protect_backup(host: str, backup_id: str, confirm: bool = False) -> Any:
        """Restore a stored Protect backup, replacing the live Protect configuration.

        POST protect/api/backup/{backup_id}/restore with no body (the singular route;
        Protect 7.3 answers 404 on the plural one). The upstream judges backup_id.
        Returns: the upstream response unchanged.

        Consequence: the live Protect configuration is replaced by the backup's;
        irreversible, and Protect may restart, interrupting recording while it does.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            backup_id: Backup id from list_protect_backups, e.g. "backup-1718000000000".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _restore_protect_backup(client, registry, host, backup_id)

    @mcp.tool(annotations=WRITE)
    async def restore_protect_database(host: str, confirm: bool = False) -> Any:
        """Restore the Protect database from its stored database dump.

        POST protect/api/nvr/restore-pg-dump with no body. Returns: the upstream response
        unchanged.

        Consequence: the live Protect database is replaced by the stored dump, losing
        changes made since it; irreversible, and Protect may restart.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _restore_protect_database(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_cloud_archive_status(host: str, provider: str) -> Any:
        """Read the authentication state of a Protect cloud archive provider.

        GET protect/api/cloud-provider/authenticate?provider=..., the console's cloud-provider
        authorize endpoint: it may start a provider authorization request and changes no
        configuration, so it stays available in read-only mode. Returns: the upstream
        body unchanged (an array arrives as {result: [...]}). A console HTTP 500 may
        require checking the provider identifier and archive configuration in Protect.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            provider: Cloud archive provider id as Protect names it, e.g. "google-drive".
        """
        client, registry = deps_fn()
        return await _get_cloud_archive_status(client, registry, host, provider)

    @mcp.tool(annotations=WRITE)
    async def start_cloud_video_archive(
        host: str, archive: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Start archiving Protect video to the connected cloud provider.

        POST protect/api/cloud-provider/video-archive with archive sent verbatim. Returns:
        the upstream response unchanged. An empty object is refused before any request.

        Consequence: Protect starts copying the requested video to the connected cloud
        provider, using upload bandwidth and provider storage; cancel it with
        cancel_cloud_archive_task.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            archive: Native archive request object, e.g.
                {"cameraIds": ["66f1a2b3c4d5e6f7a8b9c0d3"], "start": 1718000000000,
                "end": 1718003600000}. Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _start_cloud_video_archive(client, registry, host, archive)

    @mcp.tool(annotations=WRITE)
    async def connect_cloud_archive_provider(host: str, code: str, confirm: bool = False) -> Any:
        """Connect a cloud archive provider with a device authorization code.

        POST protect/api/cloud-provider/authenticate-device-code with {"code": code}. The
        code is a registered route secret. Returns: the upstream response unchanged.

        Consequence: Protect is authorized against the provider account and can archive
        video to it until disconnect_cloud_archive_provider revokes it.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            code: Device authorization code from the provider, e.g. "ABCD-EFGH".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _connect_cloud_archive_provider(client, registry, host, code)

    @mcp.tool(annotations=WRITE)
    async def cancel_cloud_archive_task(host: str, archive_id: str, confirm: bool = False) -> Any:
        """Cancel a running Protect cloud archive task.

        POST protect/api/cloud-provider/cancel-archive-task with {"archiveId": archive_id}.
        Returns: the upstream response unchanged.

        Consequence: the archive task stops; video it has not copied yet is not archived
        (start a new one with start_cloud_video_archive).
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            archive_id: Archive task id from start_cloud_video_archive,
                e.g. "66f1a2b3c4d5e6f7a8b9c0d4".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _cancel_cloud_archive_task(client, registry, host, archive_id)

    @mcp.tool(annotations=WRITE)
    async def disconnect_cloud_archive_provider(
        host: str, provider: str, confirm: bool = False
    ) -> Any:
        """Disconnect (revoke) a Protect cloud archive provider.

        POST protect/api/cloud-provider/revoke with {"provider": provider}. Returns: the
        upstream response unchanged.

        Consequence: Protect's authorization with the provider is revoked, so it can no
        longer archive video there until connect_cloud_archive_provider connects it again.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            provider: Cloud archive provider id as Protect names it, e.g. "google-drive".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _disconnect_cloud_archive_provider(client, registry, host, provider)

    @mcp.tool(annotations=WRITE)
    async def connect_unifi_video_server(
        host: str, server: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Authenticate Protect to a UniFi Video server or NAS for camera import.

        POST protect/api/cloud-provider/authenticate-nas with server sent verbatim; its
        password and token fields are registered route secrets. Returns: the upstream
        response unchanged. An empty object is refused before any request.

        Consequence: Protect authenticates to that server with the credentials sent, so
        import_unifi_video_cameras can read what it offers; no camera is imported here.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            server: Native connection object, e.g.
                {"host": "192.0.2.10", "username": "admin", "password": "example-password"}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _connect_unifi_video_server(client, registry, host, server)

    @mcp.tool(annotations=READ_ONLY)
    async def import_unifi_video_cameras(host: str, server_host: str) -> Any:
        """List what a connected UniFi Video server or NAS offers for import.

        GET protect/api/cloud-provider/shared-drives?host=server_host (a read; nothing is
        imported). Returns: the upstream body unchanged (an array arrives as {result: [...]}).
        A shared-drives HTTP 500 may require checking the connected server/provider setup.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            server_host: Hostname or address of the server passed to
                connect_unifi_video_server, e.g. "192.0.2.10".
        """
        client, registry = deps_fn()
        return await _import_unifi_video_cameras(client, registry, host, server_host)

    @mcp.tool(annotations=WRITE)
    async def accept_ironclad_terms(
        host: str, cid: str, vid: str, status: str, agreement_type: str, confirm: bool = False
    ) -> Any:
        """Record acceptance of a Protect service agreement.

        POST protect/api/ironclad/sendAcceptance with {"cid", "vid", "status", "type"},
        where type is agreement_type. Returns: the upstream response unchanged.

        Consequence: a legal acceptance of that agreement version is recorded upstream; it
        cannot be withdrawn through this tool.
        Honours UNIFI_READ_ONLY and UNIFI_PROTECT_MUTATIONS_ENABLED=0, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when UNIFI_DRY_RUN is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            cid: Agreement contract id as Protect supplies it, e.g. "contract-1".
            vid: Agreement version id as Protect supplies it, e.g. "version-3".
            status: Acceptance status sent as status, e.g. "accepted".
            agreement_type: Agreement type sent as type, e.g. "cloud-archive".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await _accept_ironclad_terms(
            client, registry, host, cid, vid, status, agreement_type
        )
