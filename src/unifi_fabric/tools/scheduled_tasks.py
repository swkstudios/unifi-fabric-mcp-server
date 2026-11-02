"""Classic REST scheduled-task CRUD, defined by go-unifi ScheduleTask.

Route source: github.com/filipowm/go-unifi/unifi/schedule_task.generated.go.
Classic listScheduleTask uses an unpaged collection GET. All native response fields
and free-form body fields are preserved, including controller-version extensions.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, UniFiConnectionError, validate_id
from ..refusal_audit import credential_values
from ..registry import Registry
from ..secret_scrub import request_secret_scope
from ..tool_annotations import WRITE
from ._classic_objects import (
    _classic_data,
    checked_classic_response,
    classic_rest,
    listed_record_id,
    resolve_site_slug,
    select_classic_record,
)
from ._results import deletion_result


def _incomplete(response: Any) -> bool:
    if not isinstance(response, dict):
        return False
    rows = response.get("data")
    count = len(rows) if isinstance(rows, list) else 0
    meta = response.get("meta")
    sources = [response, meta] if isinstance(meta, dict) else [response]
    return any(
        source.get("incomplete")
        or source.get("_incomplete")
        or source.get("nextToken")
        or source.get("nextPage")
        or source.get("hasMore")
        or any(
            isinstance(source.get(field), int) and source[field] > count
            for field in ("count", "total", "totalCount")
        )
        for source in sources
    )


async def _resolve(client: UniFiClient, registry: Registry, host: str, site: str, task_id: str):
    validate_id(task_id, "task_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    path = classic_rest(host_id, slug, "/scheduletask")
    response = checked_classic_response(
        await client.get(path, key=key), path, client=client, key=key
    )
    rows = _classic_data(response, path, client=client, key=key)
    if _incomplete(response):
        raise UniFiConnectionError(
            "Scheduled-task lookup is incomplete; cannot resolve an id safely."
        )
    record = select_classic_record(rows, task_id, "Scheduled task", "list_scheduled_tasks")
    identity = listed_record_id(record, "task_id")
    return key, path + "/" + identity, record


async def _create_scheduled_task(
    client: UniFiClient, registry: Registry, host: str, site: str, task: dict[str, Any]
) -> Any:
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    path = classic_rest(host_id, slug, "/scheduletask")
    with request_secret_scope(credential_values(task)):
        return checked_classic_response(
            await client.post(path, json=task, key=key), path, client=client, key=key
        )


async def _update_scheduled_task(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    task_id: str,
    task: dict[str, Any],
) -> Any:
    key, path, record = await _resolve(client, registry, host, site, task_id)
    # Preserve the full current record and every array unless the caller
    # deliberately provides its replacement. Never mutate a cached GET object.
    body = {**deepcopy(record), **deepcopy(task), "_id": record["_id"]}
    with request_secret_scope(credential_values(body)):
        return checked_classic_response(
            await client.put(path, json=body, key=key), path, client=client, key=key
        )


async def _delete_scheduled_task(
    client: UniFiClient, registry: Registry, host: str, site: str, task_id: str
) -> Any:
    key, path, _ = await _resolve(client, registry, host, site, task_id)
    response = checked_classic_response(
        await client.delete(path, key=key), path, client=client, key=key
    )
    return deletion_result(f"Scheduled task {task_id} deleted.", response)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    @mcp.tool(annotations=WRITE)
    async def create_scheduled_task(host: str, site: str, task: dict[str, Any]) -> Any:
        """Create a scheduled task using the native Classic body.

        Consequence: the controller executes the action at its scheduled time; upgrades can
        interrupt devices and clients.

        Returns the upstream body verbatim. UNIFI_DRY_RUN sends no write; returns {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#create_scheduled_task.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            task: Free-form native object. Source fields include name, action,
                cron_expr, execute_only_once and upgrade_targets, a list of objects with mac.
                Example: {"name": "Monthly upgrades", "action": "upgrade",
                "cron_expr": "0 0 1 * *", "execute_only_once": false,
                "upgrade_targets": [{"mac": "02:00:00:00:00:01"}]}.
                The controller validates actions and scheduling syntax; unknown fields
                are forwarded unchanged.
        """
        client, registry = deps_fn()
        return await _create_scheduled_task(client, registry, host, site, task)

    @mcp.tool(annotations=WRITE)
    async def update_scheduled_task(
        host: str, site: str, task_id: str, task: dict[str, Any]
    ) -> Any:
        """Update a scheduled task with a whole-record read-merge-write.

        Preserves unmentioned fields, upgrade_targets and the resolved _id. A supplied array
        replaces that array, including [] to clear it.

        Consequence: schedule or target changes affect future device actions; upgrades can interrupt
        devices and clients.

        Returns the upstream body verbatim. UNIFI_DRY_RUN sends no write; returns {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#update_scheduled_task.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            task_id: Classic _id from list_scheduled_tasks data[], for example
                "000000000000000000000001".
            task: Free-form native changed fields, for example {"name": "Monthly upgrades"}.
                Source fields include name, action, cron_expr, execute_only_once and
                upgrade_targets, a list of objects with mac. Unknown fields are retained and
                forwarded; the controller validates values.
        """
        client, registry = deps_fn()
        return await _update_scheduled_task(client, registry, host, site, task_id, task)

    @mcp.tool(annotations=WRITE)
    async def delete_scheduled_task(host: str, site: str, task_id: str) -> Any:
        """Delete a scheduled task after resolving its Classic id in the site.

        Consequence: permanently removes the scheduled action.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). UNIFI_DRY_RUN sends no write; returns {status: "dry_run", deleted: false, message,
        response}, where response is the dry-run preview {status, dryRun, sent: false, message,
        preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#delete_scheduled_task.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            task_id: Classic _id from list_scheduled_tasks data[], for example
                "000000000000000000000001".
        """
        client, registry = deps_fn()
        return await _delete_scheduled_task(client, registry, host, site, task_id)
