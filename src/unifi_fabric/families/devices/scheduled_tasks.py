"""Classic REST scheduled-task CRUD, defined by go-unifi ScheduleTask.

Route source: github.com/filipowm/go-unifi/unifi/schedule_task.generated.go.
Classic listScheduleTask uses an unpaged collection GET. All native response fields
and free-form body fields are preserved, including controller-version extensions.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from ...client import UniFiClient, UniFiConnectionError, validate_id
from ...refusal_audit import credential_values
from ...registry import Registry
from ...secret_scrub import request_secret_scope
from ...shared_shapes._classic_objects import (
    _classic_data,
    checked_classic_response,
    classic_rest,
    listed_record_id,
    resolve_site_slug,
    select_classic_record,
)
from ...shared_shapes._results import deletion_result


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
