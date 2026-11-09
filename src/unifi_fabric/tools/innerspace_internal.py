"""InnerSpace internal-route tools over the console proxy (``/proxy/innerspace/api/...``).

These tools reach the InnerSpace application's own backend routes through the same
remote console proxy the InnerSpace read tools use (``tools.innerspace``): the Site
Manager connector path ``/v1/connector/consoles/{host_id}/proxy/innerspace/...``. There
is no other transport and no local-console access.

The routes have no published request/response schema. Bodies the routes take are
free-form here (no invented required keys): the upstream judges them. Every upstream body
is returned verbatim; additive keys are ``_``-prefixed. Every GET is a read. Every POST,
PATCH and DELETE is a write (no route here is on the read-POST allowlist), so
``UNIFI_WRITE_POLICY=deny`` refuses it and ``dry-run policy`` returns the client's preview
``{status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}``
instead of sending it. Writes are sent once and never retried. An upstream 401/403 (for
example a route that needs a console session rather than an API key) is raised with its
full reason, unchanged.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
from collections.abc import Callable
from typing import Any, NoReturn, cast

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    strip_additive_keys,
    upstream_error_value,
    validate_selector,
)
from ..config import APIKeyConfig
from ..read_only import ReadOnlyModeError, guard_action
from ..redaction import drop_and_note_masked_fields
from ..registry import Registry
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import require_unmasked_fields, require_update_fields
from . import innerspace
from ._keys import with_context
from ._results import (
    ADDITIVE_READ_AFTER_ERROR_KEY,
    VERIFIED_KEY,
    deletion_result,
    requested_leaves_match,
    requested_leaves_verdict,
    safe_read_after,
    short_circuit_no_op,
)

#: The InnerSpace application root on the console proxy.
INNERSPACE_APP_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace"

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.IGNORECASE
)


def _app(host_id: str, path: str) -> str:
    """The console-proxy path of an InnerSpace application route (``/health``, ``/api/...``)."""
    return INNERSPACE_APP_BASE.format(host_id=host_id) + path


def _uuid(value: Any, name: str) -> str:
    """``value`` when it is a UUID (the route's path id); else refuse before any request.

    The value is never echoed: the shared-project token is a credential.
    """
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise ValueError(
            f"Invalid InnerSpace {name!r}: expected a UUID such as "
            "3fa85f64-5717-4562-b3fc-2c963f66afa6 (got "
            f"{describe_shape(value) if not isinstance(value, str) else 'a non-UUID string'})"
        )
    return value


def _argument_grammar(message: str) -> NoReturn:
    """Refuse an argument combination of this module (registered in refusals.py)."""
    raise ValueError(f"InnerSpace arguments: {message} Nothing was sent.")


def _query(*params: tuple[str, str, str | None]) -> dict[str, Any] | None:
    """The query parameters the caller gave, else None.

    Each entry is ``(wire name, argument name, value)``; a given value is checked as a
    selector before any request, and a refusal names the tool argument.
    """
    sent: dict[str, Any] = {}
    for wire, argument, value in params:
        if value is None:
            continue
        validate_selector(value, argument)
        sent[wire] = value
    return sent or None


def _decode_upload(content_base64: str) -> bytes:
    """The upload bytes; refuse content that is not standard base64 before any request."""
    compact = "".join(content_base64.split()) if isinstance(content_base64, str) else ""
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"content_base64 is not valid base64 ({exc}); pass the file's bytes base64-encoded "
            "(standard alphabet, padded; line breaks are allowed, a data: prefix is not)."
        ) from exc


def _update_body(fields: Any, tool: str) -> dict[str, Any]:
    """The free-form body to send: refuse an empty one before any request.

    ``_``-prefixed keys are not sent; a field still holding the redaction mask is dropped
    (never sent) and reported on the result under ``_redactedFieldsNotSent``.
    """
    require_update_fields(fields, tool)
    return cast(dict[str, Any], drop_and_note_masked_fields(strip_additive_keys(fields)))


def _guard(client: UniFiClient, tool: str, method: str) -> None:
    """Refuse a write under ``UNIFI_WRITE_POLICY=deny`` before any request (resolution included)."""
    try:
        guard_action(method)
    except ReadOnlyModeError:
        client.audit_refusal(tool=tool, reason="UNIFI_WRITE_POLICY")
        raise


async def _host(registry: Registry, host: str) -> tuple[APIKeyConfig | None, str]:
    """The owning API key and the console host id (multi-key aware)."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return key, host_id


# --------------------------------------------------------------------------- reads


async def _read(
    client: UniFiClient,
    registry: Registry,
    host: str,
    route: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """GET one InnerSpace route and return the upstream body verbatim."""
    key, host_id = await _host(registry, host)
    return await client.get(_app(host_id, route), key=key, params=params)


async def list_innerspace_doors(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET /api/access/doors: the door unique ids, verbatim."""
    try:
        return await _read(client, registry, host, "/api/access/doors")
    except UniFiConnectionError as exc:
        if exc.status != 502:
            raise
        raise type(exc)(
            f"{exc}; door listing requires the UniFi Access app on the console",
            request_sent=exc.request_sent,
            status=exc.status,
        ) from exc


async def get_innerspace_stats(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET /api/stats, verbatim."""
    return await _read(client, registry, host, "/api/stats")


async def get_innerspace_ucore_manifest(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET /api/ucore/manifest, verbatim."""
    try:
        return await _read(client, registry, host, "/api/ucore/manifest")
    except UniFiConnectionError as exc:
        if exc.status != 403:
            raise
        raise type(exc)(
            f"{exc}; the console denied access to the InnerSpace manifest; "
            "check console permissions",
            request_sent=exc.request_sent,
            status=exc.status,
        ) from exc


async def get_innerspace_ucore_status(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET /api/ucore/status, verbatim."""
    return await _read(client, registry, host, "/api/ucore/status")


async def get_innerspace_health(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET /health (the application root, not under /api), verbatim."""
    return await _read(client, registry, host, "/health")


# --------------------------------------------------------------------------- writes


async def _post(
    client: UniFiClient,
    registry: Registry,
    host: str,
    route: str,
    *,
    json: Any = None,
    params: dict[str, Any] | None = None,
) -> Any:
    """POST one InnerSpace route (a write, sent once); the upstream body verbatim."""
    key, host_id = await _host(registry, host)
    return await client.post(
        _app(host_id, route), key=key, json=cast(dict[str, Any] | None, json), params=params
    )


async def _patch(
    client: UniFiClient, registry: Registry, host: str, route: str, *, json: Any
) -> Any:
    """PATCH one InnerSpace route (a write, sent once); the upstream body verbatim."""
    key, host_id = await _host(registry, host)
    return await client.patch(_app(host_id, route), key=key, json=cast(dict[str, Any], json))


async def import_innerspace_captures(
    client: UniFiClient,
    registry: Registry,
    host: str,
    title: str,
    site_id: str,
    captures: list[dict[str, Any]],
) -> Any:
    """POST /api/project/import {title, siteId, captures}."""
    _guard(client, "import_innerspace_captures", "POST")
    validate_selector(site_id, "site_id")
    if isinstance(captures, list) and not captures:
        _argument_grammar("captures is an empty list, so there is nothing to import.")
    body = {"title": title, "siteId": site_id, "captures": captures}
    return await _post(client, registry, host, "/api/project/import", json=body)


async def create_innerspace_plan(
    client: UniFiClient, registry: Registry, host: str, plan: dict[str, Any]
) -> Any:
    """POST /api/project/plan with the plan fields as given."""
    _guard(client, "create_innerspace_plan", "POST")
    body = _update_body(plan, "create_innerspace_plan")
    return await _post(client, registry, host, "/api/project/plan", json=body)


async def delete_innerspace_plan(
    client: UniFiClient, registry: Registry, host: str, plan_id: str
) -> Any:
    """DELETE /api/project/plan/{planId}; return a canonical deletion result.

    The id is resolved in the collection list first; an unknown id lists the valid ids
    and sends no write. The plan is read through :func:`innerspace.get_innerspace_project`,
    as :func:`update_innerspace_plan` reads it, and the DELETE path carries the plan id
    as the upstream spells it.
    """
    _guard(client, "delete_innerspace_plan", "DELETE")
    plan = _uuid(plan_id, "plan_id")
    raw = await innerspace.get_innerspace_project(client, registry, host)
    selected = _select_plan(_project_plans(raw, host), plan, host)
    upstream_id = str(selected.get("id", plan))
    key, host_id = await _host(registry, host)
    response = await client.delete(_app(host_id, f"/api/project/plan/{upstream_id}"), key=key)
    return deletion_result(f"InnerSpace plan {plan} deleted.", response)


async def reorder_innerspace_plans(
    client: UniFiClient, registry: Registry, host: str, plans: list[dict[str, Any]]
) -> Any:
    """PATCH /api/project/plan/order with the plan objects as given."""
    _guard(client, "reorder_innerspace_plans", "PATCH")
    if isinstance(plans, list) and not plans:
        _argument_grammar("plans is an empty list, so there is no plan order to set.")
    return await _patch(client, registry, host, "/api/project/plan/order", json=plans)


async def update_innerspace_plan_map(
    client: UniFiClient, registry: Registry, host: str, plan_id: str, fields: dict[str, Any]
) -> Any:
    """PATCH /api/project/plan/{planId}/map with the fields as given.

    The id is resolved in the collection list first, as :func:`update_innerspace_plan`
    and :func:`delete_innerspace_plan` resolve it: the plan is read through
    :func:`innerspace.get_innerspace_project`, an unknown id lists the valid ids and sends
    no write, and the PATCH path carries the plan id as the upstream spells it.
    """
    _guard(client, "update_innerspace_plan_map", "PATCH")
    plan = _uuid(plan_id, "plan_id")
    body = _update_body(fields, "update_innerspace_plan_map")
    raw = await innerspace.get_innerspace_project(client, registry, host)
    selected = _select_plan(_project_plans(raw, host), plan, host)
    upstream_id = str(selected.get("id", plan))
    # An id field naming the same plan is sent in the upstream spelling too.
    if isinstance(body.get("id"), str) and body["id"].lower() == upstream_id.lower():
        body = {**body, "id": upstream_id}
    return await _patch(client, registry, host, f"/api/project/plan/{upstream_id}/map", json=body)


async def update_innerspace_project(
    client: UniFiClient, registry: Registry, host: str, fields: dict[str, Any]
) -> Any:
    """PATCH /api/project with the fields as given."""
    _guard(client, "update_innerspace_project", "PATCH")
    body = _update_body(fields, "update_innerspace_project")
    return await _patch(client, registry, host, "/api/project", json=body)


def _project_plans(raw: Any, host: str) -> list[dict[str, Any]]:
    """The ``plans`` array of a project document (``data`` envelope or bare)."""
    project = raw.get("data", raw) if isinstance(raw, dict) else raw
    plans = project.get("plans") if isinstance(project, dict) else None
    if not isinstance(plans, list) or not all(isinstance(p, dict) for p in plans):
        raise UniFiConnectionError(
            f"Unexpected InnerSpace project shape for host {host!r}: expected a 'plans' array "
            f"of objects (top level or under 'data'), got {describe_shape(raw)}"
        )
    return plans


def _select_plan(plans: list[dict[str, Any]], plan_id: str, host: str) -> dict[str, Any]:
    """The one plan whose ``id`` is ``plan_id``; else fail listing the valid ids."""
    matches = [p for p in plans if str(p.get("id", "")).lower() == plan_id.lower()]
    if len(matches) != 1:
        valid = [upstream_error_value(p.get("id")) for p in plans]
        raise ValueError(
            f"InnerSpace plan {plan_id!r} not found exactly once in the project of host "
            f"{host!r} ({len(matches)} matches); valid: {valid}"
        )
    return matches[0]


def _merge(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """``changes`` laid over ``base``: nested objects merge key by key, other values replace."""
    merged = dict(base)
    for key, value in changes.items():
        current = merged.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            merged[key] = _merge(current, value)
        else:
            merged[key] = value
    return merged


async def update_innerspace_plan(
    client: UniFiClient,
    registry: Registry,
    host: str,
    plan_id: str,
    fields: dict[str, Any],
) -> Any:
    """Read the plan, merge ``fields`` over it, PATCH /api/project/plan/{planId} with it.

    The plan is read through :func:`innerspace.get_innerspace_project` (the documented
    integration ``/v1/project`` first, the legacy ``/api/project`` as its fallback). The
    PATCH path carries the plan id as the upstream spells it. The result is the PATCH body
    verbatim (a non-object body under ``response``) plus ``_verified`` (requested leaves,
    type-strict, against a fresh read; null with ``_readAfterError`` when the re-read
    failed or could not be matched). A change
    already applied returns the plan as read plus ``_noOp: true``, ``_verified: true`` and
    ``_note`` without writing (never under dry-run, which returns the PATCH preview).
    """
    _guard(client, "update_innerspace_plan", "PATCH")
    plan = _uuid(plan_id, "plan_id")
    changes = _update_body(fields, "update_innerspace_plan")

    async def read_plan() -> dict[str, Any]:
        raw = await innerspace.get_innerspace_project(client, registry, host)
        return _select_plan(_project_plans(raw, host), plan, host)

    before = await read_plan()
    # The plan id in the upstream's own spelling (the match is case-insensitive); an
    # ``id`` field naming the same plan is sent in that spelling too.
    upstream_id = str(before.get("id", plan))
    if isinstance(changes.get("id"), str) and changes["id"].lower() == upstream_id.lower():
        changes = {**changes, "id": upstream_id}
    if short_circuit_no_op(client, requested_leaves_match(changes, before)):
        return with_context(
            before, {"_noOp": True, VERIFIED_KEY: True, "_note": "no change needed"}
        )
    merged = _merge(strip_additive_keys(before), changes)
    key, host_id = await _host(registry, host)
    response = await client.patch(
        _app(host_id, f"/api/project/plan/{upstream_id}"), key=key, json=merged
    )
    if is_dry_run_preview(response):
        return response
    after, error = await safe_read_after(read_plan)
    verdict, reason = requested_leaves_verdict(changes, after, error)
    result = response if isinstance(response, dict) else {"response": response}
    context: dict[str, Any] = {VERIFIED_KEY: verdict}
    if reason is not None:
        context[ADDITIVE_READ_AFTER_ERROR_KEY] = reason
    # Beside the upstream body, never over it: a colliding upstream key keeps its value.
    return with_context(result, context)


async def upload_innerspace_plan_asset(
    client: UniFiClient,
    registry: Registry,
    host: str,
    filename: str,
    content_base64: str,
    assets_dir: str,
    content_type: str | None = None,
) -> Any:
    """POST /api/project/plan/upload as multipart: ``files`` (the file) and ``assetsDir``."""
    _guard(client, "upload_innerspace_plan_asset", "POST")
    data = _decode_upload(content_base64)
    part: tuple[Any, ...] = (
        (filename, io.BytesIO(data), content_type)
        if content_type is not None
        else (filename, io.BytesIO(data))
    )
    files: dict[str, Any] = {"files": part, "assetsDir": (None, assets_dir)}
    key, host_id = await _host(registry, host)
    response = await client.post_multipart(
        _app(host_id, "/api/project/plan/upload"), key=key, files=files
    )
    if is_dry_run_preview(response):
        return with_context(response, {"_form": {"assetsDir": assets_dir}})
    return response


async def update_innerspace_wall_type(
    client: UniFiClient, registry: Registry, host: str, wall_type: dict[str, Any]
) -> Any:
    """POST /api/project/wall-type with the wall type as given."""
    _guard(client, "update_innerspace_wall_type", "POST")
    body = _update_body(wall_type, "update_innerspace_wall_type")
    return await _post(client, registry, host, "/api/project/wall-type", json=body)


async def update_innerspace_attenuation_type(
    client: UniFiClient, registry: Registry, host: str, attenuation_type: dict[str, Any]
) -> Any:
    """POST /api/project/attenuation-object-type with the type as given."""
    _guard(client, "update_innerspace_attenuation_type", "POST")
    body = _update_body(attenuation_type, "update_innerspace_attenuation_type")
    return await _post(client, registry, host, "/api/project/attenuation-object-type", json=body)


async def import_innerspace_dc_shapes(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site_id: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST /api/import/dc-shapes?siteId=..."""
    _guard(client, "import_innerspace_dc_shapes", "POST")
    require_unmasked_fields(body, "import_innerspace_dc_shapes")
    if body is not None:
        body = drop_and_note_masked_fields(strip_additive_keys(body))
    params = _query(("siteId", "site_id", site_id))
    return await _post(client, registry, host, "/api/import/dc-shapes", json=body, params=params)


async def retry_innerspace_plan_maps(
    client: UniFiClient, registry: Registry, host: str, site_id: str
) -> Any:
    """POST /api/import/retry-maps?siteId=..."""
    _guard(client, "retry_innerspace_plan_maps", "POST")
    params = _query(("siteId", "site_id", site_id))
    return await _post(client, registry, host, "/api/import/retry-maps", params=params)


async def import_innerspace_shared_project(
    client: UniFiClient, registry: Registry, host: str, token: str, site_id: str
) -> Any:
    """POST /api/import/projects/{token}?siteId=..."""
    _guard(client, "import_innerspace_shared_project", "POST")
    share = _uuid(token, "token")
    params = _query(("siteId", "site_id", site_id))
    return await _post(client, registry, host, f"/api/import/projects/{share}", params=params)


async def transform_innerspace_shapes(
    client: UniFiClient,
    registry: Registry,
    host: str,
    transform: dict[str, Any],
    mode: str | None = None,
    socket_id: str | None = None,
) -> Any:
    """POST /api/shape/change with the transform data (plus ``mode``), ``socketId`` query."""
    _guard(client, "transform_innerspace_shapes", "POST")
    body = _update_body(transform, "transform_innerspace_shapes")
    if mode is not None:
        if "mode" in body:
            _argument_grammar(
                "mode is given twice, as the mode argument and as a 'mode' key of transform; "
                "give it once."
            )
        body = {**body, "mode": mode}
    params = _query(("socketId", "socket_id", socket_id))
    return await _post(client, registry, host, "/api/shape/change", json=body, params=params)


async def _ucore_dir(
    client: UniFiClient, registry: Registry, host: str, tool: str, route: str, directory: str
) -> Any:
    _guard(client, tool, "POST")
    return await _post(client, registry, host, route, json={"dir": directory})


async def export_innerspace_backup(
    client: UniFiClient, registry: Registry, host: str, directory: str
) -> Any:
    """POST /api/ucore/backup/export {dir}."""
    return await _ucore_dir(
        client, registry, host, "export_innerspace_backup", "/api/ucore/backup/export", directory
    )


async def import_innerspace_backup(
    client: UniFiClient, registry: Registry, host: str, directory: str
) -> Any:
    """POST /api/ucore/backup/import {dir}."""
    return await _ucore_dir(
        client, registry, host, "import_innerspace_backup", "/api/ucore/backup/import", directory
    )


async def create_innerspace_support_dump(
    client: UniFiClient, registry: Registry, host: str, directory: str
) -> Any:
    """POST /api/ucore/support-dump {dir}."""
    return await _ucore_dir(
        client,
        registry,
        host,
        "create_innerspace_support_dump",
        "/api/ucore/support-dump",
        directory,
    )


async def clean_innerspace_storage(client: UniFiClient, registry: Registry, host: str) -> Any:
    """POST /api/ucore/storage/clean (no body)."""
    _guard(client, "clean_innerspace_storage", "POST")
    return await _post(client, registry, host, "/api/ucore/storage/clean")


# --------------------------------------------------------------------------- registration


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the InnerSpace internal-route tools."""

    @mcp.tool(name="list_innerspace_doors", annotations=READ_ONLY)
    async def _list_innerspace_doors(host: str) -> Any:
        """List InnerSpace access doors (GET /proxy/innerspace/api/access/doors).

        Returns the upstream body verbatim: an array of door unique_id strings. Door listing
        needs the UniFi Access app on the console: without it the console answers HTTP 502,
        and the error says so.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await list_innerspace_doors(client, registry, host)

    @mcp.tool(name="get_innerspace_stats", annotations=READ_ONLY)
    async def _get_innerspace_stats(host: str) -> Any:
        """Get InnerSpace application statistics (GET /proxy/innerspace/api/stats).

        Returns the upstream body verbatim.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await get_innerspace_stats(client, registry, host)

    @mcp.tool(name="get_innerspace_ucore_manifest", annotations=READ_ONLY)
    async def _get_innerspace_ucore_manifest(host: str) -> Any:
        """Get the InnerSpace UniFi OS app manifest (GET /proxy/innerspace/api/ucore/manifest).

        Returns the upstream body verbatim. A 403 indicates the console denied access;
        check console permissions.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await get_innerspace_ucore_manifest(client, registry, host)

    @mcp.tool(name="get_innerspace_ucore_status", annotations=READ_ONLY)
    async def _get_innerspace_ucore_status(host: str) -> Any:
        """Get the InnerSpace UniFi OS app status (GET /proxy/innerspace/api/ucore/status).

        Returns the upstream body verbatim.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await get_innerspace_ucore_status(client, registry, host)

    @mcp.tool(name="get_innerspace_health", annotations=READ_ONLY)
    async def _get_innerspace_health(host: str) -> Any:
        """Get the InnerSpace application health (GET /proxy/innerspace/health).

        Returns the upstream body verbatim.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await get_innerspace_health(client, registry, host)

    @mcp.tool(name="import_innerspace_captures", annotations=WRITE)
    async def _import_innerspace_captures(
        host: str,
        title: str,
        site_id: str,
        captures: list[dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Import scan captures as a new InnerSpace project (POST .../api/project/import).

        Consequence: a new project is created on the console under site_id; existing
        projects are not changed.

        Sends {title, siteId, captures}. Each capture is free-form and is sent as given;
        captures carry files (topView, 3d.gltf), a title and devices [{id, sku}].
        Returns the upstream body verbatim. Write: sent once, never retried.
        UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Required arguments: host, title, site_id, captures (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            title: Project title, e.g. "Main office".
            site_id: UniFi site id the project belongs to, e.g. "default".
            captures: Non-empty list of capture objects (an empty list fails before any
                request), e.g. [{"title": "Lobby", "files": {"topView":
                "top.png", "3d.gltf": "scan.gltf"}, "devices": [{"id": "dev-1",
                "sku": "U7-Pro"}]}].
                Shape: {title?:string,files?:{topView?:string,'3d.gltf'?:string},
                devices?:{id:string,sku:string}[]}[]; keys the server reads: none, each capture is
                sent as given
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await import_innerspace_captures(client, registry, host, title, site_id, captures)

    @mcp.tool(name="create_innerspace_plan", annotations=WRITE)
    async def _create_innerspace_plan(
        host: str, plan: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create an InnerSpace floor plan (POST /proxy/innerspace/api/project/plan).

        The plan object is free-form and sent as given; the web app sends type, url,
        title and siteId. Returns the upstream body verbatim ({data: plan}). An empty
        plan fails before any request. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny
        refuses it before any request. dry-run policy returns a dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}.

        Required arguments: host, plan (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            plan: Plan fields, e.g. {"type": "image", "url": "/assets/plan.png",
                "title": "Ground floor", "siteId": "default"}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await create_innerspace_plan(client, registry, host, plan)

    @mcp.tool(name="delete_innerspace_plan", annotations=WRITE)
    async def _delete_innerspace_plan(host: str, plan_id: str, confirm: bool = False) -> Any:
        """Delete an InnerSpace floor plan (DELETE .../api/project/plan/{planId}).

        Consequence: the plan and its shapes are removed; there is no undo.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). The upstream body is {data: {plans, shapes}}. A plan_id that is not a UUID fails
        before any request. The id is resolved in the collection list first; an unknown id lists the
        valid ids and sends no write. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny
        refuses it
        before any request. dry-run policy returns {status: "dry_run", deleted: false, message,
        response} where response is the dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}}.

        Required arguments: host, plan_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            plan_id: Plan id (UUID) from get_innerspace_project plans[].id, e.g.
                "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await delete_innerspace_plan(client, registry, host, plan_id)

    @mcp.tool(name="reorder_innerspace_plans", annotations=WRITE)
    async def _reorder_innerspace_plans(
        host: str, plans: list[dict[str, Any]], confirm: bool = False
    ) -> Any:
        """Reorder InnerSpace floor plans (PATCH /proxy/innerspace/api/project/plan/order).

        Sends the array of plan objects as given; each carries its
        new ordering. Returns the upstream body verbatim. Write: sent once, never retried.
        UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Required arguments: host, plans (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            plans: Non-empty list of plan objects with ordering (an empty list fails before
                any request), e.g. [{"id":
                "3fa85f64-5717-4562-b3fc-2c963f66afa6", "ordering": 0}].
                Shape: {id:string,ordering:integer}[]; keys the server reads: none, the array is
                sent as given
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await reorder_innerspace_plans(client, registry, host, plans)

    @mcp.tool(name="update_innerspace_plan_map", annotations=WRITE)
    async def _update_innerspace_plan_map(
        host: str, plan_id: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a floor plan's map (PATCH .../api/project/plan/{planId}/map).

        The fields are free-form and sent as given. An empty update or a plan_id that is
        not a UUID fails before any request. The id is resolved in the collection list
        first; an unknown id lists the valid ids and sends no write. Returns the upstream
        body verbatim. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny refuses it before
        any request.
        dry-run policy returns a dry-run preview {status: "dry_run", dryRun, sent: false, message,
        preview: {method, path, params, body}}.

        Required arguments: host, plan_id, fields (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            plan_id: Plan id (UUID) from get_innerspace_project plans[].id, e.g.
                "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            fields: Map fields to send, e.g. {"rotation": 90}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await update_innerspace_plan_map(client, registry, host, plan_id, fields)

    @mcp.tool(name="update_innerspace_plan", annotations=WRITE)
    async def _update_innerspace_plan(
        host: str,
        plan_id: str,
        fields: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Update an InnerSpace floor plan (PATCH .../api/project/plan/{planId}).

        Read-merge-write: reads the plan the way get_innerspace_project does (the documented
        integration project route first, the legacy .../api/project as fallback), lays
        fields over it (nested objects merge key by key) and PATCHes the whole plan. An
        unknown plan id fails listing the valid ids; an empty update or a plan_id that is
        not a UUID fails before any request. Returns the PATCH body verbatim (a non-object
        body under response) plus _verified (type-strict, leaf by leaf against a fresh
        read; null with _readAfterError when the re-read fails). A change already applied
        returns the plan as read plus _noOp: true, _verified: true and _note, without
        writing. When UNIFI_REDACT_SECRETS is enabled, a field still holding the redaction
        mask is not sent and is listed under _redactedFieldsNotSent. Write: sent once, never
        retried. UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a
        dry-run
        preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}.

        Required arguments: host, plan_id, fields (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            plan_id: Plan id (UUID), e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            fields: Plan fields to change, e.g. {"title": "First floor"}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await update_innerspace_plan(client, registry, host, plan_id, fields)

    @mcp.tool(name="update_innerspace_project", annotations=WRITE)
    async def _update_innerspace_project(
        host: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update the InnerSpace project document (PATCH /proxy/innerspace/api/project).

        The fields are free-form and sent as given. An empty update fails before any
        request. Returns the upstream body verbatim; it is not read back, and an earlier
        live test saw this route answer HTTP 200 without persisting the change, so confirm
        with get_innerspace_project. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny
        refuses it before any request. dry-run policy returns a dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}.

        Required arguments: host, fields (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            fields: Project fields to send, e.g. {"title": "Main office"}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await update_innerspace_project(client, registry, host, fields)

    @mcp.tool(name="upload_innerspace_plan_asset", annotations=WRITE)
    async def _upload_innerspace_plan_asset(
        host: str,
        filename: str,
        content_base64: str,
        assets_dir: str,
        content_type: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Upload a floor-plan asset (multipart POST .../api/project/plan/upload).

        Consequence: the file is stored on the console in assets_dir for InnerSpace plans to
        use.

        Sends the decoded file as the files part and assets_dir as the assetsDir field.
        No size limit. Content that is not base64 fails before any request. Returns the
        upstream body verbatim. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny refuses
        it before any request. dry-run policy returns a dry-run preview {status: "dry_run", dryRun,
        sent: false, message, preview: {method, path, params, body, multipart}} plus _form.

        Required arguments: host, filename, content_base64, assets_dir (see each parameter's
        description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            filename: File name sent with the part, e.g. "ground-floor.png".
            content_base64: File bytes, base64-encoded, e.g. "iVBORw0KGgo=".
            assets_dir: Target assets directory (assetsDir), e.g. "plans".
            content_type: Optional part media type, e.g. "image/png"; omitted lets the
                HTTP library pick it from the file name.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await upload_innerspace_plan_asset(
            client, registry, host, filename, content_base64, assets_dir, content_type
        )

    @mcp.tool(name="update_innerspace_wall_type", annotations=WRITE)
    async def _update_innerspace_wall_type(
        host: str, wall_type: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create or update an InnerSpace wall type (POST .../api/project/wall-type).

        Consequence: the wall type is stored on the console, and its attenuation applies
        wherever plans use that wall type.

        The wall type is free-form and sent as given. An empty body fails before any
        request. Returns the upstream body verbatim. Write: sent once, never retried.
        UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Required arguments: host, wall_type (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            wall_type: Wall type fields, e.g. {"id": "drywall", "attenuation": 3}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await update_innerspace_wall_type(client, registry, host, wall_type)

    @mcp.tool(name="update_innerspace_attenuation_type", annotations=WRITE)
    async def _update_innerspace_attenuation_type(
        host: str, attenuation_type: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create or update an attenuation object type (POST .../attenuation-object-type).

        Consequence: the type is stored on the console, and its attenuation applies wherever
        plans use that object type.

        Route: /proxy/innerspace/api/project/attenuation-object-type. The type is
        free-form and sent as given. An empty body fails before any request. Returns the
        upstream body verbatim. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny refuses
        it before any request. dry-run policy returns a dry-run preview {status: "dry_run", dryRun,
        sent: false, message, preview: {method, path, params, body}}.

        Required arguments: host, attenuation_type (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            attenuation_type: Type fields, e.g. {"id": "cabinet", "attenuation": 6}.
                Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await update_innerspace_attenuation_type(client, registry, host, attenuation_type)

    @mcp.tool(name="import_innerspace_dc_shapes", annotations=WRITE)
    async def _import_innerspace_dc_shapes(
        host: str, site_id: str, body: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Import design-center shapes into InnerSpace (POST .../api/import/dc-shapes).

        Consequence: the imported shapes become plans under site_id (data.planIds); failed
        maps are listed in mapFailures and can be retried with retry_innerspace_plan_maps.

        Sends siteId as a query parameter and the optional free-form body after removing
        additive underscore-prefixed keys and masked credential fields.
        Returns the upstream body verbatim ({data: {planIds, mapFailures}}). Write: sent
        once, never retried. UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy
        returns a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Required arguments: host, site_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site_id: UniFi site id (siteId query), e.g. "default".
            body: Optional free-form request body, e.g. {"shapes": []}; additive keys and
                masked credential fields are removed before sending.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await import_innerspace_dc_shapes(client, registry, host, site_id, body)

    @mcp.tool(name="retry_innerspace_plan_maps", annotations=WRITE)
    async def _retry_innerspace_plan_maps(host: str, site_id: str, confirm: bool = False) -> Any:
        """Retry failed InnerSpace plan map imports (POST .../api/import/retry-maps).

        Consequence: the console re-runs the failed map imports of site_id, which may add
        the plans they produce.

        Sends siteId as a query parameter and no body. Returns the upstream body
        verbatim. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny refuses it before any
        request. dry-run policy returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}}.

        Required arguments: host, site_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site_id: UniFi site id (siteId query), e.g. "default".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await retry_innerspace_plan_maps(client, registry, host, site_id)

    @mcp.tool(name="import_innerspace_shared_project", annotations=WRITE)
    async def _import_innerspace_shared_project(
        host: str, token: str, site_id: str, confirm: bool = False
    ) -> Any:
        """Import a shared InnerSpace project (POST .../api/import/projects/{token}).

        Consequence: a copy of the shared project is added to the console under site_id;
        existing projects are not changed.

        The share token is a UUID path segment (checked before any request, never echoed
        in that refusal) and siteId a query parameter. Returns the upstream body verbatim.
        Write: sent once, never retried. UNIFI_WRITE_POLICY=deny refuses it before any request.
        dry-run policy returns a dry-run preview {status: "dry_run", dryRun, sent: false, message,
        preview: {method, path, params, body}}.

        Required arguments: host, token, site_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            token: Share token (UUID), e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            site_id: UniFi site id (siteId query), e.g. "default".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await import_innerspace_shared_project(client, registry, host, token, site_id)

    @mcp.tool(name="transform_innerspace_shapes", annotations=WRITE)
    async def _transform_innerspace_shapes(
        host: str,
        transform: dict[str, Any],
        mode: str | None = None,
        socket_id: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Move, rotate or otherwise change InnerSpace shapes (POST .../api/shape/change).

        Consequence: the shapes change in the stored project at once; there is no undo
        through this tool.

        The transform data is free-form and sent as the body, with mode added when
        given; socket_id is sent as the socketId query. An empty transform fails before
        any request. Returns the upstream body verbatim. Write: sent once, never retried.
        UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Required arguments: host, transform (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            transform: Transform data, e.g. {"ids": ["shape-1"], "translate": {"x": 1,
                "y": 0}}. Free-form object.
            mode: Optional mode added to the body (a 'mode' key also in transform fails before
                any request), e.g. "3D".
            socket_id: Optional socketId query of the editor session, e.g. "abc123".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await transform_innerspace_shapes(client, registry, host, transform, mode, socket_id)

    @mcp.tool(name="export_innerspace_backup", annotations=WRITE)
    async def _export_innerspace_backup(host: str, directory: str, confirm: bool = False) -> Any:
        """Export an InnerSpace backup on the console (POST .../api/ucore/backup/export).

        Consequence: the export is written as a file to directory on the console, using
        its storage; InnerSpace data is unchanged.

        Sends {dir}. The route may need a console session rather than an API key; an
        upstream 401/403 is raised with its full reason. Returns the upstream body
        verbatim. Write: sent once, never retried. UNIFI_WRITE_POLICY=deny refuses it before any
        request. dry-run policy returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}}.

        Required arguments: host, directory (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            directory: Backup directory on the console (dir), e.g. "/data/backup".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await export_innerspace_backup(client, registry, host, directory)

    @mcp.tool(name="import_innerspace_backup", annotations=WRITE)
    async def _import_innerspace_backup(host: str, directory: str, confirm: bool = False) -> Any:
        """Restore an InnerSpace backup on the console (POST .../api/ucore/backup/import).

        Consequence: the InnerSpace data is replaced by the backup. Sends {dir}. The route
        may need a console session rather than an API key; an upstream 401/403 is raised
        with its full reason. Returns the upstream body verbatim. Write: sent once, never
        retried. UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a
        dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path,
        params, body}}.

        Required arguments: host, directory (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            directory: Backup directory on the console (dir), e.g. "/data/backup".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await import_innerspace_backup(client, registry, host, directory)

    @mcp.tool(name="create_innerspace_support_dump", annotations=WRITE)
    async def _create_innerspace_support_dump(
        host: str, directory: str, confirm: bool = False
    ) -> Any:
        """Write an InnerSpace support dump on the console (POST .../api/ucore/support-dump).

        Sends {dir}. Returns the upstream body verbatim. Write: sent once, never retried.
        UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Required arguments: host, directory (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            directory: Output directory on the console (dir), e.g. "/data/support".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await create_innerspace_support_dump(client, registry, host, directory)

    @mcp.tool(name="clean_innerspace_storage", annotations=WRITE)
    async def _clean_innerspace_storage(host: str, confirm: bool = False) -> Any:
        """Clean InnerSpace storage on the console (POST .../api/ucore/storage/clean).

        Consequence: the application removes stored files it no longer references. Sends
        no body. Returns the upstream body verbatim. Write: sent once, never retried.
        UNIFI_WRITE_POLICY=deny refuses it before any request. dry-run policy returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await clean_innerspace_storage(client, registry, host)
