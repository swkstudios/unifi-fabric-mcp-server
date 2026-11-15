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
from typing import Any, NoReturn, cast

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    strip_additive_keys,
    upstream_error_value,
    validate_selector,
)
from ...config import APIKeyConfig
from ...read_only import ReadOnlyModeError, guard_action
from ...redaction import drop_and_note_masked_fields
from ...registry import Registry
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import (
    ADDITIVE_READ_AFTER_ERROR_KEY,
    VERIFIED_KEY,
    deletion_result,
    requested_leaves_match,
    requested_leaves_verdict,
    safe_read_after,
    short_circuit_no_op,
)
from ...write_body import require_unmasked_fields, require_update_fields
from . import innerspace
from .schemas import (  # the family's shapes (family-owned layout)
    INNERSPACE_APP_BASE,
)

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
        if exc.status != 403 or "errors.ucore.access" not in str(exc):
            raise
        raise type(exc)(
            f"{exc}; InnerSpace refuses this route via the connector proxy, so the key is not the "
            "cause and you cannot fix it here; get_innerspace_ucore_status works on that path",
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
