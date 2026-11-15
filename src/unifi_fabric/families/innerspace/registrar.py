"""The innerspace family registrar: its tool wrappers, in registration order (the family-owned
layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ... import output_schemas
from ...tool_annotations import READ_ONLY, WRITE
from . import innerspace, innerspace_internal, placement_snapshot


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the placement_snapshot tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(
        annotations=READ_ONLY,
        output_schema=output_schemas.SELF_BUILT["get_unifi_placement_snapshot"],
    )
    async def get_unifi_placement_snapshot(host: str) -> dict[str, Any]:
        """Return a bounded, read-only UniFi topology and placement projection (unifi.placement-snapshot/v1). Unlike other tools' whole upstream bodies, this closed schema selects, renames and derives fields (a MAC-only device gets a SHA-256 source_id, withheld under redaction; device_type is a closed enum). Sources (GET only): InnerSpace 3D placement, Protect cameras/sensors, Site Manager inventory; no connector writes. Provenance has a 120-second freshness contract.

        Returns schema_version, generated_at, freshness, provenance, floors, walls, placed_devices, topology, placement_links, plus incomplete/incompleteReason if a source list stops short. Address/asset fields (ip/mac, floor image/model/zip/bin URLs) are included by default; only opt-in UNIFI_REDACT_SECRETS removes them and URL/IP/MAC/credential strings, counting each in _withheld (section.field/reason) with _withheld_how_to_obtain naming the source tool (both absent with redaction off). Records outside schema v1 (not_an_object, no_position, no_geometry, no_source_id, not_numeric) are counted in _unprojected with _unprojected_how_to_obtain. Duplicate Network devices merge onto Protect nodes (Network-only fields omitted). For full payloads use get_innerspace_project, list_innerspace_devices, list_cameras, list_sensors or list_devices. Reference: docs/TOOL-USAGE.md#get_unifi_placement_snapshot.

        Required arguments: host.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await placement_snapshot.get_unifi_placement_snapshot(client, registry, host)

    return {"get_unifi_placement_snapshot": get_unifi_placement_snapshot}


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the innerspace tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(
        annotations=READ_ONLY, output_schema=output_schemas.SELF_BUILT["get_innerspace_summary"]
    )
    async def get_innerspace_summary(
        host: str,
        mode: str = "3D",
    ) -> dict[str, Any]:
        """Inventory a console's InnerSpace floor-plan project without the full payload.

        Returns counts and structure: shape breakdown by type (wall / device / map /
        scale), per-floor plans with each plan's own scale, product and wall-material /
        attenuation-type dictionary sizes, and project metadata. Call this before
        get_innerspace_project when you only need to know what's present. Surfaces the
        multi-floor caveat: floors do not share a coordinate origin. Top-level keys: mode,
        shape_total, shape_counts, wall_variants, plan_count, plans, plan_scales, product_count,
        wall_type_count, attenuation_object_type_count (null when the document has no
        attenuationObjectTypes), project, multi_floor, and multi_floor_note when there are
        several plans.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            mode: '3D' (default; device shapes carry real metric mounting heights) or '2D'.
        """
        client, registry = deps_fn()
        return await innerspace.get_innerspace_summary(client, registry, host, mode)

    @mcp.tool(annotations=READ_ONLY)
    async def get_innerspace_project(
        host: str,
        mode: str = "3D",
        user_email: str | None = None,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """Return the full InnerSpace floor-plan project geometry for a console.

        The complete (~66 KB) project document: shapes, plans, products, wall types,
        and attenuation-object types. The upstream response object is returned verbatim
        (the documented API wraps the project under data; the legacy path returns it bare),
        including device meta.mac / meta.ip and floor-plan image/asset URLs. Prefer
        get_innerspace_summary first
        if you only need an inventory — this payload is large.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            mode: '3D' (default; device shapes carry real metric mounting heights) or '2D' (device
                shapes flattened to z=0). 3D is the only mode with real heights.
            user_email: Optional userEmail query of the legacy /api/project route, e.g.
                "admin@example.com". When it or site_id is given the legacy route is used.
            site_id: Optional siteId query of the legacy /api/project route, e.g. "default".
        """
        client, registry = deps_fn()
        return await innerspace.get_innerspace_project(
            client, registry, host, mode, user_email, site_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_innerspace_devices(
        host: str,
        mode: str = "3D",
    ) -> dict[str, Any]:
        """List placed device shapes from a console's InnerSpace floor-plan.

        Returns {shapes, _mode, _count}: shapes holds the project's device shapes verbatim, _mode the
        normalized mode argument and _count the number of shapes.

        Each mounted device's placement: mount, productId, title, position, and
        rotation (pov = heading/yaw, base = mount tilt). Returned verbatim, including
        device meta.mac / meta.ip. Use mode='3D' (default) for real metric mounting
        heights; mode='2D' flattens positions to z=0.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            mode: '3D' (default) or '2D'.
        """
        client, registry = deps_fn()
        return await innerspace.list_innerspace_devices(client, registry, host, mode)

    @mcp.tool(annotations=READ_ONLY)
    async def list_innerspace_floor_plans(
        host: str,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """List a console's InnerSpace floor plans (documented Integration API).

        Returns the upstream body verbatim (floor_plans and every other top-level key the API sends)
        plus the additive _count of floor_plans.

        Each floor plan carries id, name, floor_number, image_url (an asset path — fetch
        with get_innerspace_asset), ppm (pixels per metre, the scale for interpreting
        coordinates/heights), width/height (image pixels), origin_x/origin_y, and site_id
        when filtered. Returned verbatim.

        Example call (list_innerspace_floor_plans):
            {"host": "my-console"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
                siteId. Get it from list_local_sites (id).
        """
        client, registry = deps_fn()
        return await innerspace.list_innerspace_floor_plans(client, registry, host, site_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_innerspace_access_points(
        host: str,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """List placed access points from a console's InnerSpace floor plans (Integration API).

        Returns the upstream body verbatim (access_points and every other top-level key the API sends)
        plus the additive _count of access_points.

        Each AP carries id, name, model (SKU), mac, serial, floor_plan_id, x/y (pixels on
        the floor-plan image), height (mounting height in metres), azimuth (antenna
        orientation, 0-360 degrees), mount, and status. Returned verbatim, including
        mac/serial.

        Example call (list_innerspace_access_points):
            {"host": "my-console"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
                siteId. Get it from list_local_sites (id).
        """
        client, registry = deps_fn()
        return await innerspace.list_innerspace_access_points(client, registry, host, site_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_innerspace_switches(
        host: str,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """List placed switches from a console's InnerSpace floor plans (Integration API).

        Returns the upstream body verbatim (switches and every other top-level key the API sends) plus
        the additive _count of switches.

        Each switch carries id, name, model, type (switch), mac, serial, floor_plan_id,
        x/y (pixels on the floor-plan image), and status. Returned verbatim, including
        mac/serial.

        Example call (list_innerspace_switches):
            {"host": "my-console"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
                siteId. Get it from list_local_sites (id).
        """
        client, registry = deps_fn()
        return await innerspace.list_innerspace_switches(client, registry, host, site_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_innerspace_inventory(
        host: str,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """List UNPLACED device inventory for a console's InnerSpace project (Integration API).

        Returns the upstream body verbatim (devices and every other top-level key the API sends) plus
        the additive _count of devices.

        Devices known to the project but not yet positioned on a floor plan. Each carries
        id, name, model, mac, and serial. Returned verbatim, including mac/serial. The
        response array key is 'devices'.

        Example call (list_innerspace_inventory):
            {"host": "my-console"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
                siteId. Get it from list_local_sites (id).
        """
        client, registry = deps_fn()
        return await innerspace.list_innerspace_inventory(client, registry, host, site_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_innerspace_asset(
        host: str,
        plan_id: str,
        filename: str,
        metadata_only: bool = False,
    ) -> dict[str, Any]:
        """Download a floor-plan asset (image) from a console's InnerSpace project via the documented .../integration/v1/assets/{planId}/{filename} endpoint (a floor plan's image_url resolves here).

        Returns {_plan_id, _filename, path, content_type, size_bytes, image_base64}: the complete bytes base64-encoded (no size cap) with the upstream Content-Type (typically image/jpeg or image/png; null when none) and size; _plan_id/_filename echo the arguments. metadata_only=true leaves out the bytes: same keys, image_base64=null.

        `plan_id` is the id in the {planId} segment of the floor plan's image_url (between '/assets/' and the trailing '/{filename}'): the asset-group UUID, NOT the floor plan's own 'id' (passing that returns HTTP 404). Parse both plan_id and filename from image_url (from list_innerspace_floor_plans).

        Example call (get_innerspace_asset):
            {"host": "my-console", "plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "filename": "plan.png"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            plan_id: Asset-group UUID parsed from a floor plan's image_url
                (/assets/{planId}/{filename}). NOT the floor plan id. From list_innerspace_floor_plans.
            filename: Filename segment from the floor plan's image_url (after /assets/{planId}/), as
                the plain (decoded) name, e.g. "2DPreview.svg"; the tool percent-encodes it. If that
                segment carries %XX escapes, pass it percent-decoded ("my%20plan.png" -> "my plan.png"),
                or the escapes are sent literally (%25XX).
            metadata_only: Optional. True leaves out the image bytes: every other key is returned
                and image_base64 is null. Default false: the full image is returned.
        """
        client, registry = deps_fn()
        return await innerspace.get_innerspace_asset(
            client, registry, host, plan_id, filename, metadata_only=metadata_only
        )

    return {
        "get_innerspace_summary": get_innerspace_summary,
        "get_innerspace_project": get_innerspace_project,
        "list_innerspace_devices": list_innerspace_devices,
        "list_innerspace_floor_plans": list_innerspace_floor_plans,
        "list_innerspace_access_points": list_innerspace_access_points,
        "list_innerspace_switches": list_innerspace_switches,
        "list_innerspace_inventory": list_innerspace_inventory,
        "get_innerspace_asset": get_innerspace_asset,
    }


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
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
        return await innerspace_internal.list_innerspace_doors(client, registry, host)

    @mcp.tool(name="get_innerspace_stats", annotations=READ_ONLY)
    async def _get_innerspace_stats(host: str) -> Any:
        """Get InnerSpace application statistics (GET /proxy/innerspace/api/stats).

        Returns the upstream body verbatim.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await innerspace_internal.get_innerspace_stats(client, registry, host)

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
        return await innerspace_internal.get_innerspace_ucore_manifest(client, registry, host)

    @mcp.tool(name="get_innerspace_ucore_status", annotations=READ_ONLY)
    async def _get_innerspace_ucore_status(host: str) -> Any:
        """Get the InnerSpace UniFi OS app status (GET /proxy/innerspace/api/ucore/status).

        Returns the upstream body verbatim.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await innerspace_internal.get_innerspace_ucore_status(client, registry, host)

    @mcp.tool(name="get_innerspace_health", annotations=READ_ONLY)
    async def _get_innerspace_health(host: str) -> Any:
        """Get the InnerSpace application health (GET /proxy/innerspace/health).

        Returns the upstream body verbatim.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await innerspace_internal.get_innerspace_health(client, registry, host)

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
        return await innerspace_internal.import_innerspace_captures(
            client, registry, host, title, site_id, captures
        )

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
        return await innerspace_internal.create_innerspace_plan(client, registry, host, plan)

    @mcp.tool(name="delete_innerspace_plan", annotations=WRITE)
    async def _delete_innerspace_plan(host: str, plan_id: str, confirm: bool = False) -> Any:
        """Delete an InnerSpace floor plan (DELETE .../api/project/plan/{planId}).

        Consequence: the plan and its shapes are removed; there is no undo.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. The upstream body is {data: {plans, shapes}}. A plan_id that is not a UUID fails
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
        return await innerspace_internal.delete_innerspace_plan(client, registry, host, plan_id)

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
        return await innerspace_internal.reorder_innerspace_plans(client, registry, host, plans)

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
        return await innerspace_internal.update_innerspace_plan_map(
            client, registry, host, plan_id, fields
        )

    @mcp.tool(name="update_innerspace_plan", annotations=WRITE)
    async def _update_innerspace_plan(
        host: str,
        plan_id: str,
        fields: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Update an InnerSpace floor plan (PATCH .../api/project/plan/{planId}). Write: sent once, never retried; UNIFI_WRITE_POLICY=deny refuses it before any request.

        Read-merge-write: reads the plan as get_innerspace_project does (documented integration route first, legacy .../api/project as fallback), lays fields over it (nested objects merge key by key) and PATCHes the whole plan. An unknown plan id fails listing the valid ids; an empty update or a non-UUID plan_id fails before any request. Returns the PATCH body verbatim (a non-object body under response) plus _verified (type-strict, leaf by leaf against a fresh read; null with _readAfterError when the re-read fails). A change already applied returns the plan as read plus _noOp: true, _verified: true and _note, without writing. When UNIFI_REDACT_SECRETS is enabled, a field still holding the redaction mask is not sent and is listed under _redactedFieldsNotSent. dry-run policy returns a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Required arguments: host, plan_id, fields (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            plan_id: Plan id (UUID), e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            fields: Plan fields to change, e.g. {"title": "First floor"}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        client, registry = deps_fn()
        return await innerspace_internal.update_innerspace_plan(
            client, registry, host, plan_id, fields
        )

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
        return await innerspace_internal.update_innerspace_project(client, registry, host, fields)

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
        return await innerspace_internal.upload_innerspace_plan_asset(
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
        return await innerspace_internal.update_innerspace_wall_type(
            client, registry, host, wall_type
        )

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
        return await innerspace_internal.update_innerspace_attenuation_type(
            client, registry, host, attenuation_type
        )

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
        return await innerspace_internal.import_innerspace_dc_shapes(
            client, registry, host, site_id, body
        )

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
        return await innerspace_internal.retry_innerspace_plan_maps(client, registry, host, site_id)

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
        return await innerspace_internal.import_innerspace_shared_project(
            client, registry, host, token, site_id
        )

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
        return await innerspace_internal.transform_innerspace_shapes(
            client, registry, host, transform, mode, socket_id
        )

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
        return await innerspace_internal.export_innerspace_backup(client, registry, host, directory)

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
        return await innerspace_internal.import_innerspace_backup(client, registry, host, directory)

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
        return await innerspace_internal.create_innerspace_support_dump(
            client, registry, host, directory
        )

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
        return await innerspace_internal.clean_innerspace_storage(client, registry, host)
