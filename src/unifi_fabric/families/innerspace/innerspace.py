"""UniFi InnerSpace tools — floor-plan project geometry via the connector proxy.

InnerSpace is the spatial/floor-plan application exposed on a UniFi console. The
connector relays its ``/api/project`` document, which describes the site as a set
of *shapes* (walls, mounted devices, a floor-plan map, a scale reference), the
per-floor *plans*, the product catalogue, and the wall-material / attenuation
type dictionaries.

The whole model is delivered as a single project document. Two render modes are
available and they are NOT interchangeable:

- ``mode="2D"`` returns device shapes with ``z = 0`` (floor-plan view).
- ``mode="3D"`` returns real metric mounting heights on device shapes.

3D is therefore the only mode carrying height information, so it is the default.

The project document is returned verbatim: device ``meta.mac`` / ``meta.ip`` and
floor-plan image/asset URLs are passed through unchanged. The server is a faithful
access layer and does not withhold data from its caller.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ... import output_schemas
from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_finite_number,
    path_segment,
    validate_id,
    validate_selector,
)
from ...registry import Registry
from ...shared_shapes._pagination import verbatim_list_result
from ...tool_annotations import READ_ONLY

# Documented "UniFi InnerSpace Integration API" (v1.3.23) connector base. This is
# the officially published, GET-only surface
# (https://developer.ui.com/innerspace/.../openapi.json) and is tried FIRST.
INNERSPACE_INTEGRATION_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace/integration"

# Legacy, UNDOCUMENTED connector base (``/proxy/innerspace/api/*``). The connector
# may answer 403 ``host not found`` for it while relaying the documented integration
# base, so it is used only as a fallback for ``/project``.
INNERSPACE_PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace/api"

_VALID_MODES = ("2D", "3D")


def exception_message(exc: BaseException) -> str:
    """Render the error and unique notes over its cause chain, as the MCP middleware does."""
    text = str(exc)
    notes: list[str] = []
    source: BaseException | None = exc
    seen: set[int] = set()
    while source is not None and id(source) not in seen:
        seen.add(id(source))
        for note in getattr(source, "__notes__", ()):
            if note not in notes:
                notes.append(note)
        source = source.__cause__
    return "\n\n".join((text, *notes)) if notes else text


def _proxy(host_id: str, path: str) -> str:
    return INNERSPACE_PROXY_BASE.format(host_id=host_id) + path


def _integration_proxy(host_id: str, path: str) -> str:
    return INNERSPACE_INTEGRATION_BASE.format(host_id=host_id) + path


#: Arrays every project document carries; each must be a JSON array.
_PROJECT_ARRAYS = ("shapes", "plans", "products", "wallTypes")


def _validated_project(raw: Any, path: str) -> dict[str, Any]:
    """Return the project document, unwrapped from its ``{"data": {…}}`` envelope.

    The documented integration ``/v1/project`` and the legacy ``/api/project`` both wrap
    the project in a ``data`` envelope (per the published OpenAPI schema); a payload
    without the envelope is the project itself. The shape is checked once, here, so no
    tool reads a missing collection as empty: the document must be an object, ``data``
    (when present) must be an object, ``shapes`` / ``plans`` / ``products`` /
    ``wallTypes`` must be arrays, ``attenuationObjectTypes`` must be an array when
    present, and ``project`` must be an object when present. Anything else raises
    naming the shape received. The document itself is returned unchanged.
    """
    if not isinstance(raw, dict):
        raise UniFiConnectionError(
            f"Unexpected InnerSpace project shape from GET {path}: expected an object, got "
            f"{describe_shape(raw)}"
        )
    project = raw
    if "data" in raw:
        project = raw["data"]
        if not isinstance(project, dict):
            raise UniFiConnectionError(
                f"Unexpected InnerSpace project shape from GET {path}: expected 'data' to be "
                f"the project object, got {describe_shape(project)}"
            )
    for key in _PROJECT_ARRAYS:
        if not isinstance(project.get(key), list):
            got = describe_shape(project[key]) if key in project else "no such key"
            raise UniFiConnectionError(
                f"Unexpected InnerSpace project shape from GET {path}: expected {key!r} to be "
                f"an array, got {got} (document keys: {sorted(project)})"
            )
    for key, kind, ok in (
        ("attenuationObjectTypes", "an array", list),
        ("project", "an object", dict),
    ):
        if key in project and not isinstance(project[key], ok):
            raise UniFiConnectionError(
                f"Unexpected InnerSpace project shape from GET {path}: expected {key!r} to be "
                f"{kind}, got {describe_shape(project[key])}"
            )
    return project


def _require_objects(items: list[Any], key: str) -> list[dict[str, Any]]:
    """``items`` (a project array) when every entry is an object; else raise naming the
    first entry that is not, so a count or selection over the array is never silently short.

    The published project schema lists ``shapes`` and ``plans`` as arrays of objects.
    """
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise UniFiConnectionError(
                f"Unexpected InnerSpace project shape: expected every {key!r} entry to be an "
                f"object, got {describe_shape(item)} at {key}[{index}] ({len(items)} entries)"
            )
    return items


class _NamespaceForbiddenError(UniFiConnectionError):
    """An augmented InnerSpace namespace rejection retains its upstream status."""

    status_code = 403


def _is_namespace_forbidden(message: str) -> bool:
    """True when an error looks like the connector-namespace 403 (not a 5xx/timeout)."""
    lowered = message.lower()
    return re.match(r"^http 403\b", lowered) is not None and "host not found" in lowered


def _normalize_mode(mode: str) -> str:
    """Validate and normalize the render mode to '2D' or '3D'."""
    normalized = str(mode).strip().upper()
    if normalized not in _VALID_MODES:
        raise ValueError(f"Invalid mode {mode!r}: expected one of {', '.join(_VALID_MODES)}")
    return normalized


async def _fetch_project(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mode: str,
) -> dict[str, Any]:
    """The InnerSpace project object (out of its ``data`` envelope), shape-checked."""
    _body, project = await _fetch_project_document(client, registry, host, mode)
    return project


#: Public name for internal consumers (the placement snapshot) that read the project
#: object itself; the ``get_innerspace_project`` tool returns the upstream body verbatim.
fetch_project = _fetch_project


async def _fetch_project_document(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mode: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fetch the InnerSpace project document, preferring the documented API.

    Returns ``(body, project)``: the upstream response object verbatim, and the project
    object it carries (``body["data"]`` when enveloped, else ``body``).

    Path preference (both accept ``mode=2D|3D``, default 3D):
    1. The documented **integration** path ``…/proxy/innerspace/integration/v1/project``
       (published "UniFi InnerSpace Integration API", GET-only). Tried FIRST.
    2. The legacy, undocumented ``…/proxy/innerspace/api/project`` — fallback only.

    The connector can answer HTTP 403 ``host not found`` for one of these routes on a
    console whose host id + key work for the ``network``/``protect`` namespaces.

    Fallback rule: a namespace-style rejection (403 / ``host not found``) on the
    integration path is treated as "this route is not relayed for this key" and the
    legacy path is tried. Any other error (5xx, timeout, network) is surfaced
    immediately — it is not the namespace regression and must not be masked by a
    second attempt. When the integration path
    was rejected and the legacy fallback then fails with any other error (a 404 on a
    console without the legacy route), that error is raised carrying the integration
    path's rejection too, so the first reason is never lost. If BOTH paths are
    rejected, a single error naming both attempted paths and both plausible
    causes (truncated host id vs. connector no longer relaying InnerSpace) is
    raised — a message blaming only the host id would be misleading, since a
    full, resolvable id can still 403 here. The document returned is shape-checked
    once by ``_validated_project``.
    """
    normalized = _normalize_mode(mode)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    integration_path = _integration_proxy(host_id, "/v1/project")
    legacy_path = _proxy(host_id, "/project")

    last_forbidden: UniFiConnectionError | None = None
    upstream_errors: list[str] = []
    for path in (integration_path, legacy_path):
        try:
            raw = await client.get(path, key=key, params={"mode": normalized})
        except UniFiConnectionError as exc:
            if _is_namespace_forbidden(str(exc)):
                last_forbidden = exc
                upstream_errors.append(str(exc))
                continue  # try the next candidate path
            if upstream_errors and exc.status == 403:
                # Both routes were denied, but only the first was established to be
                # the host-not-found namespace case. Preserve both actual responses.
                raise _NamespaceForbiddenError(
                    "InnerSpace project requests to BOTH connector paths returned HTTP 403: "
                    + " | ".join((*upstream_errors, str(exc)))
                ) from exc
            if upstream_errors:
                # The fallback failed differently: report both, the first reason intact.
                exc.add_note(
                    f"This was the legacy fallback. The documented integration "
                    f"path GET {integration_path}?mode={normalized} was rejected first: "
                    + " | ".join(upstream_errors)
                )
            raise  # non-forbidden (5xx/timeout/network): surface immediately
        try:
            project = _validated_project(raw, path)
        except UniFiConnectionError as exc:
            if upstream_errors:
                exc.add_note(
                    f"The documented integration path GET {integration_path}?mode={normalized} "
                    "was rejected first: " + " | ".join(upstream_errors)
                )
            raise
        return raw, project

    raise _NamespaceForbiddenError(
        "Upstream responses: "
        + " | ".join(upstream_errors)
        + "\n\nInnerSpace project request was rejected on BOTH the documented and legacy "
        "connector paths with 'host not found' (HTTP 403 forbidden). There are TWO "
        "known causes and this error does NOT by itself tell them apart:\n"
        "1. Host id incomplete/wrong: InnerSpace requires the full composite host id "
        "(MAC:numericId form), not a truncated one. Verify with list_hosts and pass "
        "the complete id or the console name.\n"
        "2. The connector no longer proxies the InnerSpace namespace for this key / "
        "EA program: a full, resolvable host id can still 403 here if api.ui.com has "
        "stopped relaying '/proxy/innerspace/' for the key in use, even while "
        "'/proxy/network/' and '/proxy/protect/' on the SAME host id + key return "
        "HTTP 200. To distinguish, confirm the host resolves and a sibling proxy tool "
        "(e.g. list_site_devices or list_cameras) works for this host; if they do, "
        "this is cause 2, an upstream/EA change, not a bad host id.\n"
        f"Attempted (in order): GET {integration_path}?mode={normalized} (documented "
        f"integration API), then GET {legacy_path}?mode={normalized} (legacy /api). "
        "This does NOT mean InnerSpace is uninstalled on the console."
    ) from last_forbidden


def _scale_by_plan(shapes: list[Any]) -> dict[str, dict[str, Any]]:
    """Index the documented Integration-API ``scale`` shapes by their ``planId``.

    On the documented ``/v1/project`` schema per-plan scale is neither a top-level
    ``planScales`` map nor a field on the plan object — it lives
    on ``scale``-type shapes, each carrying ``planId``, ``scale`` (pixels per
    metre), ``computedScale``, ``height``, and the ``defaultScale`` /
    ``defaultHeight`` flags. This returns ``{planId: {scale, computedScale, height,
    defaultScale, defaultHeight}}`` (only the keys actually present), so the summary
    can recover per-plan scale and a ``plan_scales`` map from the new schema instead
    of reporting ``null``.
    """
    out: dict[str, dict[str, Any]] = {}
    for shape in _require_objects(shapes, "shapes"):
        if shape.get("type") != "scale":
            continue
        plan_id = shape.get("planId")
        if plan_id is None:  # spec: planId is nullable; a null one names no plan to index
            continue
        entry: dict[str, Any] = {}
        # A candidate is a finite JSON number (never a boolean, NaN or Infinity);
        # the chosen value is passed through as the upstream sent it.
        scale = shape.get("scale")
        if not is_finite_number(scale):
            scale = shape.get("computedScale")
        if is_finite_number(scale):
            entry["scale"] = scale
        for key in ("computedScale", "height", "defaultScale", "defaultHeight"):
            if key in shape:
                entry[key] = shape.get(key)
        out[str(plan_id)] = entry
    return out


def _plan_scale(
    plan: dict[str, Any], scale_by_plan: dict[str, dict[str, Any]] | None = None
) -> float | int | None:
    """Best-effort extraction of a plan's own scale (source units per metre).

    Prefers a scale embedded on the plan (the legacy ``/api/project`` shape:
    ``scale`` / ``planScale`` / ``planScales``). When none is present — the
    documented Integration API does not publish per-plan scale on the plan
    object — it falls back to the ``scale`` shape for this plan id from
    ``scale_by_plan`` (see ``_scale_by_plan``). Returns ``None`` only when neither
    source carries a numeric scale.
    """
    for candidate in (plan.get("scale"), plan.get("planScale"), plan.get("planScales")):
        if isinstance(candidate, dict):
            value = candidate.get("scale")
            if is_finite_number(value):
                return value
        elif is_finite_number(candidate):
            return candidate
    if scale_by_plan:
        plan_id = plan.get("id")
        if plan_id is not None:
            entry = scale_by_plan.get(str(plan_id))
            if entry is not None and is_finite_number(entry.get("scale")):
                return entry["scale"]
    return None


async def get_innerspace_project(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mode: str = "3D",
    user_email: str | None = None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """Return the full InnerSpace project geometry for a console.

    mode: '3D' (default; device shapes carry real metric mounting heights) or
    '2D' (device shapes are flattened to z=0). This is the complete ~66 KB
    document; call get_innerspace_summary first if you only need an inventory.
    The upstream response object is returned verbatim (the documented API wraps the
    project in a ``data`` envelope; the legacy path returns the project itself),
    including device meta.mac / meta.ip and floor-plan asset URLs.

    user_email / site_id: the legacy ``/api/project`` route's ``userEmail`` / ``siteId``
    query parameters. The documented integration route takes only ``mode``, so when
    either is given the request goes to the legacy route (the one route that takes
    them), with ``mode`` too, and its body is returned verbatim.
    """
    if user_email is None and site_id is None:
        body, _project = await _fetch_project_document(client, registry, host, mode)
        return body
    params: dict[str, Any] = {"mode": _normalize_mode(mode)}
    for wire, argument, value in (
        ("userEmail", "user_email", user_email),
        ("siteId", "site_id", site_id),
    ):
        if value is not None:
            validate_selector(value, argument)
            params[wire] = value
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    path = _proxy(host_id, "/project")
    raw = await client.get(path, key=key, params=params)
    if not isinstance(raw, dict):
        raise UniFiConnectionError(
            f"Unexpected InnerSpace project shape from GET {path}: expected an object, got "
            f"{describe_shape(raw)}"
        )
    return raw


async def get_innerspace_summary(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """Return a structural inventory of a console's InnerSpace project.

    Counts and structure only — no full 66 KB payload. Reports the shape
    breakdown by type, per-floor plans (with each plan's own scale), the product
    and wall-material / attenuation-type dictionary sizes, and project metadata.
    Surfaces the multi-floor origin caveat: each plan carries its own scale and
    places its map at (0,0), so floors do NOT share a coordinate origin.

    mode: '3D' (default) or '2D'.
    """
    normalized = _normalize_mode(mode)
    project = await _fetch_project(client, registry, host, mode)

    # Totals over a malformed entry would be wrong, so a non-object entry raises.
    shapes = _require_objects(project["shapes"], "shapes")
    plans = _require_objects(project["plans"], "plans")
    shape_counts: dict[str, int] = {}
    wall_variants: dict[str, int] = {}
    for shape in shapes:
        stype = str(shape.get("type", "unknown"))
        shape_counts[stype] = shape_counts.get(stype, 0) + 1
        if stype == "wall":
            variant = str(shape.get("variant", "unknown"))
            wall_variants[variant] = wall_variants.get(variant, 0) + 1

    # The documented Integration API carries per-plan scale on `scale`-type shapes.
    # Index them so plans and the plan_scales map can recover it.
    scale_by_plan = _scale_by_plan(shapes)

    plan_summaries: list[dict[str, Any]] = []
    for plan in plans:
        plan_summaries.append(
            {
                "ordering": plan.get("ordering"),
                "name": plan.get("name") or plan.get("title"),
                "scale": _plan_scale(plan, scale_by_plan),
            }
        )

    project_meta = project.get("project") or {}
    attenuation = project.get("attenuationObjectTypes")

    # Prefer the legacy top-level planScales map; on the documented schema it is
    # absent, so derive an equivalent {planId: {scale, height, …}} map from the
    # scale shapes instead of surfacing null.
    plan_scales = project.get("planScales")
    if plan_scales is None and scale_by_plan:
        plan_scales = scale_by_plan

    # Legacy `unit`/`migrated` are reported (they exist on the /api payload); the
    # documented `project` object carries id/title/createdAt/updatedAt, so those are
    # surfaced when present rather than reporting an all-null block.
    project_block: dict[str, Any] = {
        "unit": project_meta.get("unit"),
        "migrated": project_meta.get("migrated"),
    }
    for key in ("id", "title", "createdAt", "updatedAt"):
        if key in project_meta:
            project_block[key] = project_meta.get(key)

    summary: dict[str, Any] = {
        "mode": normalized,
        "shape_total": sum(shape_counts.values()),
        "shape_counts": shape_counts,
        "wall_variants": wall_variants,
        "plan_count": len(plan_summaries),
        "plans": plan_summaries,
        "plan_scales": plan_scales,
        "product_count": len(project["products"]),
        "wall_type_count": len(project["wallTypes"]),
        # null (not 0) when the document carries no attenuationObjectTypes array
        "attenuation_object_type_count": len(attenuation) if attenuation is not None else None,
        "project": project_block,
        "multi_floor": len(plan_summaries) > 1,
    }
    if summary["multi_floor"]:
        summary["multi_floor_note"] = (
            "Multiple floor plans present. Each plan has its own scale and places its "
            "map at (0,0), so floors do NOT share a coordinate origin — align them by "
            "plan ordering, not by raw coordinates."
        )
    return summary


async def list_innerspace_devices(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """List placed device shapes from a console's InnerSpace project.

    Returns each mounted device's placement — mount, productId, title, position,
    and rotation (pov = heading/yaw, base = mount tilt) — passed through verbatim,
    including meta.mac / meta.ip. Use mode='3D' (default) for real metric mounting
    heights; mode='2D' flattens positions to z=0.
    """
    normalized = _normalize_mode(mode)
    project = await _fetch_project(client, registry, host, mode)
    # A non-object entry raises: its type is unknown, so dropping it could drop a device.
    shapes = _require_objects(project["shapes"], "shapes")
    devices = [shape for shape in shapes if shape.get("type") == "device"]
    return {"shapes": devices, "_mode": normalized, "_count": len(devices)}


# --- Integration-API-only read endpoints ------------------------------------
#
# floor_plans / access_points / switches / inventory / assets exist ONLY on the
# documented integration base (`…/proxy/innerspace/integration/v1/*`). Unlike
# `/v1/project` there is NO legacy `/api/*` equivalent, so these are fetched on the
# integration path only. They share the same connector namespace as `/v1/project`,
# so a namespace-style 403 affects them identically — translated here to the same
# two-cause error.


def _site_params(site_id: str | None) -> dict[str, Any] | None:
    """Return the optional ``siteId`` query param dict, or None when unset."""
    if site_id is None:
        return None
    return {"siteId": site_id}


def _extract_list(raw: Any, key: str) -> list[dict[str, Any]]:
    """Read a named list from the response, tolerating a ``{"data": {…}}`` envelope.

    The documented list endpoints return the array at the top level
    (``{"floor_plans": [...]}`` etc.), but `/v1/project` wraps its payload in a
    ``data`` envelope; this reads from whichever level carries the array so all
    tools behave the same under both shapes.
    """
    if isinstance(raw, dict):
        value = raw.get(key)
        if isinstance(value, list):
            return value
        inner = raw.get("data")
        if isinstance(inner, dict) and isinstance(inner.get(key), list):
            return inner[key]
    # An unexpected shape is an error, not an empty list (which must mean "no items").
    raise UniFiConnectionError(
        f"Unexpected InnerSpace response shape: expected a {key!r} array (top level or "
        f"under 'data'), got {describe_shape(raw)}"
    )


def _integration_namespace_error(full_path: str, upstream: Exception) -> UniFiConnectionError:
    """The two-cause namespace-403 hint, appended to the verbatim upstream error."""
    return _NamespaceForbiddenError(
        f"{upstream}\n\nInnerSpace request to GET {full_path} was rejected with 'host not found' "
        "(HTTP 403 forbidden). This is a documented InnerSpace Integration API endpoint on "
        "the 'innerspace' connector namespace; the same 403 that affects /v1/project affects "
        "it. There are TWO known causes and this error does not by itself tell them apart:\n"
        "1. Host id incomplete/wrong: InnerSpace requires the full composite host id "
        "(MAC:numericId form). Verify with list_hosts and pass the complete id or the console "
        "name.\n"
        "2. The connector no longer proxies the InnerSpace namespace for this key / EA program: "
        "a full, resolvable host id can still 403 here if api.ui.com has stopped relaying "
        "'/proxy/innerspace/' for the key in use, even while '/proxy/network/' and "
        "'/proxy/protect/' on the SAME host id + key return HTTP 200. Confirm a sibling proxy "
        "tool (e.g. list_site_devices or list_cameras) works for this host to distinguish."
    )


async def _fetch_integration_list(
    client: UniFiClient,
    registry: Registry,
    host: str,
    path: str,
    array_key: str,
    site_id: str | None,
) -> dict[str, Any]:
    """GET a documented integration list endpoint; return the body verbatim plus ``_count``.

    Resolves the key + host id (multi-key aware), issues a single GET on the
    documented integration base, translates a namespace-style 403 to the helpful
    two-cause error, and returns the upstream body unchanged (every top-level key kept)
    with the additive ``_count`` of the named array (read at the top level or under a
    ``data`` wrapper; an unexpected shape raises). ``site_id`` is checked before any
    request.
    """
    if site_id is not None:
        validate_selector(site_id, "site_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    full_path = _integration_proxy(host_id, path)
    try:
        raw = await client.get(full_path, key=key, params=_site_params(site_id))
    except UniFiConnectionError as exc:
        if _is_namespace_forbidden(str(exc)):
            raise _integration_namespace_error(full_path, exc) from exc
        raise
    return verbatim_list_result(raw, _extract_list(raw, array_key), full_path)


async def list_innerspace_floor_plans(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List a console's InnerSpace floor plans (documented Integration API).

    Each floor plan carries ``id``, ``name``, ``floor_number`` (ordering index,
    omitted when 0), ``image_url`` (an asset path under
    ``…/integration/v1/assets/{planId}/{filename}`` — fetch with
    get_innerspace_asset), ``ppm`` (pixels per metre — the scale needed to interpret
    coordinates/heights), ``width``/``height`` (image pixels), ``origin_x``/
    ``origin_y``, and ``site_id`` when a siteId filter is applied. The upstream body is
    returned verbatim (``floor_plans`` and every other top-level key) plus ``_count``.

    site_id: optional UniFi site filter — only floor plans whose product siteId
    matches are returned.
    """
    return await _fetch_integration_list(
        client, registry, host, "/v1/floor_plans", "floor_plans", site_id
    )


async def list_innerspace_access_points(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List placed access points from a console's InnerSpace floor plans (Integration API).

    Each access point carries ``id``, ``name``, ``model`` (SKU), ``mac``, ``serial``,
    ``floor_plan_id``, ``x``/``y`` (position on the floor-plan image in pixels),
    ``height`` (mounting height in metres above the floor), ``azimuth`` (antenna
    orientation, 0-360 degrees), ``mount``, and ``status``. The upstream body is returned
    verbatim (``access_points`` and every other top-level key, mac/serial included) plus
    ``_count``.

    site_id: optional UniFi site filter — only APs whose product siteId matches.
    """
    return await _fetch_integration_list(
        client, registry, host, "/v1/access_points", "access_points", site_id
    )


async def list_innerspace_switches(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List placed switches from a console's InnerSpace floor plans (Integration API).

    Each switch carries ``id``, ``name``, ``model``, ``type`` (``switch``), ``mac``,
    ``serial``, ``floor_plan_id``, ``x``/``y`` (position on the floor-plan image in
    pixels), and ``status``. The upstream body is returned verbatim (``switches`` and every
    other top-level key, mac/serial included) plus ``_count``.

    site_id: optional UniFi site filter — only switches whose product siteId matches.
    """
    return await _fetch_integration_list(
        client, registry, host, "/v1/switches", "switches", site_id
    )


async def list_innerspace_inventory(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List UNPLACED device inventory for a console's InnerSpace project (Integration API).

    These are devices known to the project but not yet positioned on any floor plan.
    Each carries ``id``, ``name``, ``model``, ``mac``, and ``serial``. The upstream body
    is returned verbatim (the array key is ``devices``; every other top-level key kept,
    mac/serial included) plus ``_count``.

    site_id: optional UniFi site filter — only inventory whose product siteId matches.
    """
    return await _fetch_integration_list(
        client, registry, host, "/v1/inventory", "devices", site_id
    )


def _asset_filename_segment(filename: str) -> str:
    """The asset filename validated against its spec and encoded as one path segment.

    The published ``{filename}`` is a string of 1-255 characters, so any such name
    without a control character is accepted (:func:`client.path_segment`): it is
    percent-encoded with nothing left safe (``/``, ``%`` and ``.`` included), so it can
    never add a segment or be decoded into a traversal, and a name that is (or decodes to)
    a ``.`` / ``..`` segment fails before any request.
    """
    try:
        return path_segment(filename, "filename", max_length=255)
    except ValueError as exc:
        raise ValueError(
            f"{exc}. Pass the asset filename exactly as it appears after the last '/' of the "
            "floor plan's image_url (e.g. 'floorplan.png')."
        ) from exc


async def get_innerspace_asset(
    client: UniFiClient,
    registry: Registry,
    host: str,
    plan_id: str,
    filename: str,
    metadata_only: bool = False,
) -> dict[str, Any]:
    """Download a floor-plan asset (image) from a console's InnerSpace project.

    Fetches the binary asset from the documented ``…/integration/v1/assets/{planId}/
    {filename}`` endpoint (the ``image_url`` on a floor plan resolves here) and returns
    the complete bytes base64-encoded under ``image_base64``, whatever the size — there
    is no size cap. Pass ``metadata_only=True`` to leave out the bytes: the same keys
    come back (``_plan_id``, ``_filename``, ``path``, ``content_type``, ``size_bytes``)
    with ``image_base64`` = null. ``content_type``
    is the upstream media type (typically image/jpeg or image/png), or None when the
    upstream sends no Content-Type.

    plan_id: the id in the ``{planId}`` segment of the floor plan's ``image_url`` (the
    value between ``/assets/`` and the trailing ``/{filename}``). This is the
    asset-group UUID and is NOT the floor plan's own ``id`` field -- the two differ, and
    passing the plan ``id`` returns HTTP 404. Parse both ``plan_id`` and ``filename`` out
    of ``image_url`` (from list_innerspace_floor_plans) rather than building them from
    the plan ``id``. ``plan_id`` is forwarded verbatim as the ``{planId}`` path segment.
    filename: the asset filename as published in the floor plan's ``image_url``, as the
    plain (decoded) name: it is percent-encoded here as one path segment. The vendored spec
    and the recorded fixtures show no encoded ``image_url`` (the recorded asset is
    ``2DPreview.svg``), so nothing is decoded: a segment carrying ``%XX`` escapes must be
    passed percent-decoded, or the escapes are sent literally (``%25XX``).
    """
    validate_id(plan_id, "plan_id")
    filename_seg = _asset_filename_segment(filename)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    full_path = _integration_proxy(host_id, f"/v1/assets/{plan_id}/{filename_seg}")
    try:
        content, content_type = await client.get_binary(full_path, key=key)
    except UniFiConnectionError as exc:
        if _is_namespace_forbidden(str(exc)):
            raise _integration_namespace_error(full_path, exc) from exc
        raise
    return {
        "_plan_id": plan_id,
        "_filename": filename,
        "content_type": content_type,
        "size_bytes": len(content),
        "path": full_path,
        "image_base64": None if metadata_only else base64.b64encode(content).decode(),
    }


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import innerspace  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
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
        """Download a floor-plan asset (image) from a console's InnerSpace project.

        Returns {_plan_id, _filename, path, content_type, size_bytes, image_base64}: the asset bytes
        complete, base64-encoded, with the upstream Content-Type and size; _plan_id / _filename echo the
        arguments.

        Fetches the binary asset from the documented …/integration/v1/assets/{planId}/
        {filename} endpoint (a floor plan's image_url resolves here). The complete bytes are
        returned base64-encoded under image_base64 whatever the size (no size cap). Pass
        metadata_only=true to leave out the bytes: the same keys come back with
        image_base64=null. content_type is the upstream media type (typically image/jpeg or
        image/png), or null when the upstream sends no Content-Type.

        `plan_id`: the id in the {planId} segment of the floor plan's image_url -- i.e. the
          value between '/assets/' and the trailing '/{filename}'. This is the asset-group
          UUID and is NOT the floor plan's own 'id' field (they differ); passing the plan
          'id' returns HTTP 404. Parse both plan_id and filename from image_url (from
          list_innerspace_floor_plans) rather than constructing them from the plan id.

        Example call (get_innerspace_asset):
            {
              "host": "my-console",
              "plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "filename": "plan.png"
            }

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
