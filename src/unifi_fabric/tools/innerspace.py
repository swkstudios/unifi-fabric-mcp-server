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
floor-plan image/asset URLs are passed through unchanged. See the pass-through
invariant in ``CLAUDE.md`` — the server is a faithful access layer and does not
withhold data from its caller.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from ..client import UniFiClient, UniFiConnectionError, validate_id
from ..registry import Registry

# Documented "UniFi InnerSpace Integration API" (v1.3.23) connector base. This is
# the officially published, GET-only surface
# (https://developer.ui.com/innerspace/.../openapi.json) and is tried FIRST.
INNERSPACE_INTEGRATION_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace/integration"

# Legacy, UNDOCUMENTED connector base (``/proxy/innerspace/api/*``). This is what
# the tools originally called; UniFi appears to have cut connector relay for it
# when it formalized the integration surface, which matches the 2026-08-09 403
# regression. Kept as a fallback only.
INNERSPACE_PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace/api"

_VALID_MODES = ("2D", "3D")

#: Positive allowlist for InnerSpace asset filenames. Published asset filenames are drawn
#: from this charset — UUID-named images (for example the illustrative
#: ``11111111-1111-4111-8111-111111111111.png``) and slugs such as ``2DPreview.svg``.
_ASSET_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

#: Inline-response cap for ``get_innerspace_asset``. A floor-plan image at or below
#: this size is returned base64-encoded inline (mirroring the Protect snapshot /
#: recognition-crop tools); a larger asset returns metadata only, with the connector
#: path to fetch it out-of-band, so a single MCP response is never unbounded.
MAX_ASSET_INLINE_BYTES = 10 * 1024 * 1024


def _proxy(host_id: str, path: str) -> str:
    return INNERSPACE_PROXY_BASE.format(host_id=host_id) + path


def _integration_proxy(host_id: str, path: str) -> str:
    return INNERSPACE_INTEGRATION_BASE.format(host_id=host_id) + path


def _unwrap_project(raw: Any) -> dict[str, Any]:
    """Return the project document, unwrapping the ``{"data": {…}}`` envelope.

    BOTH the documented integration ``/v1/project`` and the legacy ``/api/project``
    responses wrap the project in a ``data`` envelope (per the published OpenAPI
    schema and the 2026-08-02 live capture). Reading shapes/plans at the top level
    then yields nothing. Unwrap when ``data`` is a dict carrying ``shapes`` so all
    downstream tools see the project at the level they expect; a genuinely
    top-level payload (no such envelope) is returned unchanged.
    """
    project = raw if isinstance(raw, dict) else {"data": raw}
    inner = project.get("data")
    if isinstance(inner, dict) and "shapes" in inner:
        return inner
    return project


def _is_namespace_forbidden(message: str) -> bool:
    """True when an error looks like the connector-namespace 403 (not a 5xx/timeout)."""
    lowered = message.lower()
    return "host not found" in lowered or "forbidden" in lowered


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
    """Fetch the InnerSpace project document, preferring the documented API.

    Path preference (both accept ``mode=2D|3D``, default 3D):
    1. The documented **integration** path ``…/proxy/innerspace/integration/v1/project``
       (published "UniFi InnerSpace Integration API", GET-only). Tried FIRST.
    2. The legacy, undocumented ``…/proxy/innerspace/api/project`` — fallback only.

    UniFi appears to have formalized the integration surface and cut connector
    relay for the old ``/api/*`` route, which matches the 2026-08-09 regression
    where ``/api/project`` began returning HTTP 403 ``host not found`` on a
    console whose host id + key still worked for the ``network``/``protect``
    namespaces.

    Fallback rule: a namespace-style rejection (403 / ``host not found`` /
    ``forbidden``) on the integration path is treated as "this route is not
    relayed for this key" and the legacy path is tried. Any other error (5xx,
    timeout, network) is surfaced immediately — it is not the namespace
    regression and must not be masked by a second attempt. If BOTH paths are
    rejected, a single error naming both attempted paths and both plausible
    causes (truncated host id vs. connector no longer relaying InnerSpace) is
    raised — a message blaming only the host id would be misleading, since a
    full, resolvable id can still 403 here.
    """
    normalized = _normalize_mode(mode)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    integration_path = _integration_proxy(host_id, "/v1/project")
    legacy_path = _proxy(host_id, "/project")

    last_forbidden: UniFiConnectionError | None = None
    for path in (integration_path, legacy_path):
        try:
            raw = await client.get(path, key=key, params={"mode": normalized})
        except UniFiConnectionError as exc:
            if _is_namespace_forbidden(str(exc)):
                last_forbidden = exc
                continue  # try the next candidate path
            raise  # non-forbidden (5xx/timeout/network): surface immediately
        return _unwrap_project(raw)

    raise UniFiConnectionError(
        "InnerSpace project request was rejected on BOTH the documented and legacy "
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

    On the documented ``/v1/project`` schema (issue #178) per-plan scale is no
    longer a top-level ``planScales`` map nor a field on the plan object — it lives
    on ``scale``-type shapes, each carrying ``planId``, ``scale`` (pixels per
    metre), ``computedScale``, ``height``, and the ``defaultScale`` /
    ``defaultHeight`` flags. This returns ``{planId: {scale, computedScale, height,
    defaultScale, defaultHeight}}`` (only the keys actually present), so the summary
    can recover per-plan scale and a ``plan_scales`` map from the new schema instead
    of reporting ``null``.
    """
    out: dict[str, dict[str, Any]] = {}
    for shape in shapes:
        if not isinstance(shape, dict) or shape.get("type") != "scale":
            continue
        plan_id = shape.get("planId")
        if plan_id is None:
            continue
        entry: dict[str, Any] = {}
        scale = shape.get("scale")
        if not isinstance(scale, (int, float)):
            scale = shape.get("computedScale")
        if isinstance(scale, (int, float)):
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
    documented Integration API no longer publishes per-plan scale on the plan
    object — it falls back to the ``scale`` shape for this plan id from
    ``scale_by_plan`` (see ``_scale_by_plan``). Returns ``None`` only when neither
    source carries a numeric scale.
    """
    for candidate in (plan.get("scale"), plan.get("planScale"), plan.get("planScales")):
        if isinstance(candidate, dict):
            value = candidate.get("scale")
            if isinstance(value, (int, float)):
                return value
        elif isinstance(candidate, (int, float)):
            return candidate
    if scale_by_plan:
        plan_id = plan.get("id")
        if plan_id is not None:
            entry = scale_by_plan.get(str(plan_id))
            if entry is not None and isinstance(entry.get("scale"), (int, float)):
                return entry["scale"]
    return None


async def get_innerspace_project(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """Return the full InnerSpace project geometry for a console.

    mode: '3D' (default; device shapes carry real metric mounting heights) or
    '2D' (device shapes are flattened to z=0). This is the complete ~66 KB
    document; call get_innerspace_summary first if you only need an inventory.
    Returned verbatim, including device meta.mac / meta.ip and floor-plan asset URLs.
    """
    project = await _fetch_project(client, registry, host, mode)
    return {"mode": _normalize_mode(mode), "project": project}


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

    shapes = project.get("shapes") or []
    shape_counts: dict[str, int] = {}
    wall_variants: dict[str, int] = {}
    for shape in shapes:
        if not isinstance(shape, dict):
            continue
        stype = str(shape.get("type", "unknown"))
        shape_counts[stype] = shape_counts.get(stype, 0) + 1
        if stype == "wall":
            variant = str(shape.get("variant", "unknown"))
            wall_variants[variant] = wall_variants.get(variant, 0) + 1

    # Per-plan scale moved onto `scale`-type shapes in the documented Integration
    # API (issue #178). Index them so plans and the plan_scales map can recover it.
    scale_by_plan = _scale_by_plan(shapes)

    plans = project.get("plans") or []
    plan_summaries: list[dict[str, Any]] = []
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        plan_summaries.append(
            {
                "ordering": plan.get("ordering"),
                "name": plan.get("name") or plan.get("title"),
                "scale": _plan_scale(plan, scale_by_plan),
            }
        )

    project_meta = project.get("project")
    project_meta = project_meta if isinstance(project_meta, dict) else {}

    def _count(key: str) -> int:
        value = project.get(key)
        return len(value) if isinstance(value, (list, dict)) else 0

    # Prefer the legacy top-level planScales map; on the documented schema it is
    # absent, so derive an equivalent {planId: {scale, height, …}} map from the
    # scale shapes instead of surfacing null (issue #178).
    plan_scales = project.get("planScales")
    if plan_scales is None and scale_by_plan:
        plan_scales = scale_by_plan

    # Legacy `unit`/`migrated` are retained (they exist on the /api payload); the
    # documented `project` object instead carries id/title/createdAt/updatedAt, so
    # surface those when present rather than reporting an all-null block (#178).
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
        "product_count": _count("products"),
        "wall_type_count": _count("wallTypes"),
        "attenuation_object_type_count": _count("attenuationObjectTypes"),
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
    shapes = project.get("shapes") or []
    devices = [
        shape for shape in shapes if isinstance(shape, dict) and shape.get("type") == "device"
    ]
    return {"mode": normalized, "devices": devices, "count": len(devices)}


# --- Integration-API-only read endpoints ------------------------------------
#
# floor_plans / access_points / switches / inventory / assets exist ONLY on the
# documented integration base (`…/proxy/innerspace/integration/v1/*`). Unlike
# `/v1/project` there is NO legacy `/api/*` equivalent, so these are fetched on the
# integration path only. They share the same connector namespace as `/v1/project`,
# so a namespace-style 403 (the 2026-08-09 regression) affects them identically —
# translated here to the same helpful, two-cause error.


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
    return []


def _integration_namespace_error(host: str, full_path: str) -> UniFiConnectionError:
    """The two-cause namespace-403 error, specialised for a single integration path."""
    return UniFiConnectionError(
        f"InnerSpace request to GET {full_path} was rejected with 'host not found' "
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
) -> list[dict[str, Any]]:
    """GET a documented integration list endpoint and return its array.

    Resolves the key + host id (multi-key aware), issues a single GET on the
    documented integration base, translates a namespace-style 403 to the helpful
    two-cause error, and returns the named array from the (optionally
    ``data``-wrapped) response.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    full_path = _integration_proxy(host_id, path)
    try:
        raw = await client.get(full_path, key=key, params=_site_params(site_id))
    except UniFiConnectionError as exc:
        if _is_namespace_forbidden(str(exc)):
            raise _integration_namespace_error(host, full_path) from exc
        raise
    return _extract_list(raw, array_key)


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
    ``origin_y``, and ``site_id`` when a siteId filter is applied. Returned verbatim.

    site_id: optional UniFi site filter — only floor plans whose product siteId
    matches are returned.
    """
    items = await _fetch_integration_list(
        client, registry, host, "/v1/floor_plans", "floor_plans", site_id
    )
    return {"floor_plans": items, "count": len(items)}


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
    orientation, 0-360 degrees), ``mount``, and ``status``. Returned verbatim,
    including mac/serial identifiers.

    site_id: optional UniFi site filter — only APs whose product siteId matches.
    """
    items = await _fetch_integration_list(
        client, registry, host, "/v1/access_points", "access_points", site_id
    )
    return {"access_points": items, "count": len(items)}


async def list_innerspace_switches(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List placed switches from a console's InnerSpace floor plans (Integration API).

    Each switch carries ``id``, ``name``, ``model``, ``type`` (``switch``), ``mac``,
    ``serial``, ``floor_plan_id``, ``x``/``y`` (position on the floor-plan image in
    pixels), and ``status``. Returned verbatim, including mac/serial identifiers.

    site_id: optional UniFi site filter — only switches whose product siteId matches.
    """
    items = await _fetch_integration_list(
        client, registry, host, "/v1/switches", "switches", site_id
    )
    return {"switches": items, "count": len(items)}


async def list_innerspace_inventory(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List UNPLACED device inventory for a console's InnerSpace project (Integration API).

    These are devices known to the project but not yet positioned on any floor plan.
    Each carries ``id``, ``name``, ``model``, ``mac``, and ``serial``. Returned
    verbatim, including mac/serial identifiers. The response array key is ``devices``.

    site_id: optional UniFi site filter — only inventory whose product siteId matches.
    """
    items = await _fetch_integration_list(
        client, registry, host, "/v1/inventory", "devices", site_id
    )
    return {"devices": items, "count": len(items)}


def _validate_asset_filename(filename: str) -> None:
    """Reject any asset filename outside a strict positive allowlist.

    Validated positively against ``^[A-Za-z0-9._-]+$`` rather than by blocklisting
    known-bad characters. Real InnerSpace asset filenames observed live are all
    drawn from this charset, and positive validation removes the encoded-traversal
    class of attack entirely: a name matching the allowlist cannot contain a path
    separator ('/' or '\\'), a percent sign (so ``%2F``-style encoded separators are
    impossible), whitespace, or any control character — there is nothing left for an
    upstream to decode into a traversal. '.' and '..' are rejected explicitly so a
    bare dot-name can never resolve to the current or parent directory.
    """
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("filename must be a non-empty string")
    if len(filename) > 255:
        raise ValueError(f"filename exceeds 255 characters ({len(filename)})")
    if filename in (".", ".."):
        raise ValueError(f"Invalid filename {filename!r}: must not be '.' or '..'")
    if not _ASSET_FILENAME_RE.match(filename):
        raise ValueError(
            f"Invalid filename {filename!r}: only ASCII letters, digits, '.', '_', "
            "and '-' are allowed"
        )


async def get_innerspace_asset(
    client: UniFiClient,
    registry: Registry,
    host: str,
    plan_id: str,
    filename: str,
) -> dict[str, Any]:
    """Download a floor-plan asset (image) from a console's InnerSpace project.

    Fetches the binary asset from the documented ``…/integration/v1/assets/{planId}/
    {filename}`` endpoint (the ``image_url`` on a floor plan resolves here). The
    bytes are returned base64-encoded inline under ``image_base64`` when the asset is
    at or below the 10 MiB inline cap; a larger asset returns metadata only
    (``image_base64`` = null) plus a ``note`` and the connector ``path`` to fetch it
    out-of-band, so a single MCP response is never unbounded. ``content_type`` is the
    upstream media type (typically image/jpeg or image/png).

    plan_id: the id in the ``{planId}`` segment of the floor plan's ``image_url`` (the
    value between ``/assets/`` and the trailing ``/{filename}``). This is the
    asset-group UUID and is NOT the floor plan's own ``id`` field -- the two differ, and
    passing the plan ``id`` returns HTTP 404 (verified live 2026-08). Parse both
    ``plan_id`` and ``filename`` out of ``image_url`` (from list_innerspace_floor_plans)
    rather than building them from the plan ``id``. The parameter is named ``plan_id``
    for backward compatibility; it is forwarded verbatim as the ``{planId}`` path segment.
    filename: the asset filename as published in the floor plan's ``image_url``.
    """
    validate_id(plan_id, "plan_id")
    _validate_asset_filename(filename)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    full_path = _integration_proxy(host_id, f"/v1/assets/{plan_id}/{filename}")
    try:
        content, content_type = await client.get_binary(full_path, key=key)
    except UniFiConnectionError as exc:
        if _is_namespace_forbidden(str(exc)):
            raise _integration_namespace_error(host, full_path) from exc
        raise
    # Known limitation: client.get_binary already buffered the whole body, so this
    # cap bounds the base64 payload we emit but not peak download RAM. A future
    # streaming get_binary with a running byte-count would abort an oversized asset
    # mid-download; see the note on client.get_binary. Not implemented this pass.
    size = len(content)
    result: dict[str, Any] = {
        "plan_id": plan_id,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": size,
        "path": full_path,
    }
    if size <= MAX_ASSET_INLINE_BYTES:
        result["image_base64"] = base64.b64encode(content).decode()
    else:
        result["image_base64"] = None
        result["note"] = (
            f"Asset is {size} bytes, exceeding the {MAX_ASSET_INLINE_BYTES}-byte inline cap; "
            "base64 omitted to bound the response. Retrieve it directly from the connector "
            "'path' with a binary-capable client."
        )
    return result
