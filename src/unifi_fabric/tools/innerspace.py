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

from typing import Any

from ..client import UniFiClient, UniFiConnectionError
from ..registry import Registry

INNERSPACE_PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace/api"

_VALID_MODES = ("2D", "3D")


def _proxy(host_id: str, path: str) -> str:
    return INNERSPACE_PROXY_BASE.format(host_id=host_id) + path


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
    """Fetch the raw InnerSpace project document for a console.

    Translates the truncated-host-id ``403 forbidden: host not found`` failure —
    the most common misuse — into an explanation that points at the host id
    rather than implying InnerSpace itself is unavailable.
    """
    normalized = _normalize_mode(mode)
    host_id = await registry.resolve_host_id(host)
    try:
        raw = await client.get(_proxy(host_id, "/project"), params={"mode": normalized})
    except UniFiConnectionError as exc:
        message = str(exc)
        if "host not found" in message.lower() or "forbidden" in message.lower():
            raise UniFiConnectionError(
                "InnerSpace project request was rejected with 'host not found' "
                "(HTTP 403 forbidden). This almost always means the console/host id is "
                "incomplete or wrong: InnerSpace requires the full composite host id "
                "(MAC:numericId form), not a truncated one. Verify the console with "
                "list_hosts and pass the complete id or the console name. This does NOT "
                "mean InnerSpace is unavailable on the console."
            ) from exc
        raise
    project = raw if isinstance(raw, dict) else {"data": raw}
    return project


def _plan_scale(plan: dict[str, Any]) -> float | int | None:
    """Best-effort extraction of a plan's own scale (source units per metre)."""
    for candidate in (plan.get("scale"), plan.get("planScale"), plan.get("planScales")):
        if isinstance(candidate, dict):
            value = candidate.get("scale")
            if isinstance(value, (int, float)):
                return value
        elif isinstance(candidate, (int, float)):
            return candidate
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

    plans = project.get("plans") or []
    plan_summaries: list[dict[str, Any]] = []
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        plan_summaries.append(
            {
                "ordering": plan.get("ordering"),
                "name": plan.get("name") or plan.get("title"),
                "scale": _plan_scale(plan),
            }
        )

    project_meta = project.get("project")
    project_meta = project_meta if isinstance(project_meta, dict) else {}

    def _count(key: str) -> int:
        value = project.get(key)
        return len(value) if isinstance(value, (list, dict)) else 0

    summary: dict[str, Any] = {
        "mode": normalized,
        "shape_total": sum(shape_counts.values()),
        "shape_counts": shape_counts,
        "wall_variants": wall_variants,
        "plan_count": len(plan_summaries),
        "plans": plan_summaries,
        "plan_scales": project.get("planScales"),
        "product_count": _count("products"),
        "wall_type_count": _count("wallTypes"),
        "attenuation_object_type_count": _count("attenuationObjectTypes"),
        "project": {
            "unit": project_meta.get("unit"),
            "migrated": project_meta.get("migrated"),
        },
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
