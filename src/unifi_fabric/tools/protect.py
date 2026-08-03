"""UniFi Protect tools — cameras, sensors, lights, chimes, viewers via connector proxy."""

from __future__ import annotations

import base64
import io
import re
from typing import Any

from ..client import UniFiClient, UniFiConnectionError, validate_id
from ..registry import Registry
from ._history_common import (
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
)
from ._pagination import collect_offset, mark_incomplete

PROTECT_PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/protect/integration/v1"

# Protect camera IDs are 24-char hex (Mongo ObjectId style). Used to tell an ID
# from a human-readable camera name when resolving the ``cameras`` filter.
_CAMERA_ID_RE = re.compile(r"^[A-Fa-f0-9]{24}$")

# smart_detect_types is only honored by the upstream /events endpoint when
# ``types`` is also constrained (verified live: passing smart_detect_types alone
# returns the UNFILTERED result set — a silent no-op). Rejecting that case turns
# the footgun into a loud, actionable error, mirroring require_epoch_seconds.
_SMART_DETECT_NEEDS_TYPES = (
    "smart_detect_types is only honored by the API when 'types' is also set to the "
    "relevant event type(s): use types='smartDetectZone' for "
    "person/vehicle/animal/package/face/licensePlate, or types='smartAudioDetect' for "
    "alrmSpeak/alrmSiren/alrmBark/alrmCarHorn. Passing smart_detect_types without types "
    "returns UNFILTERED results upstream, so it is rejected here rather than silently "
    "returning everything."
)

# The official Protect Integration API (PROTECT_PROXY_BASE, above) exposes events
# ONLY over WebSocket at /v1/subscribe/events and has no REST query endpoint. The
# private path below is the sole source of *historical* events over REST. Do not
# "correct" it to the integration path — that path cannot answer this query.
PROTECT_PRIVATE_BASE = "/v1/connector/consoles/{host_id}/proxy/protect/api"


def _proxy(host_id: str, path: str) -> str:
    return PROTECT_PROXY_BASE.format(host_id=host_id) + path


def _private(host_id: str, path: str) -> str:
    return PROTECT_PRIVATE_BASE.format(host_id=host_id) + path


# --- Historical Events (private REST path) ---


def _normalize_sensor_reference(event: Any) -> Any:
    """Promote metadata.sensorId.text to the top-level ``sensor`` field for sensor events.

    Sensor events set the top-level ``sensor`` field to null; the actual sensor
    reference lives at ``metadata.sensorId.text``. Callers filter and join on the
    sensor, so surface it in one predictable place while leaving metadata intact.
    """
    if not isinstance(event, dict) or event.get("sensor") is not None:
        return event
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        sensor_id = metadata.get("sensorId")
        if isinstance(sensor_id, dict) and sensor_id.get("text"):
            promoted = dict(event)
            promoted["sensor"] = sensor_id["text"]
            return promoted
    return event


async def _resolve_camera_refs(
    client: UniFiClient, host_id: str, refs: str | list[str]
) -> list[str]:
    """Resolve camera name(s) to ID(s) for the ``cameras`` filter; pass IDs through.

    Mirrors the name-or-ID convention used by ``resolve_host_id``/``resolve_site_id``.
    A reference that matches a known camera ID (or is 24-hex ID-shaped) passes through
    unchanged; a reference that matches a camera *name* (case-insensitive) resolves to
    its ID; anything else raises ValueError listing the available camera names rather
    than silently filtering to a non-existent camera (which returns everything/nothing).
    """
    ref_list = [refs] if isinstance(refs, str) else list(refs)
    data = await client.get(_proxy(host_id, "/cameras"))
    cams = data if isinstance(data, list) else data.get("data", [])
    by_id = {c["id"] for c in cams if isinstance(c, dict) and c.get("id")}
    by_name: dict[str, str] = {}
    for c in cams:
        if isinstance(c, dict) and c.get("name") and c.get("id"):
            by_name.setdefault(c["name"].casefold(), c["id"])
    resolved: list[str] = []
    for ref in ref_list:
        if ref in by_id or _CAMERA_ID_RE.match(ref):
            resolved.append(ref)
        elif ref.casefold() in by_name:
            resolved.append(by_name[ref.casefold()])
        else:
            available = sorted(c["name"] for c in cams if isinstance(c, dict) and c.get("name"))
            raise ValueError(
                f"Camera {ref!r} not found on host {host_id!r}. "
                f"Pass a camera ID or one of these names: {available}"
            )
    return resolved


async def list_protect_events(
    client: UniFiClient,
    registry: Registry,
    host: str,
    start: int,
    end: int,
    types: str | list[str] | None = None,
    cameras: str | list[str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    order_direction: str = "ASC",
    smart_detect_types: str | list[str] | None = None,
    categories: str | list[str] | None = None,
    without_descriptions: bool | None = None,
) -> dict[str, Any]:
    """Query historical Protect events via the private /proxy/protect/api/events REST path.

    start/end: epoch SECONDS (UTC); converted to milliseconds internally. Ranges are
    inclusive on both ends. order_direction "DESC" yields newest-first.

    Filters (all verified live to actually narrow the result set server-side):
    * ``types`` — event TYPE; single value or list. Verified-present values:
      ``motion``, ``smartDetectZone``, ``smartAudioDetect``, ``sensorOpened``,
      ``sensorClosed``, ``access``. An unrecognised value returns zero events.
    * ``smart_detect_types`` — the smart-detect SUBTYPE within smart events
      (``person``/``vehicle``/``animal``/``package``/``face``/``licensePlate`` on
      ``smartDetectZone``; ``alrmSpeak``/``alrmSiren``/``alrmBark``/``alrmCarHorn`` on
      ``smartAudioDetect``). This is a DIFFERENT upstream parameter from ``types`` —
      these values are NOT accepted by ``types``. The API only honours
      ``smart_detect_types`` when ``types`` is also set (passing it alone is a silent
      no-op upstream), so this tool rejects that combination with a clear error.
    * ``cameras`` — camera name(s) OR ID(s); single value or list. Names resolve to
      IDs (case-insensitive); an unknown name raises rather than filtering to nothing.
    * ``categories`` — event category; single value or list. Verified values:
      ``motion``, ``smart``, ``iot``, ``admin``. Unknown values are silently ignored
      by the upstream API (it validates against its own enum).
    * ``without_descriptions`` — when True, ask the API to omit the per-event
      ``description`` block (~16% smaller payload). Opt-in only; full fidelity is the
      default and this is never applied automatically.

    Pagination is offset-based (verified live: the endpoint returns a bare JSON array
    and honours offset/limit; a wide window holds tens of thousands of events and an
    unpaginated fetch times out on the device). By default every page is drained (in
    pages of 200) and the complete, time-ordered event set is returned; a large
    window therefore returns *all* matching events rather than only the first page.
    Pass offset or limit to fetch a single manual page instead. A capped drain
    (UNIFI_PAGINATE_MAX_PAGES) returns the events gathered so far with
    ``incomplete=true`` rather than truncating silently.
    """
    if smart_detect_types is not None and types is None:
        raise ValueError(_SMART_DETECT_NEEDS_TYPES)
    start_ms = seconds_to_millis(require_epoch_seconds(start, "start"))
    end_ms = seconds_to_millis(require_epoch_seconds(end, "end"))
    host_id = await registry.resolve_host_id(host)
    params: dict[str, Any] = {"start": start_ms, "end": end_ms}
    if types is not None:
        params["types"] = types
    if cameras is not None:
        params["cameras"] = await _resolve_camera_refs(client, host_id, cameras)
    if smart_detect_types is not None:
        params["smartDetectTypes"] = smart_detect_types
    if categories is not None:
        params["categories"] = categories
    if without_descriptions:
        params["withoutDescriptions"] = "true"
    if order_direction:
        params["orderDirection"] = order_direction
    try:
        collected = await collect_offset(
            client, _private(host_id, "/events"), params=params, offset=offset, limit=limit
        )
    except UniFiConnectionError as exc:
        raise translate_host_not_found(exc, host) from exc
    events = collected["items"]
    normalized = [_normalize_sensor_reference(event) for event in events]
    result: dict[str, Any] = {"events": normalized, "count": len(normalized)}
    return mark_incomplete(result, collected)


# --- Camera Info and Settings ---


async def list_cameras(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all cameras on a Protect console.

    This endpoint is not paginated: verified live it returns a bare JSON array with
    no offset/limit/count/totalCount envelope and no cursor, and offset/limit query
    params have no effect on the response. The array is the complete camera set, so
    the single fetch below returns everything and needs no drain.
    """
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, "/cameras"))
    cameras = data if isinstance(data, list) else data.get("data", [])
    return {"cameras": cameras, "count": len(cameras)}


async def get_camera(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect camera by ID."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/cameras/{camera_id}"))
    return data if isinstance(data, dict) else {"data": data}


async def update_camera(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect camera (name, recording mode, etc.)."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.patch(_proxy(host_id, f"/cameras/{camera_id}"), json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Camera Streams and Media ---


async def get_camera_snapshot(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Request a snapshot from a Protect camera. Returns base64-encoded JPEG image data."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    raw = await client.get_bytes(_proxy(host_id, f"/cameras/{camera_id}/snapshot"))
    return {
        "image_base64": base64.b64encode(raw).decode(),
        "content_type": "image/jpeg",
        "size_bytes": len(raw),
    }


async def get_rtsps_stream(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get existing RTSPS stream URLs for a Protect camera."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/cameras/{camera_id}/rtsps-stream"))
    return data if isinstance(data, dict) else {"data": data}


async def create_rtsps_stream(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    qualities: list[str],
) -> dict[str, Any]:
    """Create an RTSPS stream for a Protect camera."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    normalized = [q.lower() for q in qualities]
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/rtsps-stream"), json={"qualities": normalized}
    )
    return data if isinstance(data, dict) else {"data": data}


async def delete_rtsps_stream(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    qualities: list[str],
) -> None:
    """Delete an RTSPS stream for a Protect camera."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    normalized = [q.lower() for q in qualities]
    await client.delete(
        _proxy(host_id, f"/cameras/{camera_id}/rtsps-stream"), params={"qualities": normalized}
    )


# --- Camera Audio ---


async def talkback_start(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Start a talkback audio session on a Protect camera."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.post(_proxy(host_id, f"/cameras/{camera_id}/talkback-session"), json={})
    return data if isinstance(data, dict) else {"status": "ok"}


async def disable_mic_permanently(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Permanently disable the microphone on a Protect camera."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/disable-mic-permanently"), json={}
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Camera PTZ Control ---


async def ptz_goto(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    slot: int,
) -> dict[str, Any]:
    """Move a PTZ camera to a preset slot."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.post(_proxy(host_id, f"/cameras/{camera_id}/ptz/goto/{slot}"), json={})
    return data if isinstance(data, dict) else {"status": "ok"}


async def ptz_patrol_start(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    slot: int,
) -> dict[str, Any]:
    """Start a PTZ patrol on a preset slot."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/ptz/patrol/start/{slot}"), json={}
    )
    return data if isinstance(data, dict) else {"status": "ok"}


async def ptz_patrol_stop(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Stop the current PTZ patrol on a camera."""
    validate_id(camera_id, "camera_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.post(_proxy(host_id, f"/cameras/{camera_id}/ptz/patrol/stop"), json={})
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Sensors ---


async def list_sensors(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all sensors on a Protect console."""
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, "/sensors"))
    sensors = data if isinstance(data, list) else data.get("data", [])
    return {"sensors": sensors, "count": len(sensors)}


async def get_sensor(
    client: UniFiClient,
    registry: Registry,
    host: str,
    sensor_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect sensor by ID."""
    validate_id(sensor_id, "sensor_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/sensors/{sensor_id}"))
    return data if isinstance(data, dict) else {"data": data}


async def update_sensor(
    client: UniFiClient,
    registry: Registry,
    host: str,
    sensor_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect sensor."""
    validate_id(sensor_id, "sensor_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.patch(_proxy(host_id, f"/sensors/{sensor_id}"), json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Lights ---


async def list_lights(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all lights on a Protect console."""
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, "/lights"))
    lights = data if isinstance(data, list) else data.get("data", [])
    return {"lights": lights, "count": len(lights)}


async def get_light(
    client: UniFiClient,
    registry: Registry,
    host: str,
    light_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect light by ID."""
    validate_id(light_id, "light_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/lights/{light_id}"))
    return data if isinstance(data, dict) else {"data": data}


async def update_light(
    client: UniFiClient,
    registry: Registry,
    host: str,
    light_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect light."""
    validate_id(light_id, "light_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.patch(_proxy(host_id, f"/lights/{light_id}"), json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Chimes ---


async def list_chimes(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all chimes on a Protect console."""
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, "/chimes"))
    chimes = data if isinstance(data, list) else data.get("data", [])
    return {"chimes": chimes, "count": len(chimes)}


async def get_chime(
    client: UniFiClient,
    registry: Registry,
    host: str,
    chime_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect chime by ID."""
    validate_id(chime_id, "chime_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/chimes/{chime_id}"))
    return data if isinstance(data, dict) else {"data": data}


async def update_chime(
    client: UniFiClient,
    registry: Registry,
    host: str,
    chime_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect chime."""
    validate_id(chime_id, "chime_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.patch(_proxy(host_id, f"/chimes/{chime_id}"), json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Viewers ---


async def list_viewers(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all viewers on a Protect console."""
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, "/viewers"))
    viewers = data if isinstance(data, list) else data.get("data", [])
    return {"viewers": viewers, "count": len(viewers)}


async def get_viewer(
    client: UniFiClient,
    registry: Registry,
    host: str,
    viewer_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect viewer by ID."""
    validate_id(viewer_id, "viewer_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/viewers/{viewer_id}"))
    return data if isinstance(data, dict) else {"data": data}


async def update_viewer(
    client: UniFiClient,
    registry: Registry,
    host: str,
    viewer_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update settings for a Protect viewer."""
    validate_id(viewer_id, "viewer_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.patch(_proxy(host_id, f"/viewers/{viewer_id}"), json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Liveviews ---


async def list_liveviews(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all liveviews on a Protect console."""
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, "/liveviews"))
    liveviews = data if isinstance(data, list) else data.get("data", [])
    return {"liveviews": liveviews, "count": len(liveviews)}


async def get_liveview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    liveview_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect liveview by ID."""
    validate_id(liveview_id, "liveview_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/liveviews/{liveview_id}"))
    return data if isinstance(data, dict) else {"data": data}


async def create_liveview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    name: str,
    **fields: Any,
) -> dict[str, Any]:
    """Create a liveview on a Protect console."""
    host_id = await registry.resolve_host_id(host)
    payload: dict[str, Any] = {"name": name, **fields}
    data = await client.post(_proxy(host_id, "/liveviews"), json=payload)
    return data if isinstance(data, dict) else {"data": data}


async def update_liveview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    liveview_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """Update a liveview on a Protect console."""
    validate_id(liveview_id, "liveview_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.patch(_proxy(host_id, f"/liveviews/{liveview_id}"), json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- NVR ---


async def get_nvr(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Get NVR details from a Protect console."""
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, "/nvrs"))
    return data if isinstance(data, dict) else {"data": data}


# --- Protect Files ---


async def list_protect_files(
    client: UniFiClient,
    registry: Registry,
    host: str,
    file_type: str,
) -> dict[str, Any]:
    """List Protect device asset files of a given type (e.g. 'sounds', 'images')."""
    host_id = await registry.resolve_host_id(host)
    data = await client.get(_proxy(host_id, f"/files/{file_type}"))
    files = data if isinstance(data, list) else data.get("data", [])
    return {"files": files, "count": len(files), "file_type": file_type}


async def upload_protect_file(
    client: UniFiClient,
    registry: Registry,
    host: str,
    file_type: str,
    filename: str,
    file_content_base64: str,
) -> dict[str, Any]:
    """Upload a Protect device asset file (base64-encoded content) to /v1/files/{fileType}."""
    host_id = await registry.resolve_host_id(host)
    raw = base64.b64decode(file_content_base64)
    files = {"file": (filename, io.BytesIO(raw))}
    data = await client.post_multipart(_proxy(host_id, f"/files/{file_type}"), files=files)
    return data if isinstance(data, dict) else {"data": data}


# --- Alarm Manager ---


async def trigger_alarm_webhook(
    client: UniFiClient,
    registry: Registry,
    host: str,
    webhook_id: str,
) -> dict[str, Any]:
    """Trigger an alarm manager webhook by ID."""
    validate_id(webhook_id, "webhook_id")
    host_id = await registry.resolve_host_id(host)
    data = await client.post(_proxy(host_id, f"/alarm-manager/webhook/{webhook_id}"), json={})
    return data if isinstance(data, dict) else {"status": "ok"}
