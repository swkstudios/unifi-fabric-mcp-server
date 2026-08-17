"""UniFi Protect tools — cameras, sensors, lights, chimes, viewers via connector proxy."""

from __future__ import annotations

import base64
import io
import os
import re
from typing import Any

from ..client import UniFiClient, UniFiConnectionError, validate_id
from ..config import APIKeyConfig
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
    client: UniFiClient, host_id: str, refs: str | list[str], *, key: APIKeyConfig | None = None
) -> list[str]:
    """Resolve camera name(s) to ID(s) for the ``cameras`` filter; pass IDs through.

    Mirrors the name-or-ID convention used by ``resolve_host_id``/``resolve_site_id``.
    A reference that matches a known camera ID (or is 24-hex ID-shaped) passes through
    unchanged; a reference that matches a camera *name* (case-insensitive) resolves to
    its ID; anything else raises ValueError listing the available camera names rather
    than silently filtering to a non-existent camera (which returns everything/nothing).
    """
    ref_list = [refs] if isinstance(refs, str) else list(refs)
    data = await client.get(_proxy(host_id, "/cameras"), key=key)
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

    start/end: REQUIRED epoch SECONDS (UTC) as integers; converted to milliseconds
    internally. Ranges are inclusive on both ends. order_direction "DESC" yields
    newest-first. (These are epoch seconds, not the ISO 8601 strings query_isp_metrics
    expects.)

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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    params: dict[str, Any] = {"start": start_ms, "end": end_ms}
    if types is not None:
        params["types"] = types
    if cameras is not None:
        params["cameras"] = await _resolve_camera_refs(client, host_id, cameras, key=key)
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
            client, _private(host_id, "/events"), key=key, params=params, offset=offset, limit=limit
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/cameras"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/cameras/{camera_id}"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.patch(_proxy(host_id, f"/cameras/{camera_id}"), key=key, json=fields)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    raw = await client.get_bytes(_proxy(host_id, f"/cameras/{camera_id}/snapshot"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/cameras/{camera_id}/rtsps-stream"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    normalized = [q.lower() for q in qualities]
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/rtsps-stream"),
        key=key,
        json={"qualities": normalized},
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    normalized = [q.lower() for q in qualities]
    await client.delete(
        _proxy(host_id, f"/cameras/{camera_id}/rtsps-stream"),
        key=key,
        params={"qualities": normalized},
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/talkback-session"), key=key, json={}
    )
    return data if isinstance(data, dict) else {"status": "ok"}


async def disable_mic_permanently(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Permanently disable the microphone on a Protect camera."""
    validate_id(camera_id, "camera_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/disable-mic-permanently"), key=key, json={}
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/ptz/goto/{slot}"), key=key, json={}
    )
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/ptz/patrol/start/{slot}"), key=key, json={}
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.post(
        _proxy(host_id, f"/cameras/{camera_id}/ptz/patrol/stop"), key=key, json={}
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Sensors ---


async def list_sensors(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all sensors on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/sensors"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/sensors/{sensor_id}"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.patch(_proxy(host_id, f"/sensors/{sensor_id}"), key=key, json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Lights ---


async def list_lights(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all lights on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/lights"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/lights/{light_id}"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.patch(_proxy(host_id, f"/lights/{light_id}"), key=key, json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Chimes ---


async def list_chimes(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all chimes on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/chimes"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/chimes/{chime_id}"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.patch(_proxy(host_id, f"/chimes/{chime_id}"), key=key, json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Viewers ---


async def list_viewers(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all viewers on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/viewers"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/viewers/{viewer_id}"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.patch(_proxy(host_id, f"/viewers/{viewer_id}"), key=key, json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- Liveviews ---


async def list_liveviews(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all liveviews on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/liveviews"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/liveviews/{liveview_id}"), key=key)
    return data if isinstance(data, dict) else {"data": data}


async def create_liveview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    name: str,
    **fields: Any,
) -> dict[str, Any]:
    """Create a liveview on a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    payload: dict[str, Any] = {"name": name, **fields}
    data = await client.post(_proxy(host_id, "/liveviews"), key=key, json=payload)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.patch(_proxy(host_id, f"/liveviews/{liveview_id}"), key=key, json=fields)
    return data if isinstance(data, dict) else {"data": data}


# --- NVR ---


async def get_nvr(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Get NVR details from a Protect console."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, "/nvrs"), key=key)
    return data if isinstance(data, dict) else {"data": data}


# --- Protect Files ---


async def list_protect_files(
    client: UniFiClient,
    registry: Registry,
    host: str,
    file_type: str,
) -> dict[str, Any]:
    """List Protect device asset files of a given type (e.g. 'sounds', 'images')."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.get(_proxy(host_id, f"/files/{file_type}"), key=key)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    raw = base64.b64decode(file_content_base64)
    files = {"file": (filename, io.BytesIO(raw))}
    data = await client.post_multipart(_proxy(host_id, f"/files/{file_type}"), key=key, files=files)
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
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    data = await client.post(
        _proxy(host_id, f"/alarm-manager/webhook/{webhook_id}"), key=key, json={}
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# ===========================================================================
# Extended Protect resource families (UniFi Protect Integration API)
# ===========================================================================
#
# Every resource below is an officially documented UniFi Protect *Integration
# API* operation reached over the SAME Fabric-only connector base as the camera
# tools above (``PROTECT_PROXY_BASE`` →
# ``/v1/connector/consoles/{host_id}/proxy/protect/integration/v1``). There is
# no UI, SSH, or direct-controller route and no private/undocumented endpoint is
# used — the paths map 1:1 onto the published OpenAPI document
# (developer.ui.com/protect; catalog v7.1.87, plus the meta/ULP/POS additions in
# v7.2.105).
#
# Availability is firmware / application-version dependent. The alarm, arm,
# siren, relay, speaker, fob, bridge, link-station, alarm-hub, and POS resources
# require a Protect application new enough to expose them, and the arm/siren/
# relay/alarm-hub/POS actions require a local Alarm Manager / feature support. A
# console that does not support a family answers the proxied request with an
# upstream 404/501 which is passed straight through — treat that as "not
# available on this console/version", not a client bug.
#
# DELIBERATELY EXCLUDED: the documented Protect WebSocket subscriptions
# ``GET /v1/subscribe/devices`` and ``GET /v1/subscribe/events`` are NOT wrapped
# as MCP tools. They are long-lived streaming endpoints; a unary request/response
# MCP tool cannot model their subscription/cancellation lifecycle. Adding them
# requires an approved MCP-compatible streaming/cancellation design first — do
# not add a one-shot wrapper for them here.

PROTECT_MUTATIONS_ENV = "UNIFI_PROTECT_MUTATIONS_ENABLED"

# POS transaction type allowlist (posTransactionRequest.type enum). Ingestion is
# rejected locally for any other value rather than forwarding an invalid write.
_POS_TXN_TYPES = ("sale", "refund")


def protect_mutations_enabled() -> bool:
    """Whether the Protect mutation family (extended write/action tools) may run.

    Env gate mirroring ``config._resolved_fastmcp_transport``'s ``os.environ``
    pattern. It governs every *create / update / delete / physical-action /
    POS-ingestion* tool in the extended Protect families. Pure read tools
    (list/get/meta) are never gated.

    DEFAULT ON: with the variable unset the family is enabled and ``confirm=true``
    remains the operative guard for the physical / irreversible actions. Set
    ``UNIFI_PROTECT_MUTATIONS_ENABLED`` to a falsey value (``0`` / ``false`` /
    ``no`` / ``off``, case-insensitive) to hard-disable every Protect mutation at
    the deployment level — a kill switch that ``confirm=true`` cannot override.
    """
    raw = os.environ.get(PROTECT_MUTATIONS_ENV)
    if raw is None or not raw.strip():
        return True
    return raw.strip().lower() not in ("0", "false", "no", "off")


_MUTATIONS_DISABLED_REASON = (
    f"Protect mutations are disabled at the deployment level: {PROTECT_MUTATIONS_ENV} "
    "is set to a falsey value. No request was sent. This is a hard kill switch that "
    "confirm=true cannot override; unset the variable (default is enabled) to allow "
    "Protect writes and physical actions."
)


def _gate_blocked() -> dict[str, Any] | None:
    """Return a refusal payload when the mutation env gate is off, else ``None``.

    Checked before any host resolution or HTTP call, so a disabled deployment makes
    zero network requests.
    """
    if not protect_mutations_enabled():
        return {"status": "disabled", "reason": _MUTATIONS_DISABLED_REASON}
    return None


def _confirm_required(operation: str, effect: str) -> dict[str, Any]:
    """Refusal payload for a physical/irreversible action called without confirm."""
    return {
        "status": "not_executed",
        "operation": operation,
        "reason": (
            f"Set confirm=true to {effect}. This is a physical or irreversible action, "
            "so no request was sent until you confirm."
        ),
    }


def _as_list(data: Any) -> list[Any]:
    """Normalise a list-or-{'data': [...]} upstream body to a plain list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get("data")
        if isinstance(inner, list):
            return inner
    return []


def _as_dict(data: Any) -> dict[str, Any]:
    """Wrap a non-dict upstream body so a tool always returns a mapping."""
    return data if isinstance(data, dict) else {"data": data}


async def _resolve(registry: Registry, host: str) -> tuple[APIKeyConfig | None, str]:
    """Resolve the owning key ONCE and the host id, threading key through both.

    Every extended-family tool routes through here so the owning Fabric API key is
    resolved a single time and passed to ``resolve_host_id`` and each client call —
    the multi-key routing contract the rest of the Protect module already follows.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return key, host_id


async def _list_family(
    client: UniFiClient, registry: Registry, host: str, family: str, plural: str
) -> dict[str, Any]:
    """GET /{family} and return ``{plural: [...], "count": n}``.

    These Integration-API list endpoints return a bare JSON array (no pagination
    envelope), matching the existing ``list_cameras``/``list_sensors`` shape.
    """
    key, host_id = await _resolve(registry, host)
    data = await client.get(_proxy(host_id, f"/{family}"), key=key)
    items = _as_list(data)
    return {plural: items, "count": len(items)}


async def _get_item(
    client: UniFiClient, registry: Registry, host: str, family: str, item_id: str, id_name: str
) -> dict[str, Any]:
    """GET /{family}/{id} and pass the upstream object through unchanged."""
    validate_id(item_id, id_name)
    key, host_id = await _resolve(registry, host)
    data = await client.get(_proxy(host_id, f"/{family}/{item_id}"), key=key)
    return _as_dict(data)


async def _update_item_verified(
    client: UniFiClient,
    registry: Registry,
    host: str,
    family: str,
    item_id: str,
    id_name: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """PATCH /{family}/{id} with read-before / no-op-detect / read-after verification.

    Reads the current object, and if every requested field already equals its current
    value returns ``status='noop'`` WITHOUT issuing the PATCH. Otherwise it PATCHes
    (with 429 auto-retry disabled — a settings write is side-effecting), re-reads, and
    reports whether the read-after confirms each requested field. The upstream object
    is preserved verbatim in ``before``/``after`` (unknown/future fields survive).
    Gated by the mutation env switch.
    """
    validate_id(item_id, id_name)
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    key, host_id = await _resolve(registry, host)
    item_path = _proxy(host_id, f"/{family}/{item_id}")
    before_raw = await client.get(item_path, key=key)
    before = before_raw if isinstance(before_raw, dict) else {}
    if before and fields and all(before.get(k) == v for k, v in fields.items()):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    await client.patch(item_path, key=key, json=fields, max_retries=0)
    after_raw = await client.get(item_path, key=key)
    after = _as_dict(after_raw)
    verified = all(after.get(k) == v for k, v in fields.items())
    return {"status": "updated", "verified": verified, "before": before, "after": after}


# --- Protect application metadata ----------------------------------------------------


async def get_protect_application_info(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    """Get Protect application metadata (``GET /v1/meta/info``). Read-only.

    Reports the Protect application version and Integration-API capabilities of the
    console — the authoritative way to check which extended families are available.
    """
    key, host_id = await _resolve(registry, host)
    data = await client.get(_proxy(host_id, "/meta/info"), key=key)
    return _as_dict(data)


# --- Arm profiles + alarm enablement -------------------------------------------------
#
# ``/v1/arm-profiles`` list/create/update/delete plus the current arm-profile selection
# (``PATCH /v1/arm-profiles/settings``) and the global arm-alarm enable/disable actions
# (``POST /v1/arm-profiles/enable`` | ``/disable``). Selection, enable, and disable are
# three DISTINCT operations from settings CRUD. Enable/disable act on the currently
# selected profile and require a local Alarm Manager. The arm-profile *collection* has
# no ``GET /{id}`` in the API, so single-profile reads (and update verification) are done
# by filtering the list — the documented read path for an individual profile.


async def list_arm_profiles(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List arm profiles (``GET /v1/arm-profiles``)."""
    return await _list_family(client, registry, host, "arm-profiles", "arm_profiles")


async def _find_arm_profile(
    client: UniFiClient, host_id: str, arm_profile_id: str, *, key: APIKeyConfig | None
) -> dict[str, Any] | None:
    """Return one arm profile by id from the list endpoint (no GET-by-id exists)."""
    data = await client.get(_proxy(host_id, "/arm-profiles"), key=key)
    for profile in _as_list(data):
        if isinstance(profile, dict) and profile.get("id") == arm_profile_id:
            return profile
    return None


async def get_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Get one arm profile by id.

    The Integration API exposes no ``GET /v1/arm-profiles/{id}``; this reads the
    documented ``GET /v1/arm-profiles`` collection and returns the matching entry
    (raising when the id is absent so an ambiguous/typo id is a loud error, not a
    silent empty result).
    """
    validate_id(arm_profile_id, "arm_profile_id")
    key, host_id = await _resolve(registry, host)
    profile = await _find_arm_profile(client, host_id, arm_profile_id, key=key)
    if profile is None:
        raise ValueError(f"Arm profile {arm_profile_id!r} not found on host {host!r}")
    return profile


async def create_arm_profile(
    client: UniFiClient, registry: Registry, host: str, name: str, **fields: Any
) -> dict[str, Any]:
    """Create an arm profile (``POST /v1/arm-profiles``).

    The API additionally requires ``automations``, ``schedules``, ``recordEverything``,
    and ``activationDelay`` in the body; pass them through ``fields``. Server-side
    validation enforces the full schema. Gated by the mutation env switch; 429
    auto-retry is disabled (a create is a non-idempotent side effect).
    """
    if not name:
        raise ValueError("'name' must not be empty")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    key, host_id = await _resolve(registry, host)
    payload: dict[str, Any] = {"name": name, **fields}
    data = await client.post(_proxy(host_id, "/arm-profiles"), key=key, json=payload, max_retries=0)
    return _as_dict(data)


async def update_arm_profile(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str, **fields: Any
) -> dict[str, Any]:
    """Update an arm profile (``PATCH /v1/arm-profiles/{id}``) with read/no-op/read-after.

    Because the collection has no ``GET /{id}``, the read-before and read-after are done
    against the list endpoint; if every requested field already matches, no PATCH is
    sent. Gated by the mutation env switch; 429 auto-retry disabled on the write.
    """
    validate_id(arm_profile_id, "arm_profile_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    key, host_id = await _resolve(registry, host)
    before = await _find_arm_profile(client, host_id, arm_profile_id, key=key)
    if before and fields and all(before.get(k) == v for k, v in fields.items()):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    await client.patch(
        _proxy(host_id, f"/arm-profiles/{arm_profile_id}"), key=key, json=fields, max_retries=0
    )
    after = await _find_arm_profile(client, host_id, arm_profile_id, key=key)
    verified = after is not None and all(after.get(k) == v for k, v in fields.items())
    return {"status": "updated", "verified": verified, "before": before, "after": after}


async def delete_arm_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    arm_profile_id: str,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete an arm profile (``DELETE /v1/arm-profiles/{id}``). Irreversible.

    Gated by the mutation env switch and requires ``confirm=true`` (no undo); 429
    auto-retry disabled on the write.
    """
    validate_id(arm_profile_id, "arm_profile_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required("delete_arm_profile", "permanently delete this arm profile")
    key, host_id = await _resolve(registry, host)
    await client.delete(_proxy(host_id, f"/arm-profiles/{arm_profile_id}"), key=key, max_retries=0)
    return {"status": "deleted", "id": arm_profile_id}


async def update_arm_profile_settings(
    client: UniFiClient, registry: Registry, host: str, arm_profile_id: str
) -> dict[str, Any]:
    """Select the active arm profile (``PATCH /v1/arm-profiles/settings``).

    A DISTINCT operation from arm-profile CRUD and from enable/disable: it chooses which
    profile is current. Body is ``{"armProfileId": <id>}``. The current selection is read
    from the NVR's ``armMode.armProfileId`` (documented ``nvrArmMode`` field) for the
    read-before / no-op / read-after flow: if already selected, no PATCH is sent. Gated
    by the mutation env switch; 429 auto-retry disabled on the write.
    """
    validate_id(arm_profile_id, "arm_profile_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    key, host_id = await _resolve(registry, host)
    before_nvr = await client.get(_proxy(host_id, "/nvrs"), key=key)
    before = before_nvr.get("armMode") if isinstance(before_nvr, dict) else None
    if isinstance(before, dict) and before.get("armProfileId") == arm_profile_id:
        return {
            "status": "noop",
            "reason": "arm profile already selected; no write sent",
            "arm_mode": before,
        }
    await client.patch(
        _proxy(host_id, "/arm-profiles/settings"),
        key=key,
        json={"armProfileId": arm_profile_id},
        max_retries=0,
    )
    after_nvr = await client.get(_proxy(host_id, "/nvrs"), key=key)
    after = after_nvr.get("armMode") if isinstance(after_nvr, dict) else None
    verified = isinstance(after, dict) and after.get("armProfileId") == arm_profile_id
    return {"status": "updated", "verified": verified, "before": before, "after": after}


async def enable_arm(
    client: UniFiClient, registry: Registry, host: str, *, confirm: bool = False
) -> dict[str, Any]:
    """Enable the arm alarm (``POST /v1/arm-profiles/enable``). Physical side effects.

    A DISTINCT operation from profile selection: arms the system using the currently
    selected arm profile; requires a local Alarm Manager. Gated by the mutation env
    switch and requires ``confirm=true``; 429 auto-retry disabled.
    """
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required(
            "enable_arm", "arm the alarm system using the currently selected arm profile"
        )
    key, host_id = await _resolve(registry, host)
    data = await client.post(
        _proxy(host_id, "/arm-profiles/enable"), key=key, json={}, max_retries=0
    )
    return data if isinstance(data, dict) else {"status": "ok"}


async def disable_arm(
    client: UniFiClient, registry: Registry, host: str, *, confirm: bool = False
) -> dict[str, Any]:
    """Disable the arm alarm (``POST /v1/arm-profiles/disable``). Physical side effects.

    Disarms the system; requires a local Alarm Manager. Gated by the mutation env
    switch and requires ``confirm=true``; 429 auto-retry disabled.
    """
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required("disable_arm", "disarm the alarm system")
    key, host_id = await _resolve(registry, host)
    data = await client.post(
        _proxy(host_id, "/arm-profiles/disable"), key=key, json={}, max_retries=0
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Sirens --------------------------------------------------------------------------


async def list_sirens(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List sirens (``GET /v1/sirens``)."""
    return await _list_family(client, registry, host, "sirens", "sirens")


async def get_siren(
    client: UniFiClient, registry: Registry, host: str, siren_id: str
) -> dict[str, Any]:
    """Get one siren by id (``GET /v1/sirens/{id}``)."""
    return await _get_item(client, registry, host, "sirens", siren_id, "siren_id")


async def update_siren(
    client: UniFiClient, registry: Registry, host: str, siren_id: str, **fields: Any
) -> dict[str, Any]:
    """Update siren settings (``PATCH /v1/sirens/{id}``) with read/no-op/read-after.

    Documented settable fields include ``name``, ``volume`` (1-100), and ``ledSettings``.
    Gated by the mutation env switch.
    """
    return await _update_item_verified(
        client, registry, host, "sirens", siren_id, "siren_id", fields
    )


async def siren_play(
    client: UniFiClient,
    registry: Registry,
    host: str,
    siren_id: str,
    *,
    confirm: bool = False,
    duration: int | None = None,
) -> dict[str, Any]:
    """Sound a siren (``POST /v1/sirens/{id}/play``). Physical side effects.

    ``duration`` (seconds) accepts the documented values 5/10/20/30 and defaults to 5
    upstream when omitted. Gated by the mutation env switch and requires ``confirm=true``;
    429 auto-retry disabled.
    """
    validate_id(siren_id, "siren_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required("siren_play", "physically sound this siren")
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if duration is not None:
        body["duration"] = duration
    data = await client.post(
        _proxy(host_id, f"/sirens/{siren_id}/play"), key=key, json=body, max_retries=0
    )
    return data if isinstance(data, dict) else {"status": "ok"}


async def siren_stop(
    client: UniFiClient,
    registry: Registry,
    host: str,
    siren_id: str,
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Stop a sounding siren (``POST /v1/sirens/{id}/stop``). Physical side effects.

    Gated by the mutation env switch and requires ``confirm=true``; 429 auto-retry
    disabled.
    """
    validate_id(siren_id, "siren_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required("siren_stop", "stop this siren")
    key, host_id = await _resolve(registry, host)
    data = await client.post(
        _proxy(host_id, f"/sirens/{siren_id}/stop"), key=key, json={}, max_retries=0
    )
    return data if isinstance(data, dict) else {"status": "ok"}


async def siren_test_sound(
    client: UniFiClient,
    registry: Registry,
    host: str,
    siren_id: str,
    *,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a siren's sound (``POST /v1/sirens/{id}/test-sound``). Physical side effects.

    ``volume`` (1-100) defaults to the configured device volume upstream when omitted.
    Gated by the mutation env switch and requires ``confirm=true``; 429 auto-retry
    disabled.
    """
    validate_id(siren_id, "siren_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required("siren_test_sound", "physically play the siren test sound")
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if volume is not None:
        body["volume"] = volume
    data = await client.post(
        _proxy(host_id, f"/sirens/{siren_id}/test-sound"), key=key, json=body, max_retries=0
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Fobs ----------------------------------------------------------------------------


async def list_fobs(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List fobs (``GET /v1/fobs``)."""
    return await _list_family(client, registry, host, "fobs", "fobs")


async def get_fob(
    client: UniFiClient, registry: Registry, host: str, fob_id: str
) -> dict[str, Any]:
    """Get one fob by id (``GET /v1/fobs/{id}``)."""
    return await _get_item(client, registry, host, "fobs", fob_id, "fob_id")


async def update_fob(
    client: UniFiClient, registry: Registry, host: str, fob_id: str, **fields: Any
) -> dict[str, Any]:
    """Update fob settings (``PATCH /v1/fobs/{id}``) with read/no-op/read-after.

    Gated by the mutation env switch.
    """
    return await _update_item_verified(client, registry, host, "fobs", fob_id, "fob_id", fields)


# --- Relays --------------------------------------------------------------------------


async def list_relays(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List relays (``GET /v1/relays``)."""
    return await _list_family(client, registry, host, "relays", "relays")


async def get_relay(
    client: UniFiClient, registry: Registry, host: str, relay_id: str
) -> dict[str, Any]:
    """Get one relay by id (``GET /v1/relays/{id}``)."""
    return await _get_item(client, registry, host, "relays", relay_id, "relay_id")


async def update_relay(
    client: UniFiClient, registry: Registry, host: str, relay_id: str, **fields: Any
) -> dict[str, Any]:
    """Update relay settings (``PATCH /v1/relays/{id}``) with read/no-op/read-after.

    Gated by the mutation env switch.
    """
    return await _update_item_verified(
        client, registry, host, "relays", relay_id, "relay_id", fields
    )


async def relay_activate_output(
    client: UniFiClient,
    registry: Registry,
    host: str,
    relay_id: str,
    output_id: str,
    *,
    confirm: bool = False,
    state: str | None = None,
    pulse_duration: int | None = None,
) -> dict[str, Any]:
    """Switch a relay output (``POST /v1/relays/{id}/outputs/{outputId}/activate``).

    Physical side effects. ``state`` is ``"on"`` or ``"off"`` (omit to toggle);
    ``pulse_duration`` is an auto-off delay in milliseconds that only applies when
    ``state="on"``. Gated by the mutation env switch and requires ``confirm=true``;
    429 auto-retry disabled.
    """
    validate_id(relay_id, "relay_id")
    validate_id(output_id, "output_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required("relay_activate_output", "physically switch this relay output")
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if state is not None:
        body["state"] = state
    if pulse_duration is not None:
        body["pulseDuration"] = pulse_duration
    data = await client.post(
        _proxy(host_id, f"/relays/{relay_id}/outputs/{output_id}/activate"),
        key=key,
        json=body,
        max_retries=0,
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Speakers ------------------------------------------------------------------------


async def list_speakers(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List speakers (``GET /v1/speakers``)."""
    return await _list_family(client, registry, host, "speakers", "speakers")


async def get_speaker(
    client: UniFiClient, registry: Registry, host: str, speaker_id: str
) -> dict[str, Any]:
    """Get one speaker by id (``GET /v1/speakers/{id}``)."""
    return await _get_item(client, registry, host, "speakers", speaker_id, "speaker_id")


async def update_speaker(
    client: UniFiClient, registry: Registry, host: str, speaker_id: str, **fields: Any
) -> dict[str, Any]:
    """Update speaker settings (``PATCH /v1/speakers/{id}``) with read/no-op/read-after.

    Gated by the mutation env switch.
    """
    return await _update_item_verified(
        client, registry, host, "speakers", speaker_id, "speaker_id", fields
    )


async def speaker_test_sound(
    client: UniFiClient,
    registry: Registry,
    host: str,
    speaker_id: str,
    *,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a speaker's sound (``POST /v1/speakers/{id}/test-sound``). Physical side effects.

    ``volume`` (0-100) defaults to the configured device volume upstream when omitted.
    Gated by the mutation env switch and requires ``confirm=true``; 429 auto-retry
    disabled.
    """
    validate_id(speaker_id, "speaker_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required("speaker_test_sound", "physically play the speaker test sound")
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if volume is not None:
        body["volume"] = volume
    data = await client.post(
        _proxy(host_id, f"/speakers/{speaker_id}/test-sound"), key=key, json=body, max_retries=0
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Bridges -------------------------------------------------------------------------


async def list_bridges(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List bridges (``GET /v1/bridges``)."""
    return await _list_family(client, registry, host, "bridges", "bridges")


async def get_bridge(
    client: UniFiClient, registry: Registry, host: str, bridge_id: str
) -> dict[str, Any]:
    """Get one bridge by id (``GET /v1/bridges/{id}``)."""
    return await _get_item(client, registry, host, "bridges", bridge_id, "bridge_id")


async def update_bridge(
    client: UniFiClient, registry: Registry, host: str, bridge_id: str, **fields: Any
) -> dict[str, Any]:
    """Update bridge settings (``PATCH /v1/bridges/{id}``) with read/no-op/read-after.

    Gated by the mutation env switch.
    """
    return await _update_item_verified(
        client, registry, host, "bridges", bridge_id, "bridge_id", fields
    )


# --- Link stations -------------------------------------------------------------------


async def list_link_stations(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List link stations (``GET /v1/link-stations``)."""
    return await _list_family(client, registry, host, "link-stations", "link_stations")


async def get_link_station(
    client: UniFiClient, registry: Registry, host: str, link_station_id: str
) -> dict[str, Any]:
    """Get one link station by id (``GET /v1/link-stations/{id}``)."""
    return await _get_item(
        client, registry, host, "link-stations", link_station_id, "link_station_id"
    )


async def update_link_station(
    client: UniFiClient, registry: Registry, host: str, link_station_id: str, **fields: Any
) -> dict[str, Any]:
    """Update link-station settings (``PATCH /v1/link-stations/{id}``) with read/no-op/read-after.

    Gated by the mutation env switch.
    """
    return await _update_item_verified(
        client, registry, host, "link-stations", link_station_id, "link_station_id", fields
    )


# --- Alarm hubs ----------------------------------------------------------------------


async def list_alarm_hubs(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List alarm hubs (``GET /v1/alarm-hubs``)."""
    return await _list_family(client, registry, host, "alarm-hubs", "alarm_hubs")


async def get_alarm_hub(
    client: UniFiClient, registry: Registry, host: str, alarm_hub_id: str
) -> dict[str, Any]:
    """Get one alarm hub by id (``GET /v1/alarm-hubs/{id}``)."""
    return await _get_item(client, registry, host, "alarm-hubs", alarm_hub_id, "alarm_hub_id")


async def update_alarm_hub(
    client: UniFiClient, registry: Registry, host: str, alarm_hub_id: str, **fields: Any
) -> dict[str, Any]:
    """Update alarm-hub settings (``PATCH /v1/alarm-hubs/{id}``) with read/no-op/read-after.

    Gated by the mutation env switch.
    """
    return await _update_item_verified(
        client, registry, host, "alarm-hubs", alarm_hub_id, "alarm_hub_id", fields
    )


async def alarm_hub_trigger_output(
    client: UniFiClient,
    registry: Registry,
    host: str,
    alarm_hub_id: str,
    output_id: str,
    *,
    confirm: bool = False,
    enable: bool | None = None,
    delay: int | None = None,
    duration: int | None = None,
) -> dict[str, Any]:
    """Trigger an alarm-hub output (``POST /v1/alarm-hubs/{id}/outputs/{outputId}/trigger``).

    Physical side effects. ``enable`` true turns the output on, false off (omit to
    toggle); ``delay`` (ms) waits before activating; ``duration`` (ms) keeps it active
    (0 = indefinite until manually turned off). Gated by the mutation env switch and
    requires ``confirm=true``; 429 auto-retry disabled.
    """
    validate_id(alarm_hub_id, "alarm_hub_id")
    validate_id(output_id, "output_id")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required(
            "alarm_hub_trigger_output", "physically trigger this alarm-hub output"
        )
    key, host_id = await _resolve(registry, host)
    body: dict[str, Any] = {}
    if enable is not None:
        body["enable"] = enable
    if delay is not None:
        body["delay"] = delay
    if duration is not None:
        body["duration"] = duration
    data = await client.post(
        _proxy(host_id, f"/alarm-hubs/{alarm_hub_id}/outputs/{output_id}/trigger"),
        key=key,
        json=body,
        max_retries=0,
    )
    return data if isinstance(data, dict) else {"status": "ok"}


# --- Protect users (read-only) -------------------------------------------------------


async def list_protect_users(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List Protect users (``GET /v1/users``). Read-only in the Integration API.

    Distinct from ULP users (``list_ulp_users`` / ``/v1/ulp-users``): this is the
    Protect application's own user list.
    """
    return await _list_family(client, registry, host, "users", "users")


async def get_protect_user(
    client: UniFiClient, registry: Registry, host: str, user_id: str
) -> dict[str, Any]:
    """Get one Protect user by id (``GET /v1/users/{id}``). Read-only."""
    return await _get_item(client, registry, host, "users", user_id, "user_id")


# --- ULP users (read-only) -----------------------------------------------------------
#
# The Unifi-account (ULP) user directory — DISTINCT from the Protect users above. These
# are the UI-account identities (``/v1/ulp-users``), not Protect's local user list.


async def list_ulp_users(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List ULP (UniFi account) users (``GET /v1/ulp-users``). Read-only.

    Distinct from Protect users (``list_protect_users`` / ``/v1/users``).
    """
    return await _list_family(client, registry, host, "ulp-users", "ulp_users")


async def get_ulp_user(
    client: UniFiClient, registry: Registry, host: str, ulp_user_id: str
) -> dict[str, Any]:
    """Get one ULP (UniFi account) user by id (``GET /v1/ulp-users/{id}``). Read-only."""
    return await _get_item(client, registry, host, "ulp-users", ulp_user_id, "ulp_user_id")


# --- POS transaction ingestion -------------------------------------------------------


async def pos_ingest_transaction(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    transaction: dict[str, Any],
    *,
    confirm: bool = False,
) -> dict[str, Any]:
    """Ingest a POS transaction to overlay on camera footage.

    ``POST /v1/pos/cameras/{id}/transactions`` with the documented ``posTransactionRequest``
    body. This is a SIDE-EFFECTING write that creates a footage overlay event with NO
    documented rollback, so it has its own confirmation boundary and idempotency guard:

    * ``confirm=true`` is required (separate from the physical-action guard).
    * ``transaction`` must carry the required fields ``type`` ('sale'|'refund', validated
      against a strict allowlist), ``externalId`` (caller-supplied, unique per camera —
      the idempotency/deduplication key the API uses for best-effort in-window dedup), and
      ``amount``. Optional documented fields (``currency``, ``lineItems``, ``location``,
      ``paymentTypes``, ``timestamp``) pass through verbatim.
    * 429 auto-retry is DISABLED (``max_retries=0``). Because dedup is best-effort and
      in-memory upstream, an automatic retry could create a duplicate overlay; the tool
      never retries a POS write. A retry, if needed, is the caller's explicit decision and
      must reuse the same ``externalId``.

    Gated by the mutation env switch.
    """
    validate_id(camera_id, "camera_id")
    if not isinstance(transaction, dict):
        raise ValueError("'transaction' must be a posTransactionRequest object")
    txn_type = transaction.get("type")
    if txn_type not in _POS_TXN_TYPES:
        raise ValueError(f"transaction 'type' must be one of {_POS_TXN_TYPES} (got {txn_type!r})")
    external_id = transaction.get("externalId")
    if not isinstance(external_id, str) or not external_id.strip():
        raise ValueError(
            "transaction 'externalId' is required (non-empty string): it is the per-camera "
            "idempotency/deduplication key for POS ingestion"
        )
    if "amount" not in transaction:
        raise ValueError("transaction 'amount' is required")
    blocked = _gate_blocked()
    if blocked is not None:
        return blocked
    if not confirm:
        return _confirm_required(
            "pos_ingest_transaction",
            "ingest a POS transaction overlay (no documented rollback)",
        )
    key, host_id = await _resolve(registry, host)
    data = await client.post(
        _proxy(host_id, f"/pos/cameras/{camera_id}/transactions"),
        key=key,
        json=transaction,
        max_retries=0,
    )
    return data if isinstance(data, dict) else {"status": "ok", "externalId": external_id}
