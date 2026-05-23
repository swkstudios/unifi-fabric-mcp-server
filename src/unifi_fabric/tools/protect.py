"""UniFi Protect tools — cameras, sensors, lights, chimes, viewers via connector proxy."""

from __future__ import annotations

import base64
import io
from typing import Any

from ..client import UniFiClient, validate_id
from ..registry import Registry

PROTECT_PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/protect/integration/v1"


def _proxy(host_id: str, path: str) -> str:
    return PROTECT_PROXY_BASE.format(host_id=host_id) + path


# --- Camera Info and Settings ---


async def list_cameras(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """List all cameras on a Protect console."""
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
