"""UniFi Protect camera controls, camera WiFi and on-camera (edge) recording storage.

Route choice (official published API first, else the private API the web app calls). The
official Protect Integration API pinned in ``tests/fixtures/spec_drift/baseline_snapshot.json``
(protect 7.3.74) has no route for any capability in this module: its camera surface is
``GET/PATCH /v1/cameras/{id}`` (name, OSD, LED, LCD message, mic volume, video mode, HDR,
smart detection), snapshots, RTSPS streams, talkback, PTZ and the permanent mic disable.
Every tool here therefore uses the private ``/proxy/protect/api`` route the Protect web
app calls, as inventoried in ``tests/fixtures/private_api/inventory_protect_5.3.18.json``
(UI bundle 5.3.18, ``swai.js``). There is no older generation of these routes.

Every response body is passed through verbatim (server pass-through invariant). A body
that is not JSON or text (an image or a recording file) is returned base64-encoded with
the upstream Content-Type, never decoded.

Validation before any request uses only the server's registered refusals (path-safe ids,
integer epoch seconds, the empty-body guard, the Protect write opt-out and read-only
mode, and the declared argument types and closed choices); every other value is the
upstream's to judge. Where the inventory records no body keys for a route, the tool takes
a free-form body object and sends it as given.

``cameras/{id}/enable-control`` and ``disable-control`` change state on a GET. The tool
that sends them is a write by behaviour: it is registered with
:func:`unifi_fabric._read_only_audit.state_changing_get`, refused under read-only mode
and the Protect write opt-out, previewed under dry-run and never retried automatically.
"""

from __future__ import annotations

import base64
from typing import Any

from pydantic import StrictBool, TypeAdapter

from ..._read_only_audit import state_changing_get
from ...client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    is_dry_run_preview,
    path_segment,
    validate_selector,
)
from ...config import APIKeyConfig
from ...read_only import guard_action
from ...registry import Registry
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._payload import upstream_hint, with_upstream_hint
from ...shared_shapes._results import deletion_result
from .protect import _fields_to_send, _private, _require_mutations, _resolve
from .schemas import (  # the family's shapes (family-owned layout)
    _ANALYTICS_SUFFIX,
    _TEXT_TYPES,
    AnalyticsKind,
    EdgeExportAction,
)
from .schemas import (
    _QR_REMOVED_HINT as _QR_REMOVED_HINT,
)

_ANALYTICS_KIND = TypeAdapter(AnalyticsKind)
_EDGE_EXPORT_ACTION = TypeAdapter(EdgeExportAction)
_STRICT_BOOL = TypeAdapter(StrictBool)


async def _get_body(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None,
    params: dict[str, Any] | None = None,
    no_retries: bool = False,
) -> Any:
    """GET ``path`` and return its body: JSON or text verbatim, anything else as base64.

    A JSON or text body (by Content-Type, or JSON by content when no type is sent) is
    decoded by the server's one pass-through rule. An image or file body is returned as
    ``{content_base64, content_type, size_bytes}`` with the upstream Content-Type as sent.
    """
    options: dict[str, Any] = {"max_retries": 0} if no_retries else {}
    resp = await client.request("GET", path, key=key, params=params or None, **options)
    content_type = resp.headers.get("content-type")
    lowered = (content_type or "").lower()
    if resp.status_code == 204 or not resp.content or any(t in lowered for t in _TEXT_TYPES):
        return decode_body(resp)
    if content_type is None:
        try:
            return resp.json()
        except ValueError:
            pass
    return {
        "content_base64": base64.b64encode(resp.content).decode(),
        "content_type": content_type,
        "size_bytes": len(resp.content),
    }


def _given(**params: Any) -> dict[str, Any]:
    """Only the query parameters the caller actually gave (no invented defaults)."""
    return {name: value for name, value in params.items() if value is not None}


def _epoch_ms(value: int, name: str) -> int:
    """A required epoch-seconds argument as epoch milliseconds (type-checked first)."""
    return seconds_to_millis(require_epoch_seconds(value, name))


def _with_epoch_unit(body: Any, **values: int | None) -> Any:
    """``body`` plus the shared ``_warnings`` epoch entries of the epoch arguments given.

    The entries are :func:`epoch_warnings`: one per argument that is negative or looks like
    epoch milliseconds. A plausible epoch-seconds value adds none, so the body is returned as
    is. With entries, an object body keeps every upstream key; any other body (an array) is
    returned under ``result`` so the entries have a place.
    """
    warnings = epoch_warnings(**values)
    if not warnings:
        return body
    if isinstance(body, dict):
        return with_context(body, {"_warnings": warnings})
    return {"result": body, "_warnings": warnings}


def _action_result(status: str, response: Any) -> dict[str, Any]:
    """A write's result: ``{status, response}`` with the upstream body verbatim.

    Under ``dry-run policy`` nothing was sent and ``response`` is the client's preview;
    the preview itself is returned (``{status: "dry_run", dryRun, sent: false, message, preview}``).
    """
    if is_dry_run_preview(response):
        return dict(response)
    return {"status": status, "response": response}


def _camera_path(host_id: str, camera_seg: str, suffix: str) -> str:
    return _private(host_id, f"/cameras/{camera_seg}/{suffix}")


def _edge_path(host_id: str, camera_seg: str, suffix: str) -> str:
    return _private(host_id, f"/edge-recording/{camera_seg}/{suffix}")


def _write_guards(method: str) -> None:
    """The Protect write opt-out and read-only mode, before any request."""
    _require_mutations()
    guard_action(method)


async def _post_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_seg: str,
    suffix: str,
    status: str,
    *,
    edge: bool = False,
    json: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """POST one camera (or edge-storage) action, sent once (never auto-retried)."""
    key, host_id = await _resolve(registry, host)
    path = (_edge_path if edge else _camera_path)(host_id, camera_seg, suffix)
    response = await client.post(path, key=key, json=json, params=params)
    return _action_result(status, response)


# --- Camera reads -----------------------------------------------------------------------


async def get_camera_analytics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    kind: str,
    start: int,
    end: int,
    step: int | None = None,
    heatmap_type: str | None = None,
) -> Any:
    """GET a camera's detection counts or analytics heatmap over a window."""
    kind = _ANALYTICS_KIND.validate_python(kind)
    camera_seg = path_segment(camera_id, "camera_id")
    params = _given(
        start=_epoch_ms(start, "start"),
        end=_epoch_ms(end, "end"),
        step=step,
        type=heatmap_type,
    )
    key, host_id = await _resolve(registry, host)
    path = _camera_path(host_id, camera_seg, _ANALYTICS_SUFFIX[kind])
    body = await _get_body(client, path, key=key, params=params)
    return _with_epoch_unit(body, start=start, end=end)


async def get_camera_lux(client: UniFiClient, registry: Registry, host: str, camera_id: str) -> Any:
    """GET a camera's current light level reading (``/cameras/{id}/lux``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    key, host_id = await _resolve(registry, host)
    return await client.get(_camera_path(host_id, camera_seg, "lux"), key=key)


async def get_camera_playback_history(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    start: int,
    end: int,
    resolution: int | None = None,
) -> Any:
    """GET a camera's recording (playback) history over a window."""
    camera_seg = path_segment(camera_id, "camera_id")
    params = _given(
        start=_epoch_ms(start, "start"), end=_epoch_ms(end, "end"), resolution=resolution
    )
    key, host_id = await _resolve(registry, host)
    body = await client.get(
        _camera_path(host_id, camera_seg, "playback-history"), key=key, params=params
    )
    return _with_epoch_unit(body, start=start, end=end)


async def get_camera_wifi_networks(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> Any:
    """GET the WiFi networks a camera can see (``/cameras/{id}/wifi-list``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    key, host_id = await _resolve(registry, host)
    return await with_upstream_hint(
        client.get(_camera_path(host_id, camera_seg, "wifi-list"), key=key),
        "Camera WiFi scan failed; check camera support and connectivity.",
    )


# --- Camera writes and actions ----------------------------------------------------------


@state_changing_get
async def _send_control_get(
    client: UniFiClient, key: APIKeyConfig | None, path: str
) -> dict[str, Any]:
    """Send the state-changing control GET (or return the client's dry-run preview).

    The route is on the write classifier's state-changing GET list
    (``read_only.STATE_CHANGING_GET_ROUTES``), so the client chokepoint treats this GET as
    a write: refused in read-only mode, previewed under ``dry-run policy`` and audited. It
    is sent once (``max_retries=0``: a retried GET could repeat the state change).
    """
    response = decode_body(await client.request("GET", path, key=key, max_retries=0))
    return _action_result("sent", response)


async def set_camera_control_enabled(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, enabled: bool
) -> dict[str, Any]:
    """Enable or disable a camera's control (``GET /cameras/{id}/enable-|disable-control``)."""
    enabled = _STRICT_BOOL.validate_python(enabled)
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("GET")
    key, host_id = await _resolve(registry, host)
    suffix = "enable-control" if enabled else "disable-control"
    result = await _send_control_get(client, key, _camera_path(host_id, camera_seg, suffix))
    if result.get("status") == "sent":
        result["status"] = "enabled" if enabled else "disabled"
    return result


async def set_camera_door_lock(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, locked: bool
) -> dict[str, Any]:
    """Lock or unlock the door lock wired to a camera (``POST /cameras/{id}/lock|unlock``)."""
    locked = _STRICT_BOOL.validate_python(locked)
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    action = "lock" if locked else "unlock"
    return await _post_action(
        client, registry, host, camera_seg, action, "locked" if locked else "unlocked"
    )


async def reset_camera_image_settings(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Reset a camera's image (ISP) settings (``POST /cameras/{id}/reset-isp``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(client, registry, host, camera_seg, "reset-isp", "reset")


async def set_camera_resolution_scale(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, scale: str
) -> dict[str, Any]:
    """Set a camera's resolution scale (``POST /cameras/{id}/resolutionScale/{scale}``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    scale_seg = path_segment(scale, "scale")
    _write_guards("POST")
    return await _post_action(
        client, registry, host, camera_seg, f"resolutionScale/{scale_seg}", "sent"
    )


async def transfer_camera_management(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, nvr_mac: str
) -> dict[str, Any]:
    """Transfer a camera to another NVR (``POST /cameras/{id}/transfer-mgmt {nvrMac}``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    validate_selector(nvr_mac, "nvr_mac")
    _write_guards("POST")
    return await _post_action(
        client, registry, host, camera_seg, "transfer-mgmt", "sent", json={"nvrMac": nvr_mac}
    )


async def turn_on_camera_flashlight(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Turn on a camera's flashlight (``POST /cameras/{id}/turnon-flashlight``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(client, registry, host, camera_seg, "turnon-flashlight", "sent")


async def configure_camera_wifi(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, settings: dict[str, Any]
) -> dict[str, Any]:
    """Send a camera's WiFi setup (``POST /cameras/{id}/wifi-setup``, free-form body)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    body = _fields_to_send(dict(settings), "camera wifi-setup")
    return await _post_action(client, registry, host, camera_seg, "wifi-setup", "sent", json=body)


async def set_camera_video_codec(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, codec: str
) -> dict[str, Any]:
    """Set a camera's video codec (``POST /cameras/{id}/videoCodec?name=CODEC``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(
        client, registry, host, camera_seg, "videoCodec", "sent", params={"name": codec}
    )


# --- Edge (on-camera) recording storage -------------------------------------------------


async def export_edge_recording(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    action: str,
    filename: str | None = None,
    start: int | None = None,
    end: int | None = None,
) -> Any:
    """Prepare, or download, a recording export from a camera's own (edge) storage.

    Protect 7.3 requires ``filename``, ``start`` and ``end`` (epoch ms) for prepare: the
    console stores the export under that file name, and download fetches it by name. Only
    the arguments given are sent; the console reports a missing one.
    """
    action = _EDGE_EXPORT_ACTION.validate_python(action)
    if action == "download" and (start is not None or end is not None):
        raise ValueError(
            "start and end only apply to action 'prepare', not action 'download'; they would "
            "be silently dropped. Nothing was sent."
        )
    params = _given(
        filename=filename,
        start=None if start is None else _epoch_ms(start, "start"),
        end=None if end is None else _epoch_ms(end, "end"),
    )
    camera_seg = path_segment(camera_id, "camera_id")
    key, host_id = await _resolve(registry, host)
    missing = action == "prepare" and any(x is None for x in (filename, start, end))
    try:
        body = await with_upstream_hint(
            _get_body(
                client,
                _edge_path(host_id, camera_seg, action),
                key=key,
                params=params or None,
                no_retries=action == "prepare",
            ),
            "Prepare requires filename, start and end; times are epoch seconds."
            if missing
            else None,
        )
    except UniFiConnectionError as exc:
        if missing or exc.status != 500:
            raise
        upstream_hint(
            exc,
            "The console could not prepare this export; check that the camera has edge "
            "(SD card) storage with recordings between start and end.",
        )
        raise
    return _with_epoch_unit(body, start=start, end=end)


async def set_edge_storage_mount_state(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, mount_state: str
) -> dict[str, Any]:
    """Mount or unmount a camera's storage (``POST /edge-recording/{id}/mount-state``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(
        client,
        registry,
        host,
        camera_seg,
        "mount-state",
        "sent",
        edge=True,
        json={"mountState": mount_state},
    )


async def reformat_edge_storage(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Reformat a camera's own storage (``POST /edge-recording/{id}/reformat``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(client, registry, host, camera_seg, "reformat", "sent", edge=True)


async def update_edge_recording_settings(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, settings: dict[str, Any]
) -> dict[str, Any]:
    """PATCH a camera's edge recording settings (free-form body, sent as given)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("PATCH")
    body = _fields_to_send(dict(settings), "edge recording")
    key, host_id = await _resolve(registry, host)
    path = _edge_path(host_id, camera_seg, "recording-settings")
    response = await client.patch(path, key=key, json=body)
    if is_dry_run_preview(response):
        return dict(response)
    # The Protect update shape. No route reads these settings, so nothing is read before
    # or after the PATCH and the change cannot be verified (verified is null, not false).
    return {
        "status": "updated",
        "verified": None,
        "before": None,
        "after": None,
        "response": response,
    }


async def delete_recordings(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, start: int, end: int
) -> dict[str, Any]:
    """Delete a camera's recordings in a window (``DELETE /video?camera&start&end``).

    The result (or the dry-run result) carries a ``_warnings`` entry for each of start and
    end that is negative or looks like epoch milliseconds.
    """
    path_segment(camera_id, "camera_id")
    params = {"camera": camera_id, "start": _epoch_ms(start, "start"), "end": _epoch_ms(end, "end")}
    _write_guards("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(_private(host_id, "/video"), key=key, params=params)
    return _with_epoch_unit(
        deletion_result(f"Recordings of camera {camera_id} deleted.", response),
        start=start,
        end=end,
    )


# Module-level aliases: the registered tools below shadow these names inside register().
_get_camera_analytics = get_camera_analytics
_set_camera_control_enabled = set_camera_control_enabled
_set_camera_door_lock = set_camera_door_lock
_get_camera_lux = get_camera_lux
_get_camera_playback_history = get_camera_playback_history
_reset_camera_image_settings = reset_camera_image_settings
_set_camera_resolution_scale = set_camera_resolution_scale
_transfer_camera_management = transfer_camera_management
_turn_on_camera_flashlight = turn_on_camera_flashlight
_get_camera_wifi_networks = get_camera_wifi_networks
_configure_camera_wifi = configure_camera_wifi
_set_camera_video_codec = set_camera_video_codec
_export_edge_recording = export_edge_recording
_set_edge_storage_mount_state = set_edge_storage_mount_state
_reformat_edge_storage = reformat_edge_storage
_update_edge_recording_settings = update_edge_recording_settings
_delete_recordings = delete_recordings
