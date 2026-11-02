"""Source-backed private Protect operations through the Fabric connector.

Routes and payloads: uilibs/uiprotect bf66a09a6bdeb759ebeb801f80349f4d39c91a0c
(api.py and data/devices.py, data/nvr.py). Retention fields also follow
hjdhjd/unifi-protect 66d5f14ba5e381ceedd5f627324079d52c50e0a5 src/types/nvr.ts.
Private routes are controller-version dependent; see the testing matrix for live evidence."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .. import switches
from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    upstream_error_text,
    validate_id,
)
from ..matching import id_key, name_keys
from ..read_only import guard_action
from ..redaction import note_dropped_fields
from ..registry import Registry
from ..selector_syntax import name_reason
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import update_problem
from . import connector, protect
from ._history_common import epoch_warnings, require_epoch_seconds, seconds_to_millis, with_warnings
from ._results import requested_leaves_match, safe_read_after


class PrivateSettings(BaseModel):
    """Extensible private-controller settings; additional upstream fields pass through."""

    model_config = ConfigDict(extra="allow", hide_input_in_errors=True)


class RecordingSettings(PrivateSettings):
    mode: Literal["adaptive", "always", "never", "schedule", "detections"] | None = Field(
        default=None,
        description="Recording mode; always records continuously, never disables recording.",
    )
    enableMotionDetection: bool | None = Field(
        default=None, description="Enable camera motion detection."
    )


class ImageSettings(PrivateSettings):
    irLedMode: str | None = Field(
        default=None,
        description="IR mode: auto, on, autoFilterOnly, off, manual, custom, customFilterOnly.",
    )
    icrCustomValue: int | None = Field(
        default=None,
        description="Controller lux-threshold index 0 through 10; use the camera's reported value.",
    )
    isColorNightVisionEnabled: bool | None = Field(
        default=None, description="Enable colour night vision on supported cameras."
    )
    wdr: int | None = Field(
        default=None,
        description="Wide dynamic range level, reported by the camera (normally 0 through 4).",
    )
    zoomPosition: int | None = Field(
        default=None, description="Optical zoom position in percent on supported cameras."
    )
    brightness: int | None = Field(default=None, description="Camera image brightness.")


class AudioSettings(PrivateSettings):
    isEnabled: bool | None = Field(default=None, description="Enable speaker output.")
    areSystemSoundsEnabled: bool | None = Field(
        default=None, description="Enable camera system sounds."
    )
    volume: int | None = Field(default=None, description="Speaker volume in percent.")
    speakerVolume: int | None = Field(
        default=None, description="Camera speaker output volume in percent."
    )
    ringVolume: int | None = Field(default=None, description="Doorbell ring volume in percent.")
    ringtoneId: str | None = Field(
        default=None, description="Doorbell ringtone identifier from the camera."
    )
    repeatTimes: int | None = Field(default=None, description="Ringtone repetition count.")


class SmartSettings(PrivateSettings):
    objectTypes: list[str] | None = Field(
        default=None,
        description=(
            "Detected types such as person, vehicle, animal, package, face, licensePlate. "
            "Shape: string[]"
        ),
    )
    audioTypes: list[str] | None = Field(
        default=None,
        description="Smart audio detection types reported by the camera. Shape: string[]",
    )
    autoTrackingObjectTypes: list[str] | None = Field(
        default=None,
        description=(
            "Tracking types; person enables person tracking and an empty list disables it. "
            "Shape: string[]"
        ),
    )


class CameraZone(PrivateSettings):
    id: int | None = Field(default=None, description="Zone identifier from the camera.")
    name: str | None = Field(default=None, description="Zone display name.")
    color: str | None = Field(default=None, description="Zone colour, e.g. #85BCEC.")
    points: list[list[float]] | None = Field(
        default=None,
        description=(
            "Polygon coordinate pairs in the camera's 0 to 1 coordinate space. Shape: number[][]"
        ),
    )
    sensitivity: int | None = Field(
        default=None, description="Motion sensitivity in percent when this zone supports it."
    )
    objectTypes: list[str] | None = Field(
        default=None, description="Smart object types detected in this zone. Shape: string[]"
    )


class LedSettings(PrivateSettings):
    isEnabled: bool | None = Field(default=None, description="Enable the device status light.")


class CameraSettings(PrivateSettings):
    recordingSettings: RecordingSettings | None = Field(
        default=None,
        description=(
            "Recording mode and motion detection settings. Shape: "
            "{mode?:'adaptive'|'always'|'never'|'schedule'|'detections',"
            "enableMotionDetection?:boolean}"
        ),
    )
    privacyZones: list[CameraZone] | None = Field(
        default=None,
        description=(
            "Complete desired privacy zone array; include every zone to retain. Shape: "
            "{id?:integer,name?:string,color?:string,points?:number[][],sensitivity?:integer,"
            "objectTypes?:string[]}[]"
        ),
    )
    motionZones: list[CameraZone] | None = Field(
        default=None,
        description=(
            "Complete desired motion zone array; include every zone to retain. Shape: "
            "{id?:integer,name?:string,color?:string,points?:number[][],sensitivity?:integer,"
            "objectTypes?:string[]}[]"
        ),
    )
    smartDetectZones: list[CameraZone] | None = Field(
        default=None,
        description=(
            "Complete desired smart detection zone array; include every zone to retain. "
            "Shape: {id?:integer,name?:string,color?:string,points?:number[][],"
            "sensitivity?:integer,objectTypes?:string[]}[]"
        ),
    )
    ispSettings: ImageSettings | None = Field(
        default=None,
        description=(
            "Image, IR, lux index, colour night vision, WDR and optical zoom. Shape: "
            "{irLedMode?:string,icrCustomValue?:integer,isColorNightVisionEnabled?:boolean,"
            "wdr?:integer,zoomPosition?:integer,brightness?:integer}"
        ),
    )
    speakerSettings: AudioSettings | None = Field(
        default=None,
        description=(
            "Speaker, ring and system sound configuration. Shape: "
            "{isEnabled?:boolean,areSystemSoundsEnabled?:boolean,volume?:integer,"
            "speakerVolume?:integer,ringVolume?:integer,ringtoneId?:string,repeatTimes?:integer}"
        ),
    )
    smartDetectSettings: SmartSettings | None = Field(
        default=None,
        description=(
            "Motion object/audio detection and person tracking. Shape: "
            "{objectTypes?:string[],audioTypes?:string[],autoTrackingObjectTypes?:string[]}"
        ),
    )
    ledSettings: LedSettings | None = Field(
        default=None, description="Camera status light configuration. Shape: {isEnabled?:boolean}"
    )
    chimeDuration: int | None = Field(
        default=None,
        description=(
            "External chime duration in milliseconds: 0 none, 300 mechanical, 1000 digital."
        ),
    )
    micVolume: int | None = Field(default=None, description="Microphone volume in percent.")
    isMicEnabled: bool | None = Field(
        default=None, description="Enable the microphone when the hardware supports it."
    )


class DoorbellSettings(PrivateSettings):
    customMessages: list[str] | None = Field(
        default=None,
        description=(
            "Complete custom-message list; retain entries to keep them. "
            "Controller normally accepts at most 30 characters per message. Shape: string[]"
        ),
    )


class NvrSettings(PrivateSettings):
    doorbellSettings: DoorbellSettings | None = Field(
        default=None,
        description="NVR-wide doorbell custom-message list. Shape: {customMessages?:string[]}",
    )
    isInsightsEnabled: bool | None = Field(default=None, description="Enable Protect insights.")
    analyticsData: Literal["none", "anonymous", "full"] | None = Field(
        default=None, description="Protect analytics sharing level."
    )
    autoRetentionEnabled: bool | None = Field(
        default=None,
        description="Automatic recording retention; coupled behaviour is controller-dependent.",
    )
    recordingRetentionDurationMs: StrictInt | str | None = Field(
        default=None,
        description=(
            "Retention duration in milliseconds as an integer or string, or null. "
            "Shortening it can permanently delete footage."
        ),
    )


class SensorSettings(PrivateSettings):
    mountType: Literal["none", "leak", "door", "window", "garage"] | None = Field(
        default=None, description="Sensor mounting/use type."
    )
    ledSettings: LedSettings | None = Field(
        default=None, description="Sensor status light configuration. Shape: {isEnabled?:boolean}"
    )


DEVICE_TYPES = Literal["camera", "sensor"]


def _guard(method: str) -> None:
    guard_action(method)
    protect._require_mutations()
    if not switches.env_flag(connector.CONNECTOR_WRITE_ENV, True):
        raise ValueError(connector.connector_write_refusal(method))


async def _resolve(
    client: UniFiClient, registry: Registry, host: str, collection: str, ref: str
) -> str:
    reason = name_reason(ref)
    argument = (
        "camera_id"
        if collection == "cameras"
        else "sensor_id"
        if collection == "sensors"
        else "device_id"
    )
    if reason:
        raise ValueError(f"{argument} {reason}")
    # Native ObjectIds can be addressed directly; their GET reports upstream unknown-id errors.
    if re.fullmatch(r"[a-fA-F0-9]{24}", ref):
        return ref.lower()
    response = await connector.connector_get(
        client, registry, host, f"protect/api/{collection}", raise_on_error=True
    )
    if response.get("status") != 200:
        raise UniFiConnectionError(
            f"GET protect/api/{collection}: HTTP {response.get('status')}: "
            f"{upstream_error_text(response.get('body'), client)}"
        )
    body = response.get("body")
    if not isinstance(body, list) or any(not isinstance(v, dict) for v in body):
        raise UniFiConnectionError(
            f"Unexpected Protect {collection} response: {describe_shape(body)}"
        )
    records = body
    matches = [
        v for v in records if isinstance(v.get("id"), str) and id_key(v["id"]) == id_key(ref)
    ]
    if not matches:
        for tier, target in enumerate(name_keys(ref)):
            matches = [
                v
                for v in records
                if isinstance(v.get("name"), str) and name_keys(v["name"])[tier] == target
            ]
            if matches:
                break
    if len(matches) != 1:
        choices = "; ".join(f"{v.get('name')!r} ({v.get('id')})" for v in records)
        raise ValueError(
            f"{'Ambiguous' if matches else 'Unknown'} {collection[:-1]} {ref!r}; "
            f"valid choices: {choices}"
        )
    native = matches[0].get("id")
    validate_id(native, f"{collection[:-1]}_id")
    return str(native)


async def _device_path(
    client: UniFiClient, registry: Registry, host: str, collection: str, ref: str
) -> str:
    native = await _resolve(client, registry, host, collection, ref)
    validate_id(native, "device_id")
    return f"protect/api/{collection}/{native}"


async def get_camera_private(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    path = await _device_path(client, registry, host, "cameras", camera_id)
    return await connector.connector_get(client, registry, host, path)


async def list_ptz_presets(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    path = await _device_path(client, registry, host, "cameras", camera_id)
    result = await connector.connector_get(client, registry, host, path + "/ptz/preset")
    if result.get("status") == 500:
        result = {
            **result,
            "_hint": "the camera may have no PTZ capability; check get_camera featureFlags",
        }
    return result


async def list_ptz_patrols(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    path = await _device_path(client, registry, host, "cameras", camera_id)
    return await connector.connector_get(client, registry, host, path + "/ptz/patrol")


async def get_nvr_private(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    return await connector.connector_get(client, registry, host, "protect/api/nvr")


async def get_sensor_private(
    client: UniFiClient, registry: Registry, host: str, sensor_id: str
) -> dict[str, Any]:
    path = await _device_path(client, registry, host, "sensors", sensor_id)
    return await connector.connector_get(client, registry, host, path)


def _merge(current: Any, requested: Any) -> Any:
    if isinstance(current, dict) and isinstance(requested, dict):
        return {
            **copy.deepcopy(current),
            **{k: _merge(current.get(k), v) for k, v in requested.items()},
        }
    return copy.deepcopy(requested)


def _requested_match(requested: Any, actual: Any) -> bool:
    """Prove requested leaves while retaining controller-added zone fields.

    Arrays still require the exact requested length and order. Each object entry may
    carry extra controller fields; every field the caller supplied must match.
    """
    if isinstance(requested, dict):
        return isinstance(actual, dict) and all(
            key in actual and _requested_match(value, actual[key])
            for key, value in requested.items()
        )
    if isinstance(requested, list):
        return (
            isinstance(actual, list)
            and len(requested) == len(actual)
            and all(_requested_match(a, b) for a, b in zip(requested, actual, strict=True))
        )
    return requested_leaves_match(requested, actual)


async def _update(
    client: UniFiClient, registry: Registry, host: str, path: str, settings: dict[str, Any]
) -> dict[str, Any]:
    before = await connector.connector_get(client, registry, host, path)
    if before.get("status") != 200:
        return {**before, "_writeNotSent": True, "_verified": False, "_noOp": None}
    current = before.get("body")
    if not isinstance(current, dict):
        raise UniFiConnectionError(
            f"Read-before GET {path} needs an object, received {describe_shape(current)}"
        )
    # Send only the requested top-level fields, with nested siblings preserved.
    body = {k: _merge(current.get(k), v) for k, v in settings.items()}
    result = await connector.connector_write(client, registry, host, "PATCH", path, body=body)
    read_after = result.get("readAfter")
    after = read_after.get("body") if isinstance(read_after, dict) else None
    read_status = read_after.get("status") if isinstance(read_after, dict) else None
    status = result.get("status")
    dry = status == "dry_run"
    if not dry and not result.get("readAfterError") and not result.get("postWriteError"):
        if not isinstance(read_status, int) or not 200 <= read_status < 300:
            result["readAfterError"] = (
                f"Read-after GET {path} did not return a successful HTTP status: "
                f"{upstream_error_text(read_after, client)}"
            )
        elif not isinstance(after, dict):
            result["readAfterError"] = (
                f"Read-after GET {path} needs an object, received {describe_shape(after)}"
            )
    if not dry and result.get("postWriteError") and not result.get("readAfterError"):
        result["readAfterError"] = result["postWriteError"]
    result["_verified"] = (
        None
        if dry or result.get("readAfterError")
        else bool(
            isinstance(status, int)
            and 200 <= status < 300
            and isinstance(read_status, int)
            and 200 <= read_status < 300
            and not result.get("readAfterError")
            and not result.get("postWriteError")
            and isinstance(after, dict)
            and _requested_match(settings, after)
        )
    )
    # The no-op verdict compares only the requested leaves, leaf by leaf and
    # type-strict. The read-after already matches every requested leaf (_verified), so the
    # write was a no-op exactly when the read-before matched them too. Unrequested siblings
    # (the merged body, volatile statistics) never enter either verdict.
    result["_noOp"] = (
        None if dry or not result["_verified"] else _requested_match(settings, current)
    )
    if result["_noOp"] is not None:
        # The relay twin compared whole records; report the same requested-leaf basis.
        result["noOp"] = result["_noOp"]
        result["changed"] = not result["_noOp"]
    if not dry and result["_noOp"] is None:
        # The relay twin compared whole records, which can call an unsaved write
        # "already applied" (noOp true, changed false) when the controller discarded it.
        # Without requested-leaf verification (failed or mismatched read-after) there is
        # no no-op verdict at this surface, so the relay's derived verdict is withdrawn.
        if "noOp" in result:
            result["noOp"] = None
        result.pop("changed", None)
    if not dry and not result["_verified"]:
        result["_verificationWarning"] = (
            "Requested settings were not proven saved; "
            "inspect readAfter and read back before retrying."
        )
    if path == "protect/api/nvr" and any(
        k in settings for k in ("recordingRetentionDurationMs", "autoRetentionEnabled")
    ):
        result["_warnings"] = [
            {
                "code": "RETENTION_DATA_LOSS",
                "message": (
                    "Shorter retention can permanently delete older footage; "
                    "automatic-retention coupling needs live verification."
                ),
            }
        ]
    return result


def _settings_body(settings: dict[str, Any], what: str) -> dict[str, Any]:
    clean, dropped, reason = update_problem(
        settings, what, identity=frozenset({"id", "_id", "site_id"})
    )
    if reason:
        raise ValueError(reason)
    note_dropped_fields(dropped)
    return clean


async def update_camera_private(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, settings: dict[str, Any]
) -> dict[str, Any]:
    _guard("PATCH")
    body = _settings_body(settings, "camera settings")
    path = await _device_path(client, registry, host, "cameras", camera_id)
    return await _update(client, registry, host, path, body)


async def update_nvr(
    client: UniFiClient, registry: Registry, host: str, settings: dict[str, Any]
) -> dict[str, Any]:
    _guard("PATCH")
    body = _settings_body(settings, "NVR settings")
    return await _update(client, registry, host, "protect/api/nvr", body)


async def update_sensor_private(
    client: UniFiClient, registry: Registry, host: str, sensor_id: str, settings: dict[str, Any]
) -> dict[str, Any]:
    _guard("PATCH")
    body = _settings_body(settings, "sensor settings")
    path = await _device_path(client, registry, host, "sensors", sensor_id)
    return await _update(client, registry, host, path, body)


async def export_camera_video(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    start: int,
    end: int,
    channel: int = 0,
    fps: int | None = None,
) -> dict[str, Any]:
    require_epoch_seconds(start, "start")
    require_epoch_seconds(end, "end")
    native = await _resolve(client, registry, host, "cameras", camera_id)
    params: dict[str, Any] = {
        "camera": native,
        "start": seconds_to_millis(start),
        "end": seconds_to_millis(end),
    }
    params.update({"lens": 2} if channel == 3 else {"channel": channel})
    if fps is not None:
        params.update({"fps": fps, "type": "timelapse"})
    result = await connector.connector_get(
        client, registry, host, "protect/api/video/export", params=params
    )
    return with_warnings(result, epoch_warnings(start=start, end=end))


async def _action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        result = await connector.connector_write(client, registry, host, method, path, body=body)
        status = result.get("status")
        if status == "dry_run":
            return result
        if not isinstance(status, int) or not 200 <= status < 300:
            result["_writeFailed"] = True
            return result
        warning = (
            (
                "Removing a managed device deletes its configuration and interrupts recording; "
                "re-adoption may be required."
            )
            if method == "DELETE"
            else "Reboot interrupts recording and live view until the device returns."
            if path.endswith("/reboot")
            else "Adoption changes management and may interrupt service."
            if path.endswith("/adopt")
            else "Clears the sensor's latched tamper alert."
        )
        result["_warnings"] = [{"code": "PHYSICAL_ACTION", "message": warning}]
        return result
    except UniFiConnectionError as exc:
        raise UniFiConnectionError(f"{exc}; outcome unknown; read back before retrying") from exc


async def reboot_protect_device(
    client: UniFiClient, registry: Registry, host: str, device_type: DEVICE_TYPES, device_id: str
) -> dict[str, Any]:
    _guard("POST")
    if device_type not in ("camera", "sensor"):
        raise ValueError("device_type must be camera or sensor")
    path = await _device_path(client, registry, host, device_type + "s", device_id)
    return await _action(client, registry, host, "POST", path + "/reboot")


async def adopt_protect_device(
    client: UniFiClient, registry: Registry, host: str, device_type: DEVICE_TYPES, device_id: str
) -> dict[str, Any]:
    _guard("POST")
    if device_type not in ("camera", "sensor"):
        raise ValueError("device_type must be camera or sensor")
    native = await _resolve(client, registry, host, device_type + "s", device_id)
    return await _action(
        client,
        registry,
        host,
        "POST",
        "protect/api/devices/adopt",
        {device_type + "s": {native: {}}},
    )


async def unadopt_protect_device(
    client: UniFiClient, registry: Registry, host: str, device_type: DEVICE_TYPES, device_id: str
) -> dict[str, Any]:
    _guard("DELETE")
    if device_type not in ("camera", "sensor"):
        raise ValueError("device_type must be camera or sensor")
    path = await _device_path(client, registry, host, device_type + "s", device_id)
    result = await _action(client, registry, host, "DELETE", path)
    if result.get("status") == "dry_run":
        return result
    read_after = result.get("readAfter")
    read_status = read_after.get("status") if isinstance(read_after, dict) else None
    after = read_after.get("body") if isinstance(read_after, dict) else None
    error = result.get("readAfterError") or result.get("postWriteError")
    before = result.get("readBefore")
    before_status = before.get("status") if isinstance(before, dict) else None
    write_status = result.get("status")
    if (
        not error
        and read_status == 404
        and isinstance(write_status, int)
        and 200 <= write_status < 300
        and isinstance(before_status, int)
        and 200 <= before_status < 300
        and isinstance(before, dict)
        and isinstance(before.get("body"), dict)
    ):
        # A successful write removed an object established by the pre-read.
        result["_verified"] = True
        result["_noOp"] = False
        result["noOp"] = False
        result["changed"] = True
        return result
    if not error and (not isinstance(read_status, int) or not 200 <= read_status < 300):
        error = (
            f"Read-after GET {path} did not return a successful HTTP status: "
            f"{upstream_error_text(read_after, client)}"
        )
    elif not error and not isinstance(after, dict):
        error = f"Read-after GET {path} needs an object, received {describe_shape(after)}"
    if error:
        result["readAfterError"] = error
        result["_verified"] = None
        result["_noOp"] = None
        result["noOp"] = None
        result.pop("changed", None)
    return result


async def reboot_nvr(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    _guard("POST")
    return await _action(client, registry, host, "POST", "protect/api/nvr/reboot")


async def clear_sensor_tamper(
    client: UniFiClient, registry: Registry, host: str, sensor_id: str
) -> dict[str, Any]:
    _guard("POST")
    path = await _device_path(client, registry, host, "sensors", sensor_id)
    result = await _action(client, registry, host, "POST", path + "/clear-tamper-flag")
    status = result.get("status")
    if isinstance(status, int) and 200 <= status < 300:
        after, error = await safe_read_after(
            lambda: connector.connector_get(client, registry, host, path)
        )
        result["_readAfter"] = after
        if after is not None and after.get("status") != 200:
            error = (
                f"Read-after HTTP {after.get('status')}: "
                f"{upstream_error_text(after.get('body'), client)}"
            )
        if error is None and after is not None and not isinstance(after.get("body"), dict):
            shape = describe_shape(after.get("body"))
            error = f"Read-after GET {path} needs an object, received {shape}"
        if error:
            result["readAfterError"] = error
            result["_verified"] = None
            result["_noOp"] = None

    return result


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register source-backed private Protect tools in the Protect family."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_private(host: str, camera_id: str) -> dict[str, Any]:
        """Read the complete private camera settings. The relay returns status, contentType and the
        upstream body unchanged; use body as the source for update_camera_private.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (get_camera_private):
            {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "66d025b301ebc903e80003ea", or an unambiguous camera name such as "Front Door".
        """
        client, registry = deps_fn()
        return await _get_camera_private(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_ptz_presets(host: str, camera_id: str) -> dict[str, Any]:
        """List PTZ presets, including native id, name, slot and pan/tilt/zoom. Non-PTZ cameras
        reject this route: the console answers HTTP 500 (a console-side limit), and the upstream
        status and body are returned unchanged.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (list_ptz_presets):
            {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "66d025b301ebc903e80003ea", or an unambiguous camera name such as "Front Door".
        """
        client, registry = deps_fn()
        return await _list_ptz_presets(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_ptz_patrols(host: str, camera_id: str) -> dict[str, Any]:
        """List PTZ patrols with slots, preset lists and duration. Returns the upstream body under
        body, with status and contentType.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (list_ptz_patrols):
            {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "66d025b301ebc903e80003ea", or an unambiguous camera name such as "Front Door".
        """
        client, registry = deps_fn()
        return await _list_ptz_patrols(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_sensor_private(host: str, sensor_id: str) -> dict[str, Any]:
        """Read complete private sensor settings and tamper state. Use body with
        update_sensor_private; status and contentType accompany the unchanged upstream body.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (get_sensor_private):
            {"host": "my-console", "sensor_id": "66d025b301ebc903e80003eb"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            sensor_id: Protect sensor id (24-hex) from list_sensors (id), e.g.
                "66d025b301ebc903e80003eb", or an unambiguous sensor name such as
                "Back Door".
        """
        client, registry = deps_fn()
        return await _get_sensor_private(client, registry, host, sensor_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_nvr_private(host: str) -> dict[str, Any]:
        """Read NVR-wide settings including doorbell messages, insights, analytics and retention.
        Returns the complete upstream body under body with status and contentType. Use body with
        update_nvr.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (get_nvr_private):
            {"host": "my-console"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await _get_nvr_private(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def update_camera_private(
        host: str, camera_id: str, settings: CameraSettings
    ) -> dict[str, Any]:
        """Change camera recording, zones, image, IR, lux index, audio, motion detection and
        tracking. Read-merge-PATCH preserves nested siblings; zone arrays replace in full,
        so retain every wanted zone. Privacy masks hide covered imagery.

        Consequence: the PATCH persistently changes stored camera settings. Restore prior
        readBefore values to reverse settings changes. Disabling recording leaves footage gaps.
        Disabling motion detection loses footage only in motion- or detection-triggered recording
        modes; recordingSettings.mode="always" continues recording. Privacy masks hide covered
        imagery. Missing footage and masked imagery cannot be recovered later.

        Returns relay method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes. Write metadata includes
        writeEnabled. Read twins add readBefore/readAfter, noOp and changed when known.
        _verified says requested fields saved; noOp, changed and _noOp compare requested leaves,
        type-strict. If requested fields are absent from both 2xx reads, noOpReason explains why
        noOp is unknown. Failed read-back leaves _verified and _noOp null; readAfterError and
        _verificationWarning explain failed or unproven verification.

        Under UNIFI_DRY_RUN no write is sent. Status is "dry_run"; body contains the exact
        merged preview {status, dryRun, sent: false, message, preview: {method, path, params,
        body}}. _verified remains null; otherwise status is the upstream HTTP number.

        Example call (update_camera_private):
            {"host":"my-console","camera_id":"66d025b301ebc903e80003ea",
             "settings":{"recordingSettings":{"mode":"always"}}}

        Args:
            host: Console short name from list_hosts (reportedState.hostname/name,
                case-insensitive) or data[].id (MAC:numericId); serves Network and Protect.
            camera_id: Protect 24-hex id from list_cameras or an unambiguous camera name.
            settings: Typed partial private settings; additional controller fields pass through.
        """
        client, registry = deps_fn()
        return await _update_camera_private(
            client, registry, host, camera_id, settings.model_dump(exclude_unset=True)
        )

    @mcp.tool(annotations=WRITE)
    async def update_nvr(host: str, settings: NvrSettings) -> dict[str, Any]:
        """Change NVR doorbell custom messages, insights, analytics and retention. Nested objects
        merge; arrays replace in full. DANGER: shorter recording retention can permanently
        delete older footage; retention coupling is controller-dependent and needs live testing.
        Returns the relay response with readBefore/readAfter, _verified and _noOp. A failed or
        non-object read-after leaves _verified and _noOp null, preserving the relay error.
        Dry-run previews the exact merged body.

        Consequence: the PATCH persistently changes NVR-wide settings, reversible by writing back
        the prior values returned in readBefore; shortening recording retention, however, can make
        the NVR permanently delete older footage, which no later write restores.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.
        Write metadata includes writeEnabled; retention changes may add _warnings.
        Read twins add readBefore, readAfter, noOp and changed when known; _noOp compares
        requested leaves, type-strict. If requested fields are absent from both 2xx reads,
        noOpReason explains why noOp is unknown. readAfterError and _verificationWarning
        explain failed or unproven read-back.

        Under UNIFI_DRY_RUN no upstream write is sent: status is "dry_run" and body
        contains the exact preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}}.

        Result status is the upstream HTTP number or dry_run for a preview.

        Example call (update_nvr):
            {"host": "my-console", "settings": {"isInsightsEnabled": true}}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            settings: Typed partial private settings, e.g.
                {"isInsightsEnabled":true,"analyticsData":"anonymous"}; additional controller fields
                pass through.
        """
        client, registry = deps_fn()
        return await _update_nvr(client, registry, host, settings.model_dump(exclude_unset=True))

    @mcp.tool(annotations=WRITE)
    async def update_sensor_private(
        host: str, sensor_id: str, settings: SensorSettings
    ) -> dict[str, Any]:
        """Change sensor mount type and status light via read-merge-PATCH, preserving nested
        siblings. Returns the relay response with readBefore/readAfter, _verified and _noOp.
        A failed or non-object read-after leaves _verified and _noOp null, preserving
        the relay error; dry-run previews the exact merged body.

        Consequence: the PATCH persistently changes the sensor's stored settings. Mount type and
        status light changes are reversible by restoring readBefore values; additional controller
        fields may have other effects.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.
        Write metadata includes writeEnabled.
        Read twins add readBefore, readAfter, noOp and changed when known; _noOp compares
        requested leaves, type-strict. If requested fields are absent from both 2xx reads,
        noOpReason explains why noOp is unknown. readAfterError and _verificationWarning
        explain failed or unproven read-back.

        Under UNIFI_DRY_RUN no upstream write is sent: status is "dry_run" and body
        contains the exact preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}}.

        Result status is the upstream HTTP number or dry_run for a preview.

        Example call (update_sensor_private):
            {
              "host": "my-console",
              "sensor_id": "66d025b301ebc903e80003eb",
              "settings": {
                "mountType": "door"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            sensor_id: Protect sensor id (24-hex) from list_sensors (id), e.g.
                "66d025b301ebc903e80003eb", or an unambiguous sensor name such as
                "Back Door".
            settings: Typed partial private settings, e.g.
                {"mountType":"door","ledSettings":{"isEnabled":true}}; additional controller fields
                pass through.
        """
        client, registry = deps_fn()
        return await _update_sensor_private(
            client, registry, host, sensor_id, settings.model_dump(exclude_unset=True)
        )

    @mcp.tool(annotations=READ_ONLY)
    async def export_camera_video(
        host: str, camera_id: str, start: int, end: int, channel: int = 0, fps: int | None = None
    ) -> dict[str, Any]:
        """Export an MP4 clip or timelapse through the private video route. Returns the entire
        uncapped payload base64-encoded in bodyBase64 with sizeBytes and contentType; body is
        null for binary output. Base64 expands bytes by about one third and the whole response
        occupies memory, so long clips can produce very large MCP messages. Requested clip
        boundaries may differ by a few seconds. Set fps for a timelapse; no duration or payload
        cap is imposed.
        The additive ``_warnings`` entry flags negative or millisecond-looking epoch inputs while
        sending values as given.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (export_camera_video):
            {
              "host": "my-console",
              "camera_id": "66d025b301ebc903e80003ea",
              "start": 1735689600,
              "end": 1735689610
            }

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "66d025b301ebc903e80003ea", or an unambiguous camera name such as "Front Door".
            start: Clip start in epoch seconds, e.g. 1735689600; converted to controller
                milliseconds.
            end: Clip end in epoch seconds, e.g. 1735689610; converted to controller
                milliseconds.
            channel: Stream index, e.g. 0 for high quality; index 3 selects package-camera lens
                2.
            fps: Optional timelapse frame rate, e.g. 4 for 60x or 8 for 120x; omitted for a
                normal clip.
        """
        client, registry = deps_fn()
        return await _export_camera_video(
            client, registry, host, camera_id, start, end, channel, fps
        )

    @mcp.tool(annotations=WRITE)
    async def reboot_protect_device(
        host: str, device_type: DEVICE_TYPES, device_id: str
    ) -> dict[str, Any]:
        """Reboot a Protect device once. Camera recording and live view are interrupted while it
        restarts. No automatic retry; a timeout means outcome unknown, read back before
        retrying.

        Consequence: the camera or sensor restarts and is offline until it comes back; a camera
        records nothing and serves no live view meanwhile, and that gap in footage cannot be
        recovered. No setting is changed.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.
        Write metadata includes writeEnabled; _warnings describes operational risks.

        Under UNIFI_DRY_RUN no upstream write is sent: status is "dry_run" and body
        contains the exact preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}}.

        Result status is the upstream HTTP number or dry_run for a preview.

        Example call (reboot_protect_device):
            {"host": "my-console", "device_type": "camera", "device_id": "66d025b301ebc903e80003ea"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            device_type: Protect resource kind, singular: "camera" or "sensor" (the route
                adds the plural collection, e.g. protect/api/cameras).
            device_id: Protect device id (24-hex) from list_cameras / list_sensors (id),
                e.g. "66d025b301ebc903e80003ea", or an unambiguous device name such as
                "Front Door".
        """
        client, registry = deps_fn()
        return await _reboot_protect_device(client, registry, host, device_type, device_id)

    @mcp.tool(annotations=WRITE)
    async def adopt_protect_device(
        host: str, device_type: DEVICE_TYPES, device_id: str
    ) -> dict[str, Any]:
        """Adopt an available Protect device using its native id. Adoption changes management and
        may interrupt service. Returns the relay status and unchanged upstream adoption result;
        no automatic retry. An unknown id may return a per-device error in an HTTP 200 response.

        Consequence: this console's Protect application takes over management of the device, which
        is provisioned and may restart (briefly interrupting its stream). Adoption persists until
        the device is removed with unadopt_protect_device.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.
        Write metadata includes writeEnabled; _warnings describes operational risks.

        Under UNIFI_DRY_RUN no upstream write is sent: status is "dry_run" and body
        contains the exact preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}}.

        Result status is the upstream HTTP number or dry_run for a preview.

        Example call (adopt_protect_device):
            {"host": "my-console", "device_type": "camera", "device_id": "66d025b301ebc903e80003ea"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            device_type: Protect resource kind, singular: "camera" or "sensor" (the route
                adds the plural collection, e.g. protect/api/cameras).
            device_id: Protect device id (24-hex) from list_cameras / list_sensors (id),
                e.g. "66d025b301ebc903e80003ea", or an unambiguous device name such as
                "Front Door".
        """
        client, registry = deps_fn()
        return await _adopt_protect_device(client, registry, host, device_type, device_id)

    @mcp.tool(annotations=WRITE)
    async def unadopt_protect_device(
        host: str, device_type: DEVICE_TYPES, device_id: str
    ) -> dict[str, Any]:
        """Unadopt and remove a Protect device from management. This deletes its managed-device
        configuration and interrupts recording; re-adoption may be required. Returns the
        unchanged upstream body under body; no automatic retry.

        Consequence: the device and its managed-device configuration are removed from Protect;
        cameras stop recording. Undo requires re-adoption and reconfiguration.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.
        Write metadata includes writeEnabled; _warnings describes operational risks.
        Read twins add readBefore/readAfter, noOp and changed. HTTP 404 after a 2xx read-before
        confirms removal: changed true, noOp false, _verified true, _noOp false. A 2xx read-after
        with the device still present gives noOp null and noOpReason "deletion not confirmed".
        Other failed read-backs set readAfterError and leave _verified and _noOp null.

        Under UNIFI_DRY_RUN no upstream write is sent: status is "dry_run" and body
        contains the exact preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}}.

        Result status is the upstream HTTP number or dry_run for a preview.

        Example call (unadopt_protect_device):
            {"host": "my-console", "device_type": "camera", "device_id": "66d025b301ebc903e80003ea"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            device_type: Protect resource kind, singular: "camera" or "sensor" (the route
                adds the plural collection, e.g. protect/api/cameras).
            device_id: Protect device id (24-hex) from list_cameras / list_sensors (id),
                e.g. "66d025b301ebc903e80003ea", or an unambiguous device name such as
                "Front Door".
        """
        client, registry = deps_fn()
        return await _unadopt_protect_device(client, registry, host, device_type, device_id)

    @mcp.tool(annotations=WRITE)
    async def reboot_nvr(host: str) -> dict[str, Any]:
        """Reboot the Protect NVR once. All camera recording and live view are interrupted until it
        returns. Returns the relay status and complete upstream body. No automatic retry; a
        timeout means outcome unknown, read back before retrying.

        Consequence: the NVR restarts, so no camera footage is recorded and live view is unavailable
        until it is back; that gap in footage cannot be recovered. No setting is changed.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.
        Write metadata includes writeEnabled; _warnings describes operational risks.

        Under UNIFI_DRY_RUN no upstream write is sent: status is "dry_run" and body
        contains the exact preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}}.

        Result status is the upstream HTTP number or dry_run for a preview.

        Example call (reboot_nvr):
            {"host": "my-console"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await _reboot_nvr(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def clear_sensor_tamper(host: str, sensor_id: str) -> dict[str, Any]:
        """Clear a sensor's latched tamper flag once. Returns the relay status and unchanged
        response; _readAfter reports current sensor state without claiming success from HTTP
        alone. Failed read-back preserves the response with readAfterError and null
        _verified/_noOp verdicts. No automatic retry.

        Consequence: the sensor's latched tamper alert is cleared on the controller, so the sensor
        no longer shows as tampered; the cleared flag cannot be restored, but a new tamper event
        latches it again. Nothing happens physically at the sensor.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.
        Write metadata includes writeEnabled; _warnings describes operational risks.

        Under UNIFI_DRY_RUN no upstream write is sent: status is "dry_run" and body
        contains the exact preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}}.

        Result status is the upstream HTTP number or dry_run for a preview.

        Example call (clear_sensor_tamper):
            {"host": "my-console", "sensor_id": "66d025b301ebc903e80003eb"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            sensor_id: Protect sensor id (24-hex) from list_sensors (id), e.g.
                "66d025b301ebc903e80003eb", or an unambiguous sensor name such as
                "Back Door".
        """
        client, registry = deps_fn()
        return await _clear_sensor_tamper(client, registry, host, sensor_id)


# Stable aliases prevent nested registration wrappers from calling themselves.
_get_camera_private = get_camera_private
_list_ptz_presets = list_ptz_presets
_list_ptz_patrols = list_ptz_patrols
_get_sensor_private = get_sensor_private
_get_nvr_private = get_nvr_private
_update_camera_private = update_camera_private
_update_nvr = update_nvr
_update_sensor_private = update_sensor_private
_export_camera_video = export_camera_video
_reboot_protect_device = reboot_protect_device
_adopt_protect_device = adopt_protect_device
_unadopt_protect_device = unadopt_protect_device
_reboot_nvr = reboot_nvr
_clear_sensor_tamper = clear_sensor_tamper
