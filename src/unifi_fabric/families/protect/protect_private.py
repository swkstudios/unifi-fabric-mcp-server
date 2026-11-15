"""Source-backed private Protect operations through the Fabric connector.

Routes and payloads: uilibs/uiprotect bf66a09a6bdeb759ebeb801f80349f4d39c91a0c
(api.py and data/devices.py, data/nvr.py). Retention fields also follow
hjdhjd/unifi-protect 66d5f14ba5e381ceedd5f627324079d52c50e0a5 src/types/nvr.ts.
Private routes are controller-version dependent; see the testing matrix for live evidence."""

from __future__ import annotations

import copy
import re
from typing import Any

from ... import switches
from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    upstream_error_text,
    upstream_error_value,
    validate_id,
)
from ...matching import id_key, name_keys
from ...read_only import guard_action, mark_write_denied
from ...redaction import note_dropped_fields
from ...registry import Registry
from ...selector_syntax import name_reason
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    with_warnings,
)
from ...shared_shapes._results import requested_leaves_match, safe_read_after
from ...write_body import update_problem
from ..connector import connector
from . import protect
from .schemas import (
    _MODE_FLAG,
    _NOT_DETERMINED,
    DEVICE_TYPES,
    EXTERNAL_ARM_PROFILE_TOOLS,
    GLOBAL_ALARM_MANAGER_ROUTES,
    GLOBAL_ALARM_MANAGER_UNSUPPORTED,
    INTEGRATION_ARM_PROFILE_TOOLS,
)
from .schemas import (  # the family's shapes (family-owned layout)
    AudioSettings as AudioSettings,
)
from .schemas import (
    CameraSettings as CameraSettings,
)
from .schemas import (
    CameraZone as CameraZone,
)
from .schemas import (
    DoorbellSettings as DoorbellSettings,
)
from .schemas import (
    ImageSettings as ImageSettings,
)
from .schemas import (
    LedSettings as LedSettings,
)
from .schemas import (
    NvrSettings as NvrSettings,
)
from .schemas import (
    PrivateSettings as PrivateSettings,
)
from .schemas import (
    RecordingSettings as RecordingSettings,
)
from .schemas import (
    SensorSettings as SensorSettings,
)
from .schemas import (
    SmartSettings as SmartSettings,
)


def _guard(method: str) -> None:
    guard_action(method)
    protect._require_mutations()
    if not switches.connector_writes_enabled():
        raise mark_write_denied(ValueError(connector.connector_write_refusal(method)))


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
        choices = "; ".join(
            f"{upstream_error_value(v.get('name'))!r} ({upstream_error_value(v.get('id'))})"
            for v in records
        )
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


def _alarm_manager_mode(status: Any, body: Any, client: UniFiClient) -> dict[str, Any]:
    """The additive ``_alarmManager`` summary for one ``GET protect/api/nvr`` relay result.

    ``featureFlags.useExternalAlarmManager`` true is global; false is local; a console that
    reports no ``featureFlags`` or no flag predates the global Alarm Manager and is local.
    A non-200 answer (a 401/403 permission refusal included) or any other shape leaves
    ``mode`` null with the reason: it is never read as a mode.
    """
    disposition = {
        "supported": False,
        "routes": list(GLOBAL_ALARM_MANAGER_ROUTES),
        "reason": GLOBAL_ALARM_MANAGER_UNSUPPORTED,
    }

    def undetermined(reason: str) -> dict[str, Any]:
        return {
            "mode": None,
            "reason": f"{reason}; {_NOT_DETERMINED}",
            "integrationArmProfiles": None,
            "globalAlarmManagerApi": disposition,
        }

    if status != 200:
        return undetermined(f"GET protect/api/nvr answered HTTP {status} (see status and body)")
    if not isinstance(body, dict):
        return undetermined(f"unexpected Protect NVR response: {describe_shape(body)}")
    flags = body.get("featureFlags")
    if "featureFlags" in body and not isinstance(flags, dict):
        return undetermined(f"unexpected Protect NVR featureFlags: {describe_shape(flags)}")
    present = isinstance(flags, dict) and _MODE_FLAG in flags
    flag = flags.get(_MODE_FLAG) if isinstance(flags, dict) else None
    if present and not isinstance(flag, bool):
        return undetermined(
            f"unexpected featureFlags.{_MODE_FLAG}: {describe_shape(flag)} "
            f"{upstream_error_value(flag, client)!r} (expected true or false)"
        )
    is_global = flag is True
    source = f"body.featureFlags.{_MODE_FLAG}"
    if not present:
        source += (
            " (absent: consoles that predate the global Alarm Manager do not report it, "
            "so the mode is local)"
        )
    return {
        "mode": "global" if is_global else "local",
        "reason": source,
        "integrationArmProfiles": {
            "available": not is_global,
            "tools": list(INTEGRATION_ARM_PROFILE_TOOLS),
            "reason": (
                "the Protect Integration API documents the arm-profile routes as available "
                "only with the local Alarm Manager; in global mode the console answered the "
                "arm-profile reads with HTTP 400 'This operation is not available when global "
                "alarm manager is enabled'; the write and arm/disarm routes were not exercised "
                "in global mode, so their answer is not known and a sent result from them is "
                "not proof of the arm state"
                if is_global
                else None
            ),
        },
        "externalArmProfiles": {
            "available": is_global,
            "tools": list(EXTERNAL_ARM_PROFILE_TOOLS),
            "reason": (
                "the Protect 7.4.96 Integration API serves the external Alarm Manager's arm "
                "profiles and their arm/disarm actions under /v1/external/arm-profiles, "
                "available only when this flag is true; a console on an older Protect "
                "answers 404 there"
                if is_global
                else None
            ),
        },
        "globalAlarmManagerApi": disposition,
    }


async def get_protect_alarm_manager_mode(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    """Report whether a Protect console's Alarm Manager runs in local or global mode, and
    which alarm operations this server can perform there. Read-only: one GET of the private
    NVR object (protect/api/nvr); nothing is sent to the alarm APIs.

    Returns method, routeClass, scope, path, resolvedPath, status (upstream HTTP),
    contentType and body (the NVR object, as get_nvr_private returns it), plus _alarmManager
    {mode, reason, integrationArmProfiles, externalArmProfiles, globalAlarmManagerApi}. mode
    is "global" when body.featureFlags.useExternalAlarmManager is true and "local" when it is
    false or absent (older consoles omit it). mode is null, with reason, when the
    NVR read failed (any non-200 status, returned unchanged) or the flag is
    malformed; a failure is never a mode.
    integrationArmProfiles is {available, tools, reason}, or null when mode is null. In local
    mode the listed tools (list_arm_profiles, enable_arm, ...) work; the API documents them
    for the local Alarm Manager only. In global mode available is false: the console answered
    the arm-profile reads with HTTP 400; writes were not exercised. A sent enable_arm or
    disable_arm response is not proof of the arm state (their verified flag reads armMode
    back); read body.armMode here for the current state.
    externalArmProfiles {available, tools, reason} is present only when mode is known:
    available is true in global mode, where the Protect 7.4.96 external arm-profile tools
    (list_external_arm_profiles and its get, create, update, delete, arm and disarm
    siblings) manage the external Alarm Manager's arm profiles; an older Protect answers
    404. It is false, with a null reason, in local mode.
    globalAlarmManagerApi {supported, routes, reason}: supported is always false; this
    server has no tool for the global Alarm Manager API (/api/v2/alarms), at the console
    root outside the paths the Fabric connector relays. The external arm profiles are a
    separate, relayed API.

    Example call (get_protect_alarm_manager_mode):
        {"host": "my-console"}

    Args:
        host: Console name or id: the short name from list_hosts
            (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
            "my-console") or the long data[].id (MAC:numericId composite). One console
            serves both Network and Protect.
    """
    response = await connector.connector_get(client, registry, host, "protect/api/nvr")
    response["_alarmManager"] = _alarm_manager_mode(
        response.get("status"), response.get("body"), client
    )
    return response


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
    elif isinstance(after, dict):
        result["_verified"] = False
        result["_noOp"] = None
        result["noOp"] = None
        result.pop("changed", None)
    return result


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


# Stable aliases prevent nested registration wrappers from calling themselves.
_get_camera_private = get_camera_private
_list_ptz_presets = list_ptz_presets
_list_ptz_patrols = list_ptz_patrols
_get_sensor_private = get_sensor_private
_get_nvr_private = get_nvr_private
_get_protect_alarm_manager_mode = get_protect_alarm_manager_mode
_update_camera_private = update_camera_private
_update_nvr = update_nvr
_update_sensor_private = update_sensor_private
_export_camera_video = export_camera_video
_reboot_protect_device = reboot_protect_device
_adopt_protect_device = adopt_protect_device
_unadopt_protect_device = unadopt_protect_device
_clear_sensor_tamper = clear_sensor_tamper
