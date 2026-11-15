"""The protect family registrar: its tool wrappers, in registration order (the family-owned layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP

from ..._read_only_audit import write_verbs_for
from ...client import validate_id
from ...read_only import guard_action
from ...shared_shapes._results import deletion_result
from ...shared_shapes._shared import _image_result
from ...tool_annotations import READ_ONLY, WRITE, for_tool
from . import (
    protect,
    protect_automation_backup,
    protect_camera_recording,
    protect_device_lifecycle,
    protect_door_locks,
    protect_events_cases,
    protect_private,
    protect_ptz_doorbell,
    protect_recognition_search,
    protect_users_assets,
    recognition,
)
from .schemas import (
    DEFAULT_FORM_FIELD,
    DEVICE_TYPES,
    AnalyticsKind,
    CameraSettings,
    ChimeOutput,
    CredentialType,
    DoorLockRequest,
    EdgeExportAction,
    EnrollStep,
    ExportAction,
    FavoriteObject,
    FirmwareDeviceType,
    LocateDeviceType,
    MediaKind,
    NvrSettings,
    ReadoptDeviceType,
    RetroactiveAction,
    SensorSettings,
    SettingsDeviceType,
    StreamKind,
)


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
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "00000000000000000000010b", or an unambiguous camera name such as "Front Door".
        """
        client, registry = deps_fn()
        return await protect_private._get_camera_private(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_ptz_presets(host: str, camera_id: str) -> dict[str, Any]:
        """List PTZ presets, including native id, name, slot and pan/tilt/zoom. Non-PTZ cameras
        reject this route: the console answers HTTP 500 (a console-side limit), and the upstream
        status and body are returned unchanged, with an additive _hint about PTZ capability.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (list_ptz_presets):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "00000000000000000000010b", or an unambiguous camera name such as "Front Door".
        """
        client, registry = deps_fn()
        return await protect_private._list_ptz_presets(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_ptz_patrols(host: str, camera_id: str) -> dict[str, Any]:
        """List PTZ patrols with slots, preset lists and duration. Returns the upstream body under
        body, with status and contentType.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (list_ptz_patrols):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "00000000000000000000010b", or an unambiguous camera name such as "Front Door".
        """
        client, registry = deps_fn()
        return await protect_private._list_ptz_patrols(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_sensor_private(host: str, sensor_id: str) -> dict[str, Any]:
        """Read complete private sensor settings and tamper state. Use body with
        update_sensor_private; status and contentType accompany the unchanged upstream body.

        Returns method, routeClass, scope, path, resolvedPath, status, contentType and
        body; binary responses use bodyBase64 and sizeBytes.

        Result status is the upstream HTTP number.

        Example call (get_sensor_private):
            {"host": "my-console", "sensor_id": "00000000000000000000010c"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            sensor_id: Protect sensor id (24-hex) from list_sensors (id), e.g.
                "00000000000000000000010c", or an unambiguous sensor name such as
                "Back Door".
        """
        client, registry = deps_fn()
        return await protect_private._get_sensor_private(client, registry, host, sensor_id)

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
        return await protect_private._get_nvr_private(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_alarm_manager_mode(host: str) -> dict[str, Any]:
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
        client, registry = deps_fn()
        return await protect_private._get_protect_alarm_manager_mode(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def update_camera_private(
        host: str, camera_id: str, settings: CameraSettings
    ) -> dict[str, Any]:
        """Change camera recording, zones, image, IR, lux index, audio, motion detection and tracking by read-merge-PATCH (nested siblings kept; zone arrays replace in full, so retain every wanted zone).

        Consequence: persistently changes stored camera settings; restore readBefore values to reverse. Disabling recording leaves footage gaps; disabling motion detection loses footage only in motion/detection recording modes (mode="always" keeps recording). Privacy masks hide covered imagery. Missing footage and masked imagery cannot be recovered.

        Returns the relay envelope {method, routeClass, scope, path, resolvedPath, status, contentType, body} plus writeEnabled, readBefore/readAfter, noOp, changed (type-strict leaf compare), _verified (requested fields saved). If requested fields are absent from both reads, noOpReason says why noOp is unknown. A failed read-back leaves _verified/_noOp null with readAfterError and _verificationWarning. Under dry-run policy nothing is sent: status "dry_run", body the merged preview, _verified null.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_camera_private):
            {"host": "my-console", "camera_id": "00000000000000000000010b",
             "settings": {"recordingSettings": {"mode": "always"}}}

        Args:
            host: Console short name from list_hosts (reportedState.hostname/name,
                case-insensitive) or data[].id (MAC:numericId); serves Network and Protect.
            camera_id: Protect 24-hex id from list_cameras or an unambiguous camera name.
            settings: Typed partial private settings; additional controller fields pass through.
        """
        client, registry = deps_fn()
        return await protect_private._update_camera_private(
            client, registry, host, camera_id, settings.model_dump(exclude_unset=True)
        )

    @mcp.tool(annotations=WRITE)
    async def update_nvr(host: str, settings: NvrSettings) -> dict[str, Any]:
        """Change NVR doorbell custom messages, insights, analytics and retention (nested objects merge; arrays replace in full). DANGER: shortening recording retention can make the NVR permanently delete older footage; retention coupling is controller-dependent and needs live testing.

        Consequence: the PATCH persistently changes NVR-wide settings, reversible by writing back the readBefore values; shortened retention, however, deletes footage no later write restores.

        Returns the relay envelope {method, routeClass, scope, path, resolvedPath, status, contentType, body} plus writeEnabled, readBefore/readAfter, noOp, changed (type-strict leaf compare), _verified, and _warnings on retention changes. If requested fields are absent from both reads, noOpReason says why noOp is unknown; a failed or non-object read-after leaves _verified/_noOp null with readAfterError and _verificationWarning. Under dry-run policy nothing is sent: status "dry_run", body the exact merged preview.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

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
        return await protect_private._update_nvr(
            client, registry, host, settings.model_dump(exclude_unset=True)
        )

    @mcp.tool(annotations=WRITE)
    async def update_sensor_private(
        host: str, sensor_id: str, settings: SensorSettings
    ) -> dict[str, Any]:
        """Change sensor mount type and status light by read-merge-PATCH, preserving nested siblings. Consequence: persistently changes the sensor's stored settings; mount type and status light are reversible by restoring readBefore values; other controller fields may have other effects.

        Returns the relay envelope {method, routeClass, scope, path, resolvedPath, status, contentType, body} plus writeEnabled, readBefore/readAfter, noOp, changed (type-strict leaf compare), _verified. If requested fields are absent from both reads, noOpReason says why noOp is unknown; a failed or non-object read-after leaves _verified/_noOp null with readAfterError and _verificationWarning. Under dry-run policy nothing is sent: status "dry_run", body the exact merged preview.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_sensor_private):
            {"host": "my-console", "sensor_id": "00000000000000000000010c",
             "settings": {"mountType": "door"}}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            sensor_id: Protect sensor id (24-hex) from list_sensors (id), e.g.
                "00000000000000000000010c", or an unambiguous sensor name such as
                "Back Door".
            settings: Typed partial private settings, e.g.
                {"mountType":"door","ledSettings":{"isEnabled":true}}; additional controller fields
                pass through.
        """
        client, registry = deps_fn()
        return await protect_private._update_sensor_private(
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
              "camera_id": "00000000000000000000010b",
              "start": 1735689600,
              "end": 1735689610
            }

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            camera_id: Protect camera id (24-hex) from list_cameras (id), e.g.
                "00000000000000000000010b", or an unambiguous camera name such as "Front Door".
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
        return await protect_private._export_camera_video(
            client, registry, host, camera_id, start, end, channel, fps
        )

    @mcp.tool(annotations=WRITE)
    async def reboot_protect_device(
        host: str, device_type: DEVICE_TYPES, device_id: str
    ) -> dict[str, Any]:
        """Reboot a Protect device once. Camera recording and live view are interrupted while it restarts. No automatic retry; a timeout means outcome unknown, read back before retrying.

        Consequence: the camera or sensor restarts and is offline until it comes back; a camera records nothing and serves no live view meanwhile, and that gap in footage cannot be recovered. No setting is changed.

        Returns the relay envelope {method, routeClass, scope, path, resolvedPath, status, contentType, body} (binary: bodyBase64, sizeBytes). Adds writeEnabled and _warnings.

        Under dry-run policy no upstream write is sent: status is "dry_run" and body contains the exact dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (reboot_protect_device):
            {"host": "my-console", "device_type": "camera", "device_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            device_type: Protect resource kind, singular: "camera" or "sensor" (the route
                adds the plural collection, e.g. protect/api/cameras).
            device_id: Protect device id (24-hex) from list_cameras / list_sensors (id),
                e.g. "00000000000000000000010b", or an unambiguous device name such as
                "Front Door".
        """
        client, registry = deps_fn()
        return await protect_private._reboot_protect_device(
            client, registry, host, device_type, device_id
        )

    @mcp.tool(annotations=WRITE)
    async def adopt_protect_device(
        host: str, device_type: DEVICE_TYPES, device_id: str
    ) -> dict[str, Any]:
        """Adopt an available Protect device using its native id. Adoption changes management and may interrupt service. Returns the relay status and unchanged upstream adoption result; no automatic retry. An unknown id may return a per-device error in an HTTP 200 response.

        Consequence: this console's Protect application takes over management of the device, which is provisioned and may restart (briefly interrupting its stream). Adoption persists until the device is removed with unadopt_protect_device.

        Returns the relay envelope {method, routeClass, scope, path, resolvedPath, status, contentType, body} (binary: bodyBase64, sizeBytes). Adds writeEnabled and _warnings.

        Under dry-run policy no upstream write is sent: status is "dry_run" and body contains the exact dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (adopt_protect_device):
            {"host": "my-console", "device_type": "camera", "device_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            device_type: Protect resource kind, singular: "camera" or "sensor" (the route
                adds the plural collection, e.g. protect/api/cameras).
            device_id: Protect device id (24-hex) from list_cameras / list_sensors (id),
                e.g. "00000000000000000000010b", or an unambiguous device name such as
                "Front Door".
        """
        client, registry = deps_fn()
        return await protect_private._adopt_protect_device(
            client, registry, host, device_type, device_id
        )

    @mcp.tool(annotations=WRITE)
    async def unadopt_protect_device(
        host: str, device_type: DEVICE_TYPES, device_id: str
    ) -> dict[str, Any]:
        """Unadopt and remove a Protect device from management. This deletes its managed-device configuration and interrupts recording; re-adoption may be required. Returns the unchanged upstream body under body; no automatic retry.

        Consequence: the device and its managed-device configuration are removed from Protect; cameras stop recording. Undo requires re-adoption and reconfiguration.

        Returns the relay envelope {method, routeClass, scope, path, resolvedPath, status, contentType, body} (binary: bodyBase64, sizeBytes). Adds writeEnabled and _warnings. Read twins add readBefore/readAfter, noOp and changed. HTTP 404 after a 2xx read-before confirms removal: changed true, noOp false, _verified true, _noOp false. A 2xx read-after with the device still present gives noOp null and noOpReason "deletion not confirmed". Other failed read-backs set readAfterError and leave _verified and _noOp null.

        Under dry-run policy no upstream write is sent: status is "dry_run" and body contains the exact dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (unadopt_protect_device):
            {"host": "my-console", "device_type": "camera", "device_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            device_type: Protect resource kind, singular: "camera" or "sensor" (the route
                adds the plural collection, e.g. protect/api/cameras).
            device_id: Protect device id (24-hex) from list_cameras / list_sensors (id),
                e.g. "00000000000000000000010b", or an unambiguous device name such as
                "Front Door".
        """
        client, registry = deps_fn()
        return await protect_private._unadopt_protect_device(
            client, registry, host, device_type, device_id
        )

    @mcp.tool(annotations=WRITE)
    async def clear_sensor_tamper(host: str, sensor_id: str) -> dict[str, Any]:
        """Clear a sensor's latched tamper flag once. Returns the relay status and unchanged response; _readAfter reports current sensor state without claiming success from HTTP alone. Failed read-back preserves the response with readAfterError and null _verified/_noOp verdicts. No automatic retry.

        Consequence: the sensor's latched tamper alert is cleared on the controller, so the sensor no longer shows as tampered; the cleared flag cannot be restored, but a new tamper event latches it again. Nothing happens physically at the sensor.

        Returns the relay envelope {method, routeClass, scope, path, resolvedPath, status, contentType, body} (binary: bodyBase64, sizeBytes). Adds writeEnabled and _warnings.

        Under dry-run policy no upstream write is sent: status is "dry_run" and body contains the exact dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (clear_sensor_tamper):
            {"host": "my-console", "sensor_id": "00000000000000000000010c"}

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite). One console
                serves both Network and Protect.
            sensor_id: Protect sensor id (24-hex) from list_sensors (id), e.g.
                "00000000000000000000010c", or an unambiguous sensor name such as
                "Back Door".
        """
        client, registry = deps_fn()
        return await protect_private._clear_sensor_tamper(client, registry, host, sensor_id)


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_analytics(
        host: str,
        camera_id: str,
        kind: AnalyticsKind,
        start: int,
        end: int,
        step: int | None = None,
        heatmap_type: str | None = None,
    ) -> Any:
        """Get a Protect camera's analytics over a time window.

        Kind "detections" reads GET /cameras/{camera_id}/analytics-detections (detection
        counts, bucketed by step); kind "heatmap" reads analytics-heatmap (heatmap_type
        sent as type). start and end are epoch SECONDS, sent as epoch milliseconds.
        Returns the upstream body verbatim, and an image as {content_base64,
        content_type, size_bytes}. _warnings is added (one entry per such time
        argument) only when start or end is negative or looks like epoch milliseconds;
        an array body then is returned under result.

        Required arguments: host, camera_id, kind, start, end (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            kind: "detections" or "heatmap"; for example "detections".
            start: Window start, epoch SECONDS; for example 1760227200.
            end: Window end, epoch SECONDS; for example 1760313600.
            step: Detection bucket width in MILLISECONDS (the unit start and end are sent
                in), sent as given without conversion; for example 3600000 (1 hour).
            heatmap_type: Heatmap object type, sent as type; for example "person".
        """
        client, registry = deps_fn()
        return await protect_camera_recording._get_camera_analytics(
            client,
            registry,
            host,
            camera_id,
            kind,
            start,
            end,
            step=step,
            heatmap_type=heatmap_type,
        )

    @mcp.tool(annotations=WRITE)
    async def set_camera_control_enabled(
        host: str, camera_id: str, enabled: bool, confirm: bool = False
    ) -> dict[str, Any]:
        """Enable or disable control of a Protect camera.

        Sends GET /cameras/{camera_id}/enable-control (enabled=true) or disable-control
        (false). The console changes state on this GET, so it is a write: refused under
        read-only mode and the Protect write opt-out, and sent once (never retried).
        Returns {status: "enabled" | "disabled", response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes whether the camera can be controlled until it is set back.

        Required arguments: host, camera_id, enabled (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            enabled: true sends enable-control, false sends disable-control; for example
                false.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._set_camera_control_enabled(
            client, registry, host, camera_id, enabled
        )

    @mcp.tool(annotations=WRITE)
    async def set_camera_door_lock(
        host: str, camera_id: str, locked: bool, confirm: bool = False
    ) -> dict[str, Any]:
        """Lock or unlock the door lock connected to a Protect camera (a doorbell or access
        reader with a lock).

        Sends POST /cameras/{camera_id}/lock (locked=true) or /unlock (false), once.
        Returns {status: "locked" | "unlocked", response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: physically locks or unlocks the door; unlocking lets anyone in.

        Required arguments: host, camera_id, locked (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            locked: true locks, false unlocks; for example true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._set_camera_door_lock(
            client, registry, host, camera_id, locked
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_lux(host: str, camera_id: str) -> Any:
        """Get a Protect camera's current light level (lux) reading.

        Sends GET /cameras/{camera_id}/lux. Returns the upstream body verbatim (an
        upstream array is returned under result).

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
        """
        client, registry = deps_fn()
        return await protect_camera_recording._get_camera_lux(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_playback_history(
        host: str, camera_id: str, start: int, end: int, resolution: int | None = None
    ) -> Any:
        """Get a Protect camera's recording (playback) history over a time window.

        Sends GET /cameras/{camera_id}/playback-history with start and end (epoch
        SECONDS, sent as epoch milliseconds) and resolution (the recording quality channel,
        not a time span) only when given. Returns the upstream body verbatim. _warnings is
        added (one entry per such time argument) only when start or end is negative or looks
        like epoch milliseconds; an array body then is returned under result.

        Required arguments: host, camera_id, start, end (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            start: Window start, epoch SECONDS; for example 1760227200.
            end: Window end, epoch SECONDS; for example 1760313600.
            resolution: Recording quality channel whose segments to list, sent as given:
                0 = high quality (HQ), 2 = low quality (LQ), the values the Protect web app
                sends (its enum also has 1 = AUTO); not a time span; for example 0.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._get_camera_playback_history(
            client, registry, host, camera_id, start, end, resolution=resolution
        )

    @mcp.tool(annotations=WRITE)
    async def reset_camera_image_settings(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Reset a Protect camera's image (ISP) settings to their defaults.

        Sends POST /cameras/{camera_id}/reset-isp, once. Returns {status: "reset",
        response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: discards the camera's tuned image settings; they are not restored.

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._reset_camera_image_settings(
            client, registry, host, camera_id
        )

    @mcp.tool(annotations=WRITE)
    async def set_camera_resolution_scale(
        host: str, camera_id: str, scale: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Set a Protect camera's resolution scale.

        Sends POST /cameras/{camera_id}/resolutionScale/{scale}, once; the console judges
        the value. Returns {status: "sent", response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes the resolution the camera streams and records at.

        Required arguments: host, camera_id, scale (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            scale: Scale value sent as one path segment; for example "1".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._set_camera_resolution_scale(
            client, registry, host, camera_id, scale
        )

    @mcp.tool(annotations=WRITE)
    async def transfer_camera_management(
        host: str, camera_id: str, nvr_mac: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Transfer management of a Protect camera to another NVR.

        Sends POST /cameras/{camera_id}/transfer-mgmt with {nvrMac}, once (never retried).
        Returns {status: "sent", response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: irreversible from this console: the camera leaves it for the other
        NVR and is managed (and recorded) there; only that NVR can transfer it back.

        Required arguments: host, camera_id, nvr_mac (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            nvr_mac: MAC address of the NVR to take over the camera, sent as nvrMac; for
                example "02:00:5e:00:53:01".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._transfer_camera_management(
            client, registry, host, camera_id, nvr_mac
        )

    @mcp.tool(annotations=WRITE)
    async def turn_on_camera_flashlight(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Turn on a Protect camera's flashlight (its built-in light).

        Sends POST /cameras/{camera_id}/turnon-flashlight, once. Returns {status: "sent",
        response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: physically switches on the camera's light.

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._turn_on_camera_flashlight(
            client, registry, host, camera_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_wifi_networks(host: str, camera_id: str) -> Any:
        """Get the WiFi networks a Protect camera can see (for a WiFi camera).

        Sends GET /cameras/{camera_id}/wifi-list. Returns the upstream body verbatim (an
        upstream array is returned under result).

        Required arguments: host, camera_id (see each parameter's description).

        A console HTTP 500 may require checking camera WiFi support and connectivity.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
        """
        client, registry = deps_fn()
        return await protect_camera_recording._get_camera_wifi_networks(
            client, registry, host, camera_id
        )

    @mcp.tool(annotations=WRITE)
    async def configure_camera_wifi(
        host: str, camera_id: str, settings: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Configure the WiFi network a Protect WiFi camera connects to.

        Sends settings as the body of POST /cameras/{camera_id}/wifi-setup, once. The body
        is free-form: its keys are not published, so it is sent exactly as given and the
        console judges it. An empty settings object fails before any request. Returns
        {status: "sent", response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: the camera rejoins WiFi with these settings; wrong ones take it
        offline until it is set up again on site.

        Required arguments: host, camera_id, settings (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            settings: Free-form wifi-setup body, sent as given (keys unpublished); for
                example {"ssid": "Cameras-IoT", "password": "correct-horse-battery"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._configure_camera_wifi(
            client, registry, host, camera_id, settings
        )

    @mcp.tool(annotations=WRITE)
    async def set_camera_video_codec(
        host: str, camera_id: str, codec: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Set the video codec a Protect camera encodes with.

        Sends POST /cameras/{camera_id}/videoCodec?name=CODEC, once; the console judges
        the codec name. Returns {status: "sent", response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes the codec of the camera's streams and new recordings.

        Required arguments: host, camera_id, codec (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            codec: Codec name, sent as the name query parameter; for example "h265".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._set_camera_video_codec(
            client, registry, host, camera_id, codec
        )

    @mcp.tool(annotations=READ_ONLY)
    async def export_edge_recording(
        host: str,
        camera_id: str,
        action: EdgeExportAction,
        filename: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> Any:
        """Export a recording from a Protect camera's own (edge) storage, in two steps.

        Action "prepare" sends GET /edge-recording/{camera_id}/prepare with filename, start and end (the console requires all three; start and end are epoch SECONDS sent as ms); the console creates an export job, copies that window off the camera and answers {filename, expiresAfter}, without changing configuration. Prepare is never retried. This read is allowed in read-only mode and executes under dry-run policy. Action "download" sends GET /edge-recording/{camera_id}/download with the same filename. Only the arguments given are sent (start or end with download fails before any request). Returns the upstream body verbatim: JSON or text as sent (an upstream array under result), and a file as {content_base64, content_type, size_bytes} with the upstream Content-Type; start or end values that look like milliseconds or are negative add _warnings.

        Required arguments: host, camera_id, action (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Id of the camera whose storage holds the recording, from
                list_cameras; for example "000000000000000000000103".
            action: "prepare" or "download"; for example "prepare".
            filename: Export file name, sent as filename: the name to store it under
                (prepare) and to fetch (download); for example "edge-export.mp4".
            start: Window start for prepare, epoch SECONDS (sent as ms); for example
                1760227200.
            end: Window end for prepare, epoch SECONDS (sent as ms); for example 1760227260.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._export_edge_recording(
            client, registry, host, camera_id, action, filename=filename, start=start, end=end
        )

    @mcp.tool(annotations=WRITE)
    async def set_edge_storage_mount_state(
        host: str, camera_id: str, mount_state: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Mount or unmount a Protect camera's own (edge) recording storage.

        Sends POST /edge-recording/{camera_id}/mount-state with {mountState}, once; the
        console judges the value. Returns {status: "sent", response} (response is the
        upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: an unmounted card stops on-camera recording until it is mounted.

        Required arguments: host, camera_id, mount_state (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Id of the camera whose storage to mount or unmount, from
                list_cameras; for example "000000000000000000000103".
            mount_state: Value sent as mountState: "unmounted" unmounts the storage and "mounted"
                mounts it again (the console judges the value); for example "unmounted".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._set_edge_storage_mount_state(
            client, registry, host, camera_id, mount_state
        )

    @mcp.tool(annotations=WRITE)
    async def reformat_edge_storage(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Reformat a Protect camera's own (edge) recording storage.

        Sends POST /edge-recording/{camera_id}/reformat, once (never retried). Returns
        {status: "sent", response} (response is the upstream body verbatim).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: irreversible: erases every recording on the camera's own storage.

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Id of the camera whose storage to reformat, from list_cameras;
                for example "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._reformat_edge_storage(
            client, registry, host, camera_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_edge_recording_settings(
        host: str, camera_id: str, settings: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Update a Protect camera's edge (on-camera) recording settings.

        Sends settings as the body of PATCH /edge-recording/{camera_id}/recording-settings,
        once. The body is free-form: its keys are not published, so it is sent exactly
        as given and the console judges it. An empty settings object fails before any
        request. Returns {status: "updated", verified, before, after, response} (response
        is the upstream body verbatim). There is no read route for these settings, so
        nothing is read back: verified, before and after are always null.
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes what and how the camera records to its own storage.

        Required arguments: host, camera_id, settings (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            settings: Free-form recording-settings body, sent as given (keys
                unpublished); for example {"enabled": true}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._update_edge_recording_settings(
            client, registry, host, camera_id, settings
        )

    @mcp.tool(annotations=WRITE)
    async def delete_recordings(
        host: str, camera_id: str, start: int, end: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Delete a Protect camera's recordings in a time window.

        Sends DELETE /video?camera=CAMERA_ID&start&end, once (never retried); start and end are epoch SECONDS, sent as epoch milliseconds. Returns {deleted: true, message, response} (response is the upstream body verbatim). With dry-run policy, returns a dry-run preview wrapped as {status: "dry_run", deleted: false, message, response} (response is the preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}) and sends nothing. Either result also carries _warnings (one entry per such time argument) when start or end is negative or looks like epoch milliseconds.

        Consequence: irreversible: the camera's recordings in the window are erased from the NVR and cannot be recovered.

        Required arguments: host, camera_id, start, end (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras, sent as camera; for example
                "000000000000000000000103".
            start: Window start, epoch SECONDS; for example 1760227200.
            end: Window end, epoch SECONDS; for example 1760230800.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_camera_recording._delete_recordings(
            client, registry, host, camera_id, start, end
        )


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the protect tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_cameras(
        host: str,
    ) -> dict[str, Any]:
        """List all cameras on a Protect console.

        Returns {result, _count}: result is the upstream array of cameras verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_cameras(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera(
        host: str,
        camera_id: str,
    ) -> dict[str, Any]:
        """Get details for a single Protect camera by ID.

        Returns: the camera object, verbatim. To change it, pass only the fields to change as `settings`
        to update_camera (a partial PATCH).

        Example call (get_camera):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_camera(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def update_camera(
        host: str,
        camera_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update settings for a Protect camera (name, OSD, LED, LCD message, mic volume, video mode, HDR, smart detection).

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Details: docs/TOOL-USAGE.md#update_camera.

        Required arguments: host, camera_id, settings (see parameter descriptions for identifiers).

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/cameras/{id} body. Keys: name, osdSettings, ledSettings, lcdMessage, micVolume
                (number 1-100), videoMode, hdrType, smartDetectSettings (nested keys in the
                parameter schema and
                docs/TOOL-USAGE.md#update_camera).
        """
        client, registry = deps_fn()
        return await protect.update_camera(client, registry, host, camera_id, **settings)

    @mcp.tool(annotations=WRITE)
    async def enable_camera_share_link(host: str, camera_id: str) -> Any:
        """Enable a bearer share link that exposes a camera livestream to anyone with the link.

        Consequence: anyone holding the link can watch the camera's live video, without signing in, until it expires or disable_camera_share_link revokes it.

        Cloud-only: POST protect/api/cameras/{id}/sharedStream through the Fabric connector. No request body. Returns the upstream body verbatim, including null for an empty body. Expiry and maxStreams are server configuration (defaults 24 hours and 1 stream), not tool parameters. The share URL/token is a bearer secret: keep it out of logs, evidence and fixtures. Writes are enabled by default; family:protect=deny or UNIFI_WRITE_POLICY=deny refuses the mutation. dry-run policy sends nothing and returns the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}. Exposure actions are sent once, never automatically retried.

        Example call (enable_camera_share_link):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id from list_hosts, e.g. "my-console"; resolved to its owning
                Fabric API key and console id before the camera request.
            camera_id: Protect camera id from list_cameras, e.g. "00000000000000000000010b";
                pass the full id, not a camera name or Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.enable_camera_share_link(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_share_link(host: str, camera_id: str) -> Any:
        """Read a camera's current livestream share link and status.

        Cloud-only: GET protect/api/cameras/{id}/sharedStream through the Fabric connector.
        No request body. Returns the upstream body verbatim. Object bodies are returned
        directly as structured output; arrays use {result: body}, and an empty body uses
        {result: null}. String, integer and boolean bodies have structured_content=None
        and are returned as text content.
        Expiry and maxStreams are server configuration (defaults 24 hours and 1 stream),
        not tool parameters. The share URL/token is a bearer secret: keep it out of logs,
        evidence and fixtures. This is a read and does not enable sharing.

        Example call (get_camera_share_link):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id from list_hosts, e.g. "my-console"; resolved to its owning
                Fabric API key and console id before the camera request.
            camera_id: Protect camera id from list_cameras, e.g. "00000000000000000000010b";
                pass the full id, not a camera name or Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_camera_share_link(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def disable_camera_share_link(host: str, camera_id: str) -> Any:
        """Disable a camera's livestream share link, revoking public viewing access.

        Consequence: the existing link stops working for everyone who holds it; a new link needs enable_camera_share_link.

        Cloud-only: DELETE protect/api/cameras/{id}/sharedStream through the Fabric connector. No request body. Returns the upstream body verbatim, including null for an empty body. Expiry and maxStreams are server configuration (defaults 24 hours and 1 stream), not tool parameters. The share URL/token is a bearer secret: keep it out of logs, evidence and fixtures. Writes are enabled by default; family:protect=deny or UNIFI_WRITE_POLICY=deny refuses the mutation. dry-run policy sends nothing and returns the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}. Exposure actions are sent once, never automatically retried.

        Example call (disable_camera_share_link):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id from list_hosts, e.g. "my-console"; resolved to its owning
                Fabric API key and console id before the camera request.
            camera_id: Protect camera id from list_cameras, e.g. "00000000000000000000010b";
                pass the full id, not a camera name or Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.disable_camera_share_link(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_snapshot(
        host: str,
        camera_id: str,
        channel: str | None = None,
        high_quality: bool | None = None,
        ts: int | None = None,
    ) -> Any:
        """Get a snapshot from a Protect camera. Returns MCP ImageContent plus image metadata.

        Returns MCP ImageContent plus text and structured metadata
        {image_base64, content_type, size_bytes}; content_type is the upstream
        Content-Type header (typically image/jpeg), not assumed, and null when the upstream
        sends none. channel and high_quality are the spec's optional query parameters, sent only
        when given. With ts the tool reads a past moment from the private Protect route
        cameras/{id}/recording-snapshot instead of the live frame (see ts below for its
        provenance).

        Example call (get_camera_snapshot):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            channel: Optional camera channel (query channel): 'main', or 'package' for the package
                camera of a camera whose hasPackageCamera is true. Sent verbatim; omit for the
                controller default.
            high_quality: Optional (query highQuality): true forces a 1080p-or-higher snapshot, false
                does not. Omit for the controller default.
            ts: Optional moment to snapshot, sent as query ts to the private route
                cameras/{id}/recording-snapshot instead of the live snapshot. Provenance: probed
                on a live console 2026-10-17 (Protect 5.3.18), where the route answered 400 without
                ts and 404 "Recording not found" with it, so the key is accepted; the unit is
                inferred to be epoch milliseconds and is unverified, and a returned image has not
                been observed. Omit for the live frame. Example: `1760140800000`.
        """
        client, registry = deps_fn()
        return _image_result(
            await protect.get_camera_snapshot(
                client, registry, host, camera_id, channel=channel, high_quality=high_quality, ts=ts
            )
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_rtsps_stream(
        host: str,
        camera_id: str,
    ) -> dict[str, Any]:
        """Get existing RTSPS stream URLs for a Protect camera.

        Returns the upstream RTSPS stream (one URL per quality) object verbatim, exactly as the API
        answers it.

        Example call (get_rtsps_stream):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_rtsps_stream(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def create_rtsps_stream(
        host: str,
        camera_id: str,
        qualities: list[str],
    ) -> dict[str, Any]:
        """Create an RTSPS stream for a Protect camera.

        Returns {status: "created", response}: response is the upstream body verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty). Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        `qualities`: list of channel names to enable. The exhaustive set is 'high', 'medium', 'low', and 'package' (verified live against get_rtsps_stream, which reports exactly these four channel keys). 'package' exists only on package-camera doorbells; on other cameras it is null. There is NO 'highest' channel. Each value must be exactly one of those spec enum values (lowercase); any other value, a different case included, fails before any request.

        Request body (Protect 7.3.74, POST /v1/cameras/{id}/rtsps-stream; schema "inline requestBody
        schema") is built from scalar parameters. Required keys — qualities.
        - qualities: array of enum high|medium|low|package

        Example call (create_rtsps_stream):
            {"host": "my-console", "camera_id": "00000000000000000000010b", "qualities": ["high"]}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            qualities: Channels to enable (at least one; an empty list fails before any request,
                spec minItems 1); spec enum channelQuality: high|medium|low|package (package only on
                cameras with a package lens).
        """
        client, registry = deps_fn()
        return await protect.create_rtsps_stream(client, registry, host, camera_id, qualities)

    @mcp.tool(annotations=WRITE)
    async def delete_rtsps_stream(
        host: str,
        camera_id: str,
        qualities: str | list[str],
    ) -> dict[str, Any]:
        """Delete an RTSPS stream for a Protect camera. Consequence: the RTSPS URL of each deleted quality stops working for every consumer; there is no undo.

        `qualities`: one channel name or a non-empty list: 'high', 'medium', 'low' or 'package' (package only on package-camera doorbells; there is no 'highest'). Values must be exact lowercase spec values; any other value, an empty list or a different case fails before any request. Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the dry-run preview; preview.params.qualities is the lowercased list the DELETE would send)}.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (delete_rtsps_stream):
            {"host": "my-console", "camera_id": "00000000000000000000010b", "qualities": ["high"]}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            qualities: Channel to delete ('high'), or a list of channels (at least one; an empty list
                fails before any request); spec enum channelQuality: high|medium|low|package.
                Shape: 'high'|'medium'|'low'|'package'|('high'|'medium'|'low'|'package')[]
        """
        client, registry = deps_fn()
        response = await protect.delete_rtsps_stream(client, registry, host, camera_id, qualities)
        return deletion_result(f"RTSPS stream for camera {camera_id} deleted.", response)

    @mcp.tool(annotations=WRITE)
    async def start_talkback_session(
        host: str,
        camera_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Start a talkback audio session on a Protect camera.

        Consequence: audio sent to the session plays aloud from the camera's speaker.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty). Protect 7.4.96 answers
        HTTP 409 when another talkback session is already in progress on the camera; that error
        is returned as received.
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (start_talkback_session):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.talkback_start(client, registry, host, camera_id, confirm=confirm)

    @mcp.tool(annotations=WRITE)
    async def disable_camera_mic_permanently(
        host: str,
        camera_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Permanently disable the microphone on a Protect camera. This cannot be undone.

        Consequence: the camera's microphone cannot be re-enabled.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (disable_camera_mic_permanently):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.disable_mic_permanently(
            client, registry, host, camera_id, confirm=confirm
        )

    @mcp.tool(annotations=WRITE)
    async def ptz_goto_preset(
        host: str,
        camera_id: str,
        slot: int,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Move a PTZ camera to a preset position slot.

        Consequence: the camera physically moves, changing what it records.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (ptz_goto_preset):
            {"host": "my-console", "camera_id": "00000000000000000000010b", "slot": 0}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            slot: PTZ preset slot to move to (path param slot): -1 is the home preset, 0 or more
                the other presets (spec); a smaller value is refused before any request.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.ptz_goto(client, registry, host, camera_id, slot, confirm=confirm)

    @mcp.tool(annotations=WRITE)
    async def ptz_patrol_start(
        host: str,
        camera_id: str,
        slot: int,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Start a PTZ patrol: the patrol saved in patrol slot 0-4 (not a preset slot).

        Consequence: the camera physically moves along the patrol, changing what it records, until
        stopped.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (ptz_patrol_start):
            {"host": "my-console", "camera_id": "00000000000000000000010b", "slot": 0}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            slot: PTZ patrol slot number 0-4 (path param slot).
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.ptz_patrol_start(
            client, registry, host, camera_id, slot, confirm=confirm
        )

    @mcp.tool(annotations=WRITE)
    async def ptz_patrol_stop(
        host: str,
        camera_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Stop the current PTZ patrol on a camera.

        Consequence: the camera stops patrolling.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (ptz_patrol_stop):
            {"host": "my-console", "camera_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.ptz_patrol_stop(client, registry, host, camera_id, confirm=confirm)

    # --- Protect Sensor Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_sensors(
        host: str,
    ) -> dict[str, Any]:
        """List all sensors on a Protect console.

        Returns {result, _count}: result is the upstream array of sensors verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_sensors(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_sensor(
        host: str,
        sensor_id: str,
    ) -> dict[str, Any]:
        """Get details for a single Protect sensor by ID.

        Returns: the sensor object, verbatim. To change it, pass only the fields to change as `settings`
        to update_sensor (a partial PATCH).

        Example call (get_sensor):
            {"host": "my-console", "sensor_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            sensor_id: Protect sensor id. Get it from list_sensors (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_sensor(client, registry, host, sensor_id)

    @mcp.tool(annotations=WRITE)
    async def update_sensor(
        host: str,
        sensor_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update settings for a Protect sensor.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Example call (update_sensor):
            {"host": "my-console", "sensor_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#update_sensor.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            sensor_id: Protect sensor id. Get it from list_sensors (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/sensors/{id} body.
        """
        client, registry = deps_fn()
        return await protect.update_sensor(client, registry, host, sensor_id, **settings)

    # --- Protect Historical Events ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_events(
        host: str,
        start: int,
        end: int,
        types: str | list[str] | None = None,
        cameras: str | list[str] | None = None,
        limit: int | None = None,
        offset: int | None = None,
        order_direction: str | None = None,
        smart_detect_types: str | list[str] | None = None,
        categories: str | list[str] | None = None,
        without_descriptions: bool | None = None,
    ) -> dict[str, Any]:
        """Query historical Protect events via private /proxy/protect/api/events; the official Integration events endpoint is WebSocket-only.

        Returns drained object pages preserving data and the first page's envelope fields, adding _count and _warnings. A drain of bare arrays returns {result, _count} with _warnings when applicable. Capped drains also carry incomplete/incompleteReason. An explicit offset/limit fetches one page when offset is supplied: a bare list stays a list (without warnings); an object page preserves every upstream top-level field verbatim, including data and totalCount, adding only _count and _warnings. Sensor events retain sensor:null and gain _resolved_sensor from metadata.sensorId.text. All event fields and identifiers are preserved. Object pages carry epoch-unit and smart-detect _warnings, as drained results do.

        Required host/start/end; time is integer epoch SECONDS, never ISO strings or milliseconds. Negative or millisecond-magnitude times are not refused: they are converted to milliseconds like any time and object results carry _warnings. query_isp_metrics instead takes ISO 8601 strings. Face names are at metadata.detectedThumbnails[].matchedName. types, smart_detect_types and categories are forwarded as given (empty list sends no parameter); empty cameras applies no filter. Full examples: docs/TOOL-USAGE.md#list_protect_events.

        Required arguments: host, start, end (see parameter descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            start: REQUIRED. Epoch SECONDS (UTC) as integers, converted to milliseconds internally.
                Bounds are exact millisecond instants; end excludes the remainder of its second.
                History depth is bounded by the NVR's retention.
                (Contrast query_isp_metrics, which wants ISO 8601 strings.)
            end: REQUIRED. Epoch SECONDS (UTC) as integers, converted to milliseconds internally. Ranges
                are exact millisecond instants; end excludes the remainder of its second.
                History depth is bounded by the NVR's retention. (Contrast
                query_isp_metrics, which wants ISO 8601 strings.)
            types: Filter by event TYPE; single value or a list. Verified-present values: motion,
                smartDetectZone, smartAudioDetect, sensorOpened, sensorClosed, access. Smart-detect
                subtypes (person, face, animal, alrmSpeak and so on) are not event types; pass them in
                smart_detect_types instead. An unrecognised value returns zero events.
                Shape: string|string[]
            cameras: filter by camera NAME or ID; single value or list. Names resolve to IDs: an exact
                match first, then Unicode-normalized (NFC) and case-insensitive, then ignoring
                surrounding whitespace (case kept before case-insensitive); an unknown name errors
                (listing the camera names as the console has them) rather than silently matching
                nothing.
                Shape: string|string[]
            limit: Without offset, the event count gathered from the beginning across pages;
                fewer only when the window ends. With offset, limit is sent unchanged as one
                page. No size clamp is measured on this feed. _pageSize reports the requested
                count, the size sent on each request, the observed effective size and the
                returned count. Omit limit and offset to drain all events; the only page cap is
                opt-in UNIFI_PAGINATE_MAX_PAGES, which marks an early stop incomplete.
                Example: `25`.
            offset: Zero-based starting record. Fetches one page: with limit, limit is sent
                unchanged as that page size (not collected across pages). Omit both to drain every
                event for the window. The opt-in UNIFI_PAGINATE_MAX_PAGES marks an early stop
                incomplete; no default page cap applies.
                Example: `25`.
            order_direction: Optional sort order sent as orderDirection: "ASC" (oldest-first) or "DESC"
                (newest-first). Omitted (default): no orderDirection is sent and the upstream's own
                order applies.
            smart_detect_types: filter by the smart-detect SUBTYPE — person, vehicle, animal, package,
                face, licensePlate (on smartDetectZone events) and the audio alarms alrmSpeak,
                alrmSiren, alrmBark, alrmCarHorn (on smartAudioDetect events). This is a distinct
                upstream parameter from types. The API only honours it when types is also set to the
                relevant event type(s); passing smart_detect_types alone is a silent no-op upstream:
                it is still sent, and the result carries a _warnings entry
                (SMART_DETECT_TYPES_WITHOUT_TYPES). Example: types="smartDetectZone",
                smart_detect_types="person" for just person detections; types="smartAudioDetect",
                smart_detect_types="alrmSpeak" to isolate the dominant audio-alarm noise.
                Shape: string|string[]
            categories: filter by event category; single value or list. Verified values: motion, smart,
                iot, admin. Unknown values are silently ignored by the upstream API.
                Shape: string|string[]
            without_descriptions: when true, ask the API to omit each event's description block (~16%
                smaller payload). Opt-in only — full-fidelity records are the default and descriptions
                are never dropped automatically.
        """
        client, registry = deps_fn()
        return await protect.list_protect_events(
            client,
            registry,
            host,
            start,
            end,
            types,
            cameras,
            limit,
            offset,
            order_direction,
            smart_detect_types=smart_detect_types,
            categories=categories,
            without_descriptions=without_descriptions,
        )

    # --- Protect Live-Stream Collectors (explicit poll-count REST collection) ---

    @mcp.tool(annotations=READ_ONLY)
    async def collect_protect_events(
        host: str,
        poll_count: int = 6,
        max_events: int | None = None,
        since: int | None = None,
        types: str | list[str] | None = None,
        cameras: str | list[str] | None = None,
        smart_detect_types: str | list[str] | None = None,
        poll_interval_seconds: float = 2.0,
        order_direction: str | None = None,
    ) -> dict[str, Any]:
        """Collect Protect events over a bounded polling window (live-feed stand-in; read-only, stateless, no cursor between calls). The window is bounded by `poll_count` complete polls, never by elapsed time. The /v1/subscribe/events WebSocket is not reachable over the Fabric connector (an upgrade GET returns 404, never 101), so this polls the historical-events path and returns every distinct event seen.

        Returns {result, _poll_count, _polls, _truncated}: result holds verbatim upstream objects de-duplicated by event id (latest object per id kept; an id-less event by its full record, counted once toward max_events). Each poll drains every page; only the opt-in UNIFI_PAGINATE_MAX_PAGES can stop one early (incomplete: true with reason). If a poll fails after an earlier one succeeded (HTTP error, 429 that outlasted retries, transport or shape error), polling stops and gathered events return with incomplete: true and incompleteReason carrying the complete error; a failing first poll raises. An upstream 404/501 (Protect absent) passes through.

        Required arguments: host.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            poll_count: positive integer number of complete polls in the bounded polling window
                (default 6). An active poll is never interrupted by elapsed time; lifecycle
                cancellation remains available.
            max_events: Optional early stop: once this many distinct events are collected, stop and
                flag `_truncated=true`. Default None (omit it): no limit, all requested polls complete.
                A single poll is never truncated mid-page, so the count may slightly exceed it.
            since: optional epoch SECONDS lower bound; defaults to the moment the call starts, so only
                events at/after the call are collected. A negative or millisecond-magnitude value
                (>= 1e11) is not refused: it is converted to milliseconds like any time, and the result
                carries a _warnings entry.
            types: same filters and validation as `list_protect_events` (camera names resolve to IDs;
                smart_detect_types without types is sent with a _warnings entry).
                Shape: string|string[]
            cameras: same filters and validation as `list_protect_events` (camera names resolve to IDs;
                smart_detect_types without types is sent with a _warnings entry).
                Shape: string|string[]
            smart_detect_types: same filters and validation as `list_protect_events` (camera names
                resolve to IDs; smart_detect_types without types is sent with a _warnings entry).
                Shape: string|string[]
            poll_interval_seconds: pacing delay between completed polls (default 2). This never
                bounds request duration or cancels active work.
                Zero means no timed delay; the event loop still yields. Small values may hit
                the shared 429 backoff, which the client handles.
            order_direction: Optional sort order sent on every poll as orderDirection: "ASC"
                (oldest-first) or "DESC" (newest-first). Omitted (default): no orderDirection is sent
                and the upstream's own order applies.
        """
        client, registry = deps_fn()
        return await protect.collect_protect_events(
            client,
            registry,
            host,
            poll_count=poll_count,
            max_events=max_events,
            since=since,
            types=types,
            cameras=cameras,
            smart_detect_types=smart_detect_types,
            poll_interval_seconds=poll_interval_seconds,
            order_direction=order_direction,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def collect_protect_device_changes(
        host: str,
        poll_count: int = 6,
        max_changes: int | None = None,
        poll_interval_seconds: float = 2.0,
    ) -> dict[str, Any]:
        """Collect Protect device add/remove/modify changes by polling every device family for poll_count complete snapshots. The WebSocket subscription is unavailable through Fabric; this read-only, stateless tool is its REST equivalent.

        Returns {_poll_count, _polls, _truncated, changes}; each change is added|removed|modified with the upstream device object verbatim (current for added/modified, last-seen for removed). Heartbeat-only lastSeen/uptime/upSince changes are ignored. Objects without id cannot be diffed: each distinct one appears in unidentified as {family, device} (this sets incomplete/incompleteReason).

        404/501 families appear in unavailableFamilies with their upstream errors and incomplete=true; a family unavailable in either of two consecutive polls is excluded from that diff, preventing false additions/removals. If every family is unavailable the upstream error is raised. A failed first poll raises; a later failure stops and returns collected changes with incomplete=true and the poll error in incompleteReason. Workflow: docs/TOOL-USAGE.md#collect_protect_device_changes.

        Required arguments: host.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            poll_count: positive integer number of complete snapshots (default 6). At least two
                polls detect changes; elapsed time never interrupts an active snapshot.
            max_changes: Optional early stop: once this many change records accumulate, stop and flag
                `_truncated=true`. Default None (omit it): no limit, all requested polls complete.
            poll_interval_seconds: pacing delay between completed polls (default 2). This never
                bounds request duration or cancels active work.
                Zero means no timed delay; the event loop still yields. Small values may hit
                the shared 429 backoff, which the client handles.
        """
        client, registry = deps_fn()
        return await protect.collect_protect_device_changes(
            client,
            registry,
            host,
            poll_count=poll_count,
            max_changes=max_changes,
            poll_interval_seconds=poll_interval_seconds,
        )

    return {
        "list_cameras": list_cameras,
        "get_camera": get_camera,
        "update_camera": update_camera,
        "enable_camera_share_link": enable_camera_share_link,
        "get_camera_share_link": get_camera_share_link,
        "disable_camera_share_link": disable_camera_share_link,
        "get_camera_snapshot": get_camera_snapshot,
        "get_rtsps_stream": get_rtsps_stream,
        "create_rtsps_stream": create_rtsps_stream,
        "delete_rtsps_stream": delete_rtsps_stream,
        "start_talkback_session": start_talkback_session,
        "disable_camera_mic_permanently": disable_camera_mic_permanently,
        "ptz_goto_preset": ptz_goto_preset,
        "ptz_patrol_start": ptz_patrol_start,
        "ptz_patrol_stop": ptz_patrol_stop,
        "list_sensors": list_sensors,
        "get_sensor": get_sensor,
        "update_sensor": update_sensor,
        "list_protect_events": list_protect_events,
        "collect_protect_events": collect_protect_events,
        "collect_protect_device_changes": collect_protect_device_changes,
    }


def register_4(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the recognition tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_recognition_groups(
        host: str,
        type: str,
        has_name: bool | None = None,
        page_size: int | None = None,
        order_by: str | None = None,
        order_direction: str | None = None,
        page: int | None = None,
    ) -> dict[str, Any]:
        """List recognition groups (enrolled faces or vehicles) on a Protect console.

        Returns {groups, _count} plus upstream envelope fields. Each group has a stable
        monotonic id (for example face_90), name/matchedName, detectionsCount, and
        createdAt/firstDetectedAt/lastDetectedAt timestamps. Names remain unchanged.
        The private recognition API returns groups under groups, rather than data.

        Default drains all links.next pages in batches up to 100. page_size=N returns
        records [(page-1)*N, page*N): exactly N when that many exist, fewer only at the
        end, never more. page is the 1-based window number counted in units of page_size
        (default 1); without page_size, returns one native console page.
        To continue, resume from _nextPage with the same page_size. _pageSize reports requested,
        sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

        Args:
            host: Console reportedState.hostname or data[].id from list_hosts, for example "my-console";
                names match reportedState.hostname/name case-insensitively.
            type: Recognition type, normally 'face' or 'vehicle' (singular). Forwarded
                unchanged; plural forms return HTTP 400 from upstream.
            has_name: When true, return named groups only. Example: true.
            page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
                fewer only at the end, never more; resume from _nextPage with the same page_size.
                Example: `100`.
            order_by: Sort field: name, createdAt, lastDetectedAt or detectionsCount.
                Example: 'name'. With no order_direction, upstream defaults to descending.
            order_direction: 'asc' or 'desc', case-insensitive; effective only with
                order_by. Unknown values return upstream HTTP 400. Example: 'asc'.
            page: 1-based window number counted in units of page_size (default 1); without
                page_size, returns one native console page; resume from _nextPage with the same
                page_size. Example: `2`.
        """
        client, registry = deps_fn()
        return await recognition.list_recognition_groups(
            client, registry, host, type, has_name, page_size, order_by, order_direction, page
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_recognition_group_counts(
        host: str,
        type: str,
    ) -> dict[str, Any]:
        """Get aggregate recognition-group counts for a Protect console.

        Returns totals such as totalCount, nameNotNullCount (named groups), nameIsNullCount,
        notificationEnabledCount, and degradedCount.

        Required arguments: host, type (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            type: recognition type. Use 'face' or 'vehicle' (singular — plural forms return HTTP 400
                from upstream). Forwarded to the API as-is.
        """
        client, registry = deps_fn()
        return await recognition.get_recognition_group_counts(client, registry, host, type)

    @mcp.tool(annotations=READ_ONLY)
    async def get_recognition_group_image(
        host: str,
        type: str,
        group_id: str,
    ) -> Any:
        """Get a recognition group's reference crop. Returns MCP ImageContent plus image metadata.

        Returns MCP ImageContent plus text and structured metadata
        {image_base64, content_type, size_bytes}; content_type is the upstream
        Content-Type header (typically image/jpeg), not assumed, and null when the upstream
        sends none.

        `type`: recognition type. Use 'face' or 'vehicle' (singular -- plural forms
          return HTTP 400 from upstream). Forwarded to the API as-is.

        Example call (get_recognition_group_image):
            {"host": "my-console", "type": "face", "group_id": "face_90"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            type: 'face' or 'vehicle' (singular; plural returns HTTP 400).
            group_id: Recognition group id, e.g. 'face_90'. Get it from list_recognition_groups (id).
                Protect recognition id.
        """
        client, registry = deps_fn()
        return _image_result(
            await recognition.get_recognition_group_image(client, registry, host, type, group_id)
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_recognition_detections(
        host: str,
        type: str,
        group_id: str,
        page_size: int | None = None,
        start: int | None = None,
        end: int | None = None,
        page: int | None = None,
    ) -> dict[str, Any]:
        """List one enrolled recognition group's detections (sightings) on Protect.

        Returns {detections, _count} plus upstream envelope fields and epoch warnings. Required group_id comes from list_recognition_groups, for example face_90. There is no all-groups mode; a nonexistent group returns HTTP 404. Each detection has id, eventId (list_protect_events), thumbnailId (get_thumbnail), detectedAt (epoch milliseconds), cameraId and matchedGroupConfidence (0-100).

        Default drains all links.next pages in batches up to 100. page_size=N returns records [(page-1)*N, page*N): exactly N when that many exist, fewer only at the end, never more. page is the 1-based window number counted in units of page_size (default 1); without page_size, returns one native console page. To continue, resume from _nextPage with the same page_size. _pageSize reports requested, sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

        page without page_size fetches one native page, with _nextPage when more exist. An explicit page keeps a bare list verbatim (no _warnings) when page_size is absent, and preserves every field of an object page verbatim with epoch-unit _warnings. A bare-list manual page is unchanged without _warnings; object pages preserve upstream fields and add epoch warnings. Examples are in docs/TOOL-USAGE.md#list_recognition_detections.

        Args:
            host: Console reportedState.hostname or data[].id from list_hosts, for example "my-console";
                names match reportedState.hostname/name case-insensitively.
            type: 'face' or 'vehicle' (singular); plural forms return HTTP 400 upstream.
            group_id: Group id from list_recognition_groups, for example 'face_90'.
            page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
                fewer only at the end, never more; resume from _nextPage with the same page_size.
                Example: `100`.
            start: Optional UTC epoch seconds start, converted to milliseconds. Negative
                or millisecond-magnitude values add _warnings. Example: 1792972800.
            end: Optional UTC epoch seconds end, converted to milliseconds; omit both for
                all detections. The same magnitude warnings apply. Example: 1793059200.
            page: 1-based window number counted in units of page_size (default 1); without
                page_size, returns one native console page; resume from _nextPage with the same
                page_size. Example: `2`.
        """
        client, registry = deps_fn()
        return await recognition.list_recognition_detections(
            client, registry, host, type, group_id, page_size, start, end, page
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_thumbnail(
        host: str,
        thumbnail_id: str,
    ) -> Any:
        """Get a detection thumbnail crop. Returns MCP ImageContent plus image metadata.

        Returns MCP ImageContent plus text and structured metadata
        {image_base64, content_type, size_bytes}; content_type is the upstream
        Content-Type header (typically image/jpeg), not assumed, and null when the upstream
        sends none.

        Example call (get_thumbnail):
            {"host": "my-console", "thumbnail_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            thumbnail_id: Detection thumbnail id. Get it from list_recognition_detections
                (detections[].thumbnailId).
        """
        client, registry = deps_fn()
        return _image_result(await recognition.get_thumbnail(client, registry, host, thumbnail_id))

    return {
        "list_recognition_groups": list_recognition_groups,
        "get_recognition_group_counts": get_recognition_group_counts,
        "get_recognition_group_image": get_recognition_group_image,
        "list_recognition_detections": list_recognition_detections,
        "get_thumbnail": get_thumbnail,
    }


def register_5(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the protect tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_lights(
        host: str,
    ) -> dict[str, Any]:
        """List all lights on a Protect console.

        Returns {result, _count}: result is the upstream array of lights verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_lights(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_light(
        host: str,
        light_id: str,
    ) -> dict[str, Any]:
        """Get details for a single Protect light by ID.

        Returns: the light object, verbatim. To change it, pass only the fields to change as `settings`
        to update_light (a partial PATCH).

        Example call (get_light):
            {"host": "my-console", "light_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            light_id: Protect light id. Get it from list_lights (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_light(client, registry, host, light_id)

    @mcp.tool(annotations=WRITE)
    async def update_light(
        host: str,
        light_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update settings for a Protect light (brightness, sensitivity, etc.).

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Example call (update_light):
            {"host": "my-console", "light_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#update_light.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            light_id: Protect light id. Get it from list_lights (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/lights/{id} body. Keys: name, isLightForceEnabled, lightModeSettings,
                lightDeviceSettings.
        """
        client, registry = deps_fn()
        return await protect.update_light(client, registry, host, light_id, **settings)

    # --- Protect Chime Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_chimes(
        host: str,
    ) -> dict[str, Any]:
        """List all chimes on a Protect console.

        Returns {result, _count}: result is the upstream array of chimes verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_chimes(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_chime(
        host: str,
        chime_id: str,
    ) -> dict[str, Any]:
        """Get details for a single Protect chime by ID.

        Returns: the chime object, verbatim. To change it, pass only the fields to change as `settings`
        to update_chime (a partial PATCH).

        Example call (get_chime):
            {"host": "my-console", "chime_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            chime_id: Protect chime id. Get it from list_chimes (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_chime(client, registry, host, chime_id)

    @mcp.tool(annotations=WRITE)
    async def update_chime(
        host: str,
        chime_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a Protect chime: name, paired cameraIds or per-camera ringSettings (volume, ringtone).

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Example call (update_chime):
            {"host": "my-console", "chime_id": "00000000000000000000010b",
             "settings": {"name": "Hallway chime"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#update_chime.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            chime_id: Protect chime id. Get it from list_chimes (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/chimes/{id} body. Keys: name, cameraIds, ringSettings.
        """
        client, registry = deps_fn()
        return await protect.update_chime(client, registry, host, chime_id, **settings)

    # --- Protect Viewer Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_viewers(
        host: str,
    ) -> dict[str, Any]:
        """List all viewers on a Protect console.

        Returns {result, _count}: result is the upstream array of viewers verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_viewers(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_viewer(
        host: str,
        viewer_id: str,
    ) -> dict[str, Any]:
        """Get details for a single Protect viewer by ID.

        Returns: the viewer object, verbatim. To change it, pass only the fields to change as `settings`
        to update_viewer (a partial PATCH).

        Example call (get_viewer):
            {"host": "my-console", "viewer_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            viewer_id: Protect viewer id. Get it from list_viewers (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_viewer(client, registry, host, viewer_id)

    @mcp.tool(annotations=WRITE)
    async def update_viewer(
        host: str,
        viewer_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update settings for a Protect viewer (liveview assignment, etc.).

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Request body (Protect 7.3.74, PATCH /v1/viewers/{id}; schema "inline requestBody schema") is
        passed in `settings`. No key is required; send only the keys to change.
        - name: string
        - liveview: oneOf[liveviewId|null]

        Example call (update_viewer):
            {"host": "my-console", "viewer_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            viewer_id: Protect viewer id. Get it from list_viewers (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/viewers/{id} body. Keys: name, liveview.
        """
        client, registry = deps_fn()
        return await protect.update_viewer(client, registry, host, viewer_id, **settings)

    # --- Protect Liveview Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_liveviews(
        host: str,
    ) -> dict[str, Any]:
        """List all liveviews on a Protect console.

        Returns {result, _count}: result is the upstream array of liveviews verbatim and _count its
        length (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_liveviews(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_liveview(
        host: str,
        liveview_id: str,
    ) -> dict[str, Any]:
        """Get details for a single Protect liveview by ID.

        Returns: the liveview object, verbatim. To change it, pass only the fields to change as
        `settings` to update_liveview (a partial PATCH).

        Example call (get_liveview):
            {"host": "my-console", "liveview_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            liveview_id: Protect liveview id. Get it from list_liveviews (id). Protect id (24-hex) — not
                a Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_liveview(client, registry, host, liveview_id)

    @mcp.tool(annotations=WRITE)
    async def create_liveview(
        host: str,
        name: str,
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a liveview on a Protect console.

        Returns {status: "created", response}: response is the upstream body verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty). Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (create_liveview):
            {
              "host": "my-console",
              "name": "Front of house",
              "settings": {
                "id": "00000000000000000000010b",
                "modelKey": "liveview",
                "isDefault": true,
                "isGlobal": true,
                "owner": "00000000000000000000010b",
                "layout": 9,
                "slots": [
                  {
                    "cameras": ["00000000000000000000010b"],
                    "cycleMode": "motion",
                    "cycleInterval": 10
                  }
                ]
              }
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#create_liveview.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            name: Liveview display name (body field name).
            settings: Rest of the body (Protect 7.3.74 POST /v1/liveviews), merged with name. Provide
                layout, slots, id, modelKey, isDefault, isGlobal and owner, all required by the
                published schema. Leave name out; it comes from the name argument.
                Shape: {layout:number,slots:{cameras:string[],cycleMode:'motion'|'time',
                cycleInterval:number}[],id:string,modelKey:string,isDefault:boolean,
                isGlobal:boolean,owner:string}
        """
        client, registry = deps_fn()
        extra = settings or {}
        return await protect.create_liveview(client, registry, host, name, **extra)

    @mcp.tool(annotations=WRITE)
    async def update_liveview(
        host: str,
        liveview_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a liveview on a Protect console (PATCH /v1/liveviews/{id}). The spec lists id, modelKey, name, isDefault, isGlobal, owner, layout, slots as required but this tool does not check them: partial settings are sent as given.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent). verified is null, with readAfterError, when the read-after fails. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the dry-run preview)}.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_liveview):
            {
              "host": "my-console",
              "liveview_id": "00000000000000000000010b",
              "settings": {
                "id": "00000000000000000000010b",
                "modelKey": "liveview",
                "name": "Lobby",
                "isDefault": true,
                "isGlobal": true,
                "owner": "00000000000000000000010b",
                "layout": 9,
                "slots": [
                  {
                    "cameras": ["00000000000000000000010b"],
                    "cycleMode": "motion",
                    "cycleInterval": 10
                  }
                ]
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            liveview_id: Protect liveview id. Get it from list_liveviews (id). Protect id (24-hex) — not
                a Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/liveviews/{id} body. Required: id, modelKey, name, isDefault, isGlobal, owner,
                layout, slots. Spec list, not checked here: partial settings are sent as given.
        """
        client, registry = deps_fn()
        return await protect.update_liveview(client, registry, host, liveview_id, **settings)

    # --- Protect NVR Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def get_nvr(
        host: str,
    ) -> dict[str, Any]:
        """Get NVR details from a Protect console.

        Returns NVR hardware info, storage status, firmware version, and system health.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.get_nvr(client, registry, host)

    # --- Protect File Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_files(
        host: str,
        file_type: str,
    ) -> dict[str, Any]:
        """List Protect device asset files of a given type.

        Returns {result, _count}: result is the upstream array of files verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count); _file_type echoes
        the file_type argument.

        Required arguments: host, file_type (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            file_type: Protect asset category (path fileType). Protect 7.3.74 documents one value,
                'animations'; the value is passed through as given. The GET
                endpoint does NOT validate this value — an unrecognised category returns HTTP 200 with
                an empty list rather than an error, so a wrong value is indistinguishable from a
                genuinely empty category. Pass a known category exactly. Letters, digits, '-' and
                '_' only; anything else is rejected before any request.
        """
        client, registry = deps_fn()
        return await protect.list_protect_files(client, registry, host, file_type)

    @mcp.tool(annotations=WRITE)
    async def upload_protect_file(
        host: str,
        file_type: str,
        filename: str,
        file_content_base64: str,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        """Upload a Protect device asset file. WARNING: Uploads asset file to NVR storage. Overwriting system files may not be reversible.

        Consequence: the file is stored on the console and may overwrite an existing asset, which may not be reversible.

        Returns {status: "uploaded", response}: response is the upstream body verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty). Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        `file_type`: Protect asset category. Protect 7.3.74 documents one value, 'animations'; the value is passed through as given and selects the upload target path (/files/{file_type}). The category is not validated on read-back, so pass a known category exactly.

        Request body: Protect 7.3.74 POST /v1/files/{fileType} is a multipart upload; the tool builds the file part from filename + file_content_base64. No JSON body. The part's Content-Type is content_type when given, else the spec type of the filename extension: .gif image/gif, .jpg/.jpeg image/jpeg, .png image/png, .mp3 audio/mpeg, .m4a/.mp4 audio/mp4, .wav audio/wave, .caf audio/x-caf. Any other extension without content_type is rejected before any request, listing these types.

        Example call (upload_protect_file):
            {"host": "my-console", "file_type": "animations", "filename": "alert.gif",
             "file_content_base64": "R0lGODlhAQABAAAAACw="}

        The dry-run preview contains method, path, params (query parameters), body (null: no JSON body) and multipart: one {field, filename, contentType, sizeBytes} entry per file part (field "file"), never the file bytes.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            file_type: Protect asset category (path fileType); Protect 7.3.74 documents one value,
                'animations'. Letters, digits, '-' and '_' only; anything else is rejected before
                any request.
            filename: Filename for the uploaded asset; its extension selects the part's Content-Type
                unless content_type is given.
            file_content_base64: File bytes, standard base64 (padded). Line-wrapped base64 (MIME/PEM
                line breaks) is accepted; a data: URL prefix is not.
            content_type: Optional MIME type of the file part (e.g. "audio/wave"), sent as given; omit
                it to derive the type from the filename extension.
        """
        client, registry = deps_fn()
        return await protect.upload_protect_file(
            client, registry, host, file_type, filename, file_content_base64, content_type
        )

    # --- Protect Alarm Manager Tools ---

    @mcp.tool(annotations=WRITE)
    async def trigger_alarm_webhook(
        host: str,
        webhook_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Trigger an alarm manager webhook by ID. WARNING: triggers physical alarm hardware.
        Verify the webhook ID before calling; the trigger is never auto-retried.

        Consequence: the alarm hardware behind the webhook acts in the real world.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (trigger_alarm_webhook):
            {"host": "my-console", "webhook_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            webhook_id: Alarm Manager webhook id (from the Protect Alarm Manager webhook trigger; the
                spec alarmTriggerId, a user-defined string). Any non-empty string without a control
                character is accepted and percent-encoded into the path as one segment ("." / ".."
                segments are refused). No list tool exists; verify before calling.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.trigger_alarm_webhook(client, registry, host, webhook_id)

    # --- Protect Arm Profile & Alarm Tools ---
    #
    # Extended Protect Integration API families, all reached over the same
    # Fabric connector base (…/proxy/protect/integration/v1) as the camera tools. The
    # write/action tools are governed by the family:protect=deny env gate
    # (default ON); the confirm argument is accepted for compatibility and no longer required.

    @mcp.tool(annotations=READ_ONLY)
    async def list_arm_profiles(
        host: str,
    ) -> dict[str, Any]:
        """List arm profiles on a Protect console (GET /v1/arm-profiles via Fabric proxy).

        Returns {result, _count}: result is the upstream array of arm profiles verbatim and _count its
        length (an upstream object with a data array is returned verbatim plus _count).

        Availability requires a Protect application exposing the published Protect Integration API.

        Required arguments: host (see each parameter's description).

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400;
        check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile
        tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_arm_profiles(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_arm_profile(
        host: str,
        arm_profile_id: str,
    ) -> dict[str, Any]:
        """Get one arm profile by id (filters GET /v1/arm-profiles; no GET-by-id exists upstream).

        Returns: the arm profile object, verbatim. To change it, pass only the fields to change as
        `settings` to update_arm_profile (a partial PATCH). An id the list does not carry fails,
        listing every valid arm_profile_id.

        Example call (get_arm_profile):
            {"host": "my-console", "arm_profile_id": "00000000000000000000010b"}

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400;
        check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile
        tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
                (24-hex) — not a Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_arm_profile(client, registry, host, arm_profile_id)

    @mcp.tool(annotations=WRITE)
    async def create_arm_profile(
        host: str,
        name: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an arm profile (POST /v1/arm-profiles via Fabric proxy).

        In settings, schedules is a list of {start, end}, both cron expressions. Returns {status: "created", response}: response is the upstream body verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty). Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (create_arm_profile):
            {
              "host": "my-console",
              "name": "Night",
              "settings": {
                "automations": [],
                "schedules": [],
                "recordEverything": false,
                "activationDelay": 0
              }
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400; check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Details: docs/TOOL-USAGE.md#create_arm_profile.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            name: REQUIRED profile name (1-255 chars), sent as the body field name. Do not repeat it
                inside settings; a settings['name'] that differs from this value is rejected with a
                clear error.
            settings: Rest of the body (Protect 7.3.74 POST /v1/arm-profiles). Required: automations,
                schedules, recordEverything, activationDelay (0|60000|300000|600000). Leave name out; it
                comes from the name argument.
        """
        client, registry = deps_fn()
        return await protect.create_arm_profile(client, registry, host, name, **settings)

    @mcp.tool(annotations=WRITE)
    async def update_arm_profile(
        host: str,
        arm_profile_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an arm profile (PATCH /v1/arm-profiles/{id}) with read-before/no-op/read-after.

        In settings, schedules is a list of {start, end}, both cron expressions. Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Example call (update_arm_profile):
            {"host": "my-console", "arm_profile_id": "00000000000000000000010b",
             "settings": {"name": "Arm Profile"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400; check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Details: docs/TOOL-USAGE.md#update_arm_profile.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
                (24-hex) — not a Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/arm-profiles/{id} body. Keys: name, automations, schedules, recordEverything,
                activationDelay.
        """
        client, registry = deps_fn()
        return await protect.update_arm_profile(client, registry, host, arm_profile_id, **settings)

    @mcp.tool(annotations=WRITE)
    async def delete_arm_profile(
        host: str,
        arm_profile_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Delete an arm profile (DELETE /v1/arm-profiles/{id}). Irreversible — no undo.

        Consequence: the profile can no longer be selected to arm the system.

        The id is found in the arm-profile list first (as update_arm_profile does): an unknown arm_profile_id fails before any DELETE, listing every valid id, and the DELETE addresses the profile by the id the console listed (hex ids match case-insensitively).

        Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}.

        Example call (delete_arm_profile):
            {"host": "my-console", "arm_profile_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400; check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
                (24-hex) — not a Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.delete_arm_profile(
            client, registry, host, arm_profile_id, confirm=confirm
        )

    @mcp.tool(annotations=WRITE)
    async def update_arm_profile_settings(
        host: str,
        arm_profile_id: str,
    ) -> dict[str, Any]:
        """Select the active arm profile (PATCH /v1/arm-profiles/settings).

        Returns {status: "updated", verified, before, after (the NVR armMode objects), response (the PATCH body verbatim)}, or {status: "noop", reason, resource (the current armMode)}. When the read-after fails or carries no armMode object, verified and after are null and readAfterError says why. Under dry-run policy nothing is sent: {status: "dry_run", before (the body read first), response (the preview: method, path, params, body)}; there is no read-after.

        `arm_profile_id`: REQUIRED. Obtain it from `list_arm_profiles` (its id field); this becomes the console's selected arm profile. The id is checked against `list_arm_profiles` first: an id the list does not carry fails before any write, naming the valid ids; a hex id matches case-insensitively and the body sends the id as the list spells it. Reads the NVR armMode before/after (no-op if already selected). Governed by family:protect=deny.

        Request body (Protect 7.3.74, PATCH /v1/arm-profiles/settings; schema "inline requestBody
        schema") is built from scalar parameters. Required keys — armProfileId.
        - armProfileId: string

        Example call (update_arm_profile_settings):
            {"host": "my-console", "arm_profile_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400; check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
                (24-hex) — not a Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.update_arm_profile_settings(client, registry, host, arm_profile_id)

    @mcp.tool(annotations=WRITE)
    async def enable_arm(
        host: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Enable the arm alarm using the selected profile (POST /v1/arm-profiles/enable).

        Arm the alarm system using the selected arm profile.

        Consequence: the alarm system is armed: sensors in the selected profile can trigger alarms.

        Returns {status: "sent", verified, after, response}: response is the upstream body verbatim
        (decoded JSON, the text of a non-JSON body, or null when the body is empty; the route
        answers an empty 204, which proves nothing about the alarm state). After the POST the NVR
        is read back (GET /v1/nvrs) and after is its armMode object; verified is true when
        armMode.status is arming, armed or breach, false when it is any other value (disabled
        right after an enable usually means the console has not applied it yet: read the NVR
        again), and null with readAfterError when the read-back failed. A failed read-back never
        undoes or errors the sent write.
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        WARNING: arms the alarm system (physical side effects); requires a local Alarm Manager.

        Example call (enable_arm):
            {"host": "my-console"}

        The dry-run preview contains method, path, params (query parameters), and body.

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400;
        check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile
        tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.enable_arm(client, registry, host, confirm=confirm)

    @mcp.tool(annotations=WRITE)
    async def disable_arm(
        host: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Disable the arm alarm (POST /v1/arm-profiles/disable). Disarms the system.

        Consequence: the alarm system is disarmed: armed sensors no longer trigger alarms.

        Returns {status: "sent", verified, after, response}: response is the upstream body verbatim
        (decoded JSON, the text of a non-JSON body, or null when the body is empty; the route
        answers an empty 204, which proves nothing about the alarm state). After the POST the NVR
        is read back (GET /v1/nvrs) and after is its armMode object; verified is true when
        armMode.status is disabled, false when it is any other value (armed or arming right after
        a disable usually means the console has not applied it yet: read the NVR again), and null
        with readAfterError when the read-back failed. A failed read-back never undoes or errors
        the sent write.
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        WARNING: physical side effects; requires a local Alarm Manager.

        Example call (disable_arm):
            {"host": "my-console"}

        The dry-run preview contains method, path, params (query parameters), and body.

        On a console in global Alarm Manager mode the arm-profile reads answer HTTP 400;
        check get_protect_alarm_manager_mode. On Protect 7.4.96 or later the external arm-profile
        tools (list_external_arm_profiles and the rest) serve a global-mode console.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.disable_arm(client, registry, host, confirm=confirm)

    # --- Protect Siren Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_external_arm_profiles(host: str) -> dict[str, Any]:
        """List the arm profiles of the external alarm manager (GET /v1/external/arm-profiles).

        These routes require Protect 7.4.96 or later and the external alarm manager; Protect 7.3.74 answers HTTP 404 "Entity 'endpoint' not found".

        Only available when the console uses the external alarm manager (check
        get_protect_alarm_manager_mode); other consoles answer with an upstream error.
        Returns {result, _count}: result is the upstream array verbatim and _count its length.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect. The console whose
                external alarm manager arm profiles are listed.
        """
        client, registry = deps_fn()
        return await protect.list_external_arm_profiles(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_external_arm_profile(host: str, arm_profile_id: str) -> dict[str, Any]:
        """Get one external arm profile (GET /v1/external/arm-profiles/{id}).

        These routes require Protect 7.4.96 or later and the external alarm manager; Protect 7.3.74 answers HTTP 404 "Entity 'endpoint' not found".

        Only available when the console uses the external alarm manager. Returns the upstream
        object verbatim.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: External arm profile id from list_external_arm_profiles (id).
        """
        client, registry = deps_fn()
        return await protect.get_external_arm_profile(client, registry, host, arm_profile_id)

    @mcp.tool(annotations=WRITE)
    async def create_external_arm_profile(
        host: str,
        title: str,
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create an external arm profile (POST /v1/external/arm-profiles).

        These routes require Protect 7.4.96 or later and the external alarm manager; Protect 7.3.74 answers HTTP 404 "Entity 'endpoint' not found".

        Consequence: adds an arm profile to the external alarm manager. Only available when the
        console uses the external alarm manager. Returns {status: "created", response}: response
        is the upstream body verbatim. Under dry-run policy nothing is sent: {status: "dry_run",
        response (the preview)}. Sent once; a create is never auto-retried.

        Request body (Protect 7.4.96, POST /v1/external/arm-profiles; schema
        "externalArmProfileRequest") is passed in `title` + settings (merged; settings may repeat
        title only with the same value). Required key: title.
        - title: string, minLength 1
        - activation_delay: integer 0-3600 (seconds)
        - deactivation_delay: integer 0-3600 (seconds)
        - schedule: object with optional keys sun, mon, tue, wed, thu, fri, sat; each day is
          {type: "all_day"} or {type: "intervals", entries: [{start: {hour: integer 0-23,
          minute: integer 0-59}, end: {hour: integer 0-23, minute: integer 0-59}, or 24:00}]}
          (entries minItems 1; use 24:00 or 23:59 for end of day)

        - alarm_ids: array of string
        - pin_code: string, 4 to 6 digits (write-only secret: masked when UNIFI_REDACT_SECRETS is on)

        Example call (create_external_arm_profile):
            {
              "host": "my-console",
              "title": "Night",
              "settings": {"activation_delay": 30}
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            title: REQUIRED profile title, sent as the body field title.
            settings: Optional rest of the body (Protect 7.4.96 POST /v1/external/arm-profiles).
                Shape: {activation_delay?: integer, deactivation_delay?: integer,
                schedule?: object, alarm_ids?: string[], pin_code?: string}. Leave title out; it
                comes from the title argument.
        """
        client, registry = deps_fn()
        return await protect.create_external_arm_profile(
            client, registry, host, title, **(settings or {})
        )

    @mcp.tool(annotations=WRITE)
    async def update_external_arm_profile(
        host: str,
        arm_profile_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an external arm profile (PATCH /v1/external/arm-profiles/{id}).

        These routes require Protect 7.4.96 or later and the external alarm manager; Protect 7.3.74 answers HTTP 404 "Entity 'endpoint' not found".

        Consequence: changes the external arm profile. Reads it, PATCHes the given keys and
        reads it again. Returns {status: "updated", verified, before, after,
        response (the PATCH body verbatim)}; verified is true only when every requested leaf
        reads back equal, null with readAfterError when the read-back failed, or {status: "noop",
        reason, resource} when every requested leaf already matches (a pin_code is never compared
        for the no-op: the profile reports has_pin only). A pin_code is verified by has_pin reading true in read-back,
        and pin_code null (clears the PIN) by has_pin reading false: this proves presence,
        not its digits, so replacing a PIN cannot be confirmed. An empty settings fails before
        any request (minProperties 1). Under dry-run policy nothing is sent: {status: "dry_run", before, response (the
        preview: method, path, params, body)}.

        Request body (Protect 7.4.96, schema "externalArmProfilePatch") is passed in `settings`;
        omitted keys stay unchanged.
        - title: string, minLength 1 (cannot be cleared)
        - activation_delay: integer 0-3600 (seconds), or null to clear it
        - deactivation_delay: integer 0-3600 (seconds), or null to clear it
        - schedule: object with optional keys sun, mon, tue, wed, thu, fri, sat; each day is
          {type: "all_day"} or {type: "intervals", entries: [{start: {hour: integer 0-23,
          minute: integer 0-59}, end: {hour: integer 0-23, minute: integer 0-59}, or 24:00}]}
          (entries minItems 1; end of day: 24:00 or 23:59)
        - alarm_ids: array of string
        - pin_code: string, or null to clear the PIN (write-only; the profile reports has_pin)

        Example call (update_external_arm_profile):
            {
              "host": "my-console",
              "arm_profile_id": "00000000000000000000010b",
              "settings": {"title": "Night"}
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: External arm profile id from list_external_arm_profiles (id).
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.4.96 PATCH
                /v1/external/arm-profiles/{id} body. Keys: title, activation_delay,
                deactivation_delay, schedule, alarm_ids, pin_code.
        """
        client, registry = deps_fn()
        return await protect.update_external_arm_profile(
            client, registry, host, arm_profile_id, **settings
        )

    @mcp.tool(annotations=WRITE)
    async def delete_external_arm_profile(host: str, arm_profile_id: str) -> dict[str, Any]:
        """Delete an external arm profile (DELETE /v1/external/arm-profiles/{id}). Irreversible.

        These routes require Protect 7.4.96 or later and the external alarm manager; Protect 7.3.74 answers HTTP 404 "Entity 'endpoint' not found".

        Consequence: the profile is removed from the external alarm manager; there is no undo.
        Only available when the console uses the external alarm manager. Returns {deleted: true,
        message, response}; response is the upstream DELETE body verbatim (null for the spec's
        204). Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false,
        message, response (the preview)}.

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: External arm profile id from list_external_arm_profiles (id).
        """
        client, registry = deps_fn()
        return await protect.delete_external_arm_profile(client, registry, host, arm_profile_id)

    @mcp.tool(annotations=WRITE)
    async def arm_external_arm_profile(host: str, arm_profile_id: str) -> dict[str, Any]:
        """Arm one external arm profile (POST /v1/external/arm-profiles/{id}/actions/arm).

        These routes require Protect 7.4.96 or later and the external alarm manager; Protect 7.3.74 answers HTTP 404 "Entity 'endpoint' not found".

        Consequence: the external alarm manager starts arming that profile (after its activation
        delay); sensors and cameras it covers can raise alarms. Only available when the console
        uses the external alarm manager. No request body. Returns {status: "sent", response}:
        response is the upstream body verbatim. Sent once. Under dry-run policy nothing is sent:
        {status: "dry_run", response (the preview)}.

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: External arm profile id from list_external_arm_profiles (id).
        """
        client, registry = deps_fn()
        return await protect.arm_external_arm_profile(client, registry, host, arm_profile_id)

    @mcp.tool(annotations=WRITE)
    async def disarm_external_arm_profile(host: str, arm_profile_id: str) -> dict[str, Any]:
        """Disarm one external arm profile (POST /v1/external/arm-profiles/{id}/actions/disarm).

        These routes require Protect 7.4.96 or later and the external alarm manager; Protect 7.3.74 answers HTTP 404 "Entity 'endpoint' not found".

        Consequence: the external alarm manager stops guarding with that profile; detections no
        longer raise alarms until it is armed again. Only available when the console uses the
        external alarm manager. No request body. Returns {status: "sent", response}: response is
        the upstream body verbatim. Sent once. Under dry-run policy nothing is sent:
        {status: "dry_run", response (the preview)}.

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            arm_profile_id: External arm profile id from list_external_arm_profiles (id).
        """
        client, registry = deps_fn()
        return await protect.disarm_external_arm_profile(client, registry, host, arm_profile_id)

    @mcp.tool(annotations=WRITE)
    async def stop_speaker_siren(host: str, speaker_id: str) -> dict[str, Any]:
        """Stop a siren playing on a Protect speaker (POST /v1/speakers/{id}/stop-siren).

        Consequence: the siren sound on that speaker stops. Official Integration route (Protect
        7.4.96); stop_speaker_stream is the separate private route that stops other speaker
        audio. No request body; the spec answers 204 (response null) or 400. Returns {status:
        "sent", response}. Sent once. Under dry-run policy nothing is sent: {status: "dry_run",
        response (the preview)}.

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            speaker_id: Speaker id (24-hex) from list_speakers.
        """
        client, registry = deps_fn()
        return await protect.stop_speaker_siren(client, registry, host, speaker_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_sirens(
        host: str,
    ) -> dict[str, Any]:
        """List sirens on a Protect console (GET /v1/sirens via Fabric proxy).

        Returns {result, _count}: result is the upstream array of sirens verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_sirens(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_siren(
        host: str,
        siren_id: str,
    ) -> dict[str, Any]:
        """Get one siren by id (GET /v1/sirens/{id}).

        Returns: the siren object, verbatim. To change it, pass only the fields to change as `settings`
        to update_siren (a partial PATCH).

        Example call (get_siren):
            {"host": "my-console", "siren_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_siren(client, registry, host, siren_id)

    @mcp.tool(annotations=WRITE)
    async def update_siren(
        host: str,
        siren_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update siren settings (PATCH /v1/sirens/{id}) with read-before/no-op/read-after.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Example call (update_siren):
            {"host": "my-console", "siren_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#update_siren.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/sirens/{id} body. Keys: name, volume, ledSettings.
        """
        client, registry = deps_fn()
        return await protect.update_siren(client, registry, host, siren_id, **settings)

    @mcp.tool(annotations=WRITE)
    async def siren_play(
        host: str,
        siren_id: str,
        confirm: bool = False,
        duration: int | None = None,
    ) -> dict[str, Any]:
        """Sound a siren (POST /v1/sirens/{id}/play). WARNING: physical alarm sound.

        Consequence: a loud siren sounds at the site for the chosen duration.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        The siren sounds for `duration` seconds (5/10/20/30; 5 upstream when omitted).
        Governed by family:protect=deny.

        Request body (Protect 7.3.74, POST /v1/sirens/{id}/play; schema "inline requestBody schema") is
        built from scalar parameters. No key is required; send only the keys to change.
        - duration: one of 5|10|20|30 (seconds)

        Example call (siren_play):
            {"host": "my-console", "siren_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
                Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            duration: Seconds to sound: 5, 10, 20, or 30 (spec sirenDurationSeconds). Default 5.
        """
        client, registry = deps_fn()
        return await protect.siren_play(
            client, registry, host, siren_id, confirm=confirm, duration=duration
        )

    @mcp.tool(annotations=WRITE)
    async def siren_stop(
        host: str,
        siren_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Stop a sounding siren (POST /v1/sirens/{id}/stop). WARNING: physical action.

        Consequence: the siren is silenced.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (siren_stop):
            {"host": "my-console", "siren_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
                Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.siren_stop(client, registry, host, siren_id, confirm=confirm)

    @mcp.tool(annotations=WRITE)
    async def siren_test_sound(
        host: str,
        siren_id: str,
        confirm: bool = False,
        volume: int | None = None,
    ) -> dict[str, Any]:
        """Test a siren's sound (POST /v1/sirens/{id}/test-sound). WARNING: physical sound.

        Consequence: the siren plays a test sound aloud.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        `volume`: 1-100 (defaults to device volume upstream).
          Governed by family:protect=deny.

        Request body (Protect 7.3.74, POST /v1/sirens/{id}/test-sound; schema "inline requestBody
        schema") is built from scalar parameters. No key is required; send only the keys to change.
        - volume: integer (1-100)

        Example call (siren_test_sound):
            {"host": "my-console", "siren_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
                Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            volume: Test volume 1-100; omit to use the device volume.
        """
        client, registry = deps_fn()
        return await protect.siren_test_sound(
            client, registry, host, siren_id, confirm=confirm, volume=volume
        )

    # --- Protect Fob Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_fobs(
        host: str,
    ) -> dict[str, Any]:
        """List fobs on a Protect console (GET /v1/fobs via Fabric proxy).

        Returns {result, _count}: result is the upstream array of fobs verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_fobs(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_fob(
        host: str,
        fob_id: str,
    ) -> dict[str, Any]:
        """Get one fob by id (GET /v1/fobs/{id}).

        Returns: the fob object, verbatim. To change it, pass only the fields to change as `settings` to
        update_fob (a partial PATCH).

        Example call (get_fob):
            {"host": "my-console", "fob_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            fob_id: Protect fob id. Get it from list_fobs (id). Protect id (24-hex) — not a Network
                device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_fob(client, registry, host, fob_id)

    @mcp.tool(annotations=WRITE)
    async def update_fob(
        host: str,
        fob_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update fob settings (PATCH /v1/fobs/{id}) with read-before/no-op/read-after.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Request body (Protect 7.3.74, PATCH /v1/fobs/{id}; schema "inline requestBody schema") is passed
        in `settings`. No key is required; send only the keys to change.
        - name: string

        Example call (update_fob):
            {"host": "my-console", "fob_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            fob_id: Protect fob id. Get it from list_fobs (id). Protect id (24-hex) — not a Network
                device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/fobs/{id} body. Keys: name.
        """
        client, registry = deps_fn()
        return await protect.update_fob(client, registry, host, fob_id, **settings)

    # --- Protect Relay Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_relays(
        host: str,
    ) -> dict[str, Any]:
        """List relays on a Protect console (GET /v1/relays via Fabric proxy).

        Returns {result, _count}: result is the upstream array of relays verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_relays(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_relay(
        host: str,
        relay_id: str,
    ) -> dict[str, Any]:
        """Get one relay by id (GET /v1/relays/{id}).

        Returns: the relay object, verbatim. To change it, pass only the fields to change as `settings`
        to update_relay (a partial PATCH).

        Example call (get_relay):
            {"host": "my-console", "relay_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            relay_id: Protect relay id. Get it from list_relays (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_relay(client, registry, host, relay_id)

    @mcp.tool(annotations=WRITE)
    async def update_relay(
        host: str,
        relay_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update relay settings (PATCH /v1/relays/{id}) with read-before/no-op/read-after.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Request body (Protect 7.3.74, PATCH /v1/relays/{id}; schema "inline requestBody schema") is
        passed in `settings`. No key is required; send only the keys to change.
        - name: string
        - ledSettings: object {isEnabled: boolean}

        Example call (update_relay):
            {"host": "my-console", "relay_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            relay_id: Protect relay id. Get it from list_relays (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/relays/{id} body. Keys: name, ledSettings.
        """
        client, registry = deps_fn()
        return await protect.update_relay(client, registry, host, relay_id, **settings)

    @mcp.tool(annotations=WRITE)
    async def relay_activate_output(
        host: str,
        relay_id: str,
        output_id: int | str,
        confirm: bool = False,
        state: str | None = None,
        pulse_duration: int | None = None,
    ) -> dict[str, Any]:
        """Switch a relay output (POST /v1/relays/{id}/outputs/{outputId}/activate).

        Consequence: whatever is wired to the relay output (door lock, gate, light) acts in the real
        world.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        WARNING: physically switches hardware.

        Request body (Protect 7.3.74, POST /v1/relays/{id}/outputs/{outputId}/activate; schema "inline
        requestBody schema") is built from scalar parameters. No key is required; send only the keys to
        change.
        - state: enum[on|off]
        - pulseDuration: integer (ms)

        Example call (relay_activate_output):
            {"host": "my-console", "relay_id": "00000000000000000000010b", "output_id": 0}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            relay_id: Protect relay id. Get it from list_relays (id). Protect id (24-hex) — not a
                Network device UUID.
            output_id: Output channel id on that device; spec: integer 0 or 1 (an integer, or the same
                value as a decimal string '0'|'1'). See get_relay.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            state: 'on' or 'off'; omit to toggle (spec body state).
            pulse_duration: Auto-off after N ms (spec body pulseDuration, >=0). The spec applies it
                only when state is 'on'; the server sends it as given and does not check state.
        """
        client, registry = deps_fn()
        return await protect.relay_activate_output(
            client,
            registry,
            host,
            relay_id,
            output_id,
            confirm=confirm,
            state=state,
            pulse_duration=pulse_duration,
        )

    # --- Protect Speaker Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_speakers(
        host: str,
    ) -> dict[str, Any]:
        """List speakers on a Protect console (GET /v1/speakers via Fabric proxy).

        Returns {result, _count}: result is the upstream array of speakers verbatim and _count its
        length (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect. The Protect console
                whose speakers are listed.
        """
        client, registry = deps_fn()
        return await protect.list_speakers(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_speaker(
        host: str,
        speaker_id: str,
    ) -> dict[str, Any]:
        """Get one speaker by id (GET /v1/speakers/{id}).

        Returns: the speaker object, verbatim. To change it, pass only the fields to change as
        `settings` to update_speaker (a partial PATCH).

        Example call (get_speaker):
            {"host": "my-console", "speaker_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            speaker_id: Protect speaker id. Get it from list_speakers (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_speaker(client, registry, host, speaker_id)

    @mcp.tool(annotations=WRITE)
    async def update_speaker(
        host: str,
        speaker_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update speaker settings (PATCH /v1/speakers/{id}) with read-before/no-op/read-after.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Example call (update_speaker):
            {"host": "my-console", "speaker_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#update_speaker.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            speaker_id: Protect speaker id. Get it from list_speakers (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/speakers/{id} body. Keys: name, volume, micVolume, isMicEnabled.
        """
        client, registry = deps_fn()
        return await protect.update_speaker(client, registry, host, speaker_id, **settings)

    @mcp.tool(annotations=WRITE)
    async def speaker_test_sound(
        host: str,
        speaker_id: str,
        confirm: bool = False,
        volume: int | None = None,
    ) -> dict[str, Any]:
        """Test a speaker's sound (POST /v1/speakers/{id}/test-sound). WARNING: physical sound.

        Consequence: the speaker plays a test sound aloud.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
        the text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        `volume`: 0-100 (defaults to device volume upstream).
          Governed by family:protect=deny.

        Request body (Protect 7.3.74, POST /v1/speakers/{id}/test-sound; schema "inline requestBody
        schema") is built from scalar parameters. No key is required; send only the keys to change.
        - volume: integer (0-100)

        Example call (speaker_test_sound):
            {"host": "my-console", "speaker_id": "00000000000000000000010b"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            speaker_id: Protect speaker id. Get it from list_speakers (id). Protect id (24-hex) — not a
                Network device UUID.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            volume: Test volume 0-100; omit to use the device volume.
        """
        client, registry = deps_fn()
        return await protect.speaker_test_sound(
            client, registry, host, speaker_id, confirm=confirm, volume=volume
        )

    # --- Protect Bridge Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_bridges(
        host: str,
    ) -> dict[str, Any]:
        """List bridges on a Protect console (GET /v1/bridges via Fabric proxy).

        Returns {result, _count}: result is the upstream array of bridges verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_bridges(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_bridge(
        host: str,
        bridge_id: str,
    ) -> dict[str, Any]:
        """Get one bridge by id (GET /v1/bridges/{id}).

        Returns: the bridge object, verbatim. To change it, pass only the fields to change as `settings`
        to update_bridge (a partial PATCH).

        Example call (get_bridge):
            {"host": "my-console", "bridge_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            bridge_id: Protect bridge id. Get it from list_bridges (id). Protect id (24-hex) — not a
                Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_bridge(client, registry, host, bridge_id)

    @mcp.tool(annotations=WRITE)
    async def update_bridge(
        host: str,
        bridge_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update bridge settings (PATCH /v1/bridges/{id}) with read-before/no-op/read-after.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Request body (Protect 7.3.74, PATCH /v1/bridges/{id}; schema "inline requestBody schema") is
        passed in `settings`. No key is required; send only the keys to change.
        - name: string

        Example call (update_bridge):
            {"host": "my-console", "bridge_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            bridge_id: Protect bridge id. Get it from list_bridges (id). Protect id (24-hex) — not a
                Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/bridges/{id} body. Keys: name.
        """
        client, registry = deps_fn()
        return await protect.update_bridge(client, registry, host, bridge_id, **settings)

    # --- Protect Link Station Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_link_stations(
        host: str,
    ) -> dict[str, Any]:
        """List link stations on a Protect console (GET /v1/link-stations via Fabric proxy).

        Returns {result, _count}: result is the upstream array of link stations verbatim and _count its
        length (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_link_stations(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_link_station(
        host: str,
        link_station_id: str,
    ) -> dict[str, Any]:
        """Get one link station by id (GET /v1/link-stations/{id}).

        Returns: the link station object, verbatim. To change it, pass only the fields to change as
        `settings` to update_link_station (a partial PATCH).

        Example call (get_link_station):
            {"host": "my-console", "link_station_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            link_station_id: Protect link station id. Get it from list_link_stations (id). Protect id
                (24-hex) — not a Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_link_station(client, registry, host, link_station_id)

    @mcp.tool(annotations=WRITE)
    async def update_link_station(
        host: str,
        link_station_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update link-station settings (PATCH /v1/link-stations/{id}) with read/no-op/read-after.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Request body (Protect 7.3.74, PATCH /v1/link-stations/{id}; schema "inline requestBody schema")
        is passed in `settings`. No key is required; send only the keys to change.
        - name: string

        Example call (update_link_station):
            {"host": "my-console", "link_station_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            link_station_id: Protect link station id. Get it from list_link_stations (id). Protect id
                (24-hex) — not a Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/link-stations/{id} body. Keys: name.
        """
        client, registry = deps_fn()
        return await protect.update_link_station(
            client, registry, host, link_station_id, **settings
        )

    # --- Protect Alarm Hub Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_alarm_hubs(
        host: str,
    ) -> dict[str, Any]:
        """List alarm hubs on a Protect console (GET /v1/alarm-hubs via Fabric proxy).

        Returns {result, _count}: result is the upstream array of alarm hubs verbatim and _count its
        length (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_alarm_hubs(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_alarm_hub(
        host: str,
        alarm_hub_id: str,
    ) -> dict[str, Any]:
        """Get one alarm hub by id (GET /v1/alarm-hubs/{id}).

        Returns: the alarm hub object, verbatim. To change it, pass only the fields to change as
        `settings` to update_alarm_hub (a partial PATCH).

        Example call (get_alarm_hub):
            {"host": "my-console", "alarm_hub_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            alarm_hub_id: Protect alarm hub id. Get it from list_alarm_hubs (id). Protect id (24-hex) —
                not a Network device UUID.
        """
        client, registry = deps_fn()
        return await protect.get_alarm_hub(client, registry, host, alarm_hub_id)

    @mcp.tool(annotations=WRITE)
    async def update_alarm_hub(
        host: str,
        alarm_hub_id: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update alarm-hub settings (PATCH /v1/alarm-hubs/{id}) with read-before/no-op/read-after.

        Read-before, no-op check, PATCH, read-after. Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or {status: "noop", reason, resource} when every sent leaf already matches (nothing sent; nested objects compare leaf by leaf). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", before, response (the preview {method, path, params, body})}; no read-after.

        Request body (Protect 7.3.74, PATCH /v1/alarm-hubs/{id}; schema "inline requestBody schema") is
        passed in `settings`. No key is required; send only the keys to change.
        - name: string

        Example call (update_alarm_hub):
            {"host": "my-console", "alarm_hub_id": "00000000000000000000010b",
             "settings": {"name": "Front Door"}}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            alarm_hub_id: Protect alarm hub id. Get it from list_alarm_hubs (id). Protect id (24-hex) —
                not a Network device UUID.
            settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
                /v1/alarm-hubs/{id} body. Keys: name.
        """
        client, registry = deps_fn()
        return await protect.update_alarm_hub(client, registry, host, alarm_hub_id, **settings)

    @mcp.tool(annotations=WRITE)
    async def alarm_hub_trigger_output(
        host: str,
        alarm_hub_id: str,
        output_id: int | str,
        confirm: bool = False,
        enable: bool | None = None,
        delay: int | None = None,
        duration: int | None = None,
    ) -> dict[str, Any]:
        """Trigger an alarm-hub output (POST /v1/alarm-hubs/{id}/outputs/{outputId}/trigger).

        Consequence: whatever is wired to the output (siren, strobe, lock, relay) acts in the real world.

        Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty). Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        WARNING: physically triggers alarm-hub output hardware. `enable` true turns the output on, false off (omit to toggle); `delay` is ms before activating; `duration` is ms to stay active (0 = indefinite). Governed by family:protect=deny.

        Example call (alarm_hub_trigger_output):
            {"host": "my-console", "alarm_hub_id": "00000000000000000000010b", "output_id": 0}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#alarm_hub_trigger_output.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            alarm_hub_id: Protect alarm hub id. Get it from list_alarm_hubs (id). Protect id (24-hex) —
                not a Network device UUID.
            output_id: Output channel id on that device; spec: integer 0 or 1 (an integer, or the same
                value as a decimal string '0'|'1'). See get_alarm_hub.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            enable: true = on, false = off; omit to toggle.
            delay: Milliseconds to wait before activating.
            duration: Milliseconds to stay active (0 = indefinite).
        """
        client, registry = deps_fn()
        return await protect.alarm_hub_trigger_output(
            client,
            registry,
            host,
            alarm_hub_id,
            output_id,
            confirm=confirm,
            enable=enable,
            delay=delay,
            duration=duration,
        )

    # --- Protect User Tools (read-only) ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_users(
        host: str,
    ) -> dict[str, Any]:
        """List Protect users (GET /v1/users via Fabric proxy). Read-only in the Integration API.

        Returns {result, _count}: result is the upstream array of users verbatim and _count its length
        (an upstream object with a data array is returned verbatim plus _count).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_protect_users(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_user(
        host: str,
        user_id: str,
    ) -> dict[str, Any]:
        """Get one Protect user by id (GET /v1/users/{id}). Read-only.

        Returns the upstream user object verbatim, exactly as the API answers it.

        Example call (get_protect_user):
            {"host": "my-console", "user_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            user_id: Protect user id. Get it from list_protect_users (id). Not a ULP (UI account) user
                id.
        """
        client, registry = deps_fn()
        return await protect.get_protect_user(client, registry, host, user_id)

    # --- Protect Application Metadata ---

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_application_info(
        host: str,
    ) -> dict[str, Any]:
        """Get Protect application metadata (GET /v1/meta/info via Fabric proxy). Read-only.

        Returns the upstream meta-info ({applicationVersion, ...}) object verbatim, exactly as the API
        answers it.

        Reports the Protect application version and Integration-API capabilities — the
        authoritative check for which extended Protect families this console supports.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.get_protect_application_info(client, registry, host)

    # --- Protect ULP User Tools (read-only) ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_ulp_users(
        host: str,
    ) -> dict[str, Any]:
        """List ULP (UniFi account) users (GET /v1/ulp-users). Read-only.

        Returns {result, _count}: result is the upstream array of ULP users verbatim and _count its
        length (an upstream object with a data array is returned verbatim plus _count).

        Distinct from `list_protect_users` (/v1/users): these are UI-account identities.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await protect.list_ulp_users(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_ulp_user(
        host: str,
        ulp_user_id: str,
    ) -> dict[str, Any]:
        """Get one ULP (UniFi account) user by id (GET /v1/ulp-users/{id}). Read-only.

        Returns the upstream ULP user object verbatim, exactly as the API answers it.

        Example call (get_ulp_user):
            {"host": "my-console", "ulp_user_id": "00000000000000000000010b"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            ulp_user_id: ULP (UI account) user id. Get it from list_ulp_users (id). Not a Protect user
                id.
        """
        client, registry = deps_fn()
        return await protect.get_ulp_user(client, registry, host, ulp_user_id)

    # --- Protect POS Transaction Ingestion ---

    @mcp.tool(annotations=WRITE)
    async def pos_ingest_transaction(
        host: str,
        camera_id: str,
        transaction: dict[str, Any],
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Ingest a POS transaction overlay onto camera footage (POST /v1/pos/cameras/{id}/transactions via the Fabric proxy). Consequence: the transaction is overlaid on the camera's recorded footage. WARNING: creates a footage overlay event with no documented rollback; validated locally with an idempotency key; never auto-retried.

        `transaction` (REQUIRED, posTransactionRequest) needs type ('sale'|'refund'), externalId (per-camera unique idempotency key) and amount; optional currency, lineItems, location, paymentTypes, timestamp (epoch ms, within the last 24 hours and at most 5 minutes ahead of server time) pass through.

        Returns {status: "sent", response (upstream body verbatim)}. Under dry-run policy nothing is sent: {status: "dry_run", response (the dry-run preview)}.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (pos_ingest_transaction):
            {"host": "my-console", "camera_id": "00000000000000000000010b",
             "transaction": {"type": "sale", "externalId": "order-1042", "amount": 24.95}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
                Network device UUID.
            transaction: posTransactionRequest (Protect 7.3.74). Required: type ('sale'|'refund'),
                externalId (per-camera unique dedup key), amount. Never auto-retried.
            confirm: Ignored. The call runs when made; there is no confirmation step.
        """
        client, registry = deps_fn()
        return await protect.pos_ingest_transaction(
            client, registry, host, camera_id, transaction, confirm=confirm
        )

    return {
        "list_lights": list_lights,
        "get_light": get_light,
        "update_light": update_light,
        "list_chimes": list_chimes,
        "get_chime": get_chime,
        "update_chime": update_chime,
        "list_viewers": list_viewers,
        "get_viewer": get_viewer,
        "update_viewer": update_viewer,
        "list_liveviews": list_liveviews,
        "get_liveview": get_liveview,
        "create_liveview": create_liveview,
        "update_liveview": update_liveview,
        "get_nvr": get_nvr,
        "list_protect_files": list_protect_files,
        "upload_protect_file": upload_protect_file,
        "trigger_alarm_webhook": trigger_alarm_webhook,
        "list_arm_profiles": list_arm_profiles,
        "get_arm_profile": get_arm_profile,
        "create_arm_profile": create_arm_profile,
        "update_arm_profile": update_arm_profile,
        "list_external_arm_profiles": list_external_arm_profiles,
        "get_external_arm_profile": get_external_arm_profile,
        "create_external_arm_profile": create_external_arm_profile,
        "update_external_arm_profile": update_external_arm_profile,
        "delete_external_arm_profile": delete_external_arm_profile,
        "arm_external_arm_profile": arm_external_arm_profile,
        "disarm_external_arm_profile": disarm_external_arm_profile,
        "stop_speaker_siren": stop_speaker_siren,
        "delete_arm_profile": delete_arm_profile,
        "update_arm_profile_settings": update_arm_profile_settings,
        "enable_arm": enable_arm,
        "disable_arm": disable_arm,
        "list_sirens": list_sirens,
        "get_siren": get_siren,
        "update_siren": update_siren,
        "siren_play": siren_play,
        "siren_stop": siren_stop,
        "siren_test_sound": siren_test_sound,
        "list_fobs": list_fobs,
        "get_fob": get_fob,
        "update_fob": update_fob,
        "list_relays": list_relays,
        "get_relay": get_relay,
        "update_relay": update_relay,
        "relay_activate_output": relay_activate_output,
        "list_speakers": list_speakers,
        "get_speaker": get_speaker,
        "update_speaker": update_speaker,
        "speaker_test_sound": speaker_test_sound,
        "list_bridges": list_bridges,
        "get_bridge": get_bridge,
        "update_bridge": update_bridge,
        "list_link_stations": list_link_stations,
        "get_link_station": get_link_station,
        "update_link_station": update_link_station,
        "list_alarm_hubs": list_alarm_hubs,
        "get_alarm_hub": get_alarm_hub,
        "update_alarm_hub": update_alarm_hub,
        "alarm_hub_trigger_output": alarm_hub_trigger_output,
        "list_protect_users": list_protect_users,
        "get_protect_user": get_protect_user,
        "get_protect_application_info": get_protect_application_info,
        "list_ulp_users": list_ulp_users,
        "get_ulp_user": get_ulp_user,
        "pos_ingest_transaction": pos_ingest_transaction,
    }


def register_6(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_event(host: str, event_id: str) -> dict[str, Any]:
        """Get one Protect event by id, with its full metadata.

        Returns the event object verbatim (id, type, start/end in epoch ms, camera,
        smartDetectTypes, isFavorite, favoriteObjectIds, metadata.detectedThumbnails with
        objectId values, thumbnail and heatmap ids). An unknown id answers HTTP 404 from
        the console. Find event ids with list_protect_events.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            event_id: Event id from list_protect_events (24-hex or UUID); for example
                "000000000000000000000e01".
        """
        client, registry = deps_fn()
        return await protect_events_cases._get_protect_event(client, registry, host, event_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_event_media(
        host: str,
        event_id: str,
        kind: MediaKind,
        width: int | None = None,
        height: int | None = None,
        full_fov: bool | None = None,
        key_frame_only: bool | None = None,
        speedup: int | None = None,
        start: int | None = None,
        end: int | None = None,
        camera_id: str | None = None,
    ) -> Any:
        """Get one media view of a Protect event.

        Use kind thumbnail (JPEG), animated_thumbnail (GIF) and heatmap (PNG, motion events)
        for binary media. Returns {image_base64, content_type, size_bytes} with the
        upstream Content-Type. Smart_detect_track (object tracks) and transcriptions (which
        need camera_id) return the upstream JSON verbatim. Only the optional arguments you
        pass are sent.
        The console answers 404 when an event has no such media (for example a heatmap
        for a smart-detect event, or an animated thumbnail for a UUID-id event).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            event_id: Event id from list_protect_events; for example "000000000000000000000e01".
            kind: Media view: thumbnail, animated_thumbnail, heatmap, smart_detect_track or
                transcriptions; for example "thumbnail".
            width: Thumbnail or GIF width in pixels, sent as w; for example 640.
            height: Thumbnail or GIF height in pixels, sent as h; for example 360.
            full_fov: Thumbnail of the full field of view, sent as isFullfov; for example true.
            key_frame_only: GIF built from key frames only, sent as keyFrameOnly; for example true.
            speedup: GIF playback speed factor; for example 10.
            start: GIF window start, epoch SECONDS (sent as ms); for example 1760227200.
            end: GIF window end, epoch SECONDS (sent as ms); for example 1760227260.
            camera_id: Camera id of the event, required by transcriptions; for example
                "000000000000000000000103".
        """
        client, registry = deps_fn()
        return await protect_events_cases._get_protect_event_media(
            client,
            registry,
            host,
            event_id,
            kind,
            width=width,
            height=height,
            full_fov=full_fov,
            key_frame_only=key_frame_only,
            speedup=speedup,
            start=start,
            end=end,
            camera_id=camera_id,
        )

    @mcp.tool(annotations=WRITE)
    async def set_protect_event_favorite(
        host: str,
        event_ids: str | list[str],
        favorite: bool,
        object_id: str | None = None,
        objects: list[FavoriteObject] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Mark Protect events as favorite (favorite=true) or remove the mark (false).

        Consequence: only the events' favorite mark changes, as every user of the console
        sees it; no recording changes.

        One id (a string) uses the per-event route and returns {status, response,
        verified, event}: the event is read back and verified is whether isFavorite (or,
        with object_id, favoriteObjectIds) now matches. A list of ids uses the batch route.
        Returns {status, response}, where response maps each id to the console's result.
        Both forms answer status: "favorited" for favorite=true and status: "unfavorited"
        for false. The Protect write opt-out and read-only mode apply before any request.
        With dry-run policy, returns {status: "dry_run", response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            event_ids: One event id, or a non-empty list of ids for the batch route (an empty
                list fails before any request); for example
                "000000000000000000000e01".
                Shape: string|string[]
            favorite: true to favorite, false to unfavorite; for example true.
            object_id: Single-id form only (with a list it fails before any request): favorite
                one detected object of the event
                (metadata.detectedThumbnails[].objectId); for example
                "00000000-0000-4000-8000-000000000e02".
            objects: List form only (with one event id it fails before any request): per-object
                marks sent as idsWithObject, each
                {eventId, objectId}; for example [{"eventId": "0000...", "objectId": "0000..."}].
                Shape: {eventId:string,objectId:string}[]
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_events_cases._set_protect_event_favorite(
            client, registry, host, event_ids, favorite, object_id=object_id, objects=objects
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_cases(host: str) -> dict[str, Any]:
        """List every Protect case (investigation) on a console.

        Returns {result: [case, ...], _count}; each case is verbatim (id, name, summary,
        active, assetCount, incident fields, createdAt/updatedAt in epoch ms). The console
        returns the complete list in one response; there is no per-case GET route, so use
        this list to read one case.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
        """
        client, registry = deps_fn()
        return await protect_events_cases._list_protect_cases(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def create_protect_case(
        host: str,
        name: str,
        summary: str | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a Protect case (investigation) and return it.

        Sends {name, summary?, ...fields} to POST /cases. Returns {status: "created",
        response: CASE}, where CASE is the created case with its id. Add recordings with
        add_protect_case_asset. With dry-run policy, returns {status: "dry_run", response:
        PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            name: Case name; for example "Garage break-in 2026-10-11".
            summary: Case summary text; for example "Side door forced at 02:10".
            fields: Other case fields sent as given (free-form object), such as location,
                incidentType, incidentSeverity, incidentTimestamp; for example
                {"location": "Garage"}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_events_cases._create_protect_case(
            client, registry, host, name, summary=summary, fields=fields
        )

    @mcp.tool(annotations=WRITE)
    async def update_protect_case(
        host: str,
        case_id: str,
        name: str | None = None,
        summary: str | None = None,
        active: bool | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Update a Protect case: rename, edit the summary, close (active=false) or reopen.

        Requested top-level fields are sent (PATCH /cases/{case_id}), preserving current
        nested siblings; a fields key that a typed argument also sets fails before any
        request. Read-back verifies all merged leaves type-strictly. The case is read from
        list_protect_cases before and after. Returns {status: "updated", verified, before,
        after, response}, or {status: "noop", resource} when every field already matches.
        Passing no field fails before any request. With dry-run policy, returns {status:
        "dry_run", before, response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "000000000000000000000c01".
            name: New case name; for example "Garage break-in (closed)".
            summary: New summary; for example "Suspect identified".
            active: false closes the case, true reopens it; for example false.
            fields: Other case fields sent as given (free-form object); for example
                {"incidentSeverity": "high"}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_events_cases._update_protect_case(
            client,
            registry,
            host,
            case_id,
            name=name,
            summary=summary,
            active=active,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def delete_protect_case(host: str, case_id: str, confirm: bool = False) -> dict[str, Any]:
        """Delete a Protect case permanently, with all of its assets.

        Consequence: the case and every asset in it are removed for all users and cannot be
        restored; the recordings themselves stay on the NVR.

        Sends DELETE /cases/{case_id}. Returns {deleted: true, message, response}. With
        dry-run policy, returns {status: "dry_run", deleted: false, message, response:
        PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "000000000000000000000c01".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_events_cases._delete_protect_case(client, registry, host, case_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_case_activity(
        host: str, case_id: str, page: int | None = None, page_size: int | None = None
    ) -> Any:
        """Get the activity (audit) log of a Protect case.

        Returns {activities: [...], _count} with each entry unchanged (timestamp in epoch
        ms, sequenceId, description.messageRaw, ipAddress). Every links.next page is
        drained by default in batches up to 100. page_size=N returns records
        [(page-1)*N, page*N): exactly N when that many exist, fewer only at the end,
        never more. page is the 1-based window number counted in units of page_size
        (default 1); without page_size, returns one native console page.
        To continue, resume from _nextPage with the same page_size. _pageSize reports requested,
        sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "000000000000000000000c01".
            page: 1-based window number counted in units of page_size (default 1); without
                page_size, returns one native console page; resume from _nextPage with the same
                page_size. Example: `2`.
            page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
                fewer only at the end, never more; resume from _nextPage with the same page_size.
                Example: `50`.
        """
        client, registry = deps_fn()
        return await protect_events_cases._get_protect_case_activity(
            client, registry, host, case_id, page=page, page_size=page_size
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_case_assets(host: str, case_id: str) -> dict[str, Any]:
        """List every asset of a Protect case (clips plus the generated PDF report).

        Returns {result: [asset, ...], _count}; each asset is verbatim (id, type such as
        clip or pdfReport, camera, start/end in epoch ms, note, title, includeInExport).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "000000000000000000000c01".
        """
        client, registry = deps_fn()
        return await protect_events_cases._list_protect_case_assets(client, registry, host, case_id)

    @mcp.tool(annotations=WRITE)
    async def add_protect_case_asset(
        host: str,
        case_id: str,
        camera_id: str,
        start: int,
        end: int,
        note: str | None = None,
        lens: list[str] | None = None,
        asset_type: str = "clip",
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add a recording clip from one camera to a Protect case.

        Consequence: the clip is attached to the case for everyone with access to it; the
        recording itself is unchanged.

        Sends {camera, type, start, end, note?, lens?, ...fields} to POST
        /cases/{case_id}/assets, start and end converted from epoch SECONDS to ms. To add
        an event, pass its camera and start/end (event times are ms; divide by 1000).
        Returns {status: "created", response: {main: {success, data: ASSET}}}. The
        console accepts asset_type "clip" only (live-probed). With dry-run policy, returns
        {status: "dry_run", response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "000000000000000000000c01".
            camera_id: Camera id (an event's camera field); for example "000000000000000000000103".
            start: Clip start, epoch SECONDS; for example 1760227200.
            end: Clip end, epoch SECONDS; for example 1760227230.
            note: Note shown on the asset; for example "Person at side door".
            lens: Lenses of a package-camera doorbell, "main" and/or "secondary"; for
                example ["main"].
                Shape: ('main'|'secondary')[]
            asset_type: Asset type discriminator; for example "clip".
            fields: Other asset fields sent as given (free-form object); for example
                {"title": "Side door"}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_events_cases._add_protect_case_asset(
            client,
            registry,
            host,
            case_id,
            camera_id,
            start,
            end,
            note=note,
            lens=lens,
            asset_type=asset_type,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def update_protect_case_asset(
        host: str,
        case_id: str,
        asset_id: str,
        note: str | None = None,
        title: str | None = None,
        include_in_export: bool | None = None,
        asset_type: str | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Update a Protect case asset: note, title or whether it is included in exports.

        Sends PATCH /cases/{case_id}/assets/{asset_id}, preserving current nested siblings.
        Read-back verifies all merged leaves type-strictly. The
        console requires the asset type in every PATCH, so the asset's current type is sent
        when asset_type is omitted (as the Protect web app does). The asset is read from
        list_protect_case_assets before and after. Returns {status: "updated", verified,
        before, after, response} or {status: "noop", resource}. No field fails before any
        request. With dry-run policy, returns {status: "dry_run", before, response: PREVIEW}.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "000000000000000000000c01".
            asset_id: Asset id from list_protect_case_assets; for example
                "000000000000000000000a01".
            note: New note; for example "Confirmed: courier".
            title: New title; for example "Front door".
            include_in_export: Include the asset in case exports, sent as includeInExport;
                for example false.
            asset_type: Type discriminator to send (clip, externalFile, pdfReport,
                presentation); for example "clip".
            fields: Other asset fields sent as given (free-form object); for example
                {"isMuted": true}.
                A key a typed argument also sets fails before any request.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_events_cases._update_protect_case_asset(
            client,
            registry,
            host,
            case_id,
            asset_id,
            note=note,
            title=title,
            include_in_export=include_in_export,
            asset_type=asset_type,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def remove_protect_case_asset(
        host: str, case_id: str, asset_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove one asset from a Protect case (the recording stays on the NVR).

        Consequence: the asset leaves the case for every user; add it again with
        add_protect_case_asset. The recording itself stays on the NVR.

        Sends DELETE /cases/{case_id}/assets/{asset_id}. Returns {deleted: true, message,
        response}. With dry-run policy, returns {status: "dry_run", deleted: false,
        message, response: PREVIEW} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            case_id: Case id from list_protect_cases; for example "000000000000000000000c01".
            asset_id: Asset id from list_protect_case_assets; for example
                "000000000000000000000a01".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_events_cases._remove_protect_case_asset(
            client, registry, host, case_id, asset_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def export_protect_case(
        host: str,
        action: ExportAction,
        case_id: str | None = None,
        export_id: str | None = None,
    ) -> Any:
        """Export a Protect case as a zip archive, in two steps.

        With action "prepare" (which needs case_id), the console creates an export job and
        builds the archive without changing configuration. This read is allowed in read-only
        mode and executes under dry-run policy.
        Returns: for prepare, the export job verbatim ({id, type: "CaseExport", status,
        progressRatio, archiveFileName, ...}); for action "download" (needs export_id, the
        job id), {content_base64, content_type, size_bytes} for the finished zip. A download before
        the archive is ready, or of a large archive, can time out at the cloud connector
        (HTTP 408 DeviceTimeout); try again later.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            action: "prepare" or "download"; for example "prepare".
            case_id: Case id from list_protect_cases, for prepare only (with download it fails
                before any request); for example
                "000000000000000000000c01".
            export_id: Export job id returned by prepare, for download only (with prepare it
                fails before any request); for example
                "000000000000000000000d01".
        """
        client, registry = deps_fn()
        return await protect_events_cases._export_protect_case(
            client, registry, host, action, case_id=case_id, export_id=export_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_stream_url(
        host: str,
        kind: StreamKind,
        camera_id: str,
        channel: int | None = None,
        start: int | None = None,
        end: int | None = None,
        lens: int | None = None,
        stream_type: str | None = None,
        stream_format: str | None = None,
        frame_duration_ms: int | None = None,
        label: str | None = None,
        filename: str | None = None,
        fps: int | None = None,
    ) -> Any:
        """Get a short-lived stream address for a Protect camera, as the web app does.

        Returns the upstream body verbatim: {url} for livestream, playback, timelapse, heatmap
        and live_detect_track (WebSocket addresses with a per-request token); for live_alias
        the body is {alias}. livestream sends channel (default 0) and adds directUrl;
        playback and timelapse need start, end. An upstream array is returned as {result:
        [...]}. When start or end is negative or looks like epoch milliseconds, an object
        result gains an additive _warnings list and an array result is returned as
        {result, _warnings}.
        video_prepare
        (tcp/video/prepare) is not served on Protect 7.x via the connector (HTTP 404).
        Otherwise only the arguments you pass are sent; the console reports a missing one. These
        values are registered credentials: success fields and error text are masked only
        when UNIFI_REDACT_SECRETS is on, otherwise verbatim. Logs always scrub them.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            kind: livestream, playback, timelapse, heatmap, live_detect_track, live_alias or
                video_prepare; for example "livestream".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            channel: Camera channel index (0 is the highest quality; livestream defaults
                to 0); for example 0.
            start: Window start, epoch SECONDS (sent as ms); for example 1760227200.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227260.
            lens: Lens index of a multi-lens camera; for example 0.
            stream_type: Sent as type, for example "fmp4" (livestream) or "rotating"
                (video_prepare); for example "fmp4".
            stream_format: Sent as format; for example "FMP4".
            frame_duration_ms: Heatmap frame duration, sent as frameDurationMs; for example 1000.
            label: Heatmap object label; for example "person".
            filename: video_prepare output file name; for example "clip.mp4".
            fps: video_prepare frame rate; for example 0.
        """
        client, registry = deps_fn()
        return await protect_events_cases._get_protect_stream_url(
            client,
            registry,
            host,
            kind,
            camera_id,
            channel=channel,
            start=start,
            end=end,
            lens=lens,
            stream_type=stream_type,
            stream_format=stream_format,
            frame_duration_ms=frame_duration_ms,
            label=label,
            filename=filename,
            fps=fps,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def collect_protect_incident_evidence(
        host: str,
        start: int,
        end: int,
        cameras: list[str] | None = None,
        types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Collect normalized incident evidence from Protect events for one window (a plain read). Reads the private GET protect/api/events route (as list_protect_events) over [start, end), draining every page, and returns one versioned document (schema_name "unifi-fabric-incident-evidence", schema_version 1) instead of native events; use list_protect_events or get_protect_event for the verbatim event. Each record keeps the native id (provenance.record_id).

        Returns {schema_name, schema_version, product: "protect", status, causality: "not_assessed", ordering, scope, requested_window, collected_at, incomplete, incompleteReason?, _warnings?, sources, records}. status is complete, empty, partial or failed; incomplete is true when a source's drain stopped early. One source per camera (or per camera listed in cameras), each with outcome, pagination, counts, queried/observed windows and retention "unknown" (an empty source is not proof nothing happened); one failing camera makes the document partial. Records keep safe fields only (type, category, smart_detect_types, score, end_epoch_ms; no description or media), a time status (in_window, out_of_window, missing, malformed, ambiguous_timezone) and identity (exact, ambiguous, missing; camera/sensor ids only), sorted by event start; chronology claims no cause. Non-object rows are counted (counts.malformed).

        Example call (collect_protect_incident_evidence):
            {"host": "my-console", "start": 1760140800, "end": 1760144400,
             "cameras": ["Front Door"], "types": ["motion", "smartDetectZone"]}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            start: Window start, epoch seconds, inclusive; a negative or millisecond-size value is
                sent unchanged with a `_warnings` entry. Example: `1760140800`.
            end: Window end, epoch seconds, exclusive; must be after start (otherwise refused
                before any request). Example: `1760144400`.
            cameras: Optional camera names or ids, each read as its own source; a name
                resolves to its id (an unknown or shared name fails listing the cameras).
                Omit for one source covering every camera. Example: `["Front Door"]`.
                Shape: string[]
            types: Optional event types sent as the types filter, e.g. ["motion"] or
                ["smartDetectZone"]; recorded in each source's scope. Omit for every type.
                Shape: string[]
        """
        client, registry = deps_fn()
        return await protect_events_cases._collect_protect_incident_evidence(
            client, registry, host, start, end, cameras, types
        )


def register_7(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the private Protect tools."""

    def tool(fn: Callable[..., Any]) -> Any:
        return mcp.tool(annotations=for_tool(writes=bool(write_verbs_for(fn))))(fn)

    @tool
    async def list_protect_device_tags(host: str) -> Any:
        """List Protect device tags. host is a console from list_hosts, for example "Home NVR".

        GET protect/api/device-tags. Returns: the upstream body unchanged (an array arrives as {result: [...]}).

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
        """
        client, registry = deps_fn()
        return await protect_users_assets.list_protect_device_tags(client, registry, host)

    @tool
    async def create_protect_device_tag(
        host: str, tag: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a device tag from a JSON object.

        POST protect/api/device-tags with tag sent as given. Returns: the upstream response
        unchanged.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            tag: Device-tag JSON body, for example {"name": "Loading"}. Free-form object.
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.create_protect_device_tag(client, registry, host, tag)

    @tool
    async def update_protect_device_tag(
        host: str, tag_id: str, changes: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a known device tag.

        tag_id is resolved in list_protect_device_tags (an unknown id fails listing the valid
        ids), changes are merged into the tag and sent with PATCH protect/api/device-tags/{id}.
        Returns: the PATCH response with _before, _after, _verified (every requested leaf re-read) and
        _readAfterError (null unless the re-read failed); when every requested leaf already matches,
        nothing is sent and the current record is returned with _status "noop" and _verified true.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            tag_id: Required device-tag id from list_protect_device_tags, for example "000000000000000000000103".
            changes: Requested JSON leaves, for example {"name": "Operators", "settings": {"enabled": true}}.
                Free-form object.
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.update_protect_device_tag(
            client, registry, host, tag_id, changes
        )

    @tool
    async def delete_protect_device_tag(host: str, tag_id: str, confirm: bool = False) -> Any:
        """Delete a device tag. Consequence: assignments are removed.

        tag_id is resolved in list_protect_device_tags first, then DELETE
        protect/api/device-tags/{id}. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview
        {status, dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            tag_id: Required device-tag id from list_protect_device_tags, for example "000000000000000000000103".
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.delete_protect_device_tag(client, registry, host, tag_id)

    @tool
    async def create_protect_user_group(
        host: str, group: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a Protect user group.

        POST protect/api/groups with group sent as given. Returns: the upstream response
        unchanged.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            group: User-group JSON body, for example {"name": "Operators"}. Free-form object.
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.create_protect_user_group(client, registry, host, group)

    @tool
    async def update_protect_user_group(
        host: str, group_id: str, changes: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a Protect user group.

        group_id is resolved in the Protect bootstrap groups (an unknown id fails listing the
        valid ids), changes are sent with PATCH protect/api/groups/{id}.
        Returns: the PATCH response with _before, _after, _verified (every requested leaf re-read) and
        _readAfterError (null unless the re-read failed); when every requested leaf already matches,
        nothing is sent and the current record is returned with _status "noop" and _verified true.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            group_id: Required user-group id, for example "000000000000000000000103".
            changes: Requested JSON leaves, for example {"name": "Operators", "settings": {"enabled": true}}.
                Free-form object.
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.update_protect_user_group(
            client, registry, host, group_id, changes
        )

    @tool
    async def delete_protect_user_group(host: str, group_id: str, confirm: bool = False) -> Any:
        """Delete a Protect user group. Consequence: its permissions disappear.

        group_id is resolved in the Protect bootstrap groups first, then DELETE
        protect/api/groups/{id}. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview
        {status, dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            group_id: Required user-group id, for example "000000000000000000000103".
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.delete_protect_user_group(
            client, registry, host, group_id
        )

    @tool
    async def update_protect_user(
        host: str, user_id: str, changes: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a Protect user.

        user_id is resolved in the Protect bootstrap users (an unknown id fails listing the
        valid ids), changes are sent with PATCH protect/api/users/{id}.
        Returns: the PATCH response with _before, _after, _verified (every requested leaf re-read) and
        _readAfterError (null unless the re-read failed); when every requested leaf already matches,
        nothing is sent and the current record is returned with _status "noop" and _verified true.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            user_id: Required id from list_protect_users, for example "000000000000000000000103".
            changes: Requested JSON leaves, for example {"name": "Operators", "settings": {"enabled": true}}.
                Free-form object.
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.update_protect_user(
            client, registry, host, user_id, changes
        )

    @tool
    async def set_protect_notifications_muted(
        host: str, user_id: str, muted: bool, valid_until: int | None = None, confirm: bool = False
    ) -> Any:
        """Mute or unmute user notifications.

        Consequence: muted, the user gets no Protect notifications until valid_until (or the
        upstream default) passes or they are unmuted; unmuted, notifications resume at once.

        user_id is resolved in the Protect bootstrap users; muted true sends POST
        protect/api/users/{id}/notifications/mute {validUntil}, false sends DELETE on it.
        Returns: the upstream response with _before, _after, _verified, _readAfterError and
        _warnings (the epoch-milliseconds reminder) added to an object response.
        When valid_until is null, _verified checks that notificationSnoozeSettings is a
        non-null object; a concrete expiry must read back equal.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            user_id: Required id from list_protect_users, for example "000000000000000000000103".
            muted: Whether to mute notifications, for example true.
            valid_until: Mute expiry in epoch milliseconds, for example 1893456000000; null uses the upstream default.
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.set_protect_notifications_muted(
            client, registry, host, user_id, muted, valid_until
        )

    @tool
    async def get_protect_device_password(host: str) -> Any:
        """Get the NVR device password.

        GET protect/api/nvr/device-password. Returns: the upstream body unchanged
        (an array arrives as {result: [...]}); the password is masked only under UNIFI_REDACT_SECRETS.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
        """
        client, registry = deps_fn()
        return await protect_users_assets.get_protect_device_password(client, registry, host)

    @tool
    async def update_protect_device_password(
        host: str, device_password: str, confirm: bool = False
    ) -> Any:
        """Set the NVR device password. Consequence: integrations can require updating.

        PATCH protect/api/nvr/device-password with {devicePassword}. Returns: the upstream
        response unchanged.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            device_password: Device password string, for example "example-device-password".
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.update_protect_device_password(
            client, registry, host, device_password
        )

    @tool
    async def get_protect_file(host: str, file_id: str, asset_id: str) -> Any:
        """Download an uploaded Protect file.

        GET protect/api/files/{file_id}/{asset_id}. Returns: {content_base64, content_type,
        size_bytes}, the bytes base64-encoded with the upstream Content-Type.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            file_id: Required file collection id, for example "000000000000000000000103".
            asset_id: Required asset id, for example "000000000000000000000104".
        """
        client, registry = deps_fn()
        return await protect_users_assets.get_protect_file(
            client, registry, host, file_id, asset_id
        )

    @tool
    async def delete_protect_file(
        host: str,
        file_id: str,
        asset_id: str,
        ignore_file_extension: bool = False,
        confirm: bool = False,
    ) -> Any:
        """Delete an uploaded file. Consequence: the selected asset is permanently removed.

        DELETE protect/api/files/{file_id}/{asset_id} with ignoreFileExtension.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview
        {status, dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            file_id: Required file collection id, for example "000000000000000000000103".
            asset_id: Required asset id, for example "000000000000000000000104".
            ignore_file_extension: Whether to ignore the extension, for example false.
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.delete_protect_file(
            client, registry, host, file_id, asset_id, ignore_file_extension
        )

    @tool
    async def upload_ringtone(
        host: str,
        filename: str,
        content_base64: str,
        content_type: str = "audio/mpeg",
        confirm: bool = False,
    ) -> Any:
        """Upload a ringtone.

        Consequence: the sound is stored on the console as a ringtone that chimes can be set
        to play; existing ringtones are not changed.

        Multipart POST protect/api/ringtones with the decoded bytes as the file part named
        filename. Returns: the upstream response unchanged.

        Under dry-run policy nothing is sent and the tool returns the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body, multipart}}, where multipart names each part without its bytes.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            filename: Multipart filename, for example "chime.mp3".
            content_base64: Base64-encoded ringtone bytes, for example "SUQz".
            content_type: Media type, for example "audio/mpeg".
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.upload_ringtone(
            client, registry, host, filename, content_base64, content_type
        )

    @tool
    async def delete_ringtone(host: str, ringtone_id: str, confirm: bool = False) -> Any:
        """Delete a ringtone. Consequence: the sound is permanently removed.

        DELETE protect/api/ringtones/{ringtone_id}. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview
        {status, dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            ringtone_id: Required ringtone id, for example "000000000000000000000103".
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.delete_ringtone(client, registry, host, ringtone_id)

    @tool
    async def get_ringtone(host: str, ringtone_id: str) -> Any:
        """Get ringtone metadata.

        GET protect/api/ringtones/{ringtone_id}. Returns: the ringtone's metadata, the
        upstream body unchanged.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            ringtone_id: Required ringtone id, for example "000000000000000000000103".
        """
        client, registry = deps_fn()
        return await protect_users_assets.get_ringtone(client, registry, host, ringtone_id)

    @tool
    async def delete_liveview(host: str, liveview_id: str, confirm: bool = False) -> Any:
        """Delete a liveview. Consequence: its layout is permanently removed.

        DELETE protect/api/liveviews/{liveview_id}. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview
        {status, dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Required console selector from list_hosts, for example "Home NVR".
            liveview_id: Required liveview id, for example "000000000000000000000103".
            confirm: Accepted and ignored, for example true (kept for backward compatibility); the
                call executes immediately.
        """
        client, registry = deps_fn()
        return await protect_users_assets.delete_liveview(client, registry, host, liveview_id)


def register_8(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 21 P05 tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_automations(host: str) -> Any:
        """List the Protect automations on a console.

        GET protect/api/automations (private Protect API); the route takes no paging
        parameters. Returns: the upstream body unchanged (an array arrives as {result: [...]}).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console". The console whose Protect
                automations are listed.
        """
        client, registry = deps_fn()
        return await protect_automation_backup._list_protect_automations(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def create_protect_automation(
        host: str, automation: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a Protect automation.

        POST protect/api/automations with the automation object sent verbatim. Returns: the
        upstream response unchanged. An empty object is refused before any request.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation: Native Protect automation object, e.g.
                {"name": "Night lights", "enabled": true, "triggers": [], "actions": []}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._create_protect_automation(
            client, registry, host, automation
        )

    @mcp.tool(annotations=WRITE)
    async def update_protect_automation(
        host: str, automation_id: str, changes: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Change fields of one Protect automation (read, merge, write, then verify).

        Lists automations to find automation_id (an unknown id fails listing the valid
        ids, before any write), deep-merges changes into the listed record and sends it with
        PATCH protect/api/automations/{automation_id}. Returns: the upstream response
        unchanged plus _before, _after and _verified (every requested leaf re-read, type
        strict), and _readAfterError when the re-read failed; a non-object response is
        returned whole under response with those keys beside it. An empty changes object is
        refused before any request.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation_id: Automation id from list_protect_automations,
                e.g. "000000000000000000000112".
            changes: Fields to change, nested as on the record, e.g. {"enabled": false}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._update_protect_automation(
            client, registry, host, automation_id, changes
        )

    @mcp.tool(annotations=WRITE)
    async def delete_protect_automation(
        host: str, automation_id: str, confirm: bool = False
    ) -> Any:
        """Delete one Protect automation permanently.

        Lists automations to check automation_id exists (an unknown id fails listing the valid ids,
        before any write), then sends DELETE protect/api/automations/{id}.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Consequence: the automation is removed permanently and its triggers stop running
        its actions; there is no undo.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        {status: "dry_run", deleted: false, message, response} when dry-run policy is set,
        where response is the dry-run preview {status, dryRun, sent: false, message, preview:
        {method, path, params, body}} (nothing sent).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation_id: Automation id from list_protect_automations,
                e.g. "000000000000000000000112".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._delete_protect_automation(
            client, registry, host, automation_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_automation_history(
        host: str, automation_id: str, limit: int | None = None
    ) -> Any:
        """Read the run history of one Protect automation.

        GET protect/api/automations/{automation_id}/history. limit is forwarded unchanged
        when given and omitted otherwise (no default cap). Returns: the upstream body
        unchanged (an array arrives as {result: [...]}).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            automation_id: Automation id from list_protect_automations,
                e.g. "000000000000000000000112".
            limit: Upstream history limit query parameter. Omit for the upstream default.
                Example: `50`.
        """
        client, registry = deps_fn()
        return await protect_automation_backup._get_protect_automation_history(
            client, registry, host, automation_id, limit
        )

    @mcp.tool(annotations=WRITE)
    async def reset_protect_automations(host: str, confirm: bool = False) -> Any:
        """Reset the console's Protect automations to the upstream defaults.

        POST protect/api/automations/reset with no body. Returns: the upstream response
        unchanged.

        Consequence: the current configuration is replaced by the upstream defaults, and
        custom entries are lost unless recreated.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._reset_protect_automations(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def set_protect_notification_receivers(
        host: str, receivers: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Set who receives Protect system notifications.

        PATCH protect/api/automations/system-notifications/receivers with receivers sent
        verbatim. Returns: the upstream response unchanged. An empty object is refused
        before any request.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            receivers: Native receivers object, e.g.
                {"userIds": ["000000000000000000000113"]}. Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._set_protect_notification_receivers(
            client, registry, host, receivers
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_backups(host: str) -> Any:
        """List the Protect configuration backups stored on a console.

        GET protect/api/backups (private Protect API); the route takes no paging
        parameters. Returns: the upstream body unchanged (an array arrives as {result: [...]}).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await protect_automation_backup._list_protect_backups(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def create_protect_backup(host: str, confirm: bool = False) -> Any:
        """Create a Protect configuration backup now.

        POST protect/api/backups with no body; uses console storage. Returns: the upstream
        response unchanged.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._create_protect_backup(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def delete_protect_backup(host: str, backup_id: str, confirm: bool = False) -> Any:
        """Delete one stored Protect backup permanently. Lists backups to check backup_id (unknown ids fail listing the valid ones, before any write), sends DELETE protect/api/backup/{backup_id} (the singular route; Protect 7.3 answers 404 on the plural), then lists again.

        Consequence: the backup is removed from console storage and can no longer be restored with restore_protect_backup; there is no undo.

        Returns {deleted, message, response}: deleted is true only when the read-back no longer lists the backup, false when still listed, null with readAfterError when the read-back failed; response is the upstream body verbatim. Honours UNIFI_WRITE_POLICY=deny and family:protect=deny; with dry-run policy returns {status: "dry_run", deleted: false, message, response (the dry-run preview)}; nothing is sent.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            backup_id: Backup id from list_protect_backups, e.g. "backup-1718000000000".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._delete_protect_backup(
            client, registry, host, backup_id
        )

    @mcp.tool(annotations=WRITE)
    async def import_protect_backup(
        host: str, backup: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Import a Protect backup onto a console.

        POST protect/api/backups/import with backup sent verbatim. Returns: the upstream
        response unchanged. An empty object is refused before any request.

        Consequence: the console imports the backup named in the body, using console
        storage; check list_protect_backups afterwards, since what else the import changes
        is decided upstream.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            backup: Native backup import object, e.g. {"name": "backup-1718000000000"}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._import_protect_backup(
            client, registry, host, backup
        )

    @mcp.tool(annotations=WRITE)
    async def restore_protect_backup(host: str, backup_id: str, confirm: bool = False) -> Any:
        """Restore a stored Protect backup, replacing the live Protect configuration.

        POST protect/api/backup/{backup_id}/restore with no body (the singular route;
        Protect 7.3 answers 404 on the plural one). The upstream judges backup_id.
        Returns: the upstream response unchanged.

        Consequence: the live Protect configuration is replaced by the backup's;
        irreversible, and Protect may restart, interrupting recording while it does.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            backup_id: Backup id from list_protect_backups, e.g. "backup-1718000000000".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._restore_protect_backup(
            client, registry, host, backup_id
        )

    @mcp.tool(annotations=WRITE)
    async def restore_protect_database(host: str, confirm: bool = False) -> Any:
        """Restore the Protect database from a staged foreign Postgres dump; this restarts Protect.

        POST protect/api/nvr/restore-database-backup with no body (the Protect 7.x
        route). Admin only. It restores a foreign Postgres dump file already staged on
        the console, not a stored backup (use restore_protect_backup for that). With no
        dump staged, Protect is expected to answer HTTP 400 (not run against a console),
        passed through unchanged. Returns: the upstream response unchanged.

        Consequence: the live Protect database is replaced by the staged dump, losing
        changes made since it; irreversible, and Protect restarts.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._restore_protect_database(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_cloud_archive_status(host: str, provider: str) -> Any:
        """Read the authentication state of a Protect cloud archive provider.

        GET protect/api/cloud-provider/authenticate?provider=..., the console's cloud-provider
        authorize endpoint: it may start a provider authorization request and changes no
        configuration, so it stays available in read-only mode. Returns: the upstream
        body unchanged (an array arrives as {result: [...]}). A console HTTP 500 may
        require checking the provider identifier and archive configuration in Protect.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            provider: Cloud archive provider id as Protect names it, e.g. "google-drive".
        """
        client, registry = deps_fn()
        return await protect_automation_backup._get_cloud_archive_status(
            client, registry, host, provider
        )

    @mcp.tool(annotations=WRITE)
    async def start_cloud_video_archive(
        host: str, archive: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Start archiving Protect video to the connected cloud provider.

        POST protect/api/cloud-provider/video-archive with archive sent verbatim. Returns:
        the upstream response unchanged. An empty object is refused before any request.

        Consequence: Protect starts copying the requested video to the connected cloud
        provider, using upload bandwidth and provider storage; cancel it with
        cancel_cloud_archive_task.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            archive: Native archive request object, e.g.
                {"cameraIds": ["000000000000000000000114"], "start": 1718000000000,
                "end": 1718003600000}. Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._start_cloud_video_archive(
            client, registry, host, archive
        )

    @mcp.tool(annotations=WRITE)
    async def connect_cloud_archive_provider(host: str, code: str, confirm: bool = False) -> Any:
        """Connect a cloud archive provider with a device authorization code.

        POST protect/api/cloud-provider/authenticate-device-code with {"code": code}. The
        code is a registered route secret. Returns: the upstream response unchanged.

        Consequence: Protect is authorized against the provider account and can archive
        video to it until disconnect_cloud_archive_provider revokes it.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            code: Device authorization code from the provider, e.g. "ABCD-EFGH".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._connect_cloud_archive_provider(
            client, registry, host, code
        )

    @mcp.tool(annotations=WRITE)
    async def cancel_cloud_archive_task(host: str, archive_id: str, confirm: bool = False) -> Any:
        """Cancel a running Protect cloud archive task.

        POST protect/api/cloud-provider/cancel-archive-task with {"archiveId": archive_id}.
        Returns: the upstream response unchanged.

        Consequence: the archive task stops; video it has not copied yet is not archived
        (start a new one with start_cloud_video_archive).
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            archive_id: Archive task id from start_cloud_video_archive,
                e.g. "000000000000000000000115".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._cancel_cloud_archive_task(
            client, registry, host, archive_id
        )

    @mcp.tool(annotations=WRITE)
    async def disconnect_cloud_archive_provider(
        host: str, provider: str, confirm: bool = False
    ) -> Any:
        """Disconnect (revoke) a Protect cloud archive provider.

        POST protect/api/cloud-provider/revoke with {"provider": provider}. Returns: the
        upstream response unchanged.

        Consequence: Protect's authorization with the provider is revoked, so it can no
        longer archive video there until connect_cloud_archive_provider connects it again.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            provider: Cloud archive provider id as Protect names it, e.g. "google-drive".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._disconnect_cloud_archive_provider(
            client, registry, host, provider
        )

    @mcp.tool(annotations=WRITE)
    async def connect_unifi_video_server(
        host: str, server: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Authenticate Protect to a UniFi Video server or NAS for camera import.

        POST protect/api/cloud-provider/authenticate-nas with server sent verbatim; its
        password and token fields are registered route secrets. Returns: the upstream
        response unchanged. An empty object is refused before any request.

        Consequence: Protect authenticates to that server with the credentials sent, so
        import_unifi_video_cameras can read what it offers; no camera is imported here.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            server: Native connection object, e.g.
                {"host": "192.0.2.10", "username": "admin", "password": "example-password"}.
                Free-form object.
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._connect_unifi_video_server(
            client, registry, host, server
        )

    @mcp.tool(annotations=READ_ONLY)
    async def import_unifi_video_cameras(host: str, server_host: str) -> Any:
        """List what a connected UniFi Video server or NAS offers for import.

        GET protect/api/cloud-provider/shared-drives?host=server_host (a read; nothing is
        imported). Returns: the upstream body unchanged (an array arrives as {result: [...]}).
        A shared-drives HTTP 500 may require checking the connected server/provider setup.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            server_host: Hostname or address of the server passed to
                connect_unifi_video_server, e.g. "192.0.2.10".
        """
        client, registry = deps_fn()
        return await protect_automation_backup._import_unifi_video_cameras(
            client, registry, host, server_host
        )

    @mcp.tool(annotations=WRITE)
    async def accept_ironclad_terms(
        host: str, cid: str, vid: str, status: str, agreement_type: str, confirm: bool = False
    ) -> Any:
        """Record acceptance of a Protect service agreement.

        POST protect/api/ironclad/sendAcceptance with {"cid", "vid", "status", "type"},
        where type is agreement_type. Returns: the upstream response unchanged.

        Consequence: a legal acceptance of that agreement version is recorded upstream; it
        cannot be withdrawn through this tool.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny, and returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}} (nothing sent) when dry-run policy is set.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            cid: Agreement contract id as Protect supplies it, e.g. "contract-1".
            vid: Agreement version id as Protect supplies it, e.g. "version-3".
            status: Acceptance status sent as status, e.g. "accepted".
            agreement_type: Agreement type sent as type, e.g. "cloud-archive".
            confirm: Accepted and ignored; kept for compatibility. It never gates the
                call, e.g. true.
        """
        del confirm  # accepted and ignored
        client, registry = deps_fn()
        return await protect_automation_backup._accept_ironclad_terms(
            client, registry, host, cid, vid, status, agreement_type
        )


def register_9(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=WRITE)
    async def move_ptz_camera(
        host: str, camera_id: str, movement: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Move a PTZ camera (pan, tilt, zoom), as the Protect web app's PTZ joystick does.

        Sends movement as given to POST cameras/{camera_id}/move on the Protect console
        host. The web app builds this body at run time and no published schema documents
        it, so no key is required or added; the console validates it and its error is
        returned in full. To go to a saved position use ptz_goto_preset; to return home use
        ptz_home. Returns {status: "sent", response}. Sent once, never auto-retried on 429.
        With dry-run policy, returns {status: "dry_run", response (the preview)} and sends no
        write.

        Dry-run response previews include body and params.

        Consequence: the camera physically moves, so its view and any running patrol or
        auto-tracking change at once.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            movement: Movement object sent as given (free-form; shape not published); for
                example {"type": "continuous", "payload": {"x": 10, "y": 0, "z": 0}}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._move_ptz_camera(
            client, registry, host, camera_id, movement
        )

    @mcp.tool(annotations=WRITE)
    async def ptz_home(host: str, camera_id: str, confirm: bool = False) -> dict[str, Any]:
        """Move a PTZ camera to its home position.

        Uses the official Protect Integration route POST /v1/cameras/{camera_id}/ptz/goto/-1 (slot
        -1 is the home preset), the same call as ptz_goto_preset with slot -1, on the Protect
        console host. Returns {status: "sent", response}. Sent once, never auto-retried on 429. With
        dry-run policy, returns {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the camera physically moves to its home position, interrupting any
        manual view or running patrol.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._ptz_home(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def set_ptz_event_control_window(
        host: str, camera_id: str, open_window: bool, confirm: bool = False
    ) -> dict[str, Any]:
        """Open or close a PTZ camera's event PTZ control window.

        Sends {open: open_window} to POST cameras/{camera_id}/ptz/eventPtzControlWindow on
        the Protect console host, the call the Protect web app makes (UI bundle 5.3.18 names
        the open key). Returns {status: "sent", response} with the console's answer
        verbatim. With dry-run policy, returns {status: "dry_run", response (the preview)} and
        sends no write.

        Dry-run response previews include body and params.

        Consequence: changes how the PTZ camera reacts to events while the window is open
        (the console defines the effect); close it with open_window false.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            open_window: true opens the window, false closes it (sent as open); for example
                true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._set_ptz_event_control_window(
            client, registry, host, camera_id, open_window
        )

    @mcp.tool(annotations=WRITE)
    async def create_ptz_patrol(
        host: str, camera_id: str, patrol: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Create a PTZ patrol (a tour through saved presets) on a PTZ camera.

        Sends patrol as given to POST cameras/{camera_id}/ptz/patrol on the Protect console host. No
        published schema documents the body; patrol records the console lists carry name, slot
        (0-4), presets (preset slots), presetDurationSeconds and presetMovementSpeed. Returns
        {status: "created", response}. Start it with ptz_patrol_start. With dry-run policy, returns
        {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            patrol: Patrol object sent as given (free-form); for example {"name": "Yard
                tour", "slot": 0, "presets": [0, 1], "presetDurationSeconds": 10}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._create_ptz_patrol(
            client, registry, host, camera_id, patrol
        )

    @mcp.tool(annotations=WRITE)
    async def update_ptz_patrol(
        host: str, camera_id: str, slot: int, fields: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Update a PTZ patrol by its patrol slot, verified by reading it back.

        Reads the camera's patrols (GET cameras/{camera_id}/ptz/patrol on the Protect
        console host); a slot the list does not hold fails listing the valid slots. Every
        requested field already equal returns {status: "noop", resource} with no write.
        Otherwise fields are merged over the current patrol (nested siblings kept) and sent
        to PATCH cameras/{camera_id}/ptz/patrol/{slot}, then read back. Returns {status:
        "updated", verified, before, after, response}; verified is true only when every
        requested leaf matches, type-strict, and null with readAfterError when the read-back
        fails or lacks the slot. Passing no field fails before any request.
        With dry-run policy, returns {status: "dry_run", before, response (the preview)}.

        Dry-run response previews include body and params.

        Consequence: the camera's next run of this patrol follows the new settings.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Patrol slot 0-4 (the patrol's slot field); for example 0.
            fields: Patrol fields to change (free-form); for example {"name": "Yard tour",
                "presetDurationSeconds": 15}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._update_ptz_patrol(
            client, registry, host, camera_id, slot, fields
        )

    @mcp.tool(annotations=WRITE)
    async def delete_ptz_patrol(
        host: str, camera_id: str, slot: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Delete a PTZ patrol by its patrol slot.

        Reads the camera's patrols first (GET cameras/{camera_id}/ptz/patrol on the Protect
        console host); a slot the list does not hold fails listing the valid slots, with no
        delete sent. Then sends DELETE cameras/{camera_id}/ptz/patrol/{slot}. Returns
        {deleted: true, message, response}. With dry-run policy, returns {status: "dry_run",
        deleted: false, message, response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the patrol is removed permanently (its presets stay); there is no undo.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Patrol slot 0-4 (the patrol's slot field); for example 0.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._delete_ptz_patrol(
            client, registry, host, camera_id, slot
        )

    @mcp.tool(annotations=WRITE)
    async def create_ptz_preset(
        host: str, camera_id: str, preset: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Create a PTZ preset (a saved pan/tilt/zoom position) on a PTZ camera.

        Sends preset as given to POST cameras/{camera_id}/ptz/preset on the Protect console
        host. No published schema documents the body; preset records the console lists
        carry name, slot and ptz {pan, tilt, zoom}. Returns {status: "created", response}.
        Go to it with ptz_goto_preset. With dry-run policy, returns {status: "dry_run",
        response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            preset: Preset object sent as given (free-form); for example {"name": "Gate",
                "slot": 1}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._create_ptz_preset(
            client, registry, host, camera_id, preset
        )

    @mcp.tool(annotations=WRITE)
    async def update_ptz_preset(
        host: str, camera_id: str, slot: int, fields: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Update a PTZ preset by its slot (rename it or change its position), verified.

        Reads the camera's presets (GET cameras/{camera_id}/ptz/preset on the Protect
        console host); a slot the list does not hold fails listing the valid slots. Every
        requested field already equal returns {status: "noop", resource} with no write.
        Otherwise fields are merged over the current preset (nested siblings such as the
        other ptz axes kept) and sent to PATCH cameras/{camera_id}/ptz/preset/{slot}, then
        read back. Returns {status: "updated", verified, before, after, response}; verified
        is true only when every requested leaf matches, type-strict, and null with
        readAfterError when the read-back fails or lacks the slot. Passing no field fails
        before any request. With dry-run policy, returns {status: "dry_run", before,
        response (the preview)}.

        Dry-run response previews include body and params.

        Consequence: ptz_goto_preset and patrols using this slot go to the new position.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Preset slot (the preset's slot field; -1 is home); for example 1.
            fields: Preset fields to change (free-form); for example {"name": "Front gate"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._update_ptz_preset(
            client, registry, host, camera_id, slot, fields
        )

    @mcp.tool(annotations=WRITE)
    async def delete_ptz_preset(
        host: str, camera_id: str, slot: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Delete a PTZ preset by its slot.

        Reads the camera's presets first (GET cameras/{camera_id}/ptz/preset on the Protect
        console host); a slot the list does not hold fails listing the valid slots, with no
        delete sent. Then sends DELETE cameras/{camera_id}/ptz/preset/{slot}. Returns
        {deleted: true, message, response}. With dry-run policy, returns {status: "dry_run",
        deleted: false, message, response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the saved position is removed permanently and patrols that use it lose
        that stop; there is no undo.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Preset slot (the preset's slot field); for example 1.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._delete_ptz_preset(
            client, registry, host, camera_id, slot
        )

    @mcp.tool(annotations=WRITE)
    async def create_camera_shortcut(
        host: str,
        camera_id: str,
        shortcut: dict[str, Any],
        confirm: bool = False,
        validate_schema: bool = False,
    ) -> dict[str, Any]:
        """Create a camera shortcut (a one-click action shown on the camera's live view).

        Sends shortcut as a single-item array to POST cameras/{camera_id}/shortcuts on the
        Protect console host. With validate_schema=true, checks placement x/y and the nested
        shortcut type: linkedCamera needs linkedCameraId; linkedDoor needs linkedDoorId; webhook
        needs name, url, method, headers, body, auth and timeout. Missing fields fail locally.
        Legacy calls pass their body unchanged. Returns {status: "created", response}
        on success. With dry-run policy, returns {status: "dry_run",
        response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            shortcut: One shortcut object, sent inside an array (free-form); for example
                {"placement": {"x": 0, "y": 0}, "shortcut": {"type": "webhook", "name":
                "Gate view", "url": "http://192.0.2.1/", "method": "GET", "headers": null,
                "body": null, "auth": null, "timeout": 1}}.
            confirm: Accepted and ignored for compatibility; for example false.
            validate_schema: Opt in to local per-type shape checks; for example true.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._create_camera_shortcut(
            client, registry, host, camera_id, shortcut, validate_schema
        )

    @mcp.tool(annotations=WRITE)
    async def update_camera_shortcut(
        host: str,
        camera_id: str,
        body: dict[str, Any],
        confirm: bool = False,
        validate_schema: bool = False,
    ) -> dict[str, Any]:
        """Update a camera's shortcuts (PATCH cameras/{camera_id}/shortcuts).

        The route has no shortcut id in its path. The camera is read first (GET cameras/{camera_id} on the Protect console host); when body carries an id that the camera's shortcuts array lists, a no-op returns {status: "noop", resource}, and the read-back verifies every requested leaf (type-strict). An id the array does not list fails listing the valid ids. Without a locatable id the body is sent and verified is null with readAfterError. The body is sent as a single-item array. validate_schema=true checks id, any placement x/y, and any complete nested shortcut using the same per-type rules as create_camera_shortcut. Returns {status: "updated", verified, before, after, response}. An empty body fails before any request. With dry-run policy, returns {status: "dry_run", before, response (the dry-run preview)}.

        Dry-run response previews include body and params.

        Consequence: a successful request can change the shortcut buttons shown for this camera.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            body: One shortcut update, sent inside an array (free-form): the shortcut's id plus
                the parts to change; for example {"id": "000000000000000000000109",
                "placement": {"x": 0, "y": 0}}. Protect 7.3.74 rejected anything but an
                array of {id, placement?, shortcut?} with an AJV 400.
            confirm: Accepted and ignored for compatibility; for example false.
            validate_schema: Opt in to local per-type shape checks; for example true.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._update_camera_shortcut(
            client, registry, host, camera_id, body, validate_schema
        )

    @mcp.tool(annotations=WRITE)
    async def delete_camera_shortcut(
        host: str, camera_id: str, shortcut_ids: list[str], confirm: bool = False
    ) -> dict[str, Any]:
        """Delete one or more camera shortcuts.

        Reads the camera first (GET cameras/{camera_id} on the Protect console host); an id its
        shortcuts array does not list fails listing the valid ids, with no delete sent. Then sends
        DELETE cameras/{camera_id}/shortcuts with shortcut_ids as the shortcutIds query parameter
        (one per id). An empty shortcut_ids list fails before any request. Returns {deleted:
        true, message, response}. With dry-run policy, returns {status: "dry_run", deleted:
        false, message, response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: a successful deletion permanently removes shortcuts; there is no undo.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            shortcut_ids: Non-empty list of shortcut ids (the camera's shortcuts[].id); for example
                ["000000000000000000000109"].
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._delete_camera_shortcut(
            client, registry, host, camera_id, shortcut_ids
        )

    @mcp.tool(annotations=WRITE)
    async def trigger_camera_shortcut(
        host: str, camera_id: str, shortcut_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Run a camera shortcut, as clicking it in the Protect web app does.

        Reads the camera first (GET cameras/{camera_id} on the Protect console host); an id
        its shortcuts array does not list fails listing the valid ids, with nothing sent.
        Then sends POST cameras/{camera_id}/shortcuts/{shortcut_id}/click once (never
        auto-retried on 429). Returns {status: "sent", response}. With dry-run policy,
        returns {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: a successful request can run the shortcut's action (for example a PTZ move
        or an output); it is not undone automatically.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            shortcut_id: Shortcut id (the camera's shortcuts[].id); for example
                "000000000000000000000109".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._trigger_camera_shortcut(
            client, registry, host, camera_id, shortcut_id
        )

    @mcp.tool(annotations=WRITE)
    async def calibrate_camera(host: str, camera_id: str, confirm: bool = False) -> dict[str, Any]:
        """Start a camera calibration (PTZ / motorised lens), as the Protect web app does.

        Sends POST cameras/{camera_id}/calibrate (no body) once on the Protect console host,
        never auto-retried on 429. Returns {status: "sent", response} with the console's
        answer verbatim; a camera without calibration answers with its error. With
        dry-run policy, returns {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the camera moves through its full range while it calibrates, so its
        view is interrupted until calibration ends.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._calibrate_camera(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def test_doorbell_ringtone(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Play a doorbell's ringtone once to test it.

        Sends POST cameras/{camera_id}/test-ringtone (no body) once on the Protect console
        host, never auto-retried on 429. camera_id is the doorbell's camera id. Returns
        {status: "sent", response}. With dry-run policy, returns {status: "dry_run",
        response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the doorbell and its paired chimes ring audibly.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Doorbell camera id from list_cameras; for example
                "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._test_doorbell_ringtone(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def enroll_doorbell_credential(
        host: str,
        camera_id: str,
        credential_type: CredentialType,
        step: EnrollStep = "enroll",
        fingerprint_id: str | None = None,
        ulp_id: str | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Enroll an NFC card or fingerprint on a doorbell (G4/G6 Pro class) for a user. credential_type is nfc or fingerprint. step enroll (POST cameras/{camera_id}/{credential_type}/enroll) puts the doorbell into enrollment mode (present the card or finger); step assign (POST .../assign) assigns the read credential to a user: body is fields plus fingerprintId and ulpId when given (NFC body not published: pass its keys in fields); step cancel (POST .../cancel) leaves enrollment mode. fingerprint_id, ulp_id and fields apply to assign only (with another step they fail before any request).

        Consequence: an assigned card or fingerprint can unlock or identify the user at the doorbell until deleted with delete_doorbell_credential.

        Returns {status, response}: status: "enrolling" for step enroll, status: "assigned" for assign and status: "cancelled" for cancel. Credential identifiers are registered secrets, masked only under UNIFI_REDACT_SECRETS. With dry-run policy returns {status: "dry_run", response (the dry-run preview)}; no write is sent.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Doorbell camera id from list_cameras; for example
                "000000000000000000000103".
            credential_type: nfc or fingerprint; for example "fingerprint".
            step: enroll, assign or cancel; for example "enroll".
            fingerprint_id: assign only: the read fingerprint id, sent as fingerprintId;
                for example "3".
            ulp_id: assign only: the UniFi user id, sent as ulpId (list_ulp_users); for
                example "0f6a1c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b".
            fields: assign only: other body keys sent as given (free-form); for example
                {"name": "Front door card"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._enroll_doorbell_credential(
            client,
            registry,
            host,
            camera_id,
            credential_type,
            step=step,
            fingerprint_id=fingerprint_id,
            ulp_id=ulp_id,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def delete_doorbell_credential(
        host: str,
        camera_id: str,
        credential_type: CredentialType,
        credential_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Delete an enrolled NFC card or fingerprint from a doorbell.

        Sends DELETE cameras/{camera_id}/{credential_type}/{credential_id} on the Protect console
        host (credential_type nfc or fingerprint). The id is a registered secret, masked only under
        UNIFI_REDACT_SECRETS. Returns {deleted: true, message, response}. With dry-run policy,
        returns {status: "dry_run", deleted: false, message, response (the preview)} and sends no
        write.

        Dry-run response previews include body and params.

        Consequence: the card or fingerprint stops working at this doorbell at once; it
        must be enrolled again to restore it.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Doorbell camera id from list_cameras; for example
                "000000000000000000000103".
            credential_type: nfc or fingerprint; for example "nfc".
            credential_id: The enrolled card or fingerprint id; for example
                "00000000000000000000010a".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_ptz_doorbell._delete_doorbell_credential(
            client, registry, host, camera_id, credential_type, credential_id
        )


def register_10(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 18 P07 and NL-1 tools."""

    @mcp.tool(annotations=WRITE)
    async def create_recognition_group(host: str, type: str, group: dict[str, Any]) -> Any:
        """Create a Protect recognition group (an enrolled face or vehicle).

        POST protect/api/recognition/{type}/groups (private Protect API) with group sent
        verbatim; the upstream response is returned unchanged. The frontend builds this
        body dynamically, so no key is required here; the upstream judges it. An empty
        object is refused before any request. Under dry-run policy it returns a dry-run
        preview. Honours UNIFI_WRITE_POLICY=deny and family:protect=deny.
        Returns the upstream response unchanged (an object, an array or null); under
        dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Use "face" or "vehicle" (singular; plural forms return HTTP 400 upstream).
            group: Native group object, e.g. {"name": "Delivery van"}. Free-form object.
        """
        client, registry = deps_fn()
        return await protect_recognition_search._create_recognition_group(
            client, registry, host, type, group
        )

    @mcp.tool(annotations=WRITE)
    async def update_recognition_group(
        host: str, type: str, group_id: str, changes: dict[str, Any]
    ) -> Any:
        """Change fields of one Protect recognition group (read, write, then verify).

        Drains list_recognition_groups to find group_id (an unknown id fails listing the valid ids, before any write). If every requested leaf already matches it returns {status: "noop"} without writing; otherwise sends changes with PATCH protect/api/recognition/{type}/groups/{group_id}. The upstream response is returned unchanged plus _before, _after and _verified (each requested leaf re-read, type strict; _readAfterError when the re-read failed). An empty changes object is refused before any request. Under dry-run policy it returns a dry-run preview. Honours UNIFI_WRITE_POLICY=deny and family:protect=deny. Returns the upstream response plus _before, _after, _verified and _readAfterError (a non-object response sits under response); {status: "noop", reason, resource} when nothing changes; under dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Use "face" or "vehicle" (singular; plural forms return HTTP 400 upstream).
            group_id: Group id from list_recognition_groups, e.g. "face_90".
            changes: Fields to change as on the group record, e.g. {"name": "Visitors"}.
                Free-form object.
        """
        client, registry = deps_fn()
        return await protect_recognition_search._update_recognition_group(
            client, registry, host, type, group_id, changes
        )

    @mcp.tool(annotations=WRITE)
    async def delete_recognition_group(host: str, type: str, group_id: str) -> Any:
        """Delete one Protect recognition group.

        Drains list_recognition_groups to confirm group_id (an unknown id fails listing the valid
        ids, before any write), then sends DELETE protect/api/recognition/{type}/groups/{group_id}.
        Under dry-run policy it returns {status: "dry_run", deleted: false, message, response} where
        response is the dry-run preview. Honours UNIFI_WRITE_POLICY=deny and
        family:protect=deny. Consequence: the enrolled face or vehicle and its name
        are removed from the console; there is no undo. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. The dry-run preview under response
        is {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Use "face" or "vehicle" (singular; plural forms return HTTP 400 upstream).
            group_id: Group id from list_recognition_groups, e.g. "face_90".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._delete_recognition_group(
            client, registry, host, type, group_id
        )

    @mcp.tool(annotations=WRITE)
    async def assign_detections_to_recognition_group(
        host: str,
        type: str,
        detection_ids: list[str] | None = None,
        group_id: str | None = None,
        assignment: dict[str, Any] = protect_recognition_search._NATIVE_BODY_DEFAULT,
    ) -> Any:
        """Assign recognition detections to a recognition group.

        POST protect/api/recognition/{type}/assign-group with the body the Protect web app
        sends, {"objectIds": detection_ids, "groupId": group_id}; the upstream response is
        returned unchanged. An empty or non-list detection_ids, or an empty group_id, is
        refused before any request. Under dry-run policy it returns a dry-run preview.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny.
        Consequence: the detections move out of the group that held them and are
        re-labelled as the target group on the console.
        Returns the upstream response unchanged (an object, an array or null); under
        dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Use "face" or "vehicle" (singular; plural forms return HTTP 400 upstream).
            detection_ids: Shape: string[]. Ids of the detections to move, from
                list_recognition_detections, e.g. ["000000000000000000000116"].
            group_id: Id of the group that receives them, from list_recognition_groups,
                e.g. "face_90".
            assignment: Legacy native body sent verbatim when supplied instead of the typed
                arguments; it takes precedence, so detection_ids and group_id are then ignored.
                Free-form object. Shape: {objectIds:string[],groupId:string}.
        """
        client, registry = deps_fn()
        if assignment is not protect_recognition_search._NATIVE_BODY_UNSET:
            validate_id(type, "type")
            body = protect_recognition_search._body(assignment, "assignment")
            protect._require_mutations()
            guard_action("POST")
            key, hid = await protect._resolve(registry, host)
            return await client.post(
                protect._private(hid, f"/recognition/{type}/assign-group"), key=key, json=body
            )
        return await protect_recognition_search._assign_detections_to_recognition_group(
            client, registry, host, type, detection_ids, group_id
        )

    @mcp.tool(annotations=WRITE)
    async def enhance_face_detection_image(host: str, detection_id: str) -> Any:
        """Ask Protect to enhance the image of one face detection.

        POST protect/api/recognition/face/detections/{detection_id}/image/enhance with no
        body. A JSON or text response is returned unchanged; an image response is returned
        as {image_base64, content_type, size_bytes} with the upstream Content-Type. Under
        dry-run policy it returns a dry-run preview. Honours UNIFI_WRITE_POLICY=deny and
        family:protect=deny.
        Consequence: the console processes the detection image and stores the enhanced
        image for that detection.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under dry-run policy the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            detection_id: Detection id from list_recognition_detections,
                e.g. "000000000000000000000116".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._enhance_face_detection_image(
            client, registry, host, detection_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def search_recognition_group_candidates(
        host: str, type: str, query_params: dict[str, Any] | None = None
    ) -> Any:
        """Search for recognition groups that are candidates for a match or merge.

        GET protect/api/recognition/{type}/groups/search-candidates. The inventory records
        no fixed query keys, so query_params is a free-form object forwarded as query parameters
        exactly as given (omit it to send none). The upstream body is returned unchanged.
        Returns the upstream body unchanged (an object or an array).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Use "face" or "vehicle" (singular; plural forms return HTTP 400 upstream).
            query_params: Free-form query parameters, e.g. {"groupId": "face_90"}. Omit for none.
        """
        client, registry = deps_fn()
        return await protect_recognition_search._search_recognition_group_candidates(
            client, registry, host, type, query_params
        )

    @mcp.tool(annotations=WRITE)
    async def set_recognition_group_image(
        host: str,
        type: str,
        group_id: str,
        filename: str,
        file_content_base64: str,
        content_type: str | None = None,
        form_field: str = DEFAULT_FORM_FIELD,
    ) -> Any:
        """Upload a new reference image for one Protect recognition group.

        Drains list_recognition_groups to confirm group_id (an unknown id fails listing
        the valid ids, before any write), then sends the decoded image as a multipart file
        part with POST protect/api/recognition/{type}/groups/{group_id}/image. The upstream
        response is returned unchanged. Invalid base64 is refused before any request. Under
        dry-run policy it returns a dry-run preview (part name, filename, type and size).
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny.
        Consequence: the group's reference image on the console is replaced.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under dry-run policy the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Use "face" or "vehicle" (singular; plural forms return HTTP 400 upstream).
            group_id: Group id from list_recognition_groups, e.g. "face_90".
            filename: File name sent with the part, e.g. "reference.jpg".
            file_content_base64: The image bytes, base64-encoded, e.g. "iVBORw0KGgo=".
            content_type: Part MIME type, e.g. "image/jpeg". Omit to derive it from the
                filename extension.
            form_field: Multipart field name, default "file" (the published Protect
                upload's name), e.g. "file".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._set_recognition_group_image(
            client,
            registry,
            host,
            type,
            group_id,
            filename,
            file_content_base64,
            content_type,
            form_field,
        )

    @mcp.tool(annotations=WRITE)
    async def merge_recognition_groups(
        host: str,
        type: str,
        to_group_id: str | None = None,
        from_group_ids: list[str] | None = None,
        merge: dict[str, Any] = protect_recognition_search._NATIVE_BODY_DEFAULT,
    ) -> Any:
        """Merge Protect recognition groups into one.

        POST protect/api/recognition/{type}/merge-group with the body the Protect web app
        sends, {"fromGroupIds": from_group_ids, "toGroupId": to_group_id}; the upstream
        response is returned unchanged. An empty or non-list from_group_ids, an empty
        to_group_id, or a from_group_ids list that names to_group_id is refused before any
        request. Under dry-run policy it returns a dry-run preview.
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny.
        Consequence: the groups in from_group_ids are folded into to_group_id with their
        detections; there is no unmerge.
        Returns the upstream response unchanged (an object, an array or null); under
        dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            type: Recognition type, singular; plural forms return HTTP 400 upstream, e.g. "face".
            to_group_id: Id of the group that is kept, from list_recognition_groups,
                e.g. "face_90".
            from_group_ids: Shape: string[]. Ids of the groups merged into it, e.g. ["face_91"].
            merge: Legacy native body sent verbatim when supplied instead of the typed
                arguments; it takes precedence, so to_group_id and from_group_ids are then ignored.
                Free-form object. Shape: {fromGroupIds:string[],toGroupId:string}.
        """
        client, registry = deps_fn()
        if merge is not protect_recognition_search._NATIVE_BODY_UNSET:
            validate_id(type, "type")
            body = protect_recognition_search._body(merge, "merge")
            protect._require_mutations()
            guard_action("POST")
            key, hid = await protect._resolve(registry, host)
            return await client.post(
                protect._private(hid, f"/recognition/{type}/merge-group"), key=key, json=body
            )
        return await protect_recognition_search._merge_recognition_groups(
            client, registry, host, type, to_group_id, from_group_ids
        )

    @mcp.tool(annotations=WRITE)
    async def recognize_image(
        host: str,
        filename: str,
        file_content_base64: str,
        content_type: str | None = None,
        form_field: str = DEFAULT_FORM_FIELD,
    ) -> Any:
        """Run Protect recognition on an uploaded image.

        Sends the decoded image as a multipart file part with POST
        protect/api/recognition/recognize-image; the upstream response (what Protect
        recognised) is returned unchanged. This is a POST, so it is classed as a write.
        Invalid base64 is refused before any request. Under dry-run policy it returns a
        dry-run preview (part name, filename, type and size).
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny.
        Consequence: the image is uploaded to and processed by the console.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under dry-run policy the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            filename: File name sent with the part, e.g. "photo.jpg".
            file_content_base64: The image bytes, base64-encoded, e.g. "iVBORw0KGgo=".
            content_type: Part MIME type, e.g. "image/jpeg". Omit to derive it from the
                filename extension.
            form_field: Multipart field name, default "file" (the published Protect
                upload's name), e.g. "file".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._recognize_image(
            client, registry, host, filename, file_content_base64, content_type, form_field
        )

    @mcp.tool(annotations=WRITE)
    async def bulk_upload_vehicle_groups(
        host: str,
        filename: str,
        file_content_base64: str,
        content_type: str | None = None,
        form_field: str = DEFAULT_FORM_FIELD,
    ) -> Any:
        """Create vehicle recognition groups in bulk from a filled-in upload file.

        Sends the decoded file (the template from get_vehicle_group_upload_template, filled
        in) as a multipart file part with POST
        protect/api/recognition/vehicle/groups/batch-upload; the upstream response is
        returned unchanged. Invalid base64 is refused before any request. Under
        dry-run policy it returns a dry-run preview (part name, filename, type and size).
        Honours UNIFI_WRITE_POLICY=deny and family:protect=deny.
        Consequence: every vehicle row in the file is created as a recognition group.
        Returns the upstream response unchanged (an object, an array or null), a binary
        answer as {image_base64, content_type, size_bytes}; under dry-run policy the
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            filename: File name sent with the part, e.g. "vehicles.csv".
            file_content_base64: The file bytes, base64-encoded, e.g. "cGxhdGUsbmFtZQo=".
            content_type: Part MIME type, e.g. "text/csv". Required when the filename
                extension is not an image or audio type.
            form_field: Multipart field name, default "file" (the published Protect
                upload's name), e.g. "file".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._bulk_upload_vehicle_groups(
            client, registry, host, filename, file_content_base64, content_type, form_field
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_vehicle_group_upload_template(host: str) -> Any:
        """Download the vehicle recognition group bulk-upload template.

        GET protect/api/recognition/vehicle/groups/template (the link the Protect web
        application offers for download). The complete file is returned as
        {content_base64, content_type, size_bytes} with the upstream Content-Type; fill it
        in and pass it to bulk_upload_vehicle_groups.
        Returns {content_base64, content_type, size_bytes}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._get_vehicle_group_upload_template(
            client, registry, host
        )

    @mcp.tool(annotations=READ_ONLY)
    async def search_detections(
        host: str,
        search_text: str,
        start: int | None = None,
        end: int | None = None,
        cameras: list[str] | None = None,
        min_similarity: float | None = None,
        order_by: str | None = None,
        ignore_time_filter_from_text: bool | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Any:
        """Search Protect detections with a natural-language description.

        GET protect/api/detection-nls with searchText and only the filters given. start and
        end are epoch SECONDS, sent as milliseconds (_warnings flags values that look like
        milliseconds or are negative). cameras takes camera ids or names (names resolve to
        ids; an unknown name fails listing the cameras). Without limit/offset every page is
        drained (incomplete=true with the reason if a drain stops short); with either, that
        one page is returned in the upstream shape.
        Returns a drained list as {data or result, _count} plus the first page's other
        fields, incomplete and incompleteReason when it stopped short, and _warnings; an
        explicit page as the upstream page plus _count and _warnings (a bare-array page
        as that array).

        A searchHost 404 indicates detection search service availability or configuration;
        check Protect.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            search_text: What to look for, e.g. "white van in the driveway".
            start: Window start, epoch seconds, e.g. 1718000000.
            end: Window end, epoch seconds, e.g. 1718003600.
            cameras: Camera ids or names, e.g. ["000000000000000000000114"].
                Shape: string[]
            min_similarity: minSimilarity threshold sent as given, e.g. 0.25.
            order_by: orderBy value sent as given, e.g. "similarity".
            ignore_time_filter_from_text: Sent as ignoreTimeFilterFromText, e.g. true.
            limit: Page size for one explicit page. Example: `50`.
            offset: Start position for one explicit page. Example: `25`.
        """
        client, registry = deps_fn()
        return await protect_recognition_search._search_detections(
            client,
            registry,
            host,
            search_text,
            start,
            end,
            cameras,
            min_similarity,
            order_by,
            ignore_time_filter_from_text,
            limit,
            offset,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_detection_search_metadata(
        host: str, section: Literal["search", "labels", "progress"] = "labels"
    ) -> Any:
        """Read Protect detection-search metadata.

        The section selects the GET route: "search" -> protect/api/detection-search, "labels" ->
        protect/api/detection-search/labels (the searchable labels), "progress" ->
        protect/api/detection-search/progress (indexing progress). The upstream body is
        returned unchanged.
        Returns the upstream body unchanged (an object or an array).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            section: Which detection-search route to read, e.g. "progress".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._get_detection_search_metadata(
            client, registry, host, section
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_detection_statistics(
        host: str,
        start: int | None = None,
        end: int | None = None,
        period: int | str | None = None,
        group_id: str | None = None,
    ) -> Any:
        """Read Protect detection statistics, per camera, in time buckets.

        Protect 7.3 requires start, end and period; an upstream rejection adds a hint.
        GET protect/api/statistics/detections. start and end are epoch SECONDS and period
        is an integer bucket width in SECONDS (sent as milliseconds) or a string sent
        unchanged (_warnings flags start/end values that look like milliseconds or are negative).
        group_id is forwarded as given; the upstream judges it. The upstream body is
        returned unchanged.
        Returns the upstream body unchanged (an object or an array) plus _warnings for
        suspect epoch values on an object.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            start: Window start, epoch seconds, e.g. 1718000000.
            end: Window end, epoch seconds, e.g. 1718086400.
            period: Integer bucket width in seconds, or a string forwarded unchanged; e.g. 900.
            group_id: Recognition group id sent as groupId, e.g. "face_90".
        """
        client, registry = deps_fn()
        return await protect_recognition_search._get_detection_statistics(
            client, registry, host, start, end, period, group_id
        )

    @mcp.tool(annotations=WRITE)
    async def report_ai_false_positive(
        host: str, event_id: str, reported_thumbnails: list[str | dict[str, Any]]
    ) -> Any:
        """Report a Protect AI detection as a false positive.

        POST protect/api/report/ai-false-positive with {"eventId": event_id,
        "reportedThumbnails": reported_thumbnails} (the keys the frontend sends); the
        upstream response is returned unchanged. Under dry-run policy it returns a dry-run
        preview. Honours UNIFI_WRITE_POLICY=deny and family:protect=deny.
        Consequence: the report and the named thumbnails are submitted from the console.
        Returns the upstream response unchanged (an object, an array or null); under
        dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            event_id: Event id from list_protect_events, e.g. "000000000000000000000117".
            reported_thumbnails: Non-empty list of thumbnails of the event being reported, sent
                as given (an empty list fails before any request), for example
                ["e-000000000000000000000117"].
                Shape: (string|object)[]; keys the server reads: none, each entry is sent as given
        """
        client, registry = deps_fn()
        return await protect_recognition_search._report_ai_false_positive(
            client, registry, host, event_id, reported_thumbnails
        )

    @mcp.tool(annotations=WRITE)
    async def hide_face_detection_enhanced_image(host: str, detection_id: str, hide: bool) -> Any:
        """Hide or show the enhanced image of one face detection in Protect.

        PATCH protect/api/recognition/face/detections/{detection_id}/enhanced-image
        (private Protect API) with the body {"hide": hide}. The upstream response is
        returned unchanged. hide is required (no default); pass hide=false to show the
        enhanced image again. Under
        dry-run policy it returns a dry-run preview. Honours UNIFI_WRITE_POLICY=deny and
        family:protect=deny.
        Consequence: the console stops (or resumes) displaying the enhanced image of that
        detection in the Protect app; the detection itself is kept.
        Returns the upstream response unchanged (an object, an array or null); under
        dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            detection_id: Face detection id from list_recognition_detections,
                e.g. "000000000000000000000116".
            hide: Required. true to hide the enhanced image, false to show it again,
                e.g. true.
        """
        client, registry = deps_fn()
        return await protect_recognition_search._hide_face_detection_enhanced_image(
            client, registry, host, detection_id, hide
        )

    @mcp.tool(annotations=WRITE)
    async def apply_recognized_image(host: str, apply: dict[str, Any]) -> Any:
        """Apply the result of a recognize_image run to Protect's recognition data.

        POST protect/api/recognition/recognize-image/apply (private Protect API) with apply as the JSON body; the upstream response is returned unchanged. The frontend builds this body dynamically and the key set is not documented, so no key is required here and the upstream judges it. Build it from the answer of recognize_image. Fields are sent as given except: keys starting with "_" and values the server masks as redacted are dropped (reported on the result), and a body left with no field to send (empty, or only empty objects) is refused before any request with "No fields provided" (the message reads "apply 'settings'"). Nothing else is added, removed or rewritten. Under dry-run policy it returns a dry-run preview. Honours UNIFI_WRITE_POLICY=deny and family:protect=deny. Consequence: the console stores the recognition outcome of the uploaded image (for example adding it to a recognition group). Returns the upstream response unchanged (an object, an array or null); under dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            apply: Free-form JSON object built from the recognize_image response; its
                keys are not documented, so none are prescribed here. Sent as given
                apart from the dropped fields described above,
                e.g. `{"recognize_image response key": "value"}`.
        """
        client, registry = deps_fn()
        return await protect_recognition_search._apply_recognized_image(
            client, registry, host, apply
        )

    @mcp.tool(annotations=WRITE)
    async def create_recognition_object_group(host: str, object_ids: list[str]) -> Any:
        """Create a Protect object recognition group from recognized object ids.

        POST protect/api/recognition/objects/groups (private Protect API) with the body
        {"objectIds": object_ids}. The upstream response (the new group) is returned
        unchanged. An empty list is refused before any request. Under dry-run policy it
        returns a dry-run preview. Honours UNIFI_WRITE_POLICY=deny and
        family:protect=deny.
        Consequence: the console creates a new object recognition group holding those
        recognized objects.
        Returns the upstream response unchanged (an object, an array or null); under
        dry-run policy the preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            object_ids: Ids of the recognized objects to group, as the console reports
                them, e.g. ["000000000000000000000116", "000000000000000000000117"].
        """
        client, registry = deps_fn()
        return await protect_recognition_search._create_recognition_object_group(
            client, registry, host, object_ids
        )


def register_11(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=WRITE)
    async def readopt_protect_device(
        host: str,
        device_type: ReadoptDeviceType,
        device_id: str,
        reset: bool | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Re-adopt a Protect device whose adoption broke (it shows as disconnected).

        Consequence: the device drops its connection and re-provisions with the console;
        with reset=true it is also reset to defaults, losing its local settings.

        Sends POST /{collection}/{device_id}/readopt on the private Protect API (no official
        route), with ?reset= only when reset is given. Sent once, never auto-retried.
        Returns {status: "readopt_requested", response} with the upstream body verbatim.
        With dry-run policy, returns {status: "dry_run", response: PREVIEW} and sends no
        write. Dry-run response previews include body and params.

        Required arguments: host, device_type, device_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            device_type: Protect device type: aiport, aiprocessor, camera, chime, doorlock,
                light, linkstation, sensor, speaker or viewer; for example "camera".
            device_id: Protect device id (24-hex) from the device's list tool or
                get_protect_bootstrap; for example "00000000000000000000010b".
            reset: Also reset the device to defaults, sent as ?reset=; for example false.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._readopt_protect_device(
            client, registry, host, device_type, device_id, reset=reset
        )

    @mcp.tool(annotations=WRITE)
    async def upgrade_protect_device_firmware(
        host: str, device_type: FirmwareDeviceType, device_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Start a firmware update on one Protect device to the latest available release.

        Consequence: the device downloads and installs firmware and reboots, going offline
        (no recording or detection) for several minutes; a firmware upgrade cannot be
        rolled back from here.

        Sends POST /{collection}/{device_id}/update on the private Protect API (no official
        route). Run check_protect_firmware_updates first to refresh what is available.
        Sent once, never auto-retried. Returns {status: "upgrade_requested", response}
        with the upstream body verbatim. With dry-run policy, returns {status: "dry_run",
        response: PREVIEW} and sends no write. Dry-run response previews include body
        and params.

        Required arguments: host, device_type, device_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            device_type: aiport, aiprocessor, camera, chime, light, linkstation, sensor,
                speaker or viewer; for example "camera".
            device_id: Protect device id (24-hex); for example "00000000000000000000010b".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._upgrade_protect_device_firmware(
            client, registry, host, device_type, device_id
        )

    @mcp.tool(annotations=WRITE)
    async def locate_protect_device(
        host: str, device_type: LocateDeviceType, device_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Make a Protect device flash its locate LED so it can be found on site.

        Consequence: the device's status light blinks (and a light may flash its
        floodlight) for the locate period.

        Sends POST /{collection}/{device_id}/locate on the private Protect API (no
        official route); no body. Sent once, never auto-retried. Returns {status:
        "locating", response} with the upstream body verbatim. With dry-run policy, returns
        {status: "dry_run", response: PREVIEW} and sends no write. Dry-run response
        previews include body and params.

        Required arguments: host, device_type, device_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            device_type: aiport, doorlock, light, linkstation or sensor; for example "light".
            device_id: Protect device id (24-hex); for example "00000000000000000000010b".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._locate_protect_device(
            client, registry, host, device_type, device_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_protect_device_settings(
        host: str,
        device_type: SettingsDeviceType,
        settings: dict[str, Any],
        device_id: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Update settings of any Protect device type with read-back verification.

        Types bridge, camera, chime, light, linkstation, sensor, speaker and viewer use the official PATCH /v1/{family}/{id} (spec Protect 7.3.74; read from GET /v1/{family}/{id}); aiport, aiprocessor, doorlock and nvr have no official PATCH and use the private PATCH /{collection}/{id} (nvr: PATCH /nvr, no device_id), read from GET /locks/{id} or the bootstrap. settings is sent as given (partial nested objects too). The record is read first: when every leaf already matches, nothing is sent and {status: "noop", reason, resource} is returned. Returns otherwise {status: "updated", verified, before, after, response, _route}: verified is true when the read-after carries every sent leaf (type-strict), null with readAfterError when it cannot be read. An empty settings object fails before any request. With dry-run policy, returns {status: "dry_run", before, response: PREVIEW}. Dry-run response previews include body and params.

        Required arguments: host, device_type, settings (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            device_type: aiport, aiprocessor, bridge, camera, chime, doorlock, light,
                linkstation, sensor, speaker, viewer or nvr; for example "chime".
            settings: Fields to change (free-form object, sent as given); for example
                {"name": "Hallway chime"}.
            device_id: Protect device id (24-hex), required for every type but nvr; for
                example "00000000000000000000010b".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._update_protect_device_settings(
            client, registry, host, device_type, settings, device_id=device_id
        )

    @mcp.tool(annotations=WRITE)
    async def set_ai_port_pairing(
        host: str,
        aiport_id: str,
        camera_ids: list[str],
        paired: bool,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Pair cameras with an AI Port (paired=true) or unpair them (paired=false).

        Consequence: paired cameras get the AI Port's smart detections; unpaired cameras
        lose them until paired again.

        Sends {cameraIds} to POST /aiports/{aiport_id}/pair or /unpair on the private
        Protect API (no official route). Sent once. Returns {status: "paired" or
        "unpaired", response} with the upstream body verbatim. With dry-run policy, returns
        {status: "dry_run", response: PREVIEW} and sends no write. Dry-run response
        previews include body and params.

        Required arguments: host, aiport_id, camera_ids, paired (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            aiport_id: AI Port id (24-hex) from get_protect_bootstrap aiports; for example
                "00000000000000000000010c".
            camera_ids: Non-empty list of camera ids sent as cameraIds (an empty list fails
                before any request); for example ["00000000000000000000010b"].
            paired: true pairs, false unpairs; for example true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._set_ai_port_pairing(
            client, registry, host, aiport_id, camera_ids, paired
        )

    @mcp.tool(annotations=WRITE)
    async def control_retroactive_ai_processing(
        host: str,
        action: RetroactiveAction,
        options: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Start, pause, resume or cancel retroactive AI processing of recorded footage.

        Consequence: start queues past recordings for AI-processor analysis (CPU and disk
        load on the console); cancel discards the queued work.

        Sends POST /aiprocessors/retroactive-processing/{action} on the private Protect
        API (no official route). The web UI builds the start body at run time, so options
        is sent as given (free-form object) and nothing is sent when it is omitted. Sent
        once. Returns {status, response} with the upstream body verbatim; status names the
        action: status: "start_requested", status: "pause_requested", status:
        "resume_requested" or status: "cancel_requested". With dry-run policy, returns
        {status: "dry_run", response: PREVIEW}.
        Dry-run response previews include body and params.

        Required arguments: host, action (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            action: start, pause, resume or cancel; for example "pause".
            options: Request body sent as given (free-form object), such as the cameras
                and time window of a start; for example {"cameraIds": ["66d0..."]}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._control_retroactive_ai_processing(
            client, registry, host, action, options=options
        )

    @mcp.tool(annotations=WRITE)
    async def analyze_footage_with_ai(
        host: str,
        camera_id: str,
        timestamp: int | None = None,
        channel: int | None = None,
        event_id: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Ask the console's AI processor to describe a camera's footage in words.

        Consequence: runs a vision-language analysis on the console's AI processor
        (compute load); nothing is changed on the camera.

        Sends {cameraId, channel?, eventId?, timestamp?} to POST /aiprocessors/vlm/analyze
        on the private Protect API (no official route); only the arguments you pass are
        sent. timestamp is epoch SECONDS and is sent as milliseconds. A POST, so it counts
        as a write (read-only mode refuses it). Returns {status: "sent", response} with the
        analysis verbatim. With dry-run policy, returns {status: "dry_run", response:
        PREVIEW}. Dry-run response previews include body and params.

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            camera_id: Camera id (24-hex) from list_cameras; for example
                "00000000000000000000010b".
            timestamp: Moment to analyze, epoch SECONDS (sent as ms); for example 1760227200.
            channel: Camera channel index (0 is the highest quality); for example 0.
            event_id: Event id from list_protect_events; for example "000000000000000000000e01".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._analyze_footage_with_ai(
            client,
            registry,
            host,
            camera_id,
            timestamp=timestamp,
            channel=channel,
            event_id=event_id,
        )

    @mcp.tool(annotations=WRITE)
    async def check_protect_firmware_updates(host: str, confirm: bool = False) -> dict[str, Any]:
        """Ask a Protect console to check now for device firmware updates.

        Consequence: the console queries the update server and refreshes each device's
        available-firmware state; no device is upgraded.

        Sends POST /devices/checkUpdates on the private Protect API (no official route).
        Read the result afterwards from get_protect_bootstrap (each device's
        latestFirmwareVersion). A POST, so it counts as a write. Returns {status:
        "check_requested", response} with the upstream body verbatim. With dry-run policy,
        returns {status: "dry_run", response: PREVIEW}. Dry-run response previews
        include body and params.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._check_protect_firmware_updates(
            client, registry, host
        )

    @mcp.tool(annotations=WRITE)
    async def upgrade_all_protect_devices(host: str, confirm: bool = False) -> dict[str, Any]:
        """Start firmware updates on every Protect device that has one available.

        Consequence: every updatable camera, sensor, light, chime and other device
        installs firmware and reboots, so recording and detection stop on them for
        several minutes; upgrades cannot be rolled back from here.

        Sends POST /devices/updateAll on the private Protect API (no official route). Sent
        once, never auto-retried. Returns {status: "upgrade_requested", response} with the
        upstream body verbatim. With dry-run policy, returns {status: "dry_run", response:
        PREVIEW} and sends no write. Dry-run response previews include body and params.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._upgrade_all_protect_devices(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_device_metrics(
        host: str,
        device_id: str,
        predefined_time_range: str = "1day",
        aggregate_func: str | None = None,
    ) -> Any:
        """Get the metrics the console keeps for one Protect device.

        Reads GET /devices/{device_id}/metrics on the private Protect API (no official
        route) with predefinedTimeRange (always sent; default "1day") and aggregateFunc
        (only when given; the console defaults to AVG). Returns the upstream body verbatim
        (a bare array is returned as {result, _count}). An unknown id answers with the
        console's error.

        Required arguments: host, device_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            device_id: Protect device id (24-hex) of any device type; for example
                "00000000000000000000010b".
            predefined_time_range: Window to read, sent as predefinedTimeRange: "1day"
                (30-minute buckets), "1week" (2-hour) or "1month" (daily); for example
                "1week".
            aggregate_func: Bucket aggregate sent as aggregateFunc: "AVG", "MAX", "MIN" or
                "SUM" (the web app sends "MAX"); for example "MAX".
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._get_protect_device_metrics(
            client, registry, host, device_id, predefined_time_range, aggregate_func
        )

    @mcp.tool(annotations=WRITE)
    async def assign_sensor_to_bridge(
        host: str, sensor_id: str, bridge_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Assign a Protect sensor to a specific bridge for its wireless connection.

        Consequence: the sensor reconnects through the named bridge; it can be briefly
        offline while it moves.

        Sends {assignedBridge: bridge_id} to POST /sensors/{sensor_id}/assign-bridge on the
        private Protect API (no official route). Sent once. Returns {status: "assigned",
        response} with the upstream body verbatim. With dry-run policy, returns {status:
        "dry_run", response: PREVIEW}. Dry-run response previews include body and params.

        Required arguments: host, sensor_id, bridge_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            sensor_id: Sensor id (24-hex) from list_sensors; for example
                "00000000000000000000010d".
            bridge_id: Bridge id (24-hex) from list_bridges, sent as assignedBridge; for
                example "00000000000000000000010e".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._assign_sensor_to_bridge(
            client, registry, host, sensor_id, bridge_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_sensor_readings(
        host: str, sensor_id: str, start: int | None = None, end: int | None = None
    ) -> Any:
        """Get a Protect sensor's readings history (temperature, humidity, light).

        Reads GET /sensors/{sensor_id}/readings on the private Protect API (no official
        route). start and end are epoch SECONDS, sent as milliseconds when given; the
        console answers 400 without start and caps the window at 32 days. Returns the upstream
        body verbatim (a bare array as {result, _count}); a
        value that looks like milliseconds or is negative adds a _warnings entry.

        Required arguments: host, sensor_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            sensor_id: Sensor id (24-hex) from list_sensors; for example
                "00000000000000000000010d".
            start: Window start, epoch SECONDS; for example 1760140800.
            end: Window end, epoch SECONDS; for example 1760227200.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._get_sensor_readings(
            client, registry, host, sensor_id, start=start, end=end
        )

    @mcp.tool(annotations=WRITE)
    async def stop_speaker_stream(
        host: str, speaker_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Stop whatever audio a Protect speaker is playing now.

        Consequence: the speaker goes silent; an announcement or talkback stream in
        progress is cut off.

        Sends POST /speakers/{speaker_id}/stop-stream on the private Protect API (no
        official route); no body. Sent once. Returns {status: "stopped", response} with the
        upstream body verbatim. With dry-run policy, returns {status: "dry_run", response:
        PREVIEW}. Dry-run response previews include body and params.

        Required arguments: host, speaker_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            speaker_id: Speaker id (24-hex) from list_speakers; for example
                "00000000000000000000010f".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._stop_speaker_stream(
            client, registry, host, speaker_id
        )

    @mcp.tool(annotations=WRITE)
    async def play_chime_sound(
        host: str,
        chime_id: str,
        output: ChimeOutput,
        options: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Play a sound on a Protect chime: its speaker (a ringtone) or its buzzer.

        Consequence: the chime sounds aloud in the building.

        Output "speaker" sends POST /chimes/{chime_id}/play-speaker with options as the
        body (the web UI builds it at run time, so it is free-form and sent as given, for
        example ringtone and volume); output "buzzer" sends POST /chimes/{chime_id}/
        play-buzzer. Private Protect API (no official route). Sent once. Returns {status:
        "played", response} with the upstream body verbatim. With dry-run policy, returns
        {status: "dry_run", response: PREVIEW}. Dry-run response previews include body
        and params.

        Required arguments: host, chime_id, output (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            chime_id: Chime id (24-hex) from list_chimes; for example
                "000000000000000000000110".
            output: "speaker" or "buzzer"; for example "speaker".
            options: Speaker body sent as given (free-form object); for example
                {"volume": 60}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._play_chime_sound(
            client, registry, host, chime_id, output, options=options
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_door_locks(host: str) -> dict[str, Any]:
        """List the door locks that Protect 7.x manages under /locks on a Protect console.

        Reads GET /locks on the private Protect API (the Protect 7.x Thread lock model; the
        official API has no door-lock route). It covers the locks Protect 7.x manages under
        /locks, not older door-lock products. Returns {result: [lock, ...], _count} with each
        lock verbatim. The console answers the whole list. Consoles older than Protect 7.x do
        not serve this route. Upstream failures retain their body and include availability
        guidance.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._list_door_locks(client, registry, host)

    @mcp.tool(annotations=WRITE)
    async def set_door_lock_state(
        host: str,
        doorlock_id: str,
        action: DoorLockRequest,
        hold_extra_sec: int | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Request a remote unlock of a lock Protect 7.x manages under /locks (action="unlock").

        Consequence: unlock physically unlocks the door, so anyone can enter until the lock
        relocks itself.

        Sends POST /locks/{doorlock_id}/unlock on the private Protect API (the Protect 7.x
        Thread lock model, no official route); older door-lock products are not covered.
        The console must have remote unlock enabled for its Thread locks,
        otherwise it answers with a conflict error that is returned unchanged. Protect 7.x
        has no lock/close route, so only "unlock" is offered ("open" is its older name). Sent
        once, never auto-retried. Returns {status: "unlock_requested", response} with the
        upstream body verbatim (the unlock event id and request id); list the lock's
        unlock events or read it back with list_door_locks. With dry-run policy, returns
        {status: "dry_run", response: PREVIEW}. Dry-run response previews include body and
        params.

        Required arguments: host, doorlock_id, action (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            doorlock_id: Door lock id (24-hex) from list_door_locks; for example
                "000000000000000000000111".
            action: "unlock" (also accepted as "open"); for example "unlock".
            hold_extra_sec: Optional extra seconds to hold the lock open (the console accepts an
                integer from 0 to 60 and answers 400 otherwise); omitted from the request when
                not set; for example 10.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._set_door_lock_state(
            client, registry, host, doorlock_id, action, hold_extra_sec=hold_extra_sec
        )

    @mcp.tool(annotations=WRITE)
    async def adopt_third_party_camera(
        host: str, camera: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Adopt a third-party (ONVIF) camera into Protect.

        Consequence: the camera is added to the console and starts recording under its
        recording settings; it uses a camera licence slot where one is required.

        Sends camera as the body of POST /third-party-cameras/adopt on the private Protect
        API (no official route). The web UI builds the body at run time, so it is sent as
        given (free-form object), usually the camera address and its login. The camera
        password is a registered credential: it is masked in previews, results and error
        text only when UNIFI_REDACT_SECRETS is on, and always scrubbed from logs. Sent once.
        Returns {status: "adopt_requested", response} with the upstream body verbatim.
        With dry-run policy, returns {status: "dry_run", response: PREVIEW}. Dry-run
        response previews include body and params.

        Required arguments: host, camera (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            camera: Adoption body sent as given (free-form object); for example
                {"host": "192.0.2.50", "username": "admin", "password": "example-pass"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._adopt_third_party_camera(
            client, registry, host, camera
        )

    @mcp.tool(annotations=WRITE)
    async def set_nvr_stack_membership(
        host: str,
        mac: str,
        member: bool,
        reset: bool | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add a console to this Protect NVR stack (member=true) or remove it (false).

        Consequence: adding links the console's storage and cameras into this stack;
        removing detaches it, and with reset=true it is also reset to defaults, erasing
        its configuration.

        With member=true it sends {mac} to POST /nvr-stacks/adopt; member=false sends {mac,
        reset?} to POST /nvr-stacks/unadopt (private Protect API, no official route).
        reset is sent only when given. Sent once, never auto-retried. Returns {status:
        "adopt_requested" or "unadopt_requested", response} with the upstream body
        verbatim. With dry-run policy, returns {status: "dry_run", response: PREVIEW}.
        Dry-run response previews include body and params.

        Required arguments: host, mac, member (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            mac: MAC address of the console to add or remove, sent as mac; for example
                "00:00:5e:00:53:01".
            member: true adds the console to the stack, false removes it; for example true.
            reset: Removal only: also reset the console to defaults; for example false.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._set_nvr_stack_membership(
            client, registry, host, mac, member, reset=reset
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_protect_bootstrap(host: str) -> Any:
        """Get the Protect bootstrap: the console's whole application state in one object.

        Reads GET /bootstrap on the private Protect API (the official API has no
        equivalent). Returns the object verbatim and complete, never truncated: nvr,
        cameras, lights, sensors, doorlocks, chimes, viewers, bridges, speakers, aiports,
        users, groups, liveviews and the other collections the console sends (a bare array
        would be returned as {result, _count}). It is large
        on a large deployment. Camera share links and tokens in it are registered credentials:
        masked only when UNIFI_REDACT_SECRETS is on, otherwise verbatim.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._get_protect_bootstrap(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def list_protect_keyrings(host: str) -> dict[str, Any]:
        """List the Protect keyrings: NFC cards and fingerprints enrolled for door access.

        Reads GET /keyrings on the private Protect API (no official route). Returns
        {result: [keyring, ...], _count} with each keyring verbatim (id, deviceType,
        registryType, registryId, ulpUser). registryId identifies the card or fingerprint
        and is a registered credential: masked in results and error text only when
        UNIFI_REDACT_SECRETS is on, otherwise verbatim, and always scrubbed from logs.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
        """
        client, registry = deps_fn()
        return await protect_device_lifecycle._list_protect_keyrings(client, registry, host)


def register_12(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_door_lock(host: str, lock_id: str) -> dict[str, Any]:
        """Get one door lock that Protect 7.x manages under /locks.

        Reads GET /locks/{lock_id} on the private Protect API (the Protect 7.x Thread lock
        model; the official API has no door-lock route). Returns the lock object verbatim.
        The id is checked first against GET /locks: an id the console does not list fails
        before the per-lock request with an error naming the valid locks (id and name).
        Consoles older than Protect 7.x do not serve this route. Upstream failures retain
        their body and include availability guidance.

        Required arguments: host, lock_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            lock_id: Lock id from GET /locks (the Protect lock list or bootstrap); for example
                "000000000000000000000701".
        """
        client, registry = deps_fn()
        return await protect_door_locks._get_door_lock(client, registry, host, lock_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_door_lock_unlock_events(
        host: str,
        lock_id: str,
        offset: int | None = None,
        limit: int | None = None,
    ) -> Any:
        """List the remote unlock requests made to a Protect 7.x door lock, newest first.

        Reads GET /locks/{lock_id}/unlock/events on the private Protect API (no official
        route); each request is returned verbatim. An unlisted lock_id fails naming the
        valid locks. Returns {result, _count} by default (drained in pages of 100);
        {data, _count, _pageSize} for a limit; for an offset (0 to 10000), one native page
        as the bare array sent. A drain that stops early (UNIFI_PAGINATE_MAX_PAGES,
        the 10000 offset limit or a repeated page) is marked incomplete=true with an
        incompleteReason. Consoles older than Protect 7.x do not serve this route.

        Required arguments: host, lock_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts (reportedState.hostname or name,
                case-insensitive, or the long data[].id); for example "my-console".
            lock_id: Lock id from GET /locks (the Protect lock list or bootstrap); for example
                "000000000000000000000701".
            offset: Optional zero-based number of newest requests to skip; alone, fetch one
                page manually. Example: `25`.
            limit: Without offset, the number of newest requests to gather in pages of at
                most 100; fewer only when the lock has no more. With offset, limit is sent
                unchanged as one page. The console clamps that page to 100, so fewer can
                return while more exist. Page size 1 to 100. Example: `25`.
        """
        client, registry = deps_fn()
        return await protect_door_locks._list_door_lock_unlock_events(
            client, registry, host, lock_id, offset=offset, limit=limit
        )
