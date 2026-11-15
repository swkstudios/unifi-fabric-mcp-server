"""UniFi Protect device lifecycle: re-adopt, firmware, locate, settings, pairing and actions.

Route choice (the official published API when it can do the job, else the private API the
Protect web app calls). The official Protect Integration API pinned in
``tests/fixtures/spec_drift/baseline_snapshot.json`` (protect 7.3.74) serves device
settings PATCH for bridges, cameras, chimes, lights, link stations, sensors, speakers and
viewers (``PATCH /v1/{family}/{id}``), so ``update_protect_device_settings`` uses it for
those types. It has no route for re-adoption, firmware updates, locate, AI Port pairing,
retroactive AI processing, footage analysis, device metrics, sensor-bridge assignment,
sensor readings, speaker stream stop, chime playback, door locks, third-party camera
adoption, NVR stacks, the bootstrap or keyrings; those tools use the private
``/proxy/protect/api`` routes inventoried from the Protect web UI 5.3.18
(``tests/fixtures/private_api/inventory_protect_5.3.18.json``). Device-type routes come
from the shared mapper (``_protect_device_types``).

Every response body is passed through verbatim (server pass-through invariant). Request
bodies the web UI builds dynamically are taken as a free-form object and sent as given;
no key is invented. Validation before any request uses only registered refusals
(path-safe ids, the device-type route mapper, integer epoch seconds, the empty-update
guard, the Protect write opt-out and read-only mode, and the declared argument schema).
Physical actions are sent once (a 429 is never auto-retried).
"""

from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import StrictBool, TypeAdapter

from ...client import UniFiClient, is_dry_run_preview, path_segment
from ...config import APIKeyConfig
from ...matching import same_id, with_upstream_id
from ...read_only import guard_action
from ...registry import Registry
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    with_warnings,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._payload import with_upstream_hint
from ...shared_shapes._results import (
    requested_leaves_match,
    requested_leaves_verdict,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
from ...write_body import require_unmasked_fields
from ._protect_device_types import (
    ProtectDeviceType,
    action_method,
    device_path,
    parse_device_type,
    protect_private_path,
    require_camera_ids,
)
from .protect import (
    _dry_run_result,
    _fields_to_send,
    _list_body,
    _private,
    _require_mutations,
    _require_object,
    _resolve,
    _update_item_verified,
    _write_result,
)
from .schemas import (  # the family's shapes (family-owned layout)
    ChimeOutput,
    RetroactiveAction,
)
from .schemas import (
    DoorLockRequest as DoorLockRequest,
)
from .schemas import (
    FirmwareDeviceType as FirmwareDeviceType,
)
from .schemas import (
    LocateDeviceType as LocateDeviceType,
)
from .schemas import (
    ReadoptDeviceType as ReadoptDeviceType,
)
from .schemas import (
    SettingsDeviceType as SettingsDeviceType,
)

#: ``unlock`` (``open`` is its older name) is served by Protect 7.x; ``lock``/``close``
#: are accepted only to be refused with an actionable error (see ``set_door_lock_state``).
DoorLockAction = Literal["unlock", "open", "lock", "close"]
_RETROACTIVE_ACTION = TypeAdapter(RetroactiveAction)
_CHIME_OUTPUT = TypeAdapter(ChimeOutput)
_DOOR_LOCK_ACTION = TypeAdapter(DoorLockAction)
_STRICT_BOOL = TypeAdapter(StrictBool)

#: Device type -> official Integration API family (``PATCH /v1/{family}/{id}``) for the
#: types the pinned protect 7.3.74 spec serves; the others use the private route.
OFFICIAL_SETTINGS_FAMILY: dict[ProtectDeviceType, str] = {
    ProtectDeviceType.BRIDGE: "bridges",
    ProtectDeviceType.CAMERA: "cameras",
    ProtectDeviceType.CHIME: "chimes",
    ProtectDeviceType.LIGHT: "lights",
    ProtectDeviceType.LINKSTATION: "link-stations",
    ProtectDeviceType.SENSOR: "sensors",
    ProtectDeviceType.SPEAKER: "speakers",
    ProtectDeviceType.VIEWER: "viewers",
}

#: Private-only settings types read through the bootstrap (no private GET-by-id route is
#: sourced for them): device type -> the bootstrap key holding the record(s).
BOOTSTRAP_KEY: dict[ProtectDeviceType, str] = {
    ProtectDeviceType.AIPORT: "aiports",
    ProtectDeviceType.AIPROCESSOR: "aiprocessors",
    ProtectDeviceType.NVR: "nvr",
}


def _given(**params: Any) -> dict[str, Any]:
    """Only the values the caller actually gave (no invented defaults)."""
    return {k: v for k, v in params.items() if v is not None}


def _epoch_ms(value: int | None, name: str) -> int | None:
    """An optional epoch-seconds argument as epoch milliseconds (type-checked first)."""
    if value is None:
        return None
    return seconds_to_millis(require_epoch_seconds(value, name))


def _verbatim(body: Any, what: str) -> Any:
    """A read body verbatim; a bare JSON array is returned as ``{result, _count}``."""
    if isinstance(body, list):
        return _list_body(body, what)
    return body


def _write_guards(method: str) -> None:
    """The Protect write opt-out and read-only mode, before any request."""
    _require_mutations()
    guard_action(method)


async def _device_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    device_type: ProtectDeviceType,
    device_id: str,
    action: str,
    status: str,
    *,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """POST one sourced device action (validated first) and return the result verbatim."""
    method = action_method(device_type, action)
    device_path(device_type, device_id, action)
    _write_guards(method)
    key, host_id = await _resolve(registry, host)
    path = protect_private_path(host_id, device_type, device_id, action)
    response = await client.post(path, key=key, json=body, params=params or None)
    return _write_result(status, response)


async def _console_post(
    client: UniFiClient,
    registry: Registry,
    host: str,
    route: str,
    status: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """POST a console-level private route (``route`` is a fixed, sourced path)."""
    _write_guards("POST")
    key, host_id = await _resolve(registry, host)
    response = await client.post(_private(host_id, route), key=key, json=body)
    return _write_result(status, response)


# --- Lifecycle actions --------------------------------------------------------------


async def readopt_protect_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    device_type: str,
    device_id: str,
    reset: bool | None = None,
) -> dict[str, Any]:
    """Re-adopt a Protect device (``POST /{collection}/{id}/readopt[?reset=]``)."""
    kind = parse_device_type(device_type)
    return await _device_action(
        client,
        registry,
        host,
        kind,
        device_id,
        "readopt",
        "readopt_requested",
        params=_given(reset=reset),
    )


async def upgrade_protect_device_firmware(
    client: UniFiClient, registry: Registry, host: str, device_type: str, device_id: str
) -> dict[str, Any]:
    """Start a firmware update of one Protect device (``POST /{collection}/{id}/update``)."""
    kind = parse_device_type(device_type)
    return await _device_action(
        client, registry, host, kind, device_id, "update", "upgrade_requested"
    )


async def locate_protect_device(
    client: UniFiClient, registry: Registry, host: str, device_type: str, device_id: str
) -> dict[str, Any]:
    """Flash a Protect device's locate LED (``POST /{collection}/{id}/locate``)."""
    kind = parse_device_type(device_type)
    return await _device_action(client, registry, host, kind, device_id, "locate", "locating")


# --- Settings -------------------------------------------------------------------------


async def _read_private_record(
    client: UniFiClient,
    key: APIKeyConfig | None,
    host_id: str,
    kind: ProtectDeviceType,
    device_id: str | None,
) -> dict[str, Any] | None:
    """The current record of a private-only settings type, or None when not listed.

    Door locks have a private GET-by-id route; AI Ports, AI processors and the NVR are
    read from the bootstrap (the only sourced reader for them).
    """
    if kind is ProtectDeviceType.DOORLOCK:
        path = protect_private_path(host_id, kind, device_id)
        return _require_object(await client.get(path, key=key), f"GET {path}")
    bootstrap = await client.get(_private(host_id, "/bootstrap"), key=key)
    held = bootstrap.get(BOOTSTRAP_KEY[kind]) if isinstance(bootstrap, dict) else None
    if kind is ProtectDeviceType.NVR:
        return held if isinstance(held, dict) else None
    if isinstance(held, list):
        for record in held:
            if isinstance(record, dict) and same_id(device_id, record.get("id")):
                return record
    return None


async def _update_private_verified(
    client: UniFiClient,
    registry: Registry,
    host: str,
    kind: ProtectDeviceType,
    device_id: str | None,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """PATCH a private-only device type with read-before / no-op / read-after verification.

    The record is read before the PATCH; when every requested leaf already matches,
    nothing is sent (``status: "noop"``). A record the reader does not list is not
    refused: the PATCH is sent and the upstream answers. The read-after verifies every
    requested leaf type-strictly; an unlisted record leaves ``verified`` null with
    ``readAfterError``.
    """
    device_path(kind, device_id)
    _require_mutations()
    fields = _fields_to_send(fields, f"protect {kind.value}")
    guard_action("PATCH")
    key, host_id = await _resolve(registry, host)
    item_path = protect_private_path(host_id, kind, device_id)
    before = await _read_private_record(client, key, host_id, kind, device_id)
    if before is not None:
        fields = with_upstream_id(fields, "id", before.get("id"))
        upstream_id = before.get("id")
        if isinstance(upstream_id, str) and same_id(device_id, upstream_id):
            device_id = upstream_id
            item_path = protect_private_path(host_id, kind, device_id)
    if before is not None and short_circuit_no_op(client, requested_leaves_match(fields, before)):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    response = await client.patch(item_path, key=key, json=fields)
    if is_dry_run_preview(response):
        return _dry_run_result(before, response)

    async def _read() -> dict[str, Any] | None:
        return await _read_private_record(client, key, host_id, kind, device_id)

    after, error = await safe_read_after(_read)
    if error is None and after is None:
        error = (
            f"Protect {kind.value} {device_id if device_id is not None else '(singleton)'} "
            "is not listed by its reader (GET locks/{id} or the bootstrap); the write "
            "was sent but could not be verified"
        )
    comparison = with_upstream_id(fields, "id", after.get("id")) if after is not None else fields
    verified, error = requested_leaves_verdict(comparison, after, error)
    result = {
        "status": "updated",
        "verified": verified,
        "before": before,
        "after": after,
        "response": response,
    }
    return with_read_after_error(result, error)


async def update_protect_device_settings(
    client: UniFiClient,
    registry: Registry,
    host: str,
    device_type: str,
    settings: dict[str, Any],
    device_id: str | None = None,
) -> dict[str, Any]:
    """Update one Protect device's settings (official PATCH where served, else private)."""
    kind = parse_device_type(device_type)
    family = OFFICIAL_SETTINGS_FAMILY.get(kind)
    if family is not None:
        device_path(kind, device_id)  # every official type requires a device id
        guard_action("PATCH")
        result = await _update_item_verified(
            client, registry, host, family, cast(str, device_id), "device_id", settings
        )
        return with_context(result, {"_route": "official"})
    result = await _update_private_verified(client, registry, host, kind, device_id, settings)
    return with_context(result, {"_route": "private"})


# --- AI Port / AI processor -----------------------------------------------------------


async def set_ai_port_pairing(
    client: UniFiClient,
    registry: Registry,
    host: str,
    aiport_id: str,
    camera_ids: list[str],
    paired: bool,
) -> dict[str, Any]:
    """Pair cameras with (or unpair them from) an AI Port (``/aiports/{id}/pair|unpair``)."""
    path_segment(aiport_id, "aiport_id")
    require_camera_ids(camera_ids)
    paired = _STRICT_BOOL.validate_python(paired)
    action = "pair" if paired else "unpair"
    return await _device_action(
        client,
        registry,
        host,
        ProtectDeviceType.AIPORT,
        aiport_id,
        action,
        "paired" if paired else "unpaired",
        body={"cameraIds": list(camera_ids)},
    )


async def control_retroactive_ai_processing(
    client: UniFiClient,
    registry: Registry,
    host: str,
    action: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start, pause, resume or cancel retroactive AI processing on the AI processor."""
    action = _RETROACTIVE_ACTION.validate_python(action)
    require_unmasked_fields(options, "control_retroactive_ai_processing options")
    route = f"/aiprocessors/retroactive-processing/{action}"
    return await _console_post(
        client, registry, host, route, f"{action}_requested", dict(options) if options else None
    )


async def analyze_footage_with_ai(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    timestamp: int | None = None,
    channel: int | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Ask the AI processor to describe a camera's footage (``POST /aiprocessors/vlm/analyze``)."""
    timestamp_ms = _epoch_ms(timestamp, "timestamp")
    body = {"cameraId": camera_id}
    body.update(_given(channel=channel, eventId=event_id, timestamp=timestamp_ms))
    result = await _console_post(client, registry, host, "/aiprocessors/vlm/analyze", "sent", body)
    return with_warnings(result, epoch_warnings(timestamp=timestamp))


# --- Firmware and metrics -------------------------------------------------------------


async def check_protect_firmware_updates(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    """Ask the console to check for device firmware updates (``POST /devices/checkUpdates``)."""
    return await _console_post(client, registry, host, "/devices/checkUpdates", "check_requested")


async def upgrade_all_protect_devices(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    """Start firmware updates on every updatable Protect device (``POST /devices/updateAll``)."""
    return await _console_post(client, registry, host, "/devices/updateAll", "upgrade_requested")


async def get_protect_device_metrics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    device_id: str,
    predefined_time_range: str = "1day",
    aggregate_func: str | None = None,
) -> Any:
    """Read one Protect device's metrics (``GET /devices/{id}/metrics``), verbatim.

    Protect 7.3 requires ``predefinedTimeRange`` (1day, 1week or 1month; the web app
    opens on 1day); ``aggregateFunc`` is optional and the console defaults it to AVG.
    Both are forwarded as given; the console judges them.
    """
    segment = path_segment(device_id, "device_id")
    params = _given(predefinedTimeRange=predefined_time_range, aggregateFunc=aggregate_func)
    key, host_id = await _resolve(registry, host)
    body = await client.get(
        _private(host_id, f"/devices/{segment}/metrics"), key=key, params=params
    )
    return _verbatim(body, "Protect device metrics")


# --- Sensors, speakers, chimes ----------------------------------------------------------


async def assign_sensor_to_bridge(
    client: UniFiClient, registry: Registry, host: str, sensor_id: str, bridge_id: str
) -> dict[str, Any]:
    """Assign a sensor to a bridge (``POST /sensors/{id}/assign-bridge``)."""
    path_segment(sensor_id, "sensor_id")
    return await _device_action(
        client,
        registry,
        host,
        ProtectDeviceType.SENSOR,
        sensor_id,
        "assign-bridge",
        "assigned",
        body={"assignedBridge": bridge_id},
    )


async def get_sensor_readings(
    client: UniFiClient,
    registry: Registry,
    host: str,
    sensor_id: str,
    start: int | None = None,
    end: int | None = None,
) -> Any:
    """Read a sensor's readings history (``GET /sensors/{id}/readings``), verbatim.

    Protect 7.3 answers 400 without ``start``; ``end`` stays optional
    (the console picks the window end itself).
    """
    segment = path_segment(sensor_id, "sensor_id")
    params = _given(start=_epoch_ms(start, "start"), end=_epoch_ms(end, "end"))
    key, host_id = await _resolve(registry, host)
    body = await with_upstream_hint(
        client.get(
            _private(host_id, f"/sensors/{segment}/readings"), key=key, params=params or None
        ),
        "Protect requires start in epoch seconds for sensor readings." if start is None else None,
    )
    return with_warnings(
        _verbatim(body, "Protect sensor readings"), epoch_warnings(start=start, end=end)
    )


async def stop_speaker_stream(
    client: UniFiClient, registry: Registry, host: str, speaker_id: str
) -> dict[str, Any]:
    """Stop the audio a speaker is playing (``POST /speakers/{id}/stop-stream``)."""
    path_segment(speaker_id, "speaker_id")
    return await _device_action(
        client, registry, host, ProtectDeviceType.SPEAKER, speaker_id, "stop-stream", "stopped"
    )


async def play_chime_sound(
    client: UniFiClient,
    registry: Registry,
    host: str,
    chime_id: str,
    output: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Play a chime's speaker or buzzer (``POST /chimes/{id}/play-speaker|play-buzzer``)."""
    path_segment(chime_id, "chime_id")
    output = _CHIME_OUTPUT.validate_python(output)
    require_unmasked_fields(options, "play_chime_sound options")
    action = "play-speaker" if output == "speaker" else "play-buzzer"
    return await _device_action(
        client,
        registry,
        host,
        ProtectDeviceType.CHIME,
        chime_id,
        action,
        "played",
        body=dict(options) if options else None,
    )


# --- Door locks -------------------------------------------------------------------------


async def list_door_locks(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """List the door locks Protect 7.x manages under ``/locks`` (``GET /locks``)."""
    key, host_id = await _resolve(registry, host)
    body = await with_upstream_hint(
        client.get(_private(host_id, "/locks"), key=key),
        "Door lock list may be unavailable; /locks needs Protect 7.x.",
    )
    return _list_body(body, "door locks")


async def set_door_lock_state(
    client: UniFiClient,
    registry: Registry,
    host: str,
    doorlock_id: str,
    action: str,
    hold_extra_sec: int | None = None,
) -> dict[str, Any]:
    """Request a remote unlock of a lock Protect 7.x manages (``POST /locks/{id}/unlock``).

    ``open`` is the older name of ``unlock``. Protect 7.x has no lock/close route, so those
    actions are refused by the route mapper before any request, naming what is supported.
    """
    path_segment(doorlock_id, "doorlock_id")
    action = _DOOR_LOCK_ACTION.validate_python(action)
    # The console judges the range (0 to 60); the key is absent unless the caller gave it.
    body = None if hold_extra_sec is None else {"holdExtraSec": hold_extra_sec}
    return await _device_action(
        client,
        registry,
        host,
        ProtectDeviceType.DOORLOCK,
        doorlock_id,
        "unlock" if action == "open" else action,
        "unlock_requested",
        body=body,
    )


# --- Adoption, NVR stacks, bootstrap, keyrings ------------------------------------------


async def adopt_third_party_camera(
    client: UniFiClient, registry: Registry, host: str, camera: dict[str, Any]
) -> dict[str, Any]:
    """Adopt a third-party (ONVIF) camera (``POST /third-party-cameras/adopt``)."""
    return await _console_post(
        client, registry, host, "/third-party-cameras/adopt", "adopt_requested", dict(camera)
    )


async def set_nvr_stack_membership(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mac: str,
    member: bool,
    reset: bool | None = None,
) -> dict[str, Any]:
    """Add a console to (or remove it from) the NVR stack (``/nvr-stacks/adopt|unadopt``)."""
    member = _STRICT_BOOL.validate_python(member)
    body: dict[str, Any] = {"mac": mac}
    if not member:
        body.update(_given(reset=reset))
    route = "/nvr-stacks/adopt" if member else "/nvr-stacks/unadopt"
    status = "adopt_requested" if member else "unadopt_requested"
    return await _console_post(client, registry, host, route, status, body)


async def get_protect_bootstrap(client: UniFiClient, registry: Registry, host: str) -> Any:
    """Read the Protect bootstrap (``GET /bootstrap``): the whole application state, verbatim."""
    key, host_id = await _resolve(registry, host)
    return _verbatim(await client.get(_private(host_id, "/bootstrap"), key=key), "bootstrap")


async def list_protect_keyrings(
    client: UniFiClient, registry: Registry, host: str
) -> dict[str, Any]:
    """List the Protect keyrings (NFC cards and fingerprints) (``GET /keyrings``)."""
    key, host_id = await _resolve(registry, host)
    return _list_body(await client.get(_private(host_id, "/keyrings"), key=key), "keyrings")


# Module-level aliases: the registered tools below shadow these names inside register().
_readopt_protect_device = readopt_protect_device
_upgrade_protect_device_firmware = upgrade_protect_device_firmware
_locate_protect_device = locate_protect_device
_update_protect_device_settings = update_protect_device_settings
_set_ai_port_pairing = set_ai_port_pairing
_control_retroactive_ai_processing = control_retroactive_ai_processing
_analyze_footage_with_ai = analyze_footage_with_ai
_check_protect_firmware_updates = check_protect_firmware_updates
_upgrade_all_protect_devices = upgrade_all_protect_devices
_get_protect_device_metrics = get_protect_device_metrics
_assign_sensor_to_bridge = assign_sensor_to_bridge
_get_sensor_readings = get_sensor_readings
_stop_speaker_stream = stop_speaker_stream
_play_chime_sound = play_chime_sound
_list_door_locks = list_door_locks
_set_door_lock_state = set_door_lock_state
_adopt_third_party_camera = adopt_third_party_camera
_set_nvr_stack_membership = set_nvr_stack_membership
_get_protect_bootstrap = get_protect_bootstrap
_list_protect_keyrings = list_protect_keyrings
