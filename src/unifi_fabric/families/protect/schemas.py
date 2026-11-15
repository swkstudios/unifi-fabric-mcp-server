"""The protect family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field, StrictInt

# smart_detect_types is only honored by the upstream /events endpoint when
# ``types`` is also constrained (verified live: passing smart_detect_types alone
# returns the UNFILTERED result set — a silent no-op). Forward the caller's
# filters unchanged and add an actionable warning explaining the upstream behavior.
#: The ``_warnings`` entry for ``get_camera_snapshot`` called with ``ts``: the epoch unit of
#: ``ts`` is unverified (the value is sent as given).
_TS_UNIT_WARNING: dict[str, Any] = {
    "code": "TS_UNIT_UNVERIFIED",
    "argument": "ts",
    "message": (
        "ts was sent as given to the private recording-snapshot route; its epoch unit "
        "(inferred milliseconds) is unverified."
    ),
}

#: The ``_warnings`` entry for ``smart_detect_types`` given without ``types``: the call is
#: sent as given, and the private events endpoint is observed to ignore the subtype filter
#: unless ``types`` names the matching event type(s).
SMART_DETECT_WITHOUT_TYPES_WARNING: dict[str, Any] = {
    "code": "SMART_DETECT_TYPES_WITHOUT_TYPES",
    "argument": "smart_detect_types",
    "message": (
        "smart_detect_types was sent without types; the events endpoint honours it only "
        "when types is also set (types='smartDetectZone' for person/vehicle/animal/"
        "package/face/licensePlate, types='smartAudioDetect' for alrmSpeak/alrmSiren/"
        "alrmBark/alrmCarHorn), so these events may be unfiltered by subtype."
    ),
}

# The official Protect Integration API (PROTECT_PROXY_BASE, above) exposes events
# ONLY over WebSocket at /v1/subscribe/events and has no REST query endpoint. The
# private path below is the sole source of *historical* events over REST. Do not
# "correct" it to the integration path — that path cannot answer this query.
PROTECT_PRIVATE_BASE = "/v1/connector/consoles/{host_id}/proxy/protect/api"

#: Additive key carrying a sensor event's sensor id. The upstream ``sensor`` field is
#: never rewritten (it stays null on sensor events, exactly as the controller sends it).
RESOLVED_SENSOR_KEY = "_resolved_sensor"

# Protect device families polled by ``collect_protect_device_changes``. The
# Integration API has no single "all devices" REST route — the only all-device
# feed is the WebSocket ``/v1/subscribe/devices`` bootstrap, unreachable over the
# cloud connector — so the union of these per-family list endpoints is the REST
# parity source. Each returns a bare JSON array of objects carrying a unique ``id``.
# This is every device list of the vendored Protect 7.3.74 spec (each ``GET /v1/<family>``
# tagged "<Family> information & management" that returns an array);
# tests/test_protect_collectors.py derives that set from the spec and pins it equal.
DEVICE_FAMILIES = (
    "cameras",
    "sensors",
    "lights",
    "chimes",
    "viewers",
    "sirens",
    "fobs",
    "relays",
    "speakers",
    "bridges",
    "link-stations",
    "alarm-hubs",
)

# Top-level fields that change on a routine device heartbeat and therefore must
# NOT by themselves count as a device "modification". ``collect_protect_device_changes``
# compares two snapshots of the same device id by equality of the upstream object
# with exactly these keys removed; the emitted ``device`` is always the verbatim
# upstream body (these fields are stripped only for the comparison).
_VOLATILE_DEVICE_FIELDS = ("lastSeen", "uptime", "upSince")

#: The MIME types Protect 7.3.74 POST /v1/files/{fileType} accepts for the file part,
#: by filename extension (the spec: "image/gif, image/jpeg, image/png, audio/mpeg,
#: audio/mp4, audio/wave, audio/x-caf"). Not mimetypes.guess_type: it answers
#: audio/x-wav for .wav and nothing for .caf, which the spec does not list.
UPLOAD_CONTENT_TYPES: dict[str, str] = {
    ".gif": "image/gif",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".mp4": "audio/mp4",
    ".wav": "audio/wave",
    ".caf": "audio/x-caf",
}

# POS transaction type allowlist (posTransactionRequest.type enum). Ingestion is
# rejected locally for any other value rather than forwarding an invalid write.
_POS_TXN_TYPES = ("sale", "refund")

#: The console's own answer to every Integration arm-profile route in global mode.
GLOBAL_ALARM_MANAGER_REFUSAL = "not available when global alarm manager is enabled"

#: Appended (never substituted) to that upstream 400 so the caller knows what to do next.
GLOBAL_ALARM_MANAGER_HINT = (
    "this console runs the global Alarm Manager (get_protect_alarm_manager_mode reports "
    "mode 'global'), where the Protect Integration arm-profile API is unavailable. The global "
    "Alarm Manager's own API (/api/v2/alarms, at the console root) is not relayed by the "
    "Fabric connector, so alarm rules cannot be managed through this server on this console; "
    "use the UniFi Protect app for them. On Protect 7.4.96 or later its arm profiles and "
    "arm/disarm are served by list_external_arm_profiles and the other external arm-profile "
    "tools"
)

# ``nvrArmMode.status`` values (pinned spec protect-7.3.74.json ``nvrArmMode``): ``arming``,
# ``armed``, ``breach`` and ``disabled``. After an enable the alarm is in one of the three
# armed-side states (arming is the countdown, breach is an armed system that already
# tripped); after a disable only ``disabled`` confirms it.
_ARM_ENABLED_STATES = frozenset({"arming", "armed", "breach"})
_ARM_DISABLED_STATES = frozenset({"disabled"})

_EXTERNAL_ARM_PROFILES = "external/arm-profiles"

AnalyticsKind = Literal["detections", "heatmap"]
EdgeExportAction = Literal["prepare", "download"]

#: The analytics route of each kind (``/cameras/{id}/<suffix>``).
_ANALYTICS_SUFFIX: dict[str, str] = {
    "detections": "analytics-detections",
    "heatmap": "analytics-heatmap",
}

_TEXT_TYPES = ("json", "text/")

_QR_REMOVED_HINT = (
    "this console's Protect version serves no camera adoption QR route (Protect 7.3 removed "
    "it and reads cameras/qr as a camera id); add a WiFi camera with the UniFi Protect "
    "mobile app, then adopt it with adopt_protect_device."
)

#: Device types whose re-adopt action is sourced (``POST /{collection}/{id}/readopt``).
ReadoptDeviceType = Literal[
    "aiport",
    "aiprocessor",
    "camera",
    "chime",
    "doorlock",
    "light",
    "linkstation",
    "sensor",
    "speaker",
    "viewer",
]
#: Device types whose firmware-update action is sourced (``POST /{collection}/{id}/update``).
FirmwareDeviceType = Literal[
    "aiport",
    "aiprocessor",
    "camera",
    "chime",
    "light",
    "linkstation",
    "sensor",
    "speaker",
    "viewer",
]
#: Device types whose locate action is sourced (``POST /{collection}/{id}/locate``).
LocateDeviceType = Literal["aiport", "doorlock", "light", "linkstation", "sensor"]
#: Every device type with a settings PATCH (official or private), ``nvr`` included.
SettingsDeviceType = Literal[
    "aiport",
    "aiprocessor",
    "bridge",
    "camera",
    "chime",
    "doorlock",
    "light",
    "linkstation",
    "sensor",
    "speaker",
    "viewer",
    "nvr",
]
RetroactiveAction = Literal["start", "pause", "resume", "cancel"]
ChimeOutput = Literal["speaker", "buzzer"]

#: What the tool advertises and accepts: only the actions the console serves.
DoorLockRequest = Literal["unlock", "open"]

#: The Protect 7.3.74 route table caps the unlock-events page size at 100 (default 50).
UNLOCK_EVENTS_PAGE_SIZE = 100
#: The offset the console accepts is 0 to 10000.
UNLOCK_EVENTS_MAX_OFFSET = 10000
_LOCKS_HINT = (
    "Door lock reads use the Protect 7.x /locks routes; a console older than Protect 7.x "
    "does not serve them."
)

#: Event media kinds and the private route each one reads (``/events/{id}/<suffix>``).
MediaKind = Literal[
    "thumbnail", "animated_thumbnail", "heatmap", "smart_detect_track", "transcriptions"
]
_MEDIA_SUFFIX: dict[str, str] = {
    "thumbnail": "thumbnail",
    "animated_thumbnail": "animated-thumbnail",
    "heatmap": "heatmap",
    "smart_detect_track": "smartDetectTrack",
    "transcriptions": "transcriptions",
}
#: Kinds whose body is an image (returned base64 + content_type); the others are JSON.
_BINARY_MEDIA = frozenset({"thumbnail", "animated_thumbnail", "heatmap"})

#: Stream URL kinds and the private route each one reads.
StreamKind = Literal[
    "livestream",
    "playback",
    "timelapse",
    "heatmap",
    "live_detect_track",
    "live_alias",
    "video_prepare",
]
_STREAM_PATH: dict[str, str] = {
    "livestream": "/ws/livestream",
    "playback": "/ws/playback",
    "timelapse": "/ws/timelapse",
    "heatmap": "/ws/heatmap",
    "live_detect_track": "/ws/liveDetectTrack",
    "live_alias": "/video/live",
    "video_prepare": "/tcp/video/prepare",
}

ExportAction = Literal["prepare", "download"]


class FavoriteObject(TypedDict):
    """One per-object favorite mark for the batch route (``idsWithObject``)."""

    eventId: Annotated[str, Field(description="Id of the event to mark; one of event_ids.")]
    objectId: Annotated[
        str,
        Field(
            description="Detected object of that event (metadata.detectedThumbnails[].objectId)."
        ),
    ]


#: Secret-registry entries for this module. Successful fields are masked only
#: under ``UNIFI_REDACT_SECRETS``, like error text; logs always scrub them. The stream-URL tool
#: returns short-lived, tokenised stream addresses: ``url`` and ``directUrl`` carry a
#: per-request ``uniqid`` / path token and ``alias`` is the live-stream alias. Keys are
#: the response field names, matched only on the registered stream routes (a global ``url`` key
#: would mask every URL in the catalog). Route entries live in route_secrets.
SECRET_RESPONSE_FIELDS: dict[str, frozenset[str]] = {
    "get_protect_stream_url": frozenset({"url", "directUrl", "alias"}),
}


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

#: The UniFi OS global Alarm Manager routes (rules under ``protect``, profiles and their
#: arm/disarm actions). They are served at the console root, not under ``/proxy/protect``.
GLOBAL_ALARM_MANAGER_ROUTES = (
    "GET /api/v2/alarms/protect",
    "POST /api/v2/alarms/protect",
    "PATCH /api/v2/alarms/protect/{id}",
    "DELETE /api/v2/alarms/protect/{id}",
    "GET /api/v2/alarms/profiles",
    "POST /api/v2/alarms/profiles/{id}/actions/arm",
    "POST /api/v2/alarms/profiles/{id}/actions/disarm",
)

#: Why the global Alarm Manager API is unsupported through this server, in every mode.
GLOBAL_ALARM_MANAGER_UNSUPPORTED = (
    "The global Alarm Manager API (/api/v2/alarms) is served at the console root, outside the "
    "/proxy/<application>/ paths the Fabric connector relays. The connector answers it with "
    "HTTP 403 forbidden ('insufficient permissions for this endpoint'), the same answer it "
    "gives any unknown console-root path, so this server cannot list, create, update or "
    "delete global alarm rules. Manage the rules in the UniFi Protect app. The arm profiles "
    "of the external Alarm Manager are a separate, relayed API: on Protect 7.4.96 or later "
    "list_external_arm_profiles, get_external_arm_profile, create_external_arm_profile, "
    "update_external_arm_profile, delete_external_arm_profile, arm_external_arm_profile and "
    "disarm_external_arm_profile manage them."
)

#: The Protect Integration external arm-profile tools (Protect 7.4.96): the alarm surface of
#: a global-mode console (``nvr.featureFlags.useExternalAlarmManager`` true).
EXTERNAL_ARM_PROFILE_TOOLS = (
    "list_external_arm_profiles",
    "get_external_arm_profile",
    "create_external_arm_profile",
    "update_external_arm_profile",
    "delete_external_arm_profile",
    "arm_external_arm_profile",
    "disarm_external_arm_profile",
)

#: The Protect Integration arm-profile tools: the alarm surface of a local-mode console.
INTEGRATION_ARM_PROFILE_TOOLS = (
    "list_arm_profiles",
    "get_arm_profile",
    "create_arm_profile",
    "update_arm_profile",
    "delete_arm_profile",
    "update_arm_profile_settings",
    "enable_arm",
    "disable_arm",
)

_MODE_FLAG = "useExternalAlarmManager"
_NOT_DETERMINED = "the Alarm Manager mode was not determined"

#: The PTZ home position is preset slot -1 on the official goto route (Protect 7.3.74
#: ``POST /v1/cameras/{id}/ptz/goto/{slot}``; ``ptz_goto_preset`` documents -1 as home).
PTZ_HOME_SLOT = -1

CredentialType = Literal["nfc", "fingerprint"]
EnrollStep = Literal["enroll", "assign", "cancel"]

#: The three GET routes under ``detection-search`` (Protect 5.3.18 inventory), by section.
METADATA_ROUTES: dict[str, str] = {
    "search": "/detection-search",
    "labels": "/detection-search/labels",
    "progress": "/detection-search/progress",
}

#: The multipart field name the published Protect upload uses (protect-7.4.96
#: ``POST /v1/files/{fileType}``); the private routes' field name is not in the inventory.
DEFAULT_FORM_FIELD = "file"

#: Spec of the read-after comparison (no published schema: the private Protect API).
_SPEC = "protect-private-5.3.18"

RECOGNITION_PRIVATE_BASE = "/v1/connector/consoles/{host_id}/proxy/protect/api"
