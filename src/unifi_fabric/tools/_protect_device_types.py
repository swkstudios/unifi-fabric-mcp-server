"""Protect private-API device types and their route mapper (shared by per-type tools).

The Protect application's private API (``/proxy/protect/api/...``, the routes the Protect
web UI calls; not the published ``/proxy/protect/integration/v1`` surface) keeps one
collection per device type: ``aiports``, ``aiprocessors``, ``bridges``, ``cameras``,
``chimes``, ``doorlocks``, ``lights``, ``linkstations``, ``sensors``, ``speakers``,
``viewers``, plus the console-level ``nvr`` singleton. Per-type tools (readopt, locate,
reboot, unadopt, update, rename) differ only in the collection and the action, so the
mapping lives here once:

* :class:`ProtectDeviceType` - the enum; :func:`parse_device_type` turns a caller value
  into one or fails fast listing the valid types.
* :data:`DEVICE_ROUTES` - per type: the collection segment and the item actions sourced
  for it, each with its HTTP method.
* :func:`device_path` / :func:`protect_private_path` - build the route, validating the id
  (one encoded segment) and the action BEFORE any request.

Action sources: Protect 5.3.18 swai.js (2045150..2082431), inventoried 2026-10-11,
and the existing Protect
tools. The action lists are the sourced set, not proof that an unlisted action is absent:
a tool that needs a newly sourced action adds it here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from ..client import path_segment, validate_host_id


class ProtectDeviceType(StrEnum):
    """A Protect device type with a private-API collection (or the ``nvr`` singleton)."""

    AIPORT = "aiport"
    AIPROCESSOR = "aiprocessor"
    BRIDGE = "bridge"
    CAMERA = "camera"
    CHIME = "chime"
    DOORLOCK = "doorlock"
    LIGHT = "light"
    LINKSTATION = "linkstation"
    SENSOR = "sensor"
    SPEAKER = "speaker"
    VIEWER = "viewer"
    NVR = "nvr"


#: Every device type, in declaration order (for error messages and schema enums).
DEVICE_TYPES: tuple[str, ...] = tuple(t.value for t in ProtectDeviceType)


@dataclass(frozen=True)
class DeviceRoutes:
    """The private-API routes of one device type.

    Attributes:
        collection: The collection segment under ``protect/api`` (``nvr`` for the singleton).
        singleton: True for ``nvr``: the route takes no device id.
        actions: Item action segment -> HTTP method (``"locate": "POST"``), sourced.
        item_methods: Methods sourced on the item itself (``GET``/``PATCH``/``DELETE``).
    """

    collection: str
    singleton: bool = False
    actions: Mapping[str, str] = field(default_factory=dict)
    item_methods: frozenset[str] = frozenset()


def _routes(
    collection: str, actions: dict[str, str], item_methods: set[str], singleton: bool = False
) -> DeviceRoutes:
    return DeviceRoutes(
        collection=collection,
        singleton=singleton,
        actions=MappingProxyType(dict(actions)),
        item_methods=frozenset(item_methods),
    )


_LIFECYCLE = {"readopt": "POST", "reboot": "POST", "update": "POST"}

#: Device type -> its private-API routes.
DEVICE_ROUTES: Mapping[ProtectDeviceType, DeviceRoutes] = MappingProxyType(
    {
        ProtectDeviceType.AIPORT: _routes(
            "aiports",
            {**_LIFECYCLE, "locate": "POST", "pair": "POST", "unpair": "POST"},
            {"PATCH", "DELETE"},
        ),
        ProtectDeviceType.AIPROCESSOR: _routes(
            "aiprocessors", {**_LIFECYCLE, "unadopt": "POST"}, {"PATCH", "DELETE"}
        ),
        ProtectDeviceType.BRIDGE: _routes("bridges", {"unadopt": "POST"}, {"GET", "DELETE"}),
        ProtectDeviceType.CAMERA: _routes(
            "cameras",
            {**_LIFECYCLE, "unadopt": "POST", "calibrate": "POST"},
            {"GET", "PATCH", "DELETE"},
        ),
        ProtectDeviceType.CHIME: _routes(
            "chimes",
            {**_LIFECYCLE, "unadopt": "POST", "play-buzzer": "POST", "play-speaker": "POST"},
            {"PATCH", "DELETE"},
        ),
        ProtectDeviceType.DOORLOCK: _routes(
            "doorlocks",
            {
                "readopt": "POST",
                "reboot": "POST",
                "unadopt": "POST",
                "locate": "POST",
                "calibrate": "POST",
                "autoClose": "POST",
                "open": "POST",
                "close": "POST",
            },
            {"GET", "PATCH", "DELETE"},
        ),
        ProtectDeviceType.LIGHT: _routes(
            "lights",
            {**_LIFECYCLE, "unadopt": "POST", "locate": "POST"},
            {"GET", "PATCH", "DELETE"},
        ),
        ProtectDeviceType.LINKSTATION: _routes(
            "linkstations", {**_LIFECYCLE, "locate": "POST"}, {"PATCH", "DELETE"}
        ),
        ProtectDeviceType.SENSOR: _routes(
            "sensors",
            {
                **_LIFECYCLE,
                "unadopt": "POST",
                "locate": "POST",
                "assign-bridge": "POST",
                "lock-bridge": "POST",
                "clear-tamper-flag": "POST",
                "readings": "GET",
            },
            {"GET", "PATCH", "DELETE"},
        ),
        ProtectDeviceType.SPEAKER: _routes(
            "speakers",
            {**_LIFECYCLE, "unadopt": "POST", "stop-stream": "POST", "test-sound": "POST"},
            {"PATCH", "DELETE"},
        ),
        ProtectDeviceType.VIEWER: _routes(
            "viewers", {**_LIFECYCLE, "unadopt": "POST"}, {"GET", "PATCH", "DELETE"}
        ),
        ProtectDeviceType.NVR: _routes(
            "nvr", {"device-password": "GET"}, {"PATCH"}, singleton=True
        ),
    }
)

#: The console path prefix of the Protect private API.
PROTECT_PRIVATE_PREFIX = "/v1/connector/consoles/{host_id}/proxy/protect/api"


def parse_device_type(value: Any, /, name: str = "device_type") -> ProtectDeviceType:
    """``value`` as a :class:`ProtectDeviceType`; fails fast listing the valid types.

    Surrounding whitespace and case are ignored (``" Camera "`` is ``camera``). No request.
    """
    if isinstance(value, ProtectDeviceType):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in DEVICE_TYPES:
            return ProtectDeviceType(text)
    raise ValueError(f"Invalid {name} {value!r}: expected one of {', '.join(DEVICE_TYPES)}")


def require_camera_ids(camera_ids: Any, /, name: str = "camera_ids") -> None:
    """Refuse an empty camera list before any request (it names no camera to pair)."""
    if isinstance(camera_ids, list) and not camera_ids:
        raise ValueError(
            f"{name} must be a non-empty list of camera ids (from list_cameras): an empty "
            "list names no camera; nothing was sent."
        )


def device_types_with_action(action: str, /) -> tuple[ProtectDeviceType, ...]:
    """The device types whose sourced actions include ``action``, in enum order."""
    return tuple(t for t in ProtectDeviceType if action in DEVICE_ROUTES[t].actions)


def action_method(device_type: Any, action: str, /) -> str:
    """The HTTP method of ``action`` on ``device_type``; fails listing the sourced actions."""
    routes = DEVICE_ROUTES[parse_device_type(device_type)]
    method = routes.actions.get(action) if isinstance(action, str) else None
    if method is None:
        raise ValueError(
            f"Invalid action {action!r} for Protect {routes.collection}: sourced actions are "
            f"{', '.join(sorted(routes.actions)) or 'none'}"
        )
    return method


def device_path(device_type: Any, device_id: Any = None, action: str | None = None, /) -> str:
    """The route under ``protect/api`` for a device type, item and optional action.

    ``/cameras/<id>``, ``/chimes/<id>/play-buzzer``, ``/nvr``, ``/nvr/device-password``.
    ``device_id`` is required for every type but ``nvr`` (which refuses one) and travels as
    one encoded path segment. ``action`` must be a sourced action of the type. All checks
    happen before any request; each failure raises ``ValueError`` naming the argument.
    """
    routes = DEVICE_ROUTES[parse_device_type(device_type)]
    parts = ["", routes.collection]
    if routes.singleton:
        if device_id is not None:
            raise ValueError(f"Protect {routes.collection} is a singleton and takes no device id")
    else:
        if device_id is None:
            raise ValueError(f"A device id is required for Protect {routes.collection}")
        parts.append(path_segment(device_id, "device_id"))
    if action is not None:
        action_method(device_type, action)
        parts.append(action)
    return "/".join(parts)


def protect_private_path(
    host_id: str, device_type: Any, device_id: Any = None, action: str | None = None, /
) -> str:
    """The full connector path of :func:`device_path` on one console (validated)."""
    validate_host_id(host_id, "host_id")
    return PROTECT_PRIVATE_PREFIX.format(host_id=host_id) + device_path(
        device_type, device_id, action
    )
