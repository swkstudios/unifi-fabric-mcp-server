"""The one reading of a Site Manager ``/v1/devices`` console wrapper.

``/v1/devices`` returns one wrapper per console: ``{hostId, hostName, devices: [...],
updatedAt}``. A wrapper is recognised by its own keys -- a ``devices`` key, or a ``hostId``
on an object that carries no device identity (``id`` / ``mac``, the spec's device-record
keys) -- never by whether its device list is usable: a console that reports ``devices``
as ``null``, ``[]`` or omits the key (an offline console, for example) is still a wrapper. It
contributes ZERO devices and is never itself returned or counted as a device record. A
``devices`` that is present, non-null and not an array (an object, a string, a number) is
not an empty list: it raises naming the shape received, so no total is silently short.
``list_devices`` (``_count``) and ``list_all_devices`` (the flattened list) both read wrappers
through :func:`wrapper_devices`, so the two tools agree.
"""

from __future__ import annotations

from typing import Any

from ..client import UniFiConnectionError, describe_shape, upstream_error_value

#: Keys that identify a device record (the spec's device items); a wrapper has neither.
DEVICE_IDENTITY_KEYS = ("id", "mac")


def is_console_wrapper(item: Any) -> bool:
    """True for a ``/v1/devices`` console wrapper object."""
    if not isinstance(item, dict):
        return False
    if "devices" in item:
        return True
    return "hostId" in item and not any(k in item for k in DEVICE_IDENTITY_KEYS)


def wrapper_devices(item: Any) -> list[Any] | None:
    """The devices a wrapper holds (``[]`` for ``devices`` null / missing / empty), or
    ``None`` when ``item`` is not a console wrapper.

    Raises :class:`UniFiConnectionError` naming the shape when ``devices`` is present,
    non-null and not an array.
    """
    if not is_console_wrapper(item):
        return None
    inner = item.get("devices")
    if inner is None:  # documented empty case: an offline console reports null or omits it
        return []
    if not isinstance(inner, list):
        raise UniFiConnectionError(
            "Unexpected /v1/devices console wrapper: expected 'devices' to be an array or "
            f"null, got {describe_shape(inner)} "
            f"(hostId {upstream_error_value(item.get('hostId'))!r})"
        )
    return list(inner)
