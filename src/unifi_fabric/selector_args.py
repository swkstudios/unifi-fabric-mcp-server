"""One pre-resolution check of the console / site / key selectors every tool shares.

``host``, ``site`` and ``key_label`` are resolved against upstream data (the console
list, the site list, the configured keys). A value that cannot name anything — empty,
whitespace only, padded with surrounding whitespace, or carrying a control character such
as a trailing newline — used to be noticed only during that resolution, after the console
list had been fetched. :class:`SelectorArgumentMiddleware` rejects it before the tool body
runs, so the error names the argument and no upstream request is made. A selector embedded in a
list or dict argument (``compare_site_performance(sites=[...])``, ``query_isp_metrics``
``sites[].hostId`` / ``siteId``, ``host_ids[]``, ``client_ids[]``, ``cameras[]``, a
``mac`` list) gets the same check, named by its path (``sites[1].hostId``), and so does
the single-string form of such an argument (``cameras="Garage"``, ``mac="aa:bb:..."``).
A NAME selector matched against upstream object names (``cameras``) refuses only an
empty string or a control character: a camera may be literally named ``"Garage "``.
An explicit empty string is never read as "omitted" (``list_devices(host="")`` is an
error, not the fleet-wide list); an omitted or ``null`` optional selector is simply
absent. A
well-formed name that does not exist is still the resolver's error, which lists the
valid choices. The registry resolvers apply the same rule (:func:`check_selector`) for
callers inside the server.

Area write opt-outs and the empty-update guard are registered before this middleware,
so their refusals keep coming first.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .argument_errors import echoed_input
from .selector_syntax import name_reason, selector_reason

#: The selector arguments resolved against upstream data. ``device_id`` / ``client_id``
#: take an id or a MAC: a padded MAC is refused here for every tool, never stripped by
#: one and refused by another (one MAC rule).
SELECTOR_ARGUMENTS = (
    "host",
    "site",
    "key_label",
    "device_id",
    "client_id",
    "camera_id",
    "backup_id",
    "bridge_id",
    "calculation_id",
    "radio_activity_ap_mac",
    "test_config_id",
    "event_id",
)

_WHERE = {
    "host": "a console name, MAC address, or id from list_hosts",
    "site": "a site name or id (list_local_sites / list_sites)",
    "key_label": "a configured key label from list_configured_api_keys",
    "client": "a client MAC or id",
    "client_id": "a client id or MAC (no surrounding whitespace)",
    "device_id": "a device id or MAC (no surrounding whitespace)",
    "camera": "a camera name or id from list_cameras",
    "mac": "a device MAC address",
    "shortcut": "a shortcut id from the camera's shortcuts[].id",
    "id": "an object id from the corresponding list tool",
    "camera_id": "a camera id from list_cameras",
    "backup_id": "a backup id from the corresponding list tool",
    "bridge_id": "a bridge id from the corresponding list tool",
    "calculation_id": "a calculation id from the corresponding preview",
    "radio_activity_ap_mac": "an AP MAC address",
    "test_config_id": "a load-balancing test configuration id",
    "event_id": "an event id from list_protect_events",
}

#: Selectors embedded in a list (or in the objects of a list) argument, checked with the
#: SAME rule as a top-level selector before any request: argument -> the selector kind of
#: each string element; for an object element, field -> kind (only the fields present;
#: a missing field is the tool's own error).
NESTED_SELECTOR_ARGUMENTS: dict[str, str] = {
    "sites": "site",  # compare_site_performance (site names / ids)
    "host_ids": "host",  # list_all_devices
    "client_ids": "client",  # get_client_link_diagnostics
    "cameras": "camera",  # list_protect_events / collect_protect_events
    "mac": "mac",  # forget_device (one MAC or a list)
    "battery_ids": "id",  # battery action targets
    "camera_ids": "id",  # AI-port pairing targets
    "event_ids": "id",  # Protect event targets
    "object_ids": "id",  # Protect recognized-object targets
    "macs": "mac",  # LTE subscription targets
    "ids": "id",  # Protect event ids
    "shortcut_ids": "shortcut",  # delete_camera_shortcut (camera shortcuts[].id)
    "detection_ids": "id",  # assign_detections_to_recognition_group (objectIds)
    "from_group_ids": "id",  # merge_recognition_groups (fromGroupIds)
}
#: Selector kinds that match an upstream object NAME (a camera literally named
#: "Garage "): only empty and control characters are refused (:func:`name_reason`).
#: Every other kind (console, site, key label, id / MAC) also refuses surrounding
#: whitespace (:func:`selector_reason`).
NAME_SELECTOR_KINDS = frozenset({"camera"})
NESTED_SELECTOR_FIELDS: dict[str, dict[str, str]] = {
    "sites": {"hostId": "host", "siteId": "site"},  # query_isp_metrics sites[]
}


def selector_problem(name: str, value: Any) -> str | None:
    """Why ``value`` cannot be the ``name`` selector, or None when it is well formed."""
    if not isinstance(value, str):
        return None  # None (omitted) or a mistyped value: the framework reports types
    reason = selector_reason(value)
    if reason is None:
        return None
    return f"'{name}' {reason}; pass {_WHERE.get(name, 'a valid value')}."


def unknown_key_label_problem(label: str, labels: list[str]) -> str | None:
    """Why ``label`` names no configured API key (listing the valid labels), or None.

    The one message for an unknown ``key_label``, used by the client's key lookup and by
    the middleware that checks every tool's ``key_label`` before its body runs -- for any
    number of configured keys (a single-key server with a ``host`` used to skip
    the lookup and silently ignore an unknown label)."""
    if label in labels:
        return None
    return (
        f"No API key with label {echoed_input(label)}; "
        f"valid labels: {', '.join(labels) or '(none)'}"
    )


def check_selector(name: str, value: Any) -> None:
    """Raise ``ValueError`` when ``value`` is not a well-formed ``name`` selector.

    A non-string (``None`` included) is refused too: inside the server a resolver is only
    called with a selector to resolve.
    """
    if not isinstance(value, str):
        raise ValueError(f"'{name}' must be a string; pass {_WHERE.get(name, 'a valid value')}.")
    problem = selector_problem(name, value)
    if problem is not None:
        raise ValueError(problem)


def nested_selector_problem(where: str, kind: str, value: Any) -> str | None:
    """Why ``value`` (at ``where``, e.g. ``sites[1].hostId``) cannot be a ``kind``
    selector: not a string, or failing the selector rule. None when well formed."""
    hint = _WHERE.get(kind, "a valid value")
    if not isinstance(value, str):
        return f"'{where}' must be a string ({hint}); got {type(value).__name__}."
    reason = name_reason(value) if kind in NAME_SELECTOR_KINDS else selector_reason(value)
    return None if reason is None else f"'{where}' {reason}; pass {hint}."


def nested_selector_problems(name: str, value: Any) -> str | None:
    """The first malformed selector in the argument ``name`` (string or list form), or
    None.

    A selector-ish argument that also takes ONE value as a plain string (``cameras``,
    ``mac``) gets the same check in that form (a top-level string used to skip
    it). List elements are strings (``NESTED_SELECTOR_ARGUMENTS``) or objects whose
    selector fields are named in ``NESTED_SELECTOR_FIELDS``.
    """
    kind = NESTED_SELECTOR_ARGUMENTS.get(name)
    if isinstance(value, str):
        return None if kind is None else nested_selector_problem(name, kind, value)
    if not isinstance(value, list):
        return None
    fields = NESTED_SELECTOR_FIELDS.get(name, {})
    for index, item in enumerate(value):
        if isinstance(item, dict):
            for field, field_kind in fields.items():
                if field in item:
                    problem = nested_selector_problem(
                        f"{name}[{index}].{field}", field_kind, item[field]
                    )
                    if problem is not None:
                        return problem
        elif kind is not None and (isinstance(item, str) or not fields):
            problem = nested_selector_problem(f"{name}[{index}]", kind, item)
            if problem is not None:
                return problem
    return None


class SelectorArgumentMiddleware(Middleware):
    """Reject a malformed ``host`` / ``site`` / ``key_label`` -- or a malformed selector
    inside a list or dict argument (``sites[i]``, ``sites[i].hostId``, ``host_ids[i]``,
    ...) -- before the tool body runs. With ``key_labels`` (a callable returning the
    configured key labels, or ``None`` when they cannot be read), a well-formed
    ``key_label`` that names no configured key is refused too, listing the valid labels,
    for every tool and whatever the number of keys."""

    def __init__(self, key_labels: Callable[[], list[str] | None] | None = None) -> None:
        self._key_labels = key_labels

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        arguments = getattr(context.message, "arguments", None) or {}
        for name in SELECTOR_ARGUMENTS:
            if name in arguments:
                problem = selector_problem(name, arguments[name])
                if problem is not None:
                    raise ToolError(problem)
        label = arguments.get("key_label")
        if isinstance(label, str) and self._key_labels is not None:
            labels = self._key_labels()
            if labels is not None:
                problem = unknown_key_label_problem(label, labels)
                if problem is not None:
                    raise ToolError(problem)
        for name in sorted(set(NESTED_SELECTOR_ARGUMENTS) | set(NESTED_SELECTOR_FIELDS)):
            if name in arguments:
                problem = nested_selector_problems(name, arguments[name])
                if problem is not None:
                    raise ToolError(problem)
        return await call_next(context)
