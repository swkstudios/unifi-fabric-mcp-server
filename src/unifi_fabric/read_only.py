"""Global opt-in read-only mode for the UniFi Fabric MCP server.

``UNIFI_READ_ONLY`` is an **opt-in** switch, default **OFF**. When it is unset
(or set to a falsey value) the server behaves byte-for-byte as it does today:
every write and action tool works. When it is set to a truthy value, every
write/action across all product areas is refused *before any upstream write
call* with an actionable error, while read tools are unaffected.

Enforcement is centralized at the single HTTP chokepoint
(:meth:`unifi_fabric.client.UniFiClient.request`): every mutating upstream call
— ``POST``/``PUT``/``PATCH``/``DELETE`` — routes through it, so the guard covers
every current *and future* write tool automatically, with no per-tool allowlist
to maintain. The handful of ``POST`` calls that are semantically *reads* (the read-POST
allowlist, :mod:`unifi_fabric.read_post_routes`: the exact routes of the Classic
``stat/session`` and ``stat/report/{interval}.{scope}`` queries and the Site Manager
``/isp-metrics/{interval}/query`` endpoint, and the exact (route, command) pairs of the
Classic read commands ``cmd/firmware`` ``list-available`` / ``list-cached``,
``cmd/backup`` ``list-backups`` and ``cmd/devmgr`` ``speedtest-status``) are classified as
reads by
:func:`is_write_request`, the server's single write classifier (the client's dry-run,
audit and additive-key stripping use the same function). The generic
connector write relay additionally refuses up-front (before its read-before
GET) so a relayed mutation never touches the console under read-only mode, and
:class:`unifi_fabric.read_only_tools.ReadOnlyToolMiddleware` refuses every tool not
annotated ``readOnlyHint: true`` before its body runs, so a write tool that reads
before it writes makes no upstream call at all.

This module is deliberately dependency-free (reads the environment at call time,
like the per-area write flags ``UNIFI_ENABLE_CONNECTOR_WRITE`` /
``UNIFI_ENABLE_NETWORK_WRITE`` / ``UNIFI_PROTECT_MUTATIONS_ENABLED`` /
``UNIFI_ENABLE_CARRIER_FABRIC_WRITE`` / ``UNIFI_ENABLE_MOBILITY_WRITE`` /
``UNIFI_ENABLE_INNERSPACE_WRITE``; the area flags
are enforced at the same chokepoint by :func:`guard_area_write`) so the
low-level client can import it without a settings cycle, and so a deployment can
toggle it without reconstructing the client.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import unquote

from . import switches
from .read_post_routes import is_read_post

#: The single opt-in environment switch that enables global read-only mode.
ENV_VAR = switches.READ_ONLY_ENV

#: Upstream HTTP methods that mutate state.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: GET routes the upstream ACTS on: a GET that changes state is a write by behaviour, so the
#: write classifier (:func:`is_write_request`) treats it as one (read-only mode refuses it,
#: dry-run previews it, the audit log records it and it is never auto-retried). Matched on
#: the application route (the part after ``/proxy/``) of the fully percent-decoded path, so
#: no spelling of the route reads as a GET. Source: Protect web UI 5.3.18 (swai.js 2053254 /
#: 2053348, ``tests/fixtures/private_api/inventory_protect_5.3.18.json``): the camera
#: ``enable-control`` / ``disable-control`` routes.
STATE_CHANGING_GET_ROUTES: tuple[re.Pattern[str], ...] = (
    re.compile(r"protect/api/cameras/[^/]+/(?:enable|disable)-control", re.IGNORECASE),
)

#: The read-POST allowlist is :data:`unifi_fabric.read_post_routes.READ_POST_ROUTES` (the
#: one route-exact list: method + full path template, no prefixes) plus
#: :data:`unifi_fabric.read_post_routes.READ_COMMANDS` (the one list of Classic read
#: commands: exact route + exact ``{"cmd": ...}`` body). Every other POST, and every
#: PUT/PATCH/DELETE, is a write. The Classic command ``POST .../cmd/stat``
#: (``{"cmd": "reset-dpi"}``) resets counters and stays a write; a bare ``.../stat`` or an
#: unlisted ``.../stat/<x>`` POST is a write too, as is any other command on a read
#: command's route (``cmd/backup`` ``backup``, ``cmd/devmgr`` ``speedtest``).


#: How many rounds of percent-decoding :func:`decoded_path` applies at most. A path the
#: server builds is encoded once; each extra round undoes one more layer of encoding a
#: caller (or a proxy hop) could add.
_MAX_DECODE_ROUNDS = 8


def decoded_path(path: str) -> str:
    """``path`` (query string dropped) with percent-encoding undone until it is stable.

    The request guard reads this form, so ``%2e%2e``, a double-encoded
    ``%252e%252e`` or an encoded control character is judged by what an upstream that
    decodes the path would see, never by its spelling. The write classifier does NOT use
    it: a read-POST is judged on the raw path (:func:`is_write_request`).
    """
    bare = path.split("?", 1)[0]
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(bare)
        if decoded == bare:
            break
        bare = decoded
    return bare


class ReadOnlyModeError(RuntimeError):
    """Raised when a write/action is attempted while ``UNIFI_READ_ONLY`` is on."""


class AreaOptOutError(RuntimeError):
    """Raised when a write request targets an area whose write opt-out is set.

    ``env`` is the opt-out variable (``UNIFI_ENABLE_NETWORK_WRITE`` and the rest of
    ``switches.AREA_WRITE_SWITCHES``); the message is the area's actionable refusal.
    """

    def __init__(self, env: str, message: str) -> None:
        super().__init__(message)
        self.env = env


def is_read_only() -> bool:
    """Return True only when ``UNIFI_READ_ONLY`` is set to a true spelling.

    Default **OFF**: unset, empty, or a false spelling → read+write on. Parsed by the
    server's single boolean parser (``switches.env_flag``), exactly as ``Settings``
    parses it, and read at call time so tests and deploys can toggle it without
    reconstructing the client. A malformed value raises naming the variable.
    """
    return switches.is_read_only()


def state_changing_get_route(path: str) -> bool:
    """True when a GET of ``path`` changes upstream state (:data:`STATE_CHANGING_GET_ROUTES`)."""
    route = decoded_path(path)
    if "/proxy/" in route:
        route = route.split("/proxy/", 1)[1]
    route = route.strip("/")
    return any(pattern.fullmatch(route) for pattern in STATE_CHANGING_GET_ROUTES)


def is_write_request(method: str, path: str, body: Any = None) -> bool:
    """Classify an upstream method, raw path and JSON body as a write.

    The server's single write classifier: read-only mode, dry-run, the audit log and
    additive-key stripping all decide with it. ``PUT``/``PATCH``/``DELETE`` are always
    writes. ``POST`` is a write unless its RAW path, with the query split off once, is
    verbatim an allowlisted read-POST route, or is verbatim a Classic read command's route
    with exactly that command's body ``{"cmd": ...}``
    (:func:`unifi_fabric.read_post_routes.is_read_post`, the same check ``post_read``
    makes on the same path and body). Only the raw, exact route is a read: a case variant,
    a percent-encoded literal, a doubled or trailing slash, or a placeholder holding an
    encoded separator, ``?`` or ``#`` (or a dot segment) is a write; so is a command route
    with any other body.
    A ``GET`` is a write only on a route the upstream acts on
    (:data:`STATE_CHANGING_GET_ROUTES`); ``HEAD``/``OPTIONS`` are never writes.
    """
    m = method.strip().upper()
    if m == "GET":
        return state_changing_get_route(path)
    if m not in WRITE_METHODS:
        return False
    if m == "POST":
        return not is_read_post("POST", path, body)
    return True


def read_only_message(method: str, *, tool: bool = False) -> str:
    """Build the actionable refusal naming the var, its value, and how to disable.

    ``method`` is the HTTP method refused, or with ``tool=True`` the name of the write
    tool refused before it ran.
    """
    value = os.environ.get(ENV_VAR)
    what = method.strip() if tool else method.strip().upper()
    return (
        f"{what} refused: the server is in read-only mode because "
        f"{ENV_VAR}={value!r} is set to a true value ({switches.TRUE_HINT}). Every write and "
        "action tool across all areas (Network create/update/delete, device/client "
        "actions, Protect, the connector relay, Carrier Fabric, Mobility, port-profiles, "
        "vouchers, etc.) is disabled; read tools are unaffected. To re-enable writes, "
        f"unset {ENV_VAR} (or set it to a false value: {switches.FALSE_HINT}) where you set "
        "it: the server's `env` block in your MCP client's configuration (or turn off the "
        "Claude Code plugin's Read-only mode option), or the service's `environment:` block "
        "of the docker-compose file that deploys this server. Then restart the server "
        '(recreate the container for Docker). See the README "Read-only mode" section.'
    )


def guard_request(method: str, path: str, *, always_write: bool = False, body: Any = None) -> None:
    """Raise :class:`ReadOnlyModeError` if read-only mode would block this call.

    No-op when ``UNIFI_READ_ONLY`` is off (default) or the call is a read, so the
    default write-dispatch path stays byte-identical to the pre-read-only build.
    ``always_write`` marks a call the caller already classified as a write (the
    connector relay's non-GET, whatever its path). ``body`` is the JSON body the request
    carries (a Classic read command is a read only with its exact body).
    """
    if is_read_only() and (always_write or is_write_request(method, path, body)):
        raise ReadOnlyModeError(read_only_message(method))


def guard_area_write(
    method: str, path: str, *, always_write: bool = False, body: Any = None
) -> None:
    """Raise :class:`AreaOptOutError` if a per-area write opt-out refuses this call.

    The per-area opt-outs (``switches.AREA_WRITE_SWITCHES``: Network, Protect, Mobility,
    Carrier Fabric, InnerSpace; all default on) bind every write request to one of the area's routes
    (:attr:`switches.AreaWriteSwitch.routes`, matched on the fully decoded path), so a
    typed tool, a helper shared between tools and the connector relay are refused alike.
    No-op for a read (judged with the request's JSON ``body``, as in
    :func:`is_write_request`), and while every area is on (the default).
    """
    if not (always_write or is_write_request(method, path, body)):
        return
    switch = switches.opted_out_area_for_route(decoded_path(path))
    if switch is None:
        return
    from .tools.connector import area_write_refusal  # the area's own refusal text

    raise AreaOptOutError(switch.env, area_write_refusal(switch.family) or switch.env)


def guard_action(method: str = "POST") -> None:
    """Refuse an action/relay before any upstream call when read-only mode is on.

    Used by the generic connector write relay (and any action tool that performs a
    read-before step) so the mutation is refused *before* it touches the console at
    all — not merely when the write itself reaches the HTTP client.
    """
    if is_read_only():
        raise ReadOnlyModeError(read_only_message(method))
