"""Shared Classic command-manager helper (``POST api/s/{site}/cmd/<manager>``); not a tool module.

The Network controller's Classic surface runs actions through command managers: a POST to
``/proxy/network/api/s/<site>/cmd/<manager>`` with a body ``{"cmd": "<command>", ...}``
(``cmd/devmgr`` ``{"cmd": "set-locate", "mac": ...}``, ``cmd/stamgr``
``{"cmd": "authorize-guest", ...}``, ``cmd/backup`` ``{"cmd": "list-backups"}``). A few
managers carry a sub-path (``cmd/devmgr/port-locate``, ``cmd/devmgr/speedtest``,
``cmd/productinfo/refresh-sso``).

Two rules every typed tool built on this surface follows, so they live here once:

1. **Validate all local input before any request.** :func:`classic_command_body` checks the
   manager, command and parameters (names, JSON-serialisable values, no ``cmd``
   override) and raises ``ValueError`` without touching the network.
   :func:`classic_command_for_site` also checks both selectors BEFORE any resolution GETs.
2. **Success is affirmative.** A Classic route answers HTTP 200 with
   ``{"meta": {"rc": "error", "msg": "api.err.X"}, "data": []}`` when it rejects a
   command, so HTTP 2xx alone is not success. Success is HTTP 2xx AND ``meta.rc == "ok"``;
   anything else raises :class:`ClassicCommandError` carrying the full upstream body
   (``meta`` and ``data``, verbatim). A non-2xx status is raised by the client as usual.

The client chokepoint may carry the same rule (``client.classic_rc_error`` /
``client.ClassicApiError``). This module uses those when they exist (so there is one rule
and one error type) and always applies the stricter command-local affirmative-success rule.
The shared check may allow responses without a Classic envelope on other API routes.
``dry-run policy`` is respected: the client returns
its ``status: "dry_run"`` preview and this helper returns that preview unchanged (never a
success or a false error).
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

from .. import client as _client_module
from ..client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    path_segment,
    upstream_error_text,
    validate_host_id,
)
from ..config import APIKeyConfig
from ..registry import Registry
from ..selector_args import check_selector
from ._classic_objects import resolve_site_slug

#: The connector path of a Classic command manager for one site.
CLASSIC_CMD_PATH = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd/{manager}"

#: A manager name, optionally with one sub-path segment (``devmgr``, ``devmgr/port-locate``,
#: ``productinfo/refresh-sso``). Lower-case words joined by ``-`` or ``_``, as every manager
#: the controller UI calls is spelled.
MANAGER_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:/[a-z][a-z0-9_-]*)?\Z")

#: A command name (``set-locate``, ``test_mail``, ``get-turn-credentials``).
#: GAP-SWEEP-2 (101 distinct commands) and GAP-SWEEP-3 (62) source lower-case tokens;
#: camelCase UI function names are not command payload values. Keep the sourced spelling.
COMMAND_RE = re.compile(r"^[a-z][a-z0-9_-]*\Z")

# The client's shared Classic rc rule and error type, when present (one rule, one type).
_SHARED_RC_RULE = getattr(_client_module, "classic_rc_error", None)
_SHARED_ERROR = getattr(_client_module, "ClassicApiError", UniFiConnectionError)


class ClassicCommandError(_SHARED_ERROR):  # type: ignore[misc, valid-type]
    """A Classic command answered HTTP 2xx without ``meta.rc == "ok"``.

    The message carries the manager, the command, the reason (status, ``meta.rc``,
    ``meta.msg``) and the complete upstream body verbatim.
    """


def _json_problem(value: Any, where: str) -> str | None:
    """Why ``value`` cannot be sent as JSON (a non-finite float, a non-string key), else None."""
    if isinstance(value, float) and not math.isfinite(value):
        return f"{where} is {value!r}; JSON has no NaN or Infinity"
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                return f"{where} has a non-string key of type {type(key).__name__}"
            problem = _json_problem(item, f"{where}.{key}")
            if problem:
                return problem
        return None
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            problem = _json_problem(item, f"{where}[{index}]")
            if problem:
                return problem
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return None
    return f"{where} has a value of type {type(value).__name__}, which is not JSON"


def validate_manager(manager: Any, /) -> str:
    """Return ``manager`` if it is a command-manager name, else raise ``ValueError``."""
    if not isinstance(manager, str) or not MANAGER_RE.fullmatch(manager):
        raise ValueError(
            f"Invalid Classic command manager {manager!r}: expected a lower-case manager "
            "name such as 'devmgr', 'stamgr', 'backup' or 'devmgr/port-locate'"
        )
    return manager


def validate_command(cmd: Any, /) -> str:
    """Return ``cmd`` if it is a command name, else raise ``ValueError``."""
    if not isinstance(cmd, str) or not COMMAND_RE.fullmatch(cmd):
        raise ValueError(
            f"Invalid Classic command name {cmd!r}: expected a lower-case command name such as "
            "'set-locate', 'authorize-guest' or 'list-backups'"
        )
    return cmd


def classic_command_body(cmd: str, params: Mapping[str, Any] | None = None, /) -> dict[str, Any]:
    """The request body ``{"cmd": cmd, **params}``, validated locally (no request).

    Raises ``ValueError`` when ``cmd`` is not a command name, ``params`` is not an object,
    a parameter is named ``cmd`` (the command is the ``cmd`` argument), or a value is not
    JSON (NaN, Infinity, a non-string key, an object that is not a JSON type).
    """
    validate_command(cmd)
    if params is None:
        params = {}
    if not isinstance(params, Mapping):
        raise ValueError(
            f"Classic command parameters must be an object, got {describe_shape(params)}"
        )
    if "cmd" in params:
        raise ValueError(
            "Classic command parameters must not contain 'cmd': the command is given "
            "separately and is the only 'cmd' sent"
        )
    problem = _json_problem(dict(params), "parameters")
    if problem:
        raise ValueError(f"Classic command parameters are not JSON: {problem}")
    return {"cmd": cmd, **params}


def classic_cmd_path(host_id: str, site_slug: str, manager: str, /) -> str:
    """The connector path of ``manager`` on one site (inputs validated; no request)."""
    validate_host_id(host_id, "host_id")
    site_seg = path_segment(site_slug, "site")
    validate_manager(manager)
    return CLASSIC_CMD_PATH.format(host_id=host_id, site_slug=site_seg, manager=manager)


def classic_rc_failure(status: Any, body: Any, /) -> str | None:
    """Why a Classic response is not a success, or ``None`` when it is.

    The one rule: success is HTTP 2xx AND ``meta.rc == "ok"``. ``None`` for a non-2xx
    status (the client already raises those) and for ``rc == "ok"``. Checks the
    client's shared rule first, then requires affirmative success locally.
    """
    if _SHARED_RC_RULE is not None:
        probe = "/v1/connector/consoles/x/proxy/network/api/s/x/cmd/x"
        shared_reason = _SHARED_RC_RULE(probe, status, body)
        if shared_reason is not None:
            return shared_reason
    if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status < 300:
        return None
    meta = body.get("meta") if isinstance(body, dict) else None
    if not isinstance(meta, dict):
        return (
            f"HTTP {status} without the Classic meta envelope (expected an object with "
            f"meta.rc, got {describe_shape(body)}), so success is not confirmed"
        )
    rc = meta.get("rc")
    if rc == "ok":
        return None
    reason = (
        f"HTTP {status} with meta.rc {upstream_error_text(rc)!r}"
        if "rc" in meta
        else f"HTTP {status} without meta.rc"
    )
    if "msg" in meta:
        reason += f" (meta.msg {upstream_error_text(meta['msg'])!r})"
    return reason + ": the controller did not report success"


async def classic_command(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    manager: str,
    cmd: str,
    params: Mapping[str, Any] | None = None,
    /,
    *,
    key: APIKeyConfig | None = None,
    allow_empty_success: bool = False,
) -> Any:
    """POST ``{"cmd": cmd, **params}`` to ``cmd/<manager>`` and require ``meta.rc == "ok"``.

    Every input is validated before the request. Returns the controller's
    ``{meta, data}`` body verbatim on success, or the client's dry-run preview unchanged
    under ``dry-run policy``. Raises ``ValueError`` on invalid input (no request),
    :class:`ClassicCommandError` on HTTP 2xx without ``meta.rc == "ok"`` (full upstream
    body in the message), and the client's errors otherwise. ``allow_empty_success`` is
    reserved for Classic commands whose documented successful response has no body.
    """
    body = classic_command_body(cmd, params)
    url = classic_cmd_path(host_id, site_slug, manager)
    try:
        resp = await client.request("POST", url, key=key, json=body)
    except UniFiConnectionError as exc:
        raise type(exc)(
            f"Classic command {cmd!r}: {exc}", request_sent=exc.request_sent, status=exc.status
        ) from exc
    decoded = decode_body(resp)
    if is_dry_run_preview(decoded):
        return decoded
    if decoded is None and allow_empty_success and 200 <= resp.status_code < 300:
        return None
    reason = classic_rc_failure(resp.status_code, decoded)
    if reason is not None:
        text = upstream_error_text(resp.text, client)
        raise ClassicCommandError(
            f"Classic command error from POST {url} (cmd {cmd!r}): {reason}: {text}"
        )
    return decoded


async def classic_command_for_site(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    manager: str,
    cmd: str,
    params: Mapping[str, Any] | None = None,
    /,
) -> Any:
    """:func:`classic_command` for a console + site selector (names or ids).

    Both selectors, manager, command and parameters are validated BEFORE the resolution
    requests, so invalid input makes no request at all.
    """
    check_selector("host", host)
    check_selector("site", site)
    validate_manager(manager)
    classic_command_body(cmd, params)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await classic_command(client, host_id, site_slug, manager, cmd, params, key=key)


def command_data(response: Any, /) -> list[Any]:
    """The ``data`` array of a successful Classic command response (shape-checked)."""
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, list):
        raise UniFiConnectionError(
            "Unexpected Classic command response shape: expected an object with a 'data' "
            f"array, got {describe_shape(response)}: " + upstream_error_text(response)
        )
    return data
