"""UniFi Network device operations: SSH sessions, switch-port and counter commands, config
clone, PDU outlets, UPS self-test and batteries, building-bridge modes, priority uplink,
device replacement, rolling-upgrade planning, device-tag assignment and Classic bulk PUTs.

Route choice (the official published API when it can do the job or
reach the same outcome, else the newer private v2 API, else the older Classic API). The
pinned official Network Integration API (10.7.99 snapshot) offers only device RESTART and
port POWER_CYCLE actions (``execute_device_action`` / ``execute_port_action``), so none of
these operations has an official route. Each tool uses the route the Network web app
(11.0.81 front-end bundle) calls for the same operation; the choice and reason per tool are
in :data:`ROUTE_CHOICES`.

Rules every tool here follows:

* **Validate before any request.** Every argument is checked before the first upstream
  call, the console/site resolution and the device-list GET included.
* **Devices are resolved, never guessed.** A ``device`` argument (MAC, Classic ``_id`` or
  exact name) is looked up in the site's Classic ``stat/device`` list first; an unknown or
  ambiguous value fails listing every device, so no command is sent to a wrong target.
* **Affirmative Classic success.** A Classic command or bulk PUT succeeds only on HTTP 2xx
  with ``meta.rc == "ok"`` (``_classic_cmd``); the error carries the full upstream body.
* **Pass-through.** Upstream bodies are returned verbatim; request bodies the web app
  builds at run time (keys not recoverable from the bundle) are free-form arguments sent
  as given; no required key is invented.
* **Physical actions are sent once.** Writes are never auto-retried (the client's one
  retry rule retries only GETs).
* ``dry-run policy`` returns the client's preview ``{status: "dry_run", dryRun, sent: false,
message,
  preview: {method, path, params, body}}`` and sends nothing; resolution GETs still run.

``get_rolling_upgrade_plan`` with ``time_estimate=True`` reads through a POST. A
read-type POST stays a write until it is on the read-POST allowlist, so the tool is
annotated and gated as a write.

The external-URL firmware upgrade (Classic ``cmd/devmgr`` ``upgrade-external``) is not
built here: ``upgrade_device`` sends it when ``firmware_url`` is given (device_mgmt).
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit

import httpx
from fastmcp import FastMCP

from .._read_only_audit import derive_write_tools
from ..client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    path_segment,
    upstream_error_text,
    upstream_error_value,
    validate_selector,
)
from ..config import APIKeyConfig
from ..macs import colon_mac, is_mac, normalize_mac, record_mac
from ..matching import name_matches, same_id
from ..read_only import guard_action
from ..registry import Registry
from ..tool_annotations import for_tool
from ..write_body import NO_FIELDS, require_unmasked_fields
from ._classic_cmd import (
    ClassicCommandError,
    classic_command,
    classic_command_body,
    classic_rc_failure,
)
from ._classic_objects import _object_rows, v2_site
from ._classic_objects import resolve_site_slug as _resolve_site_slug

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network"


#: SSH session actions and the Classic ``cmd/devmgr`` command each sends.
SSH_COMMANDS: dict[str, str] = {
    "build": "build-ssh-session",
    "sdp_answer": "ssh-sdp-answer",
    "close": "close-ssh-session",
}


_FE = "Network 11.0.81 front-end bundle"

#: Route choice per tool: (source, route, reason the official API is not used).
ROUTE_CHOICES: dict[str, tuple[str, str, str]] = {
    "manage_device_ssh_session": (
        "classic",
        "POST api/s/{site}/cmd/devmgr build-ssh-session | ssh-sdp-answer | close-ssh-session",
        f"no official or v2 route; {_FE} swai.js devmgr enum, body built at run time",
    ),
    "clear_switch_counters": (
        "classic",
        "POST api/s/{site}/cmd/devmgr clear-switch-counters | clear-switch-port-counters",
        "no official or v2 route",
    ),
    "clone_device_config": (
        "classic",
        "POST api/s/{site}/cmd/devmgr clone-config {mac, origin, dry_run}",
        "no official route; v2 has only GET device/{id}/clone-candidates",
    ),
    "set_outlet_power": (
        "classic",
        "POST api/s/{site}/cmd/devmgr outlet-ctl {mac, outlet_table, delay_time_to_off}",
        "official port actions cover PoE POWER_CYCLE only, not PDU outlets",
    ),
    "recover_switch_port": (
        "classic",
        "POST api/s/{site}/cmd/devmgr port-recovery | rps-port-recovery",
        "no official or v2 route",
    ),
    "run_device_self_test": (
        "classic",
        "POST api/s/{site}/cmd/devmgr self-test {mac}",
        "no official or v2 route",
    ),
    "set_device_alignment_mode": (
        "classic",
        "POST api/s/{site}/cmd/devmgr set-alignment | unset-alignment {mac}",
        f"no official or v2 route; {_FE} swai.js devmgr enum",
    ),
    "set_priority_uplink": (
        "classic",
        "POST api/s/{site}/cmd/devmgr set-priority-uplink | unset-priority-uplink",
        "no official or v2 route",
    ),
    "set_device_rearrange_mode": (
        "classic",
        "POST api/s/{site}/cmd/devmgr set-rearrange | unset-rearrange {mac}",
        f"no official route; {_FE} chunk 1027 calls it with base URL '/' (Classic)",
    ),
    "disconnect_remote_vpn_user": (
        "classic",
        "POST api/s/{site}/cmd/devmgr terminate-remote-user-vpn",
        "no official or v2 route; body built at run time",
    ),
    "locate_switch_port": (
        "classic",
        "POST api/s/{site}/cmd/devmgr/port-locate set-port-locate | unset-port-locate",
        "official port actions cover PoE POWER_CYCLE only",
    ),
    "unpair_building_bridge": (
        "classic",
        "POST api/s/{site}/cmd/devmgr/ubb-unpair {cmd: ubb-unpair, mac}",
        "no official or v2 route",
    ),
    "reset_switch_port": (
        "v2",
        "POST v2/api/site/{site}/ports/{mac}/reset [{port_idx, unit_id}]",
        "no official route; the web app's Clear last seen action",
    ),
    "get_device_adoption_info": (
        "v2",
        "GET v2/api/site/{site}/adopt-info/{id}",
        "official pending-devices list lacks the adoption info",
    ),
    "get_rolling_upgrade_plan": (
        "v2",
        "GET v2/api/site/{site}/device/upgrade/rollupgrade/eligible-devices; "
        "POST .../rollupgrade/time-estimate",
        "no official route",
    ),
    "get_device_replacement_options": (
        "v2",
        "GET v2/api/site/{site}/device/{id}/replacement-candidates",
        "no official route",
    ),
    "replace_device": (
        "v2",
        "POST v2/api/site/{site}/device/{id}/replace?replacementDeviceMac=; DELETE .../replace",
        "no official route",
    ),
    "control_device_battery": (
        "v2",
        "POST v2/api/site/{site}/device/{mac}/battery/action {macs, action}",
        f"no official route; {_FE} chunk 95069",
    ),
    "update_device_battery_settings": (
        "v2",
        'POST v2/api/site/{site}/device/{mac}/battery/update {macs, action: "upgrade", url}',
        f"no official route; {_FE} chunk 95069",
    ),
    "set_device_tag_assignments": (
        "v2",
        "POST v2/api/site/{site}/device-tags/device-tag-assignment/{id}",
        "official device-tags route is GET-only",
    ),
    "bulk_update_objects": (
        "classic",
        "PUT api/s/{site}/group/{device|user|networkconf|setting}",
        "no official or v2 bulk route",
    ),
}


# --------------------------------------------------------------------------- helpers


def _classic_path(host_id: str, site_slug: str, path: str) -> str:
    """Connector URL of a site-scoped Classic ``api/s/{site}`` path."""
    return _CONSOLE.format(host_id=host_id) + f"/api/s/{site_slug}{path}"


async def _site(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str, str]:
    """``(key, host_id, site_slug)``; both selectors validated before any lookup."""
    validate_selector(host, "host")
    validate_selector(site, "site")
    return await _resolve_site_slug(registry, host, site)


def _check_device_arg(device: Any, name: str = "device") -> str:
    """A device selector (MAC, Classic ``_id`` or exact name), validated locally."""
    validate_selector(device, name)
    return cast(str, device)


def _type_error(name: str, expected: str, value: Any) -> ValueError:
    """The one argument-type refusal of this module (registered in refusals.py)."""
    return ValueError(f"'{name}' must be {expected}, got {describe_shape(value)}: {value!r}")


def _check_int(value: Any, name: str) -> int | None:
    """An optional strict JSON integer (``True`` is not ``1``)."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise _type_error(name, "an integer", value)
    return value


def _check_bool(value: Any, name: str) -> bool:
    """A strict JSON boolean."""
    if not isinstance(value, bool):
        raise _type_error(name, "a boolean", value)
    return value


def _check_str(value: Any, name: str) -> str:
    """A JSON string (empty allowed; the upstream judges the value)."""
    if not isinstance(value, str):
        raise _type_error(name, "a string", value)
    return value


def _check_object(value: Any, name: str) -> dict[str, Any] | None:
    """An optional free-form JSON object body argument."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _type_error(name, "an object (mapping)", value)
    return value


def _require_object(value: Any, name: str) -> dict[str, Any]:
    """A required free-form JSON object body argument."""
    if not isinstance(value, dict):
        raise _type_error(name, "an object (mapping)", value)
    return value


def _check_list(value: Any, name: str) -> list[Any]:
    """A JSON array argument."""
    if not isinstance(value, list):
        raise _type_error(name, "an array", value)
    return value


def _grammar(message: str) -> NoReturn:
    """Refuse an argument combination of this module (registered in refusals.py)."""
    raise ValueError(f"Device operation arguments: {message}")


def _empty(message: str) -> NoReturn:
    """Refuse an empty body (registered as ``empty-update`` in refusals.py)."""
    raise ValueError(f"{NO_FIELDS}: {message} No request was sent.")


def _classic_ok(client: UniFiClient, resp: httpx.Response, method: str, path: str) -> Any:
    """The decoded Classic body when HTTP 2xx AND ``meta.rc == "ok"`` (or a dry-run
    preview); otherwise raise with the reason and the complete upstream body."""
    decoded = decode_body(resp)
    if is_dry_run_preview(decoded):
        return decoded
    reason = classic_rc_failure(resp.status_code, decoded)
    if reason is not None:
        text = upstream_error_text(resp.text, client)
        raise ClassicCommandError(f"Classic error from {method} {path}: {reason}: {text}")
    return decoded


def _device_label(record: dict[str, Any]) -> str:
    return (
        f"{upstream_error_value(record.get('name'))!r} "
        f"(mac={upstream_error_value(record.get('mac'))}, "
        f"_id={upstream_error_value(record.get('_id'))}, "
        f"model={upstream_error_value(record.get('model'))})"
    )


async def _site_devices(
    client: UniFiClient, key: APIKeyConfig | None, host_id: str, site_slug: str
) -> list[dict[str, Any]]:
    """The site's Classic device records (``GET stat/device``), affirmative rc."""
    path = _classic_path(host_id, site_slug, "/stat/device")
    body = _classic_ok(client, await client.request("GET", path, key=key), "GET", path)
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object with a 'data' "
            f"array, got {describe_shape(body)}"
        )
    return _object_rows(data, path)


async def _find_device(
    client: UniFiClient,
    key: APIKeyConfig | None,
    host_id: str,
    site_slug: str,
    device: str,
) -> dict[str, Any]:
    """The one site device whose MAC, ``_id`` or name is ``device`` (one list read)."""
    records = await _site_devices(client, key, host_id, site_slug)
    return _match_device(records, device)


def _match_device(
    records: list[dict[str, Any]], device: str, name: str = "device"
) -> dict[str, Any]:
    """The one record whose MAC, ``_id`` or name is ``device``; else fail listing all.

    A MAC matches in any accepted form; an ``_id`` case-insensitively; a name in the
    shared name tiers (exact, then normalized). Several devices sharing a name fail and
    ask for the MAC.
    """
    valid = "; ".join(_device_label(r) for r in records) or "(none)"
    if is_mac(device):
        wanted = normalize_mac(device)
        matches = [r for r in records if record_mac(r.get("mac")) == wanted]
    else:
        matches = [r for r in records if same_id(device, r.get("_id"))]
        if not matches:
            matches = name_matches(records, device, lambda r: r.get("name"))
    if len(matches) > 1:
        raise ValueError(
            f"{name} {device!r} is ambiguous: matches {len(matches)} devices; pass the MAC. "
            f"Devices: {valid}."
        )
    if not matches:
        raise ValueError(f"{name} {device!r} not found by MAC, _id or name; devices: {valid}.")
    record = matches[0]
    if record_mac(record.get("mac")) is None:
        raise UniFiConnectionError(
            f"Unexpected response shape from GET stat/device: device {_device_label(record)} "
            "has no valid 'mac'"
        )
    return record


def _mac_of(record: dict[str, Any]) -> str:
    return colon_mac(cast(str, record_mac(record.get("mac"))))


def _id_of(record: dict[str, Any]) -> str:
    value = record.get("_id")
    if not isinstance(value, str) or not value:
        raise UniFiConnectionError(
            f"Unexpected response shape from GET stat/device: device {_device_label(record)} "
            "has no '_id'"
        )
    return path_segment(value, "_id")


async def _devmgr(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    cmd: str,
    params: dict[str, Any] | None = None,
    *,
    manager: str = "devmgr",
) -> Any:
    """Resolve ``device`` and POST ``{cmd, mac, **params}`` to ``cmd/<manager>``.

    Every argument (selectors, command, parameters) is validated before the first request.
    """
    _check_device_arg(device)
    classic_command_body(cmd, {"mac": "00:00:00:00:00:00", **(params or {})})
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    record = await _find_device(client, key, host_id, slug, device)
    body = {"mac": _mac_of(record), **(params or {})}
    return await classic_command(client, host_id, slug, manager, cmd, body, key=key)


def _given(**params: Any) -> dict[str, Any]:
    """Only the parameters the caller actually gave."""
    return {k: v for k, v in params.items() if v is not None}


# ----------------------------------------------------------------- Classic commands


async def manage_device_ssh_session(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str = "build",
    params: dict[str, Any] | None = None,
) -> Any:
    """Classic ``cmd/devmgr`` SSH-session command with a free-form body."""
    validate_selector(action, "action")
    params = _check_object(params, "params")
    cmd = SSH_COMMANDS.get(action, action)
    classic_command_body(cmd, params)
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    return await classic_command(client, host_id, slug, "devmgr", cmd, params, key=key)


async def clear_switch_counters(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    port_idx: int | None = None,
    unit_id: int | None = None,
) -> Any:
    """Clear a switch's counters, or one port's (Classic ``cmd/devmgr``)."""
    _check_int(port_idx, "port_idx")
    _check_int(unit_id, "unit_id")
    if port_idx is None:
        if unit_id is not None:
            _grammar("unit_id selects a stack member's port and needs port_idx")
        return await _devmgr(client, registry, host, site, device, "clear-switch-counters")
    params = _given(port_idx=port_idx, unit_id=unit_id)
    return await _devmgr(client, registry, host, site, device, "clear-switch-port-counters", params)


async def clone_device_config(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    source_device: str,
    clone_dry_run: bool | None = None,
) -> Any:
    """Copy one device's configuration onto another (Classic ``clone-config``)."""
    _check_device_arg(device)
    _check_device_arg(source_device, "source_device")
    if clone_dry_run is not None:
        _check_bool(clone_dry_run, "clone_dry_run")
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    records = await _site_devices(client, key, host_id, slug)
    target = _match_device(records, device)
    source = _match_device(records, source_device, "source_device")
    body = {"mac": _mac_of(target), "origin": _mac_of(source), **_given(dry_run=clone_dry_run)}
    return await classic_command(client, host_id, slug, "devmgr", "clone-config", body, key=key)


async def set_outlet_power(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    outlet_index: int,
    outlet_fields: dict[str, Any] | None = None,
    delay_time_to_off: int | None = None,
) -> Any:
    """Classic ``outlet-ctl`` for one PDU / outlet-device outlet."""
    _check_int(outlet_index, "outlet_index")
    _check_object(outlet_fields, "outlet_fields")
    _check_int(delay_time_to_off, "delay_time_to_off")
    if outlet_fields and "index" in outlet_fields:
        _grammar("outlet_fields must not contain 'index'; outlet_index names the outlet")
    entry = {"index": outlet_index, **(outlet_fields or {})}
    params: dict[str, Any] = {"outlet_table": [entry]}
    params.update(_given(delay_time_to_off=delay_time_to_off))
    return await _devmgr(client, registry, host, site, device, "outlet-ctl", params)


async def recover_switch_port(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    port_idx: int,
    unit_id: int | None = None,
    rps: bool = False,
) -> Any:
    """Classic ``port-recovery`` (or ``rps-port-recovery`` for a redundant power port)."""
    _check_int(port_idx, "port_idx")
    _check_int(unit_id, "unit_id")
    _check_bool(rps, "rps")
    cmd = "rps-port-recovery" if rps else "port-recovery"
    params = _given(port_idx=port_idx, unit_id=unit_id)
    try:
        return await _devmgr(client, registry, host, site, device, cmd, params)
    except UniFiConnectionError as exc:
        if "api.err.InvalidTargetPort" not in str(exc):
            raise
        raise type(exc)(
            f"{exc}; the port may not be in a recoverable state. The Network web app "
            "recovers only a port blocked by loop detection or BPDU guard (or, with rps, an "
            "error-disabled redundant power port); a down port alone does not need recovery",
            request_sent=exc.request_sent,
            status=exc.status,
        ) from exc


async def run_device_self_test(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str
) -> Any:
    """Classic ``self-test`` (UPS self-test)."""
    return await _devmgr(client, registry, host, site, device, "self-test")


async def set_device_alignment_mode(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str, enabled: bool
) -> Any:
    """Classic ``set-alignment`` / ``unset-alignment``."""
    _check_bool(enabled, "enabled")
    cmd = "set-alignment" if enabled else "unset-alignment"
    return await _devmgr(client, registry, host, site, device, cmd)


async def set_priority_uplink(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    enabled: bool,
    prefer1: str | None = None,
    prefer2: str | None = None,
) -> Any:
    """Classic ``set-priority-uplink {prefer1, prefer2}`` / ``unset-priority-uplink``."""
    _check_bool(enabled, "enabled")
    for name, value in (("prefer1", prefer1), ("prefer2", prefer2)):
        if value is not None:
            validate_selector(value, name)
    if not enabled:
        if prefer1 is not None or prefer2 is not None:
            _grammar("prefer1/prefer2 are sent only when enabled is true")
        return await _devmgr(client, registry, host, site, device, "unset-priority-uplink")
    params = _given(prefer1=prefer1, prefer2=prefer2)
    return await _devmgr(client, registry, host, site, device, "set-priority-uplink", params)


async def set_device_rearrange_mode(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str, enabled: bool
) -> Any:
    """Classic ``set-rearrange`` / ``unset-rearrange``."""
    _check_bool(enabled, "enabled")
    cmd = "set-rearrange" if enabled else "unset-rearrange"
    return await _devmgr(client, registry, host, site, device, cmd)


async def disconnect_remote_vpn_user(
    client: UniFiClient, registry: Registry, host: str, site: str, params: dict[str, Any]
) -> Any:
    """Classic ``terminate-remote-user-vpn`` with a free-form body."""
    params = _require_object(params, "params")
    classic_command_body("terminate-remote-user-vpn", params)
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    return await classic_command(
        client, host_id, slug, "devmgr", "terminate-remote-user-vpn", params, key=key
    )


async def locate_switch_port(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    port_idx: int,
    enabled: bool,
    unit_id: int | None = None,
) -> Any:
    """Classic ``cmd/devmgr/port-locate`` ``set-port-locate`` / ``unset-port-locate``."""
    _check_int(port_idx, "port_idx")
    _check_bool(enabled, "enabled")
    _check_int(unit_id, "unit_id")
    cmd = "set-port-locate" if enabled else "unset-port-locate"
    params = {
        "port_idx_list": [port_idx],
        **_given(unit_id=unit_id),
    }
    return await _devmgr(
        client, registry, host, site, device, cmd, params, manager="devmgr/port-locate"
    )


async def unpair_building_bridge(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str
) -> Any:
    """Classic ``cmd/devmgr/ubb-unpair {cmd: ubb-unpair, mac}``."""
    return await _devmgr(
        client, registry, host, site, device, "ubb-unpair", manager="devmgr/ubb-unpair"
    )


# ----------------------------------------------------------------------- v2 routes


def _port_list(ports: Any) -> list[dict[str, Any]]:
    """A non-empty list of ``{port_idx, unit_id?}`` objects, validated locally."""
    if not isinstance(ports, list):
        raise ValueError(
            "'ports' must be a JSON array of {port_idx, unit_id?} objects, e.g. "
            f'[{{"port_idx": 5}}]; got {describe_shape(ports)}. Nothing was sent.'
        )
    if not ports:
        raise ValueError(
            "ports must be a non-empty list: an empty list names no port; nothing was sent."
        )
    items = []
    for index, item in enumerate(ports):
        port_idx = item.get("port_idx") if isinstance(item, dict) else None
        if not isinstance(port_idx, int) or isinstance(port_idx, bool):
            raise ValueError(
                f"'ports[{index}]' must be an object with an integer port_idx, e.g. "
                f'{{"port_idx": 5, "unit_id": 1}}; got {describe_shape(item)}. Nothing was sent.'
            )
        _check_int(item.get("unit_id"), f"ports[{index}].unit_id")
        items.append(dict(item))
    return items


async def reset_switch_port(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str | None,
    ports: list[dict[str, Any]] | None,
    *,
    resolve_device: bool = True,
) -> Any:
    """POST v2 ``ports/{mac}/reset`` with ``[{port_idx, unit_id?}, ...]``.

    The Network 11.0.89 web app's "Clear last seen" port action posts this route with the
    switch MAC in the path and a JSON array of the ports to clear (ports.js:
    ``POST ports/${mac}/reset`` with ``[{port_idx, unit_id}]``).
    """
    device = _check_device_arg(device)
    items = _port_list(ports)
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    if not resolve_device and is_mac(device):
        mac = colon_mac(normalize_mac(device))
    else:
        record = await _find_device(client, key, host_id, slug, device)
        mac = _mac_of(record)
    segment = path_segment(mac, "device")
    return await client.post(v2_site(host_id, slug, f"/ports/{segment}/reset"), key=key, json=items)


async def get_device_adoption_info(
    client: UniFiClient, registry: Registry, host: str, site: str, device_ref: str
) -> Any:
    """GET v2 ``adopt-info/{device_ref}``, verbatim."""
    validate_selector(device_ref, "device_ref")
    segment = path_segment(device_ref, "device_ref")
    key, host_id, slug = await _site(registry, host, site)
    try:
        return await client.get(v2_site(host_id, slug, f"/adopt-info/{segment}"), key=key)
    except UniFiConnectionError as exc:
        if exc.status != 404:
            raise
        raise type(exc)(
            f"{exc}; check that the device is currently pending adoption in the Network console",
            request_sent=exc.request_sent,
            status=exc.status,
        ) from exc


async def get_rolling_upgrade_plan(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    time_estimate: bool = False,
    estimate_body: dict[str, Any] | None = None,
) -> Any:
    """GET rolling-upgrade eligible devices, or POST the time estimate (v2)."""
    _check_bool(time_estimate, "time_estimate")
    _check_object(estimate_body, "estimate_body")
    require_unmasked_fields(estimate_body, "get_rolling_upgrade_plan estimate_body")
    route = "/device/upgrade/rollupgrade"
    if not time_estimate:
        if estimate_body is not None:
            _grammar("estimate_body is sent only with time_estimate true")
        key, host_id, slug = await _site(registry, host, site)
        return await client.get(v2_site(host_id, slug, f"{route}/eligible-devices"), key=key)
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(
        v2_site(host_id, slug, f"{route}/time-estimate"), key=key, json=estimate_body
    )


async def get_device_replacement_options(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str
) -> Any:
    """GET v2 ``device/{_id}/replacement-candidates`` for a resolved device, verbatim."""
    _check_device_arg(device)
    key, host_id, slug = await _site(registry, host, site)
    record = await _find_device(client, key, host_id, slug, device)
    path = v2_site(host_id, slug, f"/device/{_id_of(record)}/replacement-candidates")
    return await client.get(path, key=key)


async def replace_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    replacement_mac: str | None = None,
    cancel: bool = False,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST (or, with cancel, DELETE) v2 ``device/{_id}/replace``."""
    _check_device_arg(device)
    _check_bool(cancel, "cancel")
    if replacement_mac is not None:
        validate_selector(replacement_mac, "replacement_mac")
    _check_object(body, "body")
    require_unmasked_fields(body, "replace_device body")
    guard_action("DELETE" if cancel else "POST")
    key, host_id, slug = await _site(registry, host, site)
    record = await _find_device(client, key, host_id, slug, device)
    path = v2_site(host_id, slug, f"/device/{_id_of(record)}/replace")
    params = _given(replacementDeviceMac=replacement_mac) or None
    if cancel:
        return await client.delete(path, key=key, json=body, params=params)
    return await client.post(path, key=key, json=body, params=params)


def _battery_ids(battery_ids: Any) -> list[str]:
    if not _check_list(battery_ids, "battery_ids"):
        _grammar(
            "'battery_ids' is empty, so the request names no battery pack. Pass at least one "
            "battery identifier."
        )
    for index, value in enumerate(battery_ids):
        validate_selector(value, f"battery_ids[{index}]")
    return cast(list[str], battery_ids)


async def control_device_battery(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    battery_ids: list[str],
    action: str = "set-locate",
) -> Any:
    """POST v2 ``device/{mac}/battery/action {macs, action}``."""
    _check_device_arg(device)
    macs = _battery_ids(battery_ids)
    validate_selector(action, "action")
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    record = await _find_device(client, key, host_id, slug, device)
    path = v2_site(host_id, slug, f"/device/{_mac_of(record)}/battery/action")
    return await client.post(path, key=key, json={"macs": macs, "action": action})


async def update_device_battery_settings(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    battery_ids: list[str],
    url: str = "",
) -> Any:
    """POST v2 ``device/{mac}/battery/update {macs, action: "upgrade", url}``."""
    _check_device_arg(device)
    macs = _battery_ids(battery_ids)
    _check_str(url, "url")
    if url:
        try:
            parsed = urlsplit(url)
            valid = parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("url must be an http or https URL with a host.")
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    record = await _find_device(client, key, host_id, slug, device)
    path = v2_site(host_id, slug, f"/device/{_mac_of(record)}/battery/update")
    return await client.post(path, key=key, json={"macs": macs, "action": "upgrade", "url": url})


async def set_device_tag_assignments(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    assignment_id: str,
    body: dict[str, Any],
) -> Any:
    """POST v2 ``device-tags/device-tag-assignment/{assignment_id}`` with a free-form body."""
    validate_selector(assignment_id, "assignment_id")
    segment = path_segment(assignment_id, "assignment_id")
    checked = _require_object(body, "body")
    if not checked:
        _empty(
            "set_device_tag_assignments 'body' carries no field, so there is no assignment "
            "to send. Pass the assignment body."
        )
    guard_action("POST")
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, f"/device-tags/device-tag-assignment/{segment}")
    return await client.post(path, key=key, json=checked)


async def bulk_update_objects(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    object_type: str,
    payload: dict[str, Any] | list[dict[str, Any]],
) -> Any:
    """PUT Classic ``group/{object_type}`` with ``payload`` verbatim; affirmative rc."""
    validate_selector(object_type, "object_type")
    segment = path_segment(object_type, "object_type")
    if isinstance(payload, list):
        for index, item in enumerate(payload):
            _require_object(item, f"payload[{index}]")
    else:
        _require_object(payload, "payload")
    if isinstance(payload, list) and not payload:
        _grammar(
            "bulk_update_objects 'payload' is an empty list, so there is nothing to update. "
            "Pass at least one object."
        )
    if isinstance(payload, dict) and not payload:
        _empty(
            "bulk_update_objects 'payload' is empty, so there is nothing to update. Pass "
            "the bulk body the description lists."
        )
    guard_action("PUT")
    key, host_id, slug = await _site(registry, host, site)
    path = _classic_path(host_id, slug, f"/group/{segment}")
    resp = await client.request("PUT", path, key=key, json=cast(dict[str, Any], payload))
    return _classic_ok(client, resp, "PUT", path)


# Module-level implementations, kept reachable under distinct names for registration.
_impl_ssh = manage_device_ssh_session
_impl_clear = clear_switch_counters
_impl_clone = clone_device_config
_impl_outlet = set_outlet_power
_impl_recover = recover_switch_port
_impl_self_test = run_device_self_test
_impl_alignment = set_device_alignment_mode
_impl_priority = set_priority_uplink
_impl_rearrange = set_device_rearrange_mode
_impl_vpn = disconnect_remote_vpn_user
_impl_locate = locate_switch_port
_impl_ubb = unpair_building_bridge
_impl_reset_port = reset_switch_port
_impl_adopt_info = get_device_adoption_info
_impl_rolling = get_rolling_upgrade_plan
_impl_candidates = get_device_replacement_options
_impl_replace = replace_device
_impl_battery = control_device_battery
_impl_battery_update = update_device_battery_settings
_impl_tag_assign = set_device_tag_assignments
_impl_bulk = bulk_update_objects


# ---------------------------------------------------------------------- registration


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    def tool(fn: Callable[..., Any]) -> Any:
        # Annotations derived from the implementation's call graph, never hand-set.
        writes = derive_write_tools([SimpleNamespace(name=fn.__name__, fn=fn)])
        return mcp.tool(annotations=for_tool(writes=fn.__name__ in writes))(fn)

    @tool
    async def manage_device_ssh_session(
        host: str,
        site: str,
        action: str = "build",
        params: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Open, answer or close a browser-style (WebRTC) SSH session to a device.

        Sends the Classic POST api/s/{site}/cmd/devmgr command build-ssh-session (action build),
        ssh-sdp-answer (sdp_answer) or close-ssh-session (close); any other action is sent as the
        cmd as given and the controller judges it. The Network web app builds the rest of the body
        at run time and its keys were not recovered from the 11.0.81 bundle, so params is free-form
        and sent as given beside cmd (no key is added). Returns the Classic envelope {meta, data}
        verbatim; success requires meta.rc "ok", otherwise the error carries the full upstream body.
        With dry-run policy, returns the dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing. Consequence: build opens a shell
        channel to the device; close ends it. Other action names execute arbitrary devmgr commands
        with the consequences of that command; the SSH aliases do not restrict the command set.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            action: build, sdp_answer, close or a devmgr command name; for example
                "build".
            params: Further body keys sent as given; for example
                {"mac": "02:00:5e:00:53:01"}. Free-form object.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_ssh(client, registry, host, site, action, params)

    @tool
    async def clear_switch_counters(
        host: str,
        site: str,
        device: str,
        port_idx: int | None = None,
        unit_id: int | None = None,
        confirm: bool = False,
    ) -> Any:
        """Reset a switch's traffic and error counters, or one port's.

        Without port_idx sends Classic cmd/devmgr clear-switch-counters {mac}; with port_idx sends
        clear-switch-port-counters {mac, port_idx, unit_id}. The device is looked up in the site
        device list first (unknown or ambiguous values fail listing every device). Returns {meta,
        data} verbatim; success requires meta.rc "ok". With dry-run policy, returns the dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}} and sends nothing. Consequence: the cleared counters are lost and cannot be restored.

        Required arguments: host, site, device (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Switch MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            port_idx: Port number to clear only that port; for example 5.
            unit_id: Stack member unit of the port (with port_idx); for example 1.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_clear(client, registry, host, site, device, port_idx, unit_id)

    @tool
    async def clone_device_config(
        host: str,
        site: str,
        device: str,
        source_device: str,
        clone_dry_run: bool | None = None,
        confirm: bool = False,
    ) -> Any:
        """Copy one device's configuration onto another device of the same model.

        Sends Classic cmd/devmgr clone-config {mac: target MAC, origin: source MAC, dry_run};
        dry_run (clone_dry_run) is the controller's own check of the clone and is sent only when
        given. Both devices are looked up in the site device list first. Returns {meta, data}
        verbatim; success requires meta.rc "ok". With dry-run policy, returns the dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing. Consequence: the target device's configuration is overwritten by the source's
        and it reprovisions.

        Required arguments: host, site, device, source_device (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Target device MAC, Classic _id or exact name; for example
                "02:00:5e:00:53:02".
            source_device: Source device MAC, Classic _id or exact name; for example
                "02:00:5e:00:53:01".
            clone_dry_run: Sent as the body's dry_run; for example true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_clone(client, registry, host, site, device, source_device, clone_dry_run)

    @tool
    async def set_outlet_power(
        host: str,
        site: str,
        device: str,
        outlet_index: int,
        outlet_fields: dict[str, Any] | None = None,
        delay_time_to_off: int | None = None,
        confirm: bool = False,
    ) -> Any:
        """Control one outlet of a UniFi PDU or outlet device.

        Sends Classic cmd/devmgr outlet-ctl {mac, outlet_table: [{index, ...outlet_fields}],
        delay_time_to_off}. The web app sends [{index}]; outlet_fields adds further keys of that
        entry as given (for example relay_state or cycle_enabled, as in the device's
        outlet_overrides). delay_time_to_off is sent only when given. Returns {meta, data} verbatim;
        success requires meta.rc "ok". With dry-run policy, returns the dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.
        Consequence: the outlet's power changes or cycles at once, cutting power to whatever is
        plugged in.

        Required arguments: host, site, device, outlet_index (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: PDU MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            outlet_index: outlet_table[].index of the outlet; for example 1.
            outlet_fields: Further outlet entry keys; for example {"relay_state": false}.
                Free-form object.
            delay_time_to_off: Delay before power off in seconds, sent as given; for example 0.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_outlet(
            client, registry, host, site, device, outlet_index, outlet_fields, delay_time_to_off
        )

    @tool
    async def recover_switch_port(
        host: str,
        site: str,
        device: str,
        port_idx: int,
        unit_id: int | None = None,
        rps: bool = False,
        confirm: bool = False,
    ) -> Any:
        """Recover a switch port the switch has disabled (for example after a loop or err-disable).

        Sends Classic cmd/devmgr port-recovery {mac, port_idx, unit_id}, or with rps true
        rps-port-recovery {mac, port_idx} for a redundant-power-system port (the web app sends no
        unit_id there; one given is sent as given). Returns {meta, data} verbatim; success requires
        meta.rc "ok". With dry-run policy, returns the dry-run preview {status: "dry_run", dryRun,
        sent: false, message, preview: {method, path, params, body}} and sends nothing. Consequence:
        a successful recovery may re-enable the port and resume traffic or power. The Network
        web app offers recovery only for a port blocked by loop detection or BPDU guard (rps:
        an error-disabled redundant power port); for any other port, including one that is
        merely down, the console answers HTTP 400 api.err.InvalidTargetPort and changes nothing.

        Required arguments: host, site, device, port_idx (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Switch MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            port_idx: Port number; for example 5.
            unit_id: Stack member unit of the port; for example 1.
            rps: Recover a redundant power system port instead; for example false.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_recover(client, registry, host, site, device, port_idx, unit_id, rps)

    @tool
    async def run_device_self_test(host: str, site: str, device: str, confirm: bool = False) -> Any:
        """Start a device self-test (the web app's UPS self-test).

        Sends Classic cmd/devmgr self-test {mac}. Returns {meta, data} verbatim; success requires
        meta.rc "ok". With dry-run policy, returns the dry-run preview {status: "dry_run", dryRun,
        sent: false, message, preview: {method, path, params, body}} and sends nothing. Consequence:
        a UPS switches to battery for the test; a failing battery can drop power to connected
        equipment.

        Required arguments: host, site, device (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Device MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_self_test(client, registry, host, site, device)

    @tool
    async def set_device_alignment_mode(
        host: str, site: str, device: str, enabled: bool, confirm: bool = False
    ) -> Any:
        """Turn a point-to-point bridge's antenna alignment mode on or off.

        Sends Classic cmd/devmgr set-alignment {mac} (enabled true) or unset-alignment {mac}.
        Returns {meta, data} verbatim; success requires meta.rc "ok". With dry-run policy, returns
        the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method,
        path, params, body}} and sends nothing. Consequence: alignment mode changes the link's radio
        behaviour and can interrupt the bridge link.

        Required arguments: host, site, device, enabled (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Bridge MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            enabled: True to enter alignment mode, false to leave it; for example true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_alignment(client, registry, host, site, device, enabled)

    @tool
    async def set_priority_uplink(
        host: str,
        site: str,
        device: str,
        enabled: bool,
        prefer1: str | None = None,
        prefer2: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Set or clear a device's preferred uplinks.

        With enabled true it sends Classic cmd/devmgr set-priority-uplink with mac plus prefer1 and
        prefer2 (each only when given, as given); with enabled false it sends unset-priority-uplink
        with mac. Returns {meta, data} verbatim; success requires meta.rc "ok". With dry-run policy,
        returns the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}} and sends nothing. Consequence: the device may switch its
        uplink, briefly interrupting its clients.

        Required arguments: host, site, device, enabled (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Device MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            enabled: True to set, false to clear; for example true.
            prefer1: First preferred uplink, sent as given; for example "02:00:5e:00:53:0a".
            prefer2: Second preferred uplink, sent as given; for example "02:00:5e:00:53:0b".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_priority(client, registry, host, site, device, enabled, prefer1, prefer2)

    @tool
    async def set_device_rearrange_mode(
        host: str, site: str, device: str, enabled: bool, confirm: bool = False
    ) -> Any:
        """Turn a switch stack's rearrange mode on or off (high-availability stacking).

        Sends Classic cmd/devmgr set-rearrange {mac} (enabled true) or unset-rearrange {mac}, as the
        web app's stacking page does. Returns {meta, data} verbatim; success requires meta.rc "ok".
        With dry-run policy, returns the dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing. Consequence: rearranging can
        renumber stack members and interrupt forwarding while the stack re-forms.

        Required arguments: host, site, device, enabled (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Switch MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            enabled: True to enter rearrange mode, false to leave it; for example true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_rearrange(client, registry, host, site, device, enabled)

    @tool
    async def disconnect_remote_vpn_user(
        host: str, site: str, params: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Disconnect a connected remote-access VPN user session.

        Sends Classic cmd/devmgr terminate-remote-user-vpn with params beside cmd. The web app
        builds this body at run time and its keys were not recovered from the 11.0.81 bundle, so
        params is free-form and sent as given (no key is added). Returns {meta, data} verbatim;
        success requires meta.rc "ok". With dry-run policy, returns the dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.
        Consequence: the user's VPN tunnel drops at once; they can reconnect.

        Required arguments: host, site, params (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            params: Body keys identifying the session, sent as given; for example
                {"user_id": "000000000000000000000107"}. Free-form object.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_vpn(client, registry, host, site, params)

    @tool
    async def locate_switch_port(
        host: str,
        site: str,
        device: str,
        port_idx: int,
        enabled: bool,
        unit_id: int | None = None,
        confirm: bool = False,
    ) -> Any:
        """Blink (or stop blinking) the LEDs of switch ports so they can be found.

        Sends Classic POST cmd/devmgr/port-locate {cmd: set-port-locate (enabled true) or
        unset-port-locate, mac, port_idx_list: [port_idx], unit_id}. Returns {meta, data} verbatim;
        success requires meta.rc "ok". With dry-run policy, returns the dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.
        Consequence: only the port LEDs change; traffic is unaffected.

        Required arguments: host, site, device, port_idx, enabled (see each parameter's
        description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Switch MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            port_idx: Port number; for example 5.
            enabled: True to start blinking, false to stop; for example true.
            unit_id: Stack member unit of the ports; for example 1.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_locate(client, registry, host, site, device, port_idx, enabled, unit_id)

    @tool
    async def unpair_building_bridge(
        host: str, site: str, device: str, confirm: bool = False
    ) -> Any:
        """Unpair a UniFi Building Bridge (UBB) from its peer.

        Sends Classic POST cmd/devmgr/ubb-unpair {cmd: ubb-unpair, mac}. Returns {meta, data}
        verbatim; success requires meta.rc "ok". With dry-run policy, returns the dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing. Consequence: the bridge link goes down and stays down until the pair is
        paired again; sites behind it lose connectivity.

        Required arguments: host, site, device (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Bridge MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_ubb(client, registry, host, site, device)

    @tool
    async def reset_switch_port(
        host: str,
        site: str,
        device: str | None = None,
        ports: list[dict[str, Any]] | None = None,
        confirm: bool = False,
        body: dict[str, Any] | None = None,
        port_id: str | None = None,
    ) -> Any:
        """Clear the remembered last connection ("last seen") of switch ports (Network v2 route).

        Uses a supplied MAC directly, or resolves a device name or Classic _id on the site.
        Sends POST /v2/api/site/{site}/ports/{mac}/reset with
        ports as the JSON array body, as the web app's "Clear last seen" port action does (it
        offers it for ports that are down, not trusted, and still show a last connection).
        A non-list, empty list or item without an integer port_idx is refused before any
        request. Returns the upstream body verbatim. With dry-run policy, returns the dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path,
        params, body}} and sends nothing.
        Consequence: the ports' last-seen client or uplink record is cleared; the port
        configuration and link are not changed.

        Required arguments: host, site, device, ports (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Switch MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
            ports: Ports to clear. Shape: {port_idx:integer,unit_id?:integer}[].
                Each item names a port (unit_id for a stack member);
                for example [{"port_idx": 5}].
            confirm: Accepted and ignored for compatibility; for example false.
            body: Legacy free-form object sent verbatim, taking precedence over ports.
                Uses port_id, or device when port_id is omitted; ports is ignored.
                Shape: {port_idx:integer,unit_id?:integer}.
            port_id: Legacy route selector; body is optional and ports is ignored. For example
                "02:00:5e:00:53:01". Prefer device and ports.
        """
        client, registry = deps_fn()
        if port_id is not None or body is not None:
            if port_id is not None:
                validate_selector(port_id, "port_id")
                path_segment(port_id, "port_id")
                selector = port_id
            else:
                selector = _check_device_arg(device)
            _check_object(body, "body")
            require_unmasked_fields(body, "reset_switch_port body")
            guard_action("POST")
            key, host_id, slug = await _site(registry, host, site)
            if port_id is None:
                if is_mac(selector):
                    selector = colon_mac(normalize_mac(selector))
                else:
                    record = await _find_device(client, key, host_id, slug, selector)
                    selector = _mac_of(record)
            segment = path_segment(selector, "port_id" if port_id is not None else "device")
            return await client.post(
                v2_site(host_id, slug, f"/ports/{segment}/reset"), key=key, json=body
            )
        return await _impl_reset_port(
            client, registry, host, site, device, ports, resolve_device=False
        )

    @tool
    async def get_device_adoption_info(host: str, site: str, device_ref: str) -> Any:
        """Get the adoption details the controller holds for a device.

        GET /v2/api/site/{site}/adopt-info/{device_ref}. Returns the upstream adoption record
        verbatim. The web app
        reads it in the adoption dialog; device_ref is sent as one path segment (a pending
        device is not in the adopted list, so it is not looked up first). A 404 may mean that
        the device is not currently pending adoption on the console.

        Required arguments: host, site, device_ref (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device_ref: Device identifier for the route; for example "02:00:5e:00:53:01".
        """
        client, registry = deps_fn()
        return await _impl_adopt_info(client, registry, host, site, device_ref)

    @tool
    async def get_rolling_upgrade_plan(
        host: str,
        site: str,
        time_estimate: bool = False,
        estimate_body: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Plan a rolling firmware upgrade: eligible devices or the time estimate.

        By default GET /v2/api/site/{site}/device/upgrade/rollupgrade/eligible-devices.
        time_estimate true: POST .../rollupgrade/time-estimate with estimate_body as given
        (free-form). Returns the upstream body verbatim in both modes. The estimate is a read sent
        as a POST. The whole tool, including the GET mode, is hidden under UNIFI_WRITE_POLICY=deny.
        With dry-run policy the POST returns the dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}} and sends nothing. Consequence: none on devices; nothing is upgraded.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            time_estimate: True to POST the time estimate instead; for example false.
            estimate_body: Body of the time-estimate POST; for example
                {"macs": ["02:00:5e:00:53:01"]}. Free-form object.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_rolling(client, registry, host, site, time_estimate, estimate_body)

    @tool
    async def get_device_replacement_options(host: str, site: str, device: str) -> Any:
        """List the devices that can replace an adopted device.

        The device is looked up in the site device list, then GET /v2/api/site/{site}/
        device/{_id}/replacement-candidates is read with its Classic _id. Returns the
        upstream array of candidate devices verbatim. Use a candidate's MAC as replacement_mac
        in replace_device.

        Required arguments: host, site, device (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Device MAC, Classic _id or exact name; for example "02:00:5e:00:53:01".
        """
        client, registry = deps_fn()
        return await _impl_candidates(client, registry, host, site, device)

    @tool
    async def replace_device(
        host: str,
        site: str,
        device: str,
        replacement_mac: str | None = None,
        cancel: bool = False,
        body: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Replace an adopted device with another one, or cancel a pending replacement.

        The device is looked up in the site device list; then POST /v2/api/site/{site}/
        device/{_id}/replace?replacementDeviceMac=replacement_mac (cancel true: DELETE .../replace,
        with the same query when replacement_mac is given). replacement_mac and body are sent as
        given (free-form body). Returns the upstream body verbatim. With dry-run policy, returns the
        dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path,
        params, body}} and sends nothing. Consequence: the replacement takes over the old device's
        configuration and the old device is retired; cancel removes the pending replacement.

        Required arguments: host, site, device (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Device to replace: MAC, Classic _id or exact name; for example
                "02:00:5e:00:53:01".
            replacement_mac: MAC of the new device; for example "02:00:5e:00:53:02".
            cancel: True to cancel a pending replacement; for example false.
            body: Request body sent as given; for example {"keep_name": true}. Free-form object.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_replace(
            client, registry, host, site, device, replacement_mac, cancel, body
        )

    @tool
    async def control_device_battery(
        host: str,
        site: str,
        device: str,
        battery_ids: list[str],
        action: str = "set-locate",
        confirm: bool = False,
    ) -> Any:
        """Locate or reboot battery packs attached to a UniFi power device.

        The device is looked up in the site device list; then POST /v2/api/site/{site}/
        device/{mac}/battery/action {macs: battery_ids, action}. Returns the upstream body verbatim.
        With dry-run policy, returns the dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing. Consequence: reboot restarts the
        battery packs (backup power is unavailable while they restart); set-locate/unset-locate only
        change their LEDs.

        Required arguments: host, site, device, battery_ids (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Power device MAC, Classic _id or exact name; for example
                "02:00:5e:00:53:01".
            battery_ids: Non-empty list of battery identifiers sent as macs (an empty list fails
                before any request); for example ["02:00:5e:00:53:21"].
            action: set-locate, unset-locate or reboot (sent as given); for example
                "set-locate".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_battery(client, registry, host, site, device, battery_ids, action)

    @tool
    async def update_device_battery_settings(
        host: str,
        site: str,
        device: str,
        battery_ids: list[str],
        url: str = "",
        confirm: bool = False,
    ) -> Any:
        """Upgrade the firmware of battery packs attached to a UniFi power device.

        The device is looked up in the site device list; then POST /v2/api/site/{site}/
        device/{mac}/battery/update {macs: battery_ids, action: "upgrade", url}. url "" (the web
        app's value) uses the released firmware; a URL installs custom firmware. Returns the
        upstream body verbatim. With dry-run policy, returns the dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}} and sends nothing.
        Consequence: the packs install firmware and restart; backup power is unavailable until they
        return.

        Required arguments: host, site, device, battery_ids (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            device: Power device MAC, Classic _id or exact name; for example
                "02:00:5e:00:53:01".
            battery_ids: Non-empty list of battery identifiers sent as macs (an empty list fails
                before any request); for example ["02:00:5e:00:53:21"].
            url: HTTP or HTTPS firmware URL, or "" for the release; for example "".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_battery_update(client, registry, host, site, device, battery_ids, url)

    @tool
    async def set_device_tag_assignments(
        host: str, site: str, assignment_id: str, body: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Assign device tags (Network v2 device-tag assignment route).

        Sends POST /v2/api/site/{site}/device-tags/device-tag-assignment/{assignment_id} with body
        as given. The Network 11.0.89 web app addresses the managed device by MAC and sends
        device_tag_additions and device_tag_removals arrays of tag _ids. list_device_tags returns
        the tag ids and member_device_macs showing current membership. The body is passed through
        without rewriting. Returns the upstream body verbatim. With
        dry-run policy, returns the dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing. Consequence: tag membership
        changes, which can change tag-based policies.

        Required arguments: host, site, assignment_id, body (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            assignment_id: The managed device MAC; for example "02:00:5e:00:53:01".
            body: Request body sent as given; for example {"device_tag_additions":
                ["000000000000000000000107"], "device_tag_removals": []}. Arrays contain tag
                _ids; the object remains free-form.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_tag_assign(client, registry, host, site, assignment_id, body)

    @tool
    async def bulk_update_objects(
        host: str,
        site: str,
        object_type: str,
        payload: dict[str, Any] | list[dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Update many Classic objects in one request (the web app's bulk edit).

        Sends Classic PUT api/s/{site}/group/{object_type} with payload verbatim. Types the web app
        uses: device (an array of device objects, each with _id and the fields to set), user and
        networkconf ({data: {fields}, id: [ids]}), setting ({objects: [...]}). Returns {meta, data}
        verbatim; success requires meta.rc "ok", otherwise the error carries the full upstream body.
        Not read back (the body is free-form). With dry-run policy, returns the dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing. Consequence: every listed object changes at once; devices may reprovision.

        Required arguments: host, site, object_type, payload (see each parameter's description).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            object_type: device, user, networkconf or setting; for example "user".
            payload: Body sent verbatim; an empty {} or [] fails before any request; for example
                {"data": {"usergroup_id": "65f1c0ffee01"}, "id": ["65f1c0ffee02"]}.
                Free-form object.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_bulk(client, registry, host, site, object_type, payload)
