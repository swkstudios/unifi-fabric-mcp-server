"""Merge-aware switch port override editor over Classic stat/device and rest/device.

The controller treats a PUT of ``port_overrides`` as a full replacement of the array: a
port missing from it reverts to its defaults. This editor reads the current array, merges
the requested fields into each named port's entry by ``port_idx`` (other ports and other
fields stay exactly as read), drops only the ports named for removal, PUTs the complete
array once and reads it back. Each switch's read, merge, write and read-back run under one
lock in this server process. Callers that do not take that lock (the UniFi UI, other API
clients, ``fabric_connector_put``, another server process) are not serialized against it.

Design credit: the merge-by-``port_idx`` and per-device serialization approach follows the
switch-port tools of sirkirby/unifi-mcp (MIT License, Copyright (c) 2025 Chris Kirby). No
code was copied from that project.
"""

from __future__ import annotations

import asyncio
import weakref
from collections.abc import Sequence
from copy import deepcopy
from typing import Any

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    object_records,
    upstream_error_text,
    upstream_error_value,
    validate_id,
    validate_selector,
)
from ...config import APIKeyConfig
from ...macs import is_mac
from ...read_only import ReadOnlyModeError, guard_action, mark_write_denied
from ...registry import Registry
from ...shared_shapes._classic_objects import classic_rest, resolve_site_slug
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import leaf_equal
from ...switches import connector_writes_enabled
from ..connector.connector import CONNECTOR_WRITE_ENV, connector_write_refusal
from ..statistics.statistics import _classic_stat, _select_one_record, _stat_records
from ._device_config import require_classic_success, update_device_config
from .device_radios import _read_device
from .schemas import (  # the family's shapes (family-owned layout)
    _NETWORK_LISTS,
    _NETWORK_SCALARS,
    _SPAN_MODE,
    _SPAN_PORT_FIELD,
    TOOL,
    PortOverrideChange,
)

# One asyncio.Lock per (console, site, Classic device _id), kept per client so a lock is
# never shared across event loops or server instances. An entry lives as long as its
# client, one per device ever edited (bounded by fleet size). The lock serializes this editor's
# read/merge/write/read-back only; it does not bind writers outside this process or tool.
_LOCKS: weakref.WeakKeyDictionary[UniFiClient, dict[tuple[str, str, str], asyncio.Lock]] = (
    weakref.WeakKeyDictionary()
)


def switch_lock(client: UniFiClient, host_id: str, site_slug: str, device_id: str) -> asyncio.Lock:
    """The lock serializing this editor's updates of one switch's port_overrides."""
    locks = _LOCKS.setdefault(client, {})
    return locks.setdefault((host_id, site_slug, device_id), asyncio.Lock())


def _port_number(value: Any, where: str) -> int:
    # Own selector grammar, not a spec citation: port_idx is 1-based, as stat/device
    # port_table and port_overrides number ports (no published spec covers rest/device).
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{where} must be a positive integer port number, got {value!r}")
    return value


def _validate_request(
    ports: list[PortOverrideChange], remove_ports: list[int], *, explicit: bool = False
) -> tuple[dict[int, dict[str, Any]], list[int]]:
    """Own-argument grammar, checked before any request: one action per port, no repeats."""
    updates: dict[int, dict[str, Any]] = {}
    for change in ports:
        if change.port_idx in updates:
            raise ValueError(
                f"Ambiguous port selection: port {upstream_error_value(change.port_idx)} appears "
                "more than once in ports; merge its fields into one entry"
            )
        updates[change.port_idx] = change.fields()
    removed: list[int] = []
    for value in remove_ports:
        port = _port_number(value, "remove_ports entry")
        if port in removed:
            raise ValueError(
                f"Ambiguous port selection: port {upstream_error_value(port)} appears more than "
                "once in remove_ports"
            )
        removed.append(port)
    both = sorted(set(updates) & set(removed))
    if both:
        raise ValueError(
            f"Ambiguous port selection: port {upstream_error_value(both[0])} is both updated "
            "(ports) and removed (remove_ports); choose one"
        )
    if not updates and not removed:
        if explicit:
            # The caller passed ports and/or remove_ports, but as empty lists: the selection
            # names no port at all (own argument grammar, not an empty update body).
            raise ValueError(
                "No port selected: ports and remove_ports are both empty; name at least one "
                "port to update or remove"
            )
        raise ValueError(
            "No fields provided: supply ports to update and/or remove_ports to drop overrides"
        )
    return updates, removed


def _overrides(
    record: dict[str, Any], *, require_switch: bool = True
) -> tuple[list[dict[str, Any]], bool]:
    """(current port_overrides, present); absent means none only on a device with ports.

    A read reports a device without ports as having no overrides; a write refuses it.
    """
    if "port_overrides" in record:
        rows = object_records(record["port_overrides"], "/stat/device port_overrides")
        for row in rows:
            port = row.get("port_idx")
            if not isinstance(port, int) or isinstance(port, bool):
                raise UniFiConnectionError(
                    "Unexpected /stat/device port_overrides entry without an integer "
                    f"port_idx: {upstream_error_text(row)}"
                )
        seen = [row["port_idx"] for row in rows]
        dupes = sorted({p for p in seen if seen.count(p) > 1})
        if dupes:
            raise UniFiConnectionError(
                f"Unexpected /stat/device port_overrides: port {upstream_error_value(dupes[0])} "
                "has more than one entry; refusing to merge an ambiguous array. Read back and "
                "correct it first"
            )
        return rows, True
    if require_switch and "port_table" not in record:
        ident = record.get("mac") or record.get("_id") or "unknown"
        raise ValueError(
            f"Device {upstream_error_text(ident)} has no port_table or port_overrides in "
            "/stat/device; it is not a switch. Choose a switch from list_device_stats"
        )
    return [], False


def _port_table(record: dict[str, Any]) -> list[dict[str, Any]]:
    if "port_table" not in record:
        return []
    return object_records(record["port_table"], "/stat/device port_table")


def _device_ports(record: dict[str, Any], current: list[dict[str, Any]]) -> list[int]:
    """Valid write and monitor targets: the physical ports of the port table.

    An override for an index outside the table (a phantom) can be preserved or removed but
    never written or monitored.
    """
    ports = {
        row["port_idx"]
        for row in _port_table(record)
        if isinstance(row.get("port_idx"), int) and not isinstance(row.get("port_idx"), bool)
    }
    if not ports:
        # No port table reported: the current overrides are all there is to go by.
        ports.update(row["port_idx"] for row in current)
    return sorted(ports)


def _check_against_device(
    updates: dict[int, dict[str, Any]],
    removed: list[int],
    current: list[dict[str, Any]],
    valid: list[int],
) -> None:
    """Upstream-judged: the selection must name ports this switch reported."""
    rows = {row["port_idx"]: row for row in current}
    for port in updates:
        if port not in valid:
            raise ValueError(f"Unknown port_idx {port} on this switch; valid ports: {valid}")
        # Judge the row that will be written (the existing override with the request laid over
        # it), not only the fields the caller sent: a stale aggregate size or monitored-port key
        # already on the row takes effect as soon as the request switches the mode.
        sent = updates[port]
        row = {**rows.get(port, {}), **sent}
        if _SPAN_PORT_FIELD in sent or (
            row.get("op_mode") == _SPAN_MODE and _SPAN_PORT_FIELD in row
        ):
            monitored = row[_SPAN_PORT_FIELD]
            if (
                not isinstance(monitored, int)
                or isinstance(monitored, bool)
                or monitored not in valid
            ):
                raise ValueError(
                    f"Unknown {_SPAN_PORT_FIELD} {upstream_error_value(monitored)!r} for port "
                    f"{port}; valid ports: {valid}"
                )
            if monitored == port:
                raise ValueError(
                    f"Port {port} cannot monitor itself ({_SPAN_PORT_FIELD} "
                    f"{upstream_error_value(monitored)}); name another port from "
                    f"{[p for p in valid if p != port]}"
                )
        if "aggregate_num_ports" in sent or (
            row.get("op_mode") == "aggregate" and "aggregate_num_ports" in row
        ):
            count = row["aggregate_num_ports"]
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                raise ValueError(
                    f"port {port} field aggregate_num_ports must be a positive integer, got "
                    f"{upstream_error_text(count)}"
                )
            if valid and port + count - 1 > valid[-1]:
                last = valid[-1]
                raise ValueError(
                    f"aggregate_num_ports {upstream_error_value(count)} on port {port} reaches "
                    f"port {upstream_error_value(port + count - 1)}, past the last known port "
                    f"{upstream_error_value(last)}; use at most "
                    f"{upstream_error_value(last - port + 1)}"
                )
    have = [row["port_idx"] for row in current]
    for port in removed:
        if port not in have:
            raise ValueError(
                f"Port {port} has no override to remove; ports with overrides: "
                f"{upstream_error_value(sorted(have))}"
            )


def _merge(
    current: list[dict[str, Any]], updates: dict[int, dict[str, Any]], removed: list[int]
) -> tuple[list[dict[str, Any]], dict[str, list[int]]]:
    """Field-level merge by port_idx: keep array order, append new ports in port order."""
    merged: list[dict[str, Any]] = []
    plan: dict[str, list[int]] = {"changed": [], "added": [], "removed": [], "kept": []}
    for row in current:
        port = row["port_idx"]
        if port in removed:
            plan["removed"].append(port)
            continue
        if port in updates:
            entry = deepcopy(row)
            entry.update(deepcopy(updates[port]))
            merged.append(entry)
            plan["changed"].append(port)
        else:
            merged.append(deepcopy(row))
            plan["kept"].append(port)
    for port in sorted(set(updates) - {row["port_idx"] for row in current}):
        merged.append({"port_idx": port, **deepcopy(updates[port])})
        plan["added"].append(port)
    return merged, plan


def _by_port(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    by_port: dict[int, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or "port_idx" not in row:
            raise UniFiConnectionError(
                f"Unexpected port_overrides entry without port_idx: {describe_shape(row)}"
            )
        by_port[row["port_idx"]] = row
    return by_port


def _require_string_id(row: dict[str, Any], what: str) -> str:
    """A Classic record's ``_id``; a record without a string ``_id`` is refused."""
    value = row.get("_id")
    if not isinstance(value, str):
        raise UniFiConnectionError(
            f"Unexpected {what} record without a string _id: {describe_shape(row)}"
        )
    return value


def _named_ids(rows: list[dict[str, Any]], what: str) -> dict[str, str]:
    """{_id: name} of Classic records (each must carry a string ``_id``)."""
    return {_require_string_id(row, what): str(row.get("name", "")) for row in rows}


def _diff(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    old, new = _by_port(before), _by_port(after)
    changed: dict[str, Any] = {}
    for port in sorted(set(old) | set(new)):
        if port not in new:
            changed[str(port)] = {"removed": True, "before": old[port]}
            continue
        if port not in old:
            changed[str(port)] = {"added": True, "after": new[port]}
            continue
        left, right = old[port], new[port]
        fields = {
            field: {"before": left.get(field), "after": right.get(field)}
            for field in dict.fromkeys([*left, *right])
            if (field in left) != (field in right)
            or not leaf_equal(left.get(field), right.get(field))
        }
        if fields:
            changed[str(port)] = fields
    return changed


def _verify(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    updates: dict[int, dict[str, Any]],
    removed: list[int],
    desired: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Every field of each sent entry on an updated port, removed ports gone, others unchanged.

    Extra fields the controller fills in on read-back stay allowed, on any port; a sent field the
    controller dropped or changed (even one this call did not request) is a mismatch.
    """
    old, new, sent = _by_port(before), _by_port(after), _by_port(desired)
    mismatches: list[dict[str, Any]] = []
    for port in sorted(updates):
        fields = sent[port]
        row = new.get(port)
        if row is None:
            mismatches.append({"port_idx": port, "problem": "override missing after write"})
            continue
        for field, expected in fields.items():
            if field not in row or not leaf_equal(expected, row[field]):
                mismatches.append(
                    {
                        "port_idx": port,
                        "field": field,
                        "expected": expected,
                        "actual": row.get(field),
                        "present": field in row,
                    }
                )
    for port in removed:
        if port in new:
            mismatches.append({"port_idx": port, "problem": "override still present"})
    for port, row in old.items():
        if port in updates or port in removed:
            continue
        if port not in new:
            mismatches.append({"port_idx": port, "problem": "unrelated override disappeared"})
        elif any(
            field not in new[port] or not leaf_equal(value, new[port][field])
            for field, value in row.items()
        ):
            # A field the controller adds to an untouched port is not a change; a field this
            # call did not set that went missing or changed value is.
            mismatches.append({"port_idx": port, "problem": "unrelated override changed"})
    return mismatches


def _warnings(merged: list[dict[str, Any]]) -> list[str]:
    rows = _by_port(merged)
    notes: list[str] = []
    for port, row in sorted(rows.items()):
        if row.get("op_mode") == _SPAN_MODE and _SPAN_PORT_FIELD not in row:
            notes.append(f"Port {port} has op_mode {_SPAN_MODE} but no {_SPAN_PORT_FIELD}.")
        if row.get("op_mode") != "aggregate":
            continue
        members = row.get("aggregate_members")
        if not isinstance(members, list):
            count = row.get("aggregate_num_ports")
            members = (
                list(range(port, port + count))
                if isinstance(count, int) and not isinstance(count, bool)
                else []
            )
        kept = [m for m in members if m != port and m in rows]
        if kept:
            notes.append(
                f"Port(s) {kept} in the aggregate on port {port} keep their own override; "
                "list them in remove_ports to clear them if the controller does not."
            )
    return notes


async def _profiles(
    client: UniFiClient, host_id: str, site_slug: str, key: APIKeyConfig | None
) -> tuple[Any, dict[str, str]]:
    path = classic_rest(host_id, site_slug, "/portconf")
    response = await client.get(path, key=key)
    require_classic_success(response, path)
    rows = object_records(
        response.get("data") if isinstance(response, dict) else response, "/rest/portconf data"
    )
    return response, _named_ids(rows, "/rest/portconf")


async def _networks(
    client: UniFiClient, host_id: str, site_slug: str, key: APIKeyConfig | None
) -> dict[str, str]:
    path = classic_rest(host_id, site_slug, "/networkconf")
    response = await client.get(path, key=key)
    require_classic_success(response, path)
    rows = object_records(
        response.get("data") if isinstance(response, dict) else response, "/rest/networkconf data"
    )
    return _named_ids(rows, "/rest/networkconf")


def _check_networks(
    updates: dict[int, dict[str, Any]], networks: dict[str, str], client: UniFiClient
) -> None:
    """Upstream-judged: every network id sent must be one rest/networkconf reported."""
    for port, fields in sorted(updates.items()):
        for name in _NETWORK_SCALARS:
            if name in fields and not isinstance(fields[name], str):
                raise ValueError(
                    f"port {port} field {name} must be a network id string from list_networks, "
                    f"got {upstream_error_text(fields[name], client)}"
                )
        for name in _NETWORK_LISTS:
            value = fields.get(name)
            if name in fields and (
                not isinstance(value, list) or not all(isinstance(v, str) for v in value)
            ):
                raise ValueError(
                    f"port {port} field {name} must be a list of network id strings from "
                    f"list_networks, got {upstream_error_text(value, client)}"
                )
        for name in (*_NETWORK_SCALARS, *_NETWORK_LISTS):
            if name not in fields:
                continue
            value = fields[name]
            for net in value if isinstance(value, list) else [value]:
                if net not in networks:
                    choices = [f"{label} ({nid})" for nid, label in networks.items()]
                    raise ValueError(
                        f"Unknown {name} {upstream_error_value(net, client)!r} for port "
                        f"{port}; valid networks from list_networks: {choices}"
                    )


def _ports_view(record: dict[str, Any], current: list[dict[str, Any]]) -> dict[str, Any]:
    overrides = _by_port(current)
    table = {
        row["port_idx"]: row
        for row in _port_table(record)
        if isinstance(row.get("port_idx"), int) and not isinstance(row.get("port_idx"), bool)
    }
    view: dict[str, Any] = {}
    for port in sorted(set(overrides) | set(table)):
        entry: dict[str, Any] = {
            "port_overrides": overrides.get(port),
            "port_table": table.get(port),
        }
        # An override for a port the table does not list (when the table is reported) is
        # dangling: it can be removed with remove_ports but never written or monitored.
        if table and port in overrides and port not in table:
            entry["_phantom"] = True
        view[str(port)] = entry
    return view


async def _get_switch_port_overrides(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str
) -> dict[str, Any]:
    validate_selector(device, "device")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    require_classic_success(response, "/stat/device")
    record = _select_one_record(
        _stat_records(response, "/stat/device"), device, "device", "/stat/device"
    )
    current, present = _overrides(record, require_switch=False)
    return with_context(
        response,
        {
            "_device": record,
            "_port_overrides": current,
            "_portOverridesPresent": present,
            "_ports": _ports_view(record, current),
            # Native op_mode value and companion key for port monitoring (SPAN); built at
            # runtime so an estate with no monitoring port yet can still learn them.
            "_spanMode": {"op_mode": _SPAN_MODE, "monitored_port_key": _SPAN_PORT_FIELD},
        },
    )


async def _update_switch_port_overrides(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    ports: Sequence[PortOverrideChange | dict[str, Any]] | None = None,
    remove_ports: list[int] | None = None,
    /,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    try:
        guard_action(TOOL)
    except ReadOnlyModeError:
        client.audit_refusal(tool=TOOL, reason="UNIFI_WRITE_POLICY")
        raise
    if not connector_writes_enabled():
        client.audit_refusal(tool=TOOL, reason=CONNECTOR_WRITE_ENV)
        raise mark_write_denied(PermissionError(connector_write_refusal(TOOL)))
    validate_selector(device, "device")
    parsed = [
        change
        if isinstance(change, PortOverrideChange)
        else PortOverrideChange.model_validate(change)
        for change in (ports or [])
    ]
    updates, removed = _validate_request(
        parsed,
        list(remove_ports or []),
        explicit=ports is not None or remove_ports is not None,
    )
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    lookup = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    require_classic_success(lookup, "/stat/device")
    resolved = _select_one_record(
        _stat_records(lookup, "/stat/device"), device, "device", "/stat/device"
    )
    mac, classic_id = resolved.get("mac"), resolved.get("_id")
    if not isinstance(mac, str) or not is_mac(mac) or not isinstance(classic_id, str):
        raise UniFiConnectionError(
            f"Unexpected /stat/device: a port override write needs mac and Classic _id, got "
            f"{upstream_error_text(resolved, client)}"
        )
    validate_id(classic_id, "Classic device _id")
    _overrides(resolved)  # refuse a non-switch before touching the profile list or lock
    profile_ids = {fields["portconf_id"] for fields in updates.values() if "portconf_id" in fields}
    profiles_response = None
    if profile_ids:
        profiles_response, profiles = await _profiles(client, host_id, site_slug, key)
        for port, fields in sorted(updates.items()):
            wanted = fields.get("portconf_id")
            if "portconf_id" in fields and wanted not in profiles:
                choices = [f"{name} ({pid})" for pid, name in profiles.items()]
                raise ValueError(
                    f"Unknown portconf_id {upstream_error_value(wanted, client)!r} for port "
                    f"{port}; valid port profiles from list_port_profiles: {choices}"
                )
    if any(name in f for f in updates.values() for name in (*_NETWORK_SCALARS, *_NETWORK_LISTS)):
        _check_networks(updates, await _networks(client, host_id, site_slug, key), client)
    path = classic_rest(host_id, site_slug, f"/device/{classic_id}")

    async with switch_lock(client, host_id, site_slug, classic_id):
        # Read the array under the lock, immediately before merging, so a concurrent
        # editor call on the same switch merges into this call's written result.
        before_response, record = await _read_device(client, host_id, site_slug, mac, key)
        if record.get("_id") != classic_id:
            raise ValueError(
                f"Device identity changed during resolution; read back before retrying "
                f"({upstream_error_value(classic_id, client)!r} -> "
                f"{upstream_error_text(record.get('_id'), client)})"
            )
        before, _present = _overrides(record)
        _check_against_device(updates, removed, before, _device_ports(record, before))
        desired, plan = _merge(before, updates, removed)
        body = {"port_overrides": desired}

        async def read_after() -> tuple[dict[str, Any], Any, dict[str, Any]]:
            response, after_record = await _read_device(client, host_id, site_slug, mac, key)
            if after_record.get("_id") != classic_id:
                raise UniFiConnectionError(
                    "Device identity changed on read-after; read back before retrying"
                )
            rows, _present = _overrides(after_record)
            return response, rows, {}

        result = await update_device_config(
            client, path, before, desired, body, read_after, _diff, key=key, dry_run=dry_run
        )

    context: dict[str, Any] = {
        "_plan": plan,
        "_warnings": _warnings(desired),
        "_readBeforeResponse": before_response,
        "_lookupResponse": lookup,
    }
    if profiles_response is not None:
        context["_portProfilesResponse"] = profiles_response
    if "readAfterError" in result:
        context["_outcome"] = "unknown"
        context["_mismatches"] = None
    elif "readAfter" in result:
        mismatches = _verify(before, result["readAfter"], updates, removed, desired)
        context["_mismatches"] = mismatches
        context["_outcome"] = "verified" if not mismatches else "mismatch"
        result = {**result, "_verified": not mismatches}
    else:
        context["_outcome"] = "preview"
    return with_context(result, context)
