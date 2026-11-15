"""Client record tools: forget clients, guests, and the known-client record (name, note,
fixed IP, reservation) via the Classic REST controller.

Every route here was proven live on Network 11.0.81 with synthetic objects (an RFC 7042
documentation MAC), then removed:

* ``cmd/stamgr`` ``{"cmd": "forget-sta", "macs": [...]}`` deletes the controller's record
  of each client (its ``rest/user`` entry is gone on the next read).
* ``stat/guest`` lists guest authorizations (a GET, or a POST ``{"within": hours}``).
* ``cmd/hotspot`` ``{"cmd": "extend", "_id": <guest _id>}`` extends a guest
  authorization (the controller moved ``end`` on by 24 h); an unknown ``_id`` answers
  HTTP 400 ``api.err.UnknownGuest``.
* ``rest/user`` holds the known-client record: PUT ``rest/user/{_id}`` saves ``name``,
  ``note`` and ``use_fixedip`` / ``fixed_ip`` / ``network_id`` (read back after each
  write); POST ``rest/user`` creates a record for a MAC the controller has not seen.
"""

from __future__ import annotations

import re
from typing import Any

from ...client import (
    ClassicApiError,
    UniFiClient,
    UniFiConnectionError,
    is_dry_run_preview,
    upstream_error_value,
    validate_id,
    validate_selector,
)
from ...config import APIKeyConfig
from ...macs import colon_mac, is_mac
from ...matching import find_by_id, name_matches, same_id
from ...registry import Registry
from ...shared_shapes._classic_objects import (
    _classic_data,
    classic_rest,
    listed_record_id,
    resolve_site_slug,
    v2_site,
)
from ...shared_shapes._payload import with_upstream_hint
from ...shared_shapes._results import deletion_result
from .schemas import (  # the family's shapes (family-owned layout)
    _CLASSIC_NOT_FOUND_MSGS,
    _CONSOLE_SITE,
    _FIXED_IP_HINT,
    GUEST_SOURCES,
)


def _classic(host_id: str, site_slug: str, path: str) -> str:
    """Connector URL of a Classic ``api/s/{site}`` path (``/cmd/...``, ``/stat/...``)."""
    return _CONSOLE_SITE.format(host_id=host_id, site_slug=site_slug) + path


def _require_macs(mac: Any, arg: str, source: str) -> list[str]:
    """``mac`` (one MAC or a list) as lowercase colon MACs, duplicates collapsed in order.

    Fails before any request on an empty list or any entry that is not a MAC, naming
    every bad entry."""
    macs = [mac] if isinstance(mac, str) else mac
    if not isinstance(macs, list) or not macs:
        raise ValueError(
            f"{arg} is empty: pass one client MAC (e.g. 'aa:bb:cc:dd:ee:ff') or a non-empty "
            f"list of MACs. Get them from {source}."
        )
    bad = [m for m in macs if not is_mac(m)]
    if bad:
        raise ValueError(
            f"Not a MAC address in {arg}: {bad!r}. Pass client MACs (any separator style, "
            f"e.g. 'aa:bb:cc:dd:ee:ff' or 'AABBCCDDEEFF'); get them from {source}."
        )
    return list(dict.fromkeys(colon_mac(m) for m in macs))


def _describe_users(records: list[dict[str, Any]], client: UniFiClient) -> str:
    return (
        "; ".join(
            f"{upstream_error_value(r.get('name') or r.get('hostname') or '(unnamed)', client)} "
            f"(mac={upstream_error_value(r.get('mac'), client)}, "
            f"_id={upstream_error_value(r.get('_id'), client)})"
            for r in records
        )
        or "(none)"
    )


_CLASSIC_MSG_RE = re.compile(r"\(meta\.msg '([^']*)'\)")


def _classic_msg(exc: ClassicApiError) -> str | None:
    """The ``meta.msg`` code a Classic error carries, or ``None``."""
    found = _CLASSIC_MSG_RE.search(str(exc))
    return found.group(1) if found else None


async def _read_user_by_id(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    ref: str,
    *,
    key: APIKeyConfig | None,
) -> dict[str, Any] | None:
    """The ``rest/user/{ref}`` record whose own ``_id`` is ``ref``, else ``None``.

    ``None`` means the individual resource does not exist (HTTP 404, a Classic
    not-found code, or no row) or its returned identity is not ``ref``: the caller then reports
    the usual not-found error and no write is sent. Any other failure (authentication,
    server error, transport) propagates unchanged; it is not evidence of absence.
    """
    try:
        validate_id(ref, "client")
    except ValueError:
        return None
    path = classic_rest(host_id, site_slug, f"/user/{ref}")
    try:
        rows = _classic_data(await client.get(path, key=key), path)
    except ClassicApiError as exc:
        if _classic_msg(exc) in _CLASSIC_NOT_FOUND_MSGS:
            return None
        raise
    except UniFiConnectionError as exc:
        if exc.status == 404:
            return None
        raise
    matches = [r for r in rows if same_id(ref, r.get("_id"))]
    return matches[0] if len(matches) == 1 else None


async def _resolve_user(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    ref: str,
    *,
    key: APIKeyConfig | None,
) -> dict[str, Any]:
    """The known-client (``rest/user``) record selected by its ``_id`` or MAC.

    The Classic list is read once and may be partial; an ``_id`` it omits is then read from
    the individual ``rest/user/{id}`` resource. A MAC that has no record fails
    pointing at create_client_reservation; an ``_id`` that matches nothing fails listing
    every record (name, mac, _id). The record's own ``_id`` is validated as a URL path
    id before it is used.
    """
    path = classic_rest(host_id, site_slug, "/user")
    records = _classic_data(await client.get(path, key=key), path)
    if is_mac(ref):
        mac = colon_mac(ref)
        matches = [r for r in records if is_mac(r.get("mac")) and colon_mac(r["mac"]) == mac]
        if len(matches) > 1:
            raise ValueError(
                f"MAC {ref!r} matches {len(matches)} client records: "
                f"{_describe_users(matches, client)}. Pass the record's _id."
            )
        if not matches:
            raise ValueError(
                f"Client MAC {mac} not found among this site's client records: the controller "
                "has never seen this client (create_client_reservation creates a record for "
                f"it). Records: {_describe_users(records, client)}. "
                "Pass a MAC or _id from list_users."
            )
        record = matches[0]
    else:
        found = find_by_id(records, ref, "_id")
        if found is None:
            # The collection is one answer that may be partial (capped or truncated), so
            # absence from it does not prove the id is unknown (public issue #48): ask the
            # individual resource. A syntactically unsafe id never reaches a URL.
            found = await _read_user_by_id(client, host_id, site_slug, ref, key=key)
        if found is None:
            raise ValueError(
                f"Client record {ref!r} not found by _id or MAC; records: "
                f"{_describe_users(records, client)}. Pass a client MAC or the _id from list_users."
            )
        record = found
    listed_record_id(record, "client")
    return record


async def _put_user(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ref: str,
    body: dict[str, Any],
    /,
) -> Any:
    """PUT ``body`` on the ``rest/user`` record selected by ``ref`` (``_id`` or MAC)."""
    validate_selector(ref, "client")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    record = await _resolve_user(client, host_id, site_slug, ref, key=key)
    upstream_id = listed_record_id(record, "client")
    return await client.put(
        classic_rest(host_id, site_slug, f"/user/{upstream_id}"), key=key, json=body
    )


async def _resolve_network_id(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    network: str,
    *,
    key: APIKeyConfig | None,
) -> str:
    """The networkconf ``_id`` of ``network``: its ``_id``, Integration id
    (``external_id``) or name. An unknown or ambiguous value fails listing every network."""
    validate_selector(network, "network")
    path = classic_rest(host_id, site_slug, "/networkconf")
    records = _classic_data(await client.get(path, key=key), path)
    valid = (
        "; ".join(
            f"{upstream_error_value(r.get('name'), client)!r} "
            f"(_id={upstream_error_value(r.get('_id'), client)}, "
            f"id={upstream_error_value(r.get('external_id'), client)}, "
            f"purpose={upstream_error_value(r.get('purpose'), client)})"
            for r in records
        )
        or "(none)"
    )
    match = find_by_id(records, network, "_id", "external_id")
    if match is None:
        named = name_matches(records, network, lambda r: r.get("name"))
        if len({id(r) for r in named}) > 1:
            raise ValueError(
                f"Network name {network!r} matches {len(named)} networks; pass its _id. "
                f"Networks: {valid}."
            )
        match = named[0] if named else None
    if match is None:
        raise ValueError(f"Network {network!r} not found by _id, id or name; networks: {valid}.")
    return listed_record_id(match, "network")


async def _forget_client(
    client: UniFiClient, registry: Registry, host: str, site: str, mac: str | list[str]
) -> Any:
    macs = _require_macs(mac, "mac", "list_known_clients (mac) or list_users (mac)")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.post(
        _classic(host_id, site_slug, "/cmd/stamgr"),
        key=key,
        json={"cmd": "forget-sta", "macs": macs},
    )


def _guest_source(source: str | None, within_hours: int | None) -> str:
    """The route list_guests reads: a blank or omitted ``source`` keeps Classic; a source
    outside :data:`GUEST_SOURCES`, or ``within_hours`` (Classic only) with ``v2``,
    is refused before any request."""
    chosen = source.strip().lower() if isinstance(source, str) and source.strip() else "classic"
    if chosen not in GUEST_SOURCES:
        raise ValueError(
            f"list_guests source must be one of {', '.join(GUEST_SOURCES)} (got {source!r})"
        )
    if chosen == "v2" and within_hours is not None:
        raise ValueError(
            "list_guests source conflict: within_hours applies only to source 'classic', but "
            "source 'v2' was given; omit within_hours or omit source."
        )
    return chosen


async def _list_guests(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    within_hours: int | None,
    source: str | None = None,
) -> Any:
    chosen = _guest_source(source, within_hours)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    if chosen == "v2":
        # The v2 hotspot client list, verbatim (its body shape is not published).
        return await client.get(v2_site(host_id, site_slug, "/hotspot/clients"), key=key)
    if within_hours is None:
        body = await client.get(_classic(host_id, site_slug, "/stat/guest"), key=key)
    else:
        body = await client.post(
            _classic(host_id, site_slug, "/stat/guest"), key=key, json={"within": within_hours}
        )
    if is_dry_run_preview(body):
        return body
    # The POST has already been applied.  Preserve a scalar response verbatim rather
    # than turning a successful write into an envelope-shape error.  The GET path
    # remains strict, because it has no applied mutation to report.
    if within_hours is not None and not isinstance(body, dict):
        return body
    _classic_data(body, "stat/guest")
    return body


def _describe_guests(records: list[dict[str, Any]], client: UniFiClient) -> str:
    return (
        "; ".join(
            f"mac={upstream_error_value(r.get('mac'), client)} "
            f"_id={upstream_error_value(r.get('_id'), client)} "
            f"end={upstream_error_value(r.get('end'), client)} "
            f"expired={upstream_error_value(r.get('expired'), client)}"
            for r in records
        )
        or "(none)"
    )


async def _extend_guest(
    client: UniFiClient, registry: Registry, host: str, site: str, guest: str
) -> Any:
    validate_selector(guest, "guest")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    path = _classic(host_id, site_slug, "/stat/guest")
    records = _classic_data(await client.get(path, key=key), path)
    if is_mac(guest):
        mac = colon_mac(guest)
        mine = [r for r in records if is_mac(r.get("mac")) and colon_mac(r["mac"]) == mac]
        active = [r for r in mine if r.get("expired") is not True]
        picked = active if active else mine
        if len(picked) != 1:
            raise ValueError(
                f"Guest MAC {mac} matches {len(picked)} {'active ' if active else ''}guest "
                f"authorization(s): {_describe_guests(mine or records, client)}. "
                "Pass the guest _id "
                "from list_guests."
            )
        record = picked[0]
    else:
        by_id = [r for r in records if same_id(guest, r.get("_id"))]
        if not by_id:
            raise ValueError(
                f"Guest {guest!r} not found by _id or MAC; guests: "
                f"{_describe_guests(records, client)}. "
                "Get it from list_guests (_id or mac)."
            )
        record = by_id[0]
    guest_id = listed_record_id(record, "guest")
    return await client.post(
        _classic(host_id, site_slug, "/cmd/hotspot"),
        key=key,
        json={"cmd": "extend", "_id": guest_id},
    )


async def _set_client_fixed_ip(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ref: str,
    fixed_ip: str,
    network: str | None,
) -> Any:
    validate_selector(ref, "client")
    if network is not None:
        validate_selector(network, "network")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    record = await _resolve_user(client, host_id, site_slug, ref, key=key)
    body: dict[str, Any] = {"use_fixedip": True, "fixed_ip": fixed_ip}
    if network is not None:
        body["network_id"] = await _resolve_network_id(client, host_id, site_slug, network, key=key)
    upstream_id = listed_record_id(record, "client")
    return await with_upstream_hint(
        client.put(classic_rest(host_id, site_slug, f"/user/{upstream_id}"), key=key, json=body),
        _FIXED_IP_HINT,
    )


def _fixed_ip_removal_result(ref: str, upstream_id: str, response: Any) -> dict[str, Any]:
    """The removal result, confirmed only by the returned record itself (public issue #47).

    The result is :func:`deletion_result` (``{deleted, message, response}``, the upstream
    body verbatim). A 2xx answer to the PUT means the request was accepted, not that the
    reservation is gone, so ``deleted`` stays true only when every returned Classic row for
    this client's ``_id`` states ``use_fixedip: false``. A row that still says ``true``
    contradicts the removal; a body whose ``data`` is not a list of objects, or that has no
    row for the client or no boolean state, leaves it unverified. Both report ``deleted:
    false`` with a message naming the reason, and the body received stays under
    ``response``. The PUT is never retried, and a dry-run preview keeps the dry-run result.
    """
    result = deletion_result(f"Fixed-IP reservation of client {ref} removed.", response)
    if is_dry_run_preview(response):
        return result
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        reason = "the response is not a Classic envelope whose data is a list of client records"
    else:
        states = [row.get("use_fixedip") for row in data if same_id(upstream_id, row.get("_id"))]
        if states and all(state is False for state in states):
            return result
        if any(state is True for state in states):
            reason = "the controller still returns use_fixedip: true for this client"
        else:
            reason = "the response carries no use_fixedip state for this client to confirm it"
    result.update(
        deleted=False,
        message=(
            f"Removal of the fixed-IP reservation of client {ref} is not confirmed: {reason}. "
            "The request was sent once and not retried; read the record with get_user to see "
            "its current state, then retry remove_client_fixed_ip only if it is still reserved."
        ),
    )
    return result


async def _remove_client_fixed_ip(
    client: UniFiClient, registry: Registry, host: str, site: str, ref: str
) -> Any:
    validate_selector(ref, "client")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    record = await _resolve_user(client, host_id, site_slug, ref, key=key)
    upstream_id = listed_record_id(record, "client")
    response = await client.put(
        classic_rest(host_id, site_slug, f"/user/{upstream_id}"),
        key=key,
        json={"use_fixedip": False},
    )
    return _fixed_ip_removal_result(ref, upstream_id, response)


async def _create_client_reservation(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mac: str,
    *,
    name: str | None,
    note: str | None,
    fixed_ip: str | None,
    network: str | None,
    fields: dict[str, Any] | None,
) -> Any:
    if not is_mac(mac):
        raise ValueError(
            f"Not a MAC address: {mac!r}. Pass the client's MAC (any separator style, e.g. "
            "'aa:bb:cc:dd:ee:ff' or 'AABBCCDDEEFF')."
        )
    if network is not None:
        validate_selector(network, "network")
    body: dict[str, Any] = dict(fields or {})
    body["mac"] = colon_mac(mac)
    if name is not None:
        body["name"] = name
    if note is not None:
        body["note"] = note
    if fixed_ip is not None:
        body["use_fixedip"] = True
        body["fixed_ip"] = fixed_ip
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    if network is not None:
        body["network_id"] = await _resolve_network_id(client, host_id, site_slug, network, key=key)
    return await with_upstream_hint(
        client.post(classic_rest(host_id, site_slug, "/user"), key=key, json=body),
        "create_client_reservation creates a record for a MAC the controller has not seen; "
        "a MAC that already has one is changed with set_client_name, set_client_note or "
        "set_client_fixed_ip (list_users shows the records). "
        + (_FIXED_IP_HINT if fixed_ip is not None else ""),
    )
