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

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, is_dry_run_preview, validate_selector
from ..config import APIKeyConfig
from ..macs import colon_mac, is_mac
from ..matching import find_by_id, name_matches, same_id
from ..registry import Registry
from ..tool_annotations import WRITE
from ._classic_objects import (
    _classic_data,
    classic_rest,
    listed_record_id,
    resolve_site_slug,
    v2_site,
)
from ._payload import with_upstream_hint
from ._results import deletion_result

_CONSOLE_SITE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}"


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


def _describe_users(records: list[dict[str, Any]]) -> str:
    return (
        "; ".join(
            f"{r.get('name') or r.get('hostname') or '(unnamed)'} "
            f"(mac={r.get('mac')}, _id={r.get('_id')})"
            for r in records
        )
        or "(none)"
    )


async def _resolve_user(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    ref: str,
    *,
    key: APIKeyConfig | None,
) -> dict[str, Any]:
    """The known-client (``rest/user``) record selected by its ``_id`` or MAC.

    The Classic list is read once (it is unpaged). A MAC that has no record fails
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
                f"{_describe_users(matches)}. Pass the record's _id."
            )
        if not matches:
            raise ValueError(
                f"Client MAC {mac} not found among this site's client records: the controller "
                "has never seen this client (create_client_reservation creates a record for "
                f"it). Records: {_describe_users(records)}. Pass a MAC or _id from list_users."
            )
        record = matches[0]
    else:
        found = find_by_id(records, ref, "_id")
        if found is None:
            raise ValueError(
                f"Client record {ref!r} not found by _id or MAC; records: "
                f"{_describe_users(records)}. Pass a client MAC or the _id from list_users."
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
            f"{r.get('name')!r} (_id={r.get('_id')}, id={r.get('external_id')}, "
            f"purpose={r.get('purpose')})"
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


#: ``list_guests`` sources: Classic ``stat/guest`` (default) and the controller's v2 hotspot
#: client list (Network 11.0.81 web UI, GET /proxy/network/v2/api/site/{site}/hotspot/clients).
GUEST_SOURCES = ("classic", "v2")


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


def _describe_guests(records: list[dict[str, Any]]) -> str:
    return (
        "; ".join(
            f"mac={r.get('mac')} _id={r.get('_id')} end={r.get('end')} expired={r.get('expired')}"
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
                f"authorization(s): {_describe_guests(mine or records)}. Pass the guest _id "
                "from list_guests."
            )
        record = picked[0]
    else:
        by_id = [r for r in records if same_id(guest, r.get("_id"))]
        if not by_id:
            raise ValueError(
                f"Guest {guest!r} not found by _id or MAC; guests: {_describe_guests(records)}. "
                "Get it from list_guests (_id or mac)."
            )
        record = by_id[0]
    guest_id = listed_record_id(record, "guest")
    return await client.post(
        _classic(host_id, site_slug, "/cmd/hotspot"),
        key=key,
        json={"cmd": "extend", "_id": guest_id},
    )


_FIXED_IP_HINT = (
    "set_client_fixed_ip / create_client_reservation: the controller needs the network the "
    "address belongs to; pass network (name, _id or Integration id from list_networks) when "
    "the client record has no network_id yet, and an address inside that network's subnet."
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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the client-record MCP tools."""

    @mcp.tool(annotations=WRITE)
    async def forget_client(
        host: str,
        site: str,
        mac: str | list[str],
    ) -> Any:
        """Forget clients: delete the controller's record of each client (the UI's "Forget").

        Consequence: the client's whole list_users record is deleted, with everything stored
        on it (name, note, fixed-IP reservation, user group, the blocked flag). There is no
        undo.

        No published spec covers this, so it uses the Classic REST station manager: POST
        network/api/s/{site}/cmd/stamgr with {"cmd": "forget-sta", "macs": [MAC, ...]} (MACs in
        lowercase colon form, duplicates collapsed), ONE request for every MAC given. Verified
        on Network 11.0.81: the client's list_users record is gone on the next read. A MAC the
        controller does not know is accepted (rc ok) and changes nothing.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} for one MAC or a
        list alike, since the controller answers the whole batch with one envelope (under
        UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead). Not auto-retried
        on HTTP 429: a retry could repeat the action.

        Example call (forget_client):
            {
              "host": "my-console",
              "site": "Default",
              "mac": ["aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:01"]
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            mac: Client MAC (any separator style, e.g. "aa:bb:cc:dd:ee:ff" or "AABBCCDDEEFF") or
                a list of MACs to forget several clients in one request. Get them from
                list_known_clients (mac; includes offline and blocked clients) or list_users
                (mac).
                Shape: string|string[]
        """
        client, registry = deps_fn()
        return await _forget_client(client, registry, host, site, mac)

    @mcp.tool(annotations=WRITE)
    async def list_guests(
        host: str,
        site: str,
        within_hours: int | None = None,
        source: str | None = None,
    ) -> Any:
        """List guest authorizations (hotspot / guest-portal guests) of a site.

        Each record is one authorization: {_id, mac, start, end (epoch seconds), expired,
        authorized_by, bytes, rx_bytes, tx_bytes, qos_overwrite, ...} as the controller reports
        it. The _id is what extend_guest takes.

        Classic REST network/api/s/{site}/stat/guest: a GET when within_hours is unset (the
        controller's own window), else a POST {"within": within_hours}. Returns the upstream
        body verbatim: {meta: {rc}, data: [guest, ...]}; a scalar POST response is returned
        verbatim after the write, while a malformed Classic GET envelope raises with the shape
        received. With source "v2", GET
        network/v2/api/site/{site}/hotspot/clients (the web UI's hotspot client list) is
        returned verbatim instead.

        The POST form is a write pending a separately approved read-POST allowlist PR.
        Consequence: none intended; both forms only read guest records. UNIFI_READ_ONLY
        hides the whole tool, including both GET forms. With UNIFI_DRY_RUN, the POST returns
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}} without sending it; the GET form returns the usual response.

        Example call (list_guests):
            {
              "host": "my-console",
              "site": "Default",
              "within_hours": 24
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            within_hours: Optional window in hours: only authorizations active within the last
                within_hours hours (e.g. 24, or 8760 for a year). Omitted, the request carries no
                window and the controller applies its own. Classic source only.
                Example: `24`.
            source: Optional route: "classic" (default, stat/guest) or "v2" (the v2
                hotspot client list, a GET; within_hours does not apply).
                Example: `v2`.
        """
        client, registry = deps_fn()
        return await _list_guests(client, registry, host, site, within_hours, source)

    @mcp.tool(annotations=WRITE)
    async def extend_guest(
        host: str,
        site: str,
        guest: str,
    ) -> Any:
        """Extend a guest authorization (the UI's "Extend" on a guest).

        Consequence: the guest keeps network access longer; the controller adds its own
        increment (24 hours on Network 11.0.81: end moved on by 86,400 s). Network 11.0.89
        also stored qos_usage_quota: -1 on a guest record that had none; the tool sends only
        the extend command and returns what the controller answers.

        The guest is resolved in list_guests first: by its _id, or by MAC (the one active
        authorization of that MAC; with no active one, its only authorization). An unknown
        value, or a MAC with several matching authorizations, fails listing the guests and
        nothing is sent. Then POST network/api/s/{site}/cmd/hotspot with {"cmd": "extend",
        "_id": GUEST_ID} (Classic REST, no published spec).

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead). Read
        list_guests afterwards for the new end. Not auto-retried on HTTP 429: a retry could
        extend twice.

        Example call (extend_guest):
            {
              "host": "my-console",
              "site": "Default",
              "guest": "aa:bb:cc:dd:ee:ff"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            guest: The guest authorization _id from list_guests (data[]._id, e.g.
                "6523f0c1e4b0a1b2c3d4e5f6") or the guest's MAC (any separator style).
        """
        client, registry = deps_fn()
        return await _extend_guest(client, registry, host, site, guest)

    @mcp.tool(annotations=WRITE)
    async def set_client_name(
        host: str,
        site: str,
        client: str,
        name: str,
    ) -> Any:
        """Set the display name (alias) the controller shows for a known client.

        The client's known-client record (list_users) is resolved by MAC or _id first; a MAC
        with no record fails pointing at create_client_reservation, and an unknown _id fails
        listing the records; nothing is sent then. Then Classic REST PUT
        network/api/s/{site}/rest/user/{_id} with {"name": name}, sent as given (verified on
        Network 11.0.81: the name reads back).

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the updated record]}
        (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Example call (set_client_name):
            {
              "host": "my-console",
              "site": "Default",
              "client": "aa:bb:cc:dd:ee:ff",
              "name": "Living room TV"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client: The client's MAC (any separator style) or its known-client record _id from
                list_users (_id), e.g. "aa:bb:cc:dd:ee:ff". Not the list_clients UUID.
            name: The new display name, e.g. "Living room TV"; sent as given.
        """
        client_, registry = deps_fn()
        return await _put_user(client_, registry, host, site, client, {"name": name})

    @mcp.tool(annotations=WRITE)
    async def set_client_note(
        host: str,
        site: str,
        client: str,
        note: str,
    ) -> Any:
        """Set the free-text note the controller keeps on a known client.

        The client's known-client record (list_users) is resolved by MAC or _id first; a MAC
        with no record fails pointing at create_client_reservation, and an unknown _id fails
        listing the records; nothing is sent then. Then Classic REST PUT
        network/api/s/{site}/rest/user/{_id} with {"note": note}, sent as given (verified on
        Network 11.0.81: the note reads back and the controller sets noted to true).

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the updated record]}
        (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Example call (set_client_note):
            {
              "host": "my-console",
              "site": "Default",
              "client": "aa:bb:cc:dd:ee:ff",
              "note": "Kids' tablet, bedtime schedule"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client: The client's MAC (any separator style) or its known-client record _id from
                list_users (_id), e.g. "aa:bb:cc:dd:ee:ff". Not the list_clients UUID.
            note: The note text, e.g. "Kids' tablet"; sent as given.
        """
        client_, registry = deps_fn()
        return await _put_user(client_, registry, host, site, client, {"note": note})

    @mcp.tool(annotations=WRITE)
    async def set_client_fixed_ip(
        host: str,
        site: str,
        client: str,
        fixed_ip: str,
        network: str | None = None,
    ) -> Any:
        """Reserve a fixed IP (DHCP reservation) for a known client.

        Consequence: the gateway's DHCP server reserves this address for the client; the client
        gets it when it next renews its DHCP lease.

        The client's known-client record (list_users) is resolved by MAC or _id first (a MAC
        with no record fails pointing at create_client_reservation); network, when given, is
        resolved to its networkconf _id by _id, Integration id or name, an unknown one failing
        with the list of networks. Then Classic REST PUT network/api/s/{site}/rest/user/{_id}
        with {"use_fixedip": true, "fixed_ip": fixed_ip} plus network_id when network was
        given (verified on Network 11.0.81: all three read back). The controller validates the
        address; an upstream error gets a hint.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the updated record]}
        (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Example call (set_client_fixed_ip):
            {
              "host": "my-console",
              "site": "Default",
              "client": "aa:bb:cc:dd:ee:ff",
              "fixed_ip": "192.168.1.50",
              "network": "Default"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client: The client's MAC (any separator style) or its known-client record _id from
                list_users (_id), e.g. "aa:bb:cc:dd:ee:ff". Not the list_clients UUID.
            fixed_ip: The IPv4 address to reserve, inside the network's subnet, e.g.
                "192.168.1.50".
            network: Optional network the address belongs to: its name (e.g. "Default"), its
                Integration id (list_networks data[].id) or its networkconf _id. Omitted, no
                network_id is sent and the record keeps the one it has.
        """
        client_, registry = deps_fn()
        return await _set_client_fixed_ip(client_, registry, host, site, client, fixed_ip, network)

    @mcp.tool(annotations=WRITE)
    async def remove_client_fixed_ip(
        host: str,
        site: str,
        client: str,
    ) -> Any:
        """Remove a known client's fixed-IP (DHCP) reservation.

        Consequence: the reservation no longer applies; the client gets a pool address when it
        next renews its DHCP lease.

        The client's known-client record (list_users) is resolved by MAC or _id first (a MAC
        with no record fails pointing at create_client_reservation). Then Classic REST PUT
        network/api/s/{site}/rest/user/{_id} with {"use_fixedip": false} (verified on Network
        11.0.81: use_fixedip reads back false; the controller keeps the last fixed_ip value on
        the record, unused).

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). For this PUT the body is the Classic envelope {meta: {rc}, data: [the updated
        record]}. Under UNIFI_DRY_RUN nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query
        parameters), body}}.

        Example call (remove_client_fixed_ip):
            {
              "host": "my-console",
              "site": "Default",
              "client": "aa:bb:cc:dd:ee:ff"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client: The client's MAC (any separator style) or its known-client record _id from
                list_users (_id), e.g. "aa:bb:cc:dd:ee:ff". Not the list_clients UUID.
        """
        client_, registry = deps_fn()
        response = await _put_user(client_, registry, host, site, client, {"use_fixedip": False})
        return deletion_result(f"Fixed-IP reservation of client {client} removed.", response)

    @mcp.tool(annotations=WRITE)
    async def create_client_reservation(
        host: str,
        site: str,
        mac: str,
        name: str | None = None,
        note: str | None = None,
        fixed_ip: str | None = None,
        network: str | None = None,
        fields: dict[str, Any] | None = None,
    ) -> Any:
        """Create a known-client record for a MAC the controller has not seen yet, to
        pre-assign its name, note or fixed IP before the device first connects.

        Classic REST POST network/api/s/{site}/rest/user with {"mac": MAC} plus name / note
        when given, {"use_fixedip": true, "fixed_ip": fixed_ip} when fixed_ip is given, and
        network_id when network is given (resolved by _id, Integration id or name, an unknown
        one failing with the list of networks). Verified on Network 11.0.81 with a synthetic
        MAC: the record appears in list_users. For a client that already has a record use
        set_client_name, set_client_note or set_client_fixed_ip; the controller judges a
        duplicate MAC and an upstream error gets a hint.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the created record]}
        (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Example call (create_client_reservation):
            {
              "host": "my-console",
              "site": "Default",
              "mac": "aa:bb:cc:dd:ee:ff",
              "name": "Printer",
              "fixed_ip": "192.168.1.60",
              "network": "Default"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            mac: The client's MAC (any separator style; sent in lowercase colon form), e.g.
                "aa:bb:cc:dd:ee:ff".
            name: Optional display name, e.g. "Printer"; omitted when unset.
            note: Optional note text; omitted when unset.
            fixed_ip: Optional IPv4 address to reserve, e.g. "192.168.1.60"; sets use_fixedip.
            network: Optional network for the reservation: name (e.g. "Default"), Integration id
                (list_networks data[].id) or networkconf _id.
            fields: Optional further native rest/user keys (e.g. usergroup_id,
                local_dns_record_enabled, local_dns_record), merged into the body; mac and the
                explicit arguments take precedence.
                Free-form JSON object; no fixed body shape is published.
        """
        client_, registry = deps_fn()
        return await _create_client_reservation(
            client_,
            registry,
            host,
            site,
            mac,
            name=name,
            note=note,
            fixed_ip=fixed_ip,
            network=network,
            fields=fields,
        )
