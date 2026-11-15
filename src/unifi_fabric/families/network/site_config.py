"""Site configuration CRUD on the routes the controller's own UI uses (no published spec).

User groups, static routes, legacy firewall rules, RADIUS profiles, port profiles and
Dynamic DNS are Classic REST collections (``/proxy/network/api/s/{site}/rest/<collection>``,
``{meta, data}`` envelopes); AP groups and RADIUS accounts are v2 collections
(``/proxy/network/v2/api/site/{site}/apgroups`` and ``.../radius/users``, bare JSON). RADIUS
accounts are written only through the v2 batch routes the Network 11.0.81 UI uses
(``radius/users/batch_add``, ``batch_update``, ``batch_delete``, each a POST of a JSON
array); the single-object tools send one-element batches. None of them is in a published
UniFi spec: the routes are the ones the controller web UI uses, defined by the
open-source clients (go-unifi, the Art-of-WiFi UniFi API client) or the Network 11.0.81
front end, and probed live on Network 11.0.81.

Every update and delete resolves its id in the collection list first: the controller
answers a DELETE of an unknown id with HTTP 200, so a wrong id would otherwise report a
deletion that never happened. The write then addresses the record's own ``_id``.
"""

from __future__ import annotations

from typing import Any

from ...client import (
    UniFiClient,
    is_dry_run_preview,
    strip_additive_keys,
    upstream_error_value,
    validate_id,
    validate_selector,
)
from ...macs import colon_mac, is_mac
from ...matching import find_by_id
from ...registry import Registry
from ...shared_shapes._classic_objects import (
    classic_rest,
    listed_record_id,
    resolve_site_slug,
)
from ...shared_shapes._payload import (
    missing_fields_hint,
    with_upstream_hint,
)
from ...shared_shapes._results import deletion_result, with_read_after_error
from ...shared_shapes._site_config_shared import (
    _UNCOMPARED as _UNCOMPARED,
)
from ...shared_shapes._site_config_shared import (  # noqa: F401  (shared)
    RADIUS_PROFILES as RADIUS_PROFILES,
)
from ...shared_shapes._site_config_shared import (
    _addressed_config_body as _addressed_config_body,
)
from ...shared_shapes._site_config_shared import (
    _Collection as _Collection,
)
from ...shared_shapes._site_config_shared import (
    _config_label as _config_label,
)
from ...shared_shapes._site_config_shared import (
    _config_rows as _config_rows,
)
from ...shared_shapes._site_config_shared import (
    _delete_config_record as _delete_config_record,
)
from ...shared_shapes._site_config_shared import (
    _merge_config_body as _merge_config_body,
)
from ...shared_shapes._site_config_shared import (
    _readable_config_equal as _readable_config_equal,
)
from ...shared_shapes._site_config_shared import (
    _resolve_config_record as _resolve_config_record,
)
from ...shared_shapes._site_config_shared import (
    _select_config_record as _select_config_record,
)
from ...shared_shapes._site_config_shared import (
    _update_config_record as _update_config_record,
)
from ...shared_shapes._site_config_shared import (
    _valid_config_records as _valid_config_records,
)
from ...shared_shapes._site_config_shared import (
    _with_config_write_warnings as _with_config_write_warnings,
)
from ...shared_shapes._site_config_shared import (
    _written_config_record as _written_config_record,
)
from .network_services_proxy import (
    _envelope_with_resolution,
    _name_map_or_error,
    _with_classic_networkconf_ids,
    _without_resolved_networks,
)

USER_GROUPS = _Collection("/usergroup", "User group", "list_user_groups")
STATIC_ROUTES = _Collection("/routing", "Static route", "list_routing_entries")
RADIUS_ACCOUNTS = _Collection(
    "/radius/users", "RADIUS account", "list_accounts", v2=True, batch=True
)
PORT_PROFILES = _Collection("/portconf", "Port profile", "list_port_profiles")
DYNAMIC_DNS = _Collection(
    "/dynamicdns", "Dynamic DNS config", "list_dynamic_dns", label_fields=("host_name", "service")
)
AP_GROUPS = _Collection("/apgroups", "AP group", "list_ap_groups", ("_id", "external_id"), v2=True)
KNOWN_CLIENTS = _Collection("/user", "Known client", "list_users", ("_id",), ("name", "mac"))


async def _create_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    body: dict[str, Any],
    hint: str | None,
    /,
) -> Any:
    """POST ``body`` (additive ``_`` keys a read adds dropped) to the collection; the upstream
    body is returned verbatim plus any write warnings (:func:`_with_config_write_warnings`)."""
    sent = strip_additive_keys(body)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    response = await with_upstream_hint(
        client.post(coll.url(host_id, site_slug), key=key, json=sent), hint
    )
    return _with_config_write_warnings(response, sent, coll)


async def _get_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    wanted: str,
    arg: str,
) -> Any:
    """GET one Classic record by id (the upstream envelope verbatim)."""
    validate_id(wanted, arg)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.get(coll.url(host_id, site_slug, f"/{wanted}"), key=key)


async def _create_batch_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    body: dict[str, Any],
    hint: str | None,
    /,
) -> Any:
    """POST ``[body]`` (additive ``_`` keys dropped) to the collection's v2 ``/batch_add``:
    a one-element batch, the body the UI sends. The upstream answer (a bare array of the
    created record) is returned verbatim plus any write warnings on its record."""
    sent = strip_additive_keys(body)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    response = await with_upstream_hint(
        client.post(coll.url(host_id, site_slug, "/batch_add"), key=key, json=[sent]), hint
    )
    return _with_config_write_warnings(response, sent, coll)


async def _update_batch_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    wanted: str,
    arg: str,
    body: dict[str, Any],
    /,
) -> Any:
    """POST ``[record]`` to the collection's v2 ``/batch_update``: the stored record (read
    from the list, which resolves ``wanted``) with ``body`` laid over it. The route
    replaces the whole record and refuses a partial one (live: HTTP 400 "Validation
    failure"), so every field the caller leaves out is sent as stored."""
    # A single-id collection has no aliases to resolve: reject conflicts before reads.
    if coll.id_fields == ("_id",):
        _addressed_config_body(body, {"_id": wanted}, coll)
    key, host_id, site_slug, record = await _resolve_config_record(
        client, registry, host, site, wanted, arg, coll
    )
    fields = _addressed_config_body(strip_additive_keys(body), record, coll)
    sent = _merge_config_body(record, fields)
    response = await client.post(
        coll.url(host_id, site_slug, "/batch_update"), key=key, json=[sent]
    )
    return _with_config_write_warnings(response, sent, coll)


async def _delete_batch_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    wanted: str,
    arg: str,
    /,
) -> dict[str, Any]:
    """POST ``[_id]`` to the collection's v2 ``/batch_delete`` for the record ``wanted``
    names (resolved in the list first)."""
    key, host_id, site_slug, record = await _resolve_config_record(
        client, registry, host, site, wanted, arg, coll
    )
    response = await client.post(
        coll.url(host_id, site_slug, "/batch_delete"), key=key, json=[record["_id"]]
    )
    return deletion_result(f"{coll.kind} {wanted} deleted.", response)


async def _list_config_records(
    client: UniFiClient, registry: Registry, host: str, site: str, coll: _Collection
) -> Any:
    """GET the whole collection (unpaged on the controller), verbatim."""
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.get(coll.url(host_id, site_slug), key=key)


async def _get_ap_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> dict[str, Any]:
    """One AP group from the v2 collection (the controller answers GET by id with 405)."""
    validate_id(group_id, "group_id")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    _body, records = await _config_rows(client, AP_GROUPS.url(host_id, site_slug), key)
    return _select_config_record(records, group_id, AP_GROUPS, write=False)


async def _create_port_profile(
    client: UniFiClient, registry: Registry, host: str, site: str, profile: dict[str, Any], /
) -> Any:
    """POST a port profile; the envelope plus the additive ``_resolved_networks`` key."""
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    sent = await _with_classic_networkconf_ids(
        client,
        host_id,
        site_slug,
        strip_additive_keys(_without_resolved_networks(profile)),
        key=key,
    )
    response = await with_upstream_hint(
        client.post(PORT_PROFILES.url(host_id, site_slug), key=key, json=sent),
        missing_fields_hint(
            "create_port_profile",
            profile,
            ("name", "forward"),
            "forward follows tagged_vlan_mgmt: auto=all, block_all=native, custom=customize",
        ),
    )
    if is_dry_run_preview(response):
        return response
    name_map, error = await _name_map_or_error(client, host_id, site_slug, key=key)
    checked = _with_config_write_warnings(response, sent, PORT_PROFILES)
    envelope = _envelope_with_resolution(checked, name_map, error)
    if isinstance(envelope, dict):
        envelope = with_read_after_error(dict(envelope), error, additive=True)
    return envelope


async def _set_client_user_group(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_ref: str,
    group: str,
) -> Any:
    """POST upd/user/{_id} {usergroup_id} for one known client (by _id or MAC)."""
    validate_selector(client_ref, "client")
    validate_selector(group, "group")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    _body, groups = await _config_rows(client, USER_GROUPS.url(host_id, site_slug), key)
    chosen = _select_config_record(groups, group, USER_GROUPS, write=True, by_name=True)
    _body, users = await _config_rows(client, KNOWN_CLIENTS.url(host_id, site_slug), key)
    wanted = colon_mac(client_ref) if is_mac(client_ref) else client_ref
    record = find_by_id(users, wanted, "_id", "mac")
    if record is None:
        raise ValueError(
            f"Known client {client_ref!r} not found by _id or MAC among {len(users)} known "
            "clients; valid: "
            + (
                "; ".join(
                    f"{upstream_error_value(r.get('name') or r.get('hostname'), client)!r} "
                    f"(mac={upstream_error_value(r.get('mac'), client)}, "
                    f"_id={upstream_error_value(r.get('_id'), client)})"
                    for r in users
                )
                or "(none)"
            )
            + ". No write was sent."
        )
    user_id = listed_record_id(record, "client", client=client)
    return await client.post(
        classic_rest(host_id, site_slug, "").removesuffix("/rest") + f"/upd/user/{user_id}",
        key=key,
        json={"usergroup_id": chosen["_id"]},
    )
