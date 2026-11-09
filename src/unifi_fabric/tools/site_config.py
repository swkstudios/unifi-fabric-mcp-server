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

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    strip_additive_keys,
    upstream_error_value,
    validate_id,
    validate_selector,
)
from ..config import APIKeyConfig
from ..macs import colon_mac, is_mac
from ..matching import find_by_id, name_matches, same_id
from ..redaction import (
    REDACTION_MASK,
    drop_and_note_masked_fields,
    note_dropped_fields,
    write_redaction_enabled,
)
from ..registry import Registry
from ..tool_annotations import READ_ONLY, WRITE
from ._classic_objects import (
    _object_rows,
    classic_rest,
    listed_record_id,
    resolve_site_slug,
    v2_site,
)
from ._payload import missing_fields_hint, strip_empty_list_values, with_upstream_hint
from ._results import deletion_result, leaf_equal, with_read_after_error
from .network_services_proxy import (
    _envelope_with_resolution,
    _name_map_or_error,
    _with_classic_networkconf_ids,
    _with_warning,
    _without_resolved_networks,
)


@dataclass(frozen=True)
class _Collection:
    """One controller collection: its route, its record kind and how a record is named."""

    path: str
    kind: str
    list_tool: str
    id_fields: tuple[str, ...] = ("_id",)
    label_fields: tuple[str, ...] = ("name",)
    v2: bool = False
    #: Written through v2 ``/batch_add``, ``/batch_update`` and ``/batch_delete`` POSTs of a
    #: JSON array (one element per call); the write answers a bare array of the records.
    batch: bool = False

    def url(self, host_id: str, site_slug: str, suffix: str = "") -> str:
        build = v2_site if self.v2 else classic_rest
        return build(host_id, site_slug, self.path + suffix)


USER_GROUPS = _Collection("/usergroup", "User group", "list_user_groups")
STATIC_ROUTES = _Collection("/routing", "Static route", "list_routing_entries")
RADIUS_ACCOUNTS = _Collection(
    "/radius/users", "RADIUS account", "list_accounts", v2=True, batch=True
)
RADIUS_PROFILES = _Collection(
    "/radiusprofile", "RADIUS profile", "list_radius_profiles", ("_id", "external_id")
)
PORT_PROFILES = _Collection("/portconf", "Port profile", "list_port_profiles")
DYNAMIC_DNS = _Collection(
    "/dynamicdns", "Dynamic DNS config", "list_dynamic_dns", label_fields=("host_name", "service")
)
AP_GROUPS = _Collection("/apgroups", "AP group", "list_ap_groups", ("_id", "external_id"), v2=True)
KNOWN_CLIENTS = _Collection("/user", "Known client", "list_users", ("_id",), ("name", "mac"))


async def _config_rows(
    client: UniFiClient, path: str, key: APIKeyConfig | None
) -> tuple[Any, list[dict[str, Any]]]:
    """``(body, records)`` of a collection GET: a Classic ``{meta, data}`` envelope or a v2
    bare array. Any other shape raises with the shape received."""
    body = await client.get(path, key=key)
    items = body.get("data") if isinstance(body, dict) else body
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object with a 'data' "
            f"array or a JSON array, got {describe_shape(body)}"
        )
    return body, _object_rows(items, path)


def _config_label(record: dict[str, Any], fields: tuple[str, ...]) -> Any:
    for name in fields:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return None


def _select_config_record(
    records: list[dict[str, Any]],
    wanted: str,
    coll: _Collection,
    *,
    write: bool,
    by_name: bool = False,
) -> dict[str, Any]:
    """The record ``wanted`` names (an id field of ``coll``, then -- with ``by_name`` -- its
    name). An unknown or ambiguous selector fails listing every record (label and ids)."""
    match = find_by_id(records, wanted, *coll.id_fields)
    if match is None and by_name:
        named = name_matches(records, wanted, lambda r: r.get("name"))
        if len(named) > 1:
            raise ValueError(
                f"{coll.kind} name {wanted!r} matches {len(named)} records; pass the _id. "
                f"Valid: {_valid_config_records(records, coll)}."
            )
        match = named[0] if named else None
    if match is None:
        suffix = " No write was sent." if write else ""
        raise ValueError(
            f"{coll.kind} {wanted!r} not found; valid: "
            f"{_valid_config_records(records, coll)}. Get ids from {coll.list_tool} (_id).{suffix}"
        )
    listed_record_id(match, coll.id_fields[0])
    return match


def _valid_config_records(records: list[dict[str, Any]], coll: _Collection) -> str:
    def ids(r: dict[str, Any]) -> str:
        return ", ".join(
            f"{f}={upstream_error_value(r.get(f))}" for f in coll.id_fields if r.get(f) is not None
        )

    return (
        "; ".join(
            f"{upstream_error_value(_config_label(r, coll.label_fields))!r} ({ids(r)})"
            for r in records
        )
        or "(none)"
    )


async def _resolve_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wanted: str,
    arg: str,
    coll: _Collection,
    *,
    write: bool = True,
) -> tuple[APIKeyConfig | None, str, str, dict[str, Any]]:
    """``(key, host_id, site_slug, record)`` for the record ``wanted`` names in ``coll``."""
    validate_id(wanted, arg)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    _body, records = await _config_rows(client, coll.url(host_id, site_slug), key)
    return key, host_id, site_slug, _select_config_record(records, wanted, coll, write=write)


#: Fields a write never compares: the record's identity, and the ``x_`` secrets (a
#: controller may answer them masked, so a difference proves nothing).
_UNCOMPARED = frozenset({"_id", "site_id", "external_id"})


def _written_config_record(response: Any, coll: _Collection) -> Any:
    """The record a write answered with: Classic ``data[0]``, the only element of a v2
    batch answer, or the v2 object itself."""
    if coll.batch:
        return response[0] if isinstance(response, list) and len(response) == 1 else None
    if coll.v2:
        return response
    data = response.get("data") if isinstance(response, dict) else None
    return data[0] if isinstance(data, list) and len(data) == 1 else None


def _readable_config_equal(sent: Any, stored: Any, /) -> bool:
    """Compare every readable leaf, excluding controller-masked x_ fields.

    Leaves use the shared :func:`leaf_equal`: JSON numbers compare by value (``1812``
    sent and ``1812.0`` stored are the same JSON number), a bool only equals a bool
    (``True`` is not ``1``), and a string never equals a number. RADIUS auth/acct
    server lists carry x_secret inside each server object. A masked or omitted secret
    cannot prove a mismatch; all other keys, values and list positions still
    participate in the comparison.
    """
    if isinstance(sent, dict) and isinstance(stored, dict):
        readable_sent = {k: v for k, v in sent.items() if not k.startswith("x_")}
        readable_stored = {k: v for k, v in stored.items() if not k.startswith("x_")}
        return readable_sent.keys() == readable_stored.keys() and all(
            _readable_config_equal(v, readable_stored[k]) for k, v in readable_sent.items()
        )
    if isinstance(sent, list) and isinstance(stored, list):
        return len(sent) == len(stored) and all(
            _readable_config_equal(a, b) for a, b in zip(sent, stored, strict=True)
        )
    return leaf_equal(sent, stored)


def _with_config_write_warnings(response: Any, sent: dict[str, Any], coll: _Collection, /) -> Any:
    """The write's upstream body verbatim, plus additive ``_warnings`` when the record it
    answered with shows the write did not land as sent (a 200 is never trusted alone):

    * ``NO_ID_RETURNED``: the record has no ``_id``, so nothing was stored;
    * ``NOT_STORED_AS_SENT``: top-level fields whose stored value differs from the value
      sent (JSON numbers by value, bool and other types strict; names only, never
      values; ``x_`` secrets are not compared).

    A v2 batch answer is a bare one-element array, which has no place for a key: the
    warnings then go on that array's record, and the array is returned as received.
    """
    if is_dry_run_preview(response) or not isinstance(response, (dict, list)):
        return response
    record = _written_config_record(response, coll)
    if not isinstance(record, dict):
        return response
    warnings: list[dict[str, Any]] = []
    if not record.get("_id"):
        warnings.append(
            {
                "code": "NO_ID_RETURNED",
                "message": (
                    f"The controller answered success but returned the {coll.kind.lower()} "
                    f"without an _id, so nothing was stored. Check with {coll.list_tool}. "
                    "(Seen for legacy firewall rules on consoles that use zone-based firewall "
                    "policies: use create_firewall_policy there.)"
                ),
            }
        )
    differing = sorted(
        k
        for k, v in sent.items()
        if k not in _UNCOMPARED
        and not k.startswith(("_", "x_"))
        and (k not in record or not _readable_config_equal(v, record[k]))
    )
    if differing and record.get("_id"):
        warnings.append(
            {
                "code": "NOT_STORED_AS_SENT",
                "fields": differing,
                "message": (
                    f"The controller stored these fields with a value other than the one sent "
                    f"(or dropped them): {', '.join(differing)}. Read the record back with "
                    f"{coll.list_tool} and check the values this controller accepts."
                ),
            }
        )
    if coll.batch:
        for warning in warnings:
            record = _with_warning(record, warning)
        return [record]
    for warning in warnings:
        response = _with_warning(cast(dict[str, Any], response), warning)
    return response


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


def _addressed_config_body(
    body: dict[str, Any], record: dict[str, Any], coll: _Collection, /
) -> dict[str, Any]:
    """Normalize a matching body identity; refuse an identity naming another record."""
    if "_id" not in body:
        return body
    given = body["_id"]
    if isinstance(given, str) and any(same_id(given, record.get(f)) for f in coll.id_fields):
        return {**body, "_id": record["_id"]}
    raise ValueError(
        f"{coll.kind} body _id {given!r} does not match the resolved record "
        f"_id {record['_id']!r}. Remove the body _id or use the resolved _id. "
        "No write was sent."
    )


def _merge_config_body(record: dict[str, Any], fields: dict[str, Any], /) -> dict[str, Any]:
    """Overlay explicit fields, retaining stored values wherever a mask was supplied."""
    stored = strip_empty_list_values(strip_additive_keys(record))
    missing = object()
    dropped: list[str] = []

    def keep(changes: Any, prior: Any, path: str) -> Any:
        if write_redaction_enabled() and isinstance(changes, str) and changes == REDACTION_MASK:
            dropped.append(path)
            return prior
        if isinstance(changes, dict):
            before = prior if isinstance(prior, dict) else {}
            out_dict = {}
            for key, value in changes.items():
                child = f"{path}.{key}" if path else str(key)
                kept = keep(value, before.get(key, missing), child)
                if kept is not missing:
                    out_dict[key] = kept
            return out_dict
        if isinstance(changes, list):
            before_list = prior if isinstance(prior, list) else []
            out_list = []
            for index, value in enumerate(changes):
                old = before_list[index] if index < len(before_list) else missing
                kept = keep(value, old, f"{path}[{index}]")
                if kept is not missing:
                    out_list.append(kept)
            return out_list
        return changes

    changes = keep(fields, stored, "")
    note_dropped_fields(dropped)
    return {**stored, **changes, "_id": record["_id"]}


async def _update_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    wanted: str,
    arg: str,
    body: dict[str, Any],
    /,
    *,
    merge: bool = False,
) -> Any:
    """PUT ``body`` on the record ``wanted`` names (resolved in the list first).

    With ``merge`` the stored record is read and ``body`` is laid over it, so a route that
    replaces the whole record (v2 AP groups) never loses a field the caller left out."""
    # A single-id collection has no aliases to resolve: reject conflicts before reads.
    if coll.id_fields == ("_id",):
        _addressed_config_body(body, {"_id": wanted}, coll)
    key, host_id, site_slug, record = await _resolve_config_record(
        client, registry, host, site, wanted, arg, coll
    )
    upstream_id = record["_id"]
    fields = _addressed_config_body(strip_additive_keys(body), record, coll)
    sent = _merge_config_body(record, fields) if merge else drop_and_note_masked_fields(fields)
    response = await client.put(coll.url(host_id, site_slug, f"/{upstream_id}"), key=key, json=sent)
    return _with_config_write_warnings(response, sent, coll)


async def _delete_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    wanted: str,
    arg: str,
    /,
) -> dict[str, Any]:
    """DELETE the record ``wanted`` names (resolved in the list first)."""
    key, host_id, site_slug, record = await _resolve_config_record(
        client, registry, host, site, wanted, arg, coll
    )
    response = await client.delete(coll.url(host_id, site_slug, f"/{record['_id']}"), key=key)
    return deletion_result(f"{coll.kind} {wanted} deleted.", response)


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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the site configuration CRUD tools."""

    # ------------------------------------------------------------------ user groups

    @mcp.tool(annotations=READ_ONLY)
    async def list_user_groups(host: str, site: str) -> Any:
        """List client user groups (bandwidth groups) via Classic REST GET rest/usergroup.

        Returns: the upstream body verbatim, {meta: {rc}, data: [{_id, name, qos_rate_max_down,
        qos_rate_max_up, ...}]}; a rate of -1 means unlimited (kbps). To change a group, pass the
        fields to change as `group` to update_user_group.

        Example call (list_user_groups):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await _list_config_records(client, registry, host, site, USER_GROUPS)

    @mcp.tool(annotations=READ_ONLY)
    async def get_user_group(host: str, site: str, group_id: str) -> Any:
        """Get one client user group by _id via Classic REST GET rest/usergroup/{_id}.

        Returns: the upstream body verbatim, {meta: {rc}, data: [the group]} (data is empty for
        an unknown id). To change it, pass the fields to change as `group` to update_user_group.

        Example call (get_user_group):
            {"host": "my-console", "site": "Default", "group_id": "000000000000000000000101"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group_id: User group _id from list_user_groups (data[]._id).
        """
        client, registry = deps_fn()
        return await _get_config_record(
            client, registry, host, site, USER_GROUPS, group_id, "group_id"
        )

    @mcp.tool(annotations=WRITE)
    async def create_user_group(host: str, site: str, group: dict[str, Any]) -> Any:
        """Create a client user group via Classic REST POST rest/usergroup (the UI's route).

        The body is sent verbatim: name, and the bandwidth caps qos_rate_max_down /
        qos_rate_max_up in kbps (-1 = unlimited). Nothing is defaulted.

        Returns: the upstream body verbatim, {meta: {rc}, data: [the created group with _id]}.
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (create_user_group):
            {"host": "my-console", "site": "Default", "group": {"name": "Guests 10M",
             "qos_rate_max_down": 10000, "qos_rate_max_up": 2000}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group: Native usergroup body: name (string), qos_rate_max_down and qos_rate_max_up
                (integer kbps, -1 = unlimited). Free-form JSON object; no published body shape.
        """
        client, registry = deps_fn()
        hint = missing_fields_hint(
            "create_user_group", group, ("name",), "a user group is created from its name"
        )
        return await _create_config_record(client, registry, host, site, USER_GROUPS, group, hint)

    @mcp.tool(annotations=WRITE)
    async def update_user_group(host: str, site: str, group_id: str, group: dict[str, Any]) -> Any:
        """Update a client user group via Classic REST PUT rest/usergroup/{_id}.

        The id is resolved in the group list first (an unknown id fails listing every group,
        no write is sent). Send only the fields to change; the controller keeps the rest.

        Returns: the upstream body verbatim, {meta: {rc}, data: [the updated group]}.
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (update_user_group):
            {"host": "my-console", "site": "Default", "group_id": "000000000000000000000101",
             "group": {"qos_rate_max_down": 20000}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group_id: User group _id from list_user_groups (data[]._id).
            group: Native usergroup fields to change, e.g. name, qos_rate_max_down,
                qos_rate_max_up. Free-form JSON object; no published body shape.
        """
        client, registry = deps_fn()
        return await _update_config_record(
            client, registry, host, site, USER_GROUPS, group_id, "group_id", group
        )

    @mcp.tool(annotations=WRITE)
    async def delete_user_group(host: str, site: str, group_id: str) -> dict[str, Any]:
        """Delete a client user group via Classic REST DELETE rest/usergroup/{_id}.

        Consequence: the group is gone; clients assigned to it fall back to the site's
        default group and its bandwidth limits. There is no undo.

        The id is resolved in the group list first, so an unknown id is never reported as
        deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body
        verbatim. Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false,
        message, response (the preview with method, path, params (query parameters), body)}.

        Example call (delete_user_group):
            {"host": "my-console", "site": "Default", "group_id": "000000000000000000000101"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group_id: User group _id from list_user_groups (data[]._id).
        """
        client, registry = deps_fn()
        return await _delete_config_record(
            client, registry, host, site, USER_GROUPS, group_id, "group_id"
        )

    @mcp.tool(annotations=WRITE)
    async def set_client_user_group(host: str, site: str, client: str, group: str) -> Any:
        """Assign a known client to a user group via Classic REST POST upd/user/{_id}.

        Consequence: the client's bandwidth caps change at once to the group's limits.

        The group (its _id or case-insensitive name) is resolved in rest/usergroup and the
        client (its known-client _id or MAC) in rest/user before the write; an unknown or ambiguous
        selector fails listing the choices and no write is sent. The body sent is
        {usergroup_id}.

        Returns: the upstream body verbatim, {meta: {rc}, data: [the updated client record]}.
        Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false, message,
        preview: {method, path, params, body}}.

        Example call (set_client_user_group):
            {"host": "my-console", "site": "Default", "client": "02:00:5e:10:00:01",
             "group": "Guests 10M"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client: Known client _id or MAC (any common MAC format), e.g. "02:00:5e:10:00:01".
            group: User group _id or case-insensitive name from list_user_groups, e.g. "Default".
        """
        api, registry = deps_fn()
        return await _set_client_user_group(api, registry, host, site, client, group)

    # ------------------------------------------------------------------ static routes

    @mcp.tool(annotations=READ_ONLY)
    async def get_static_route(host: str, site: str, route_id: str) -> Any:
        """Get one static route by _id via Classic REST GET rest/routing/{_id}.

        Returns: the upstream body verbatim, {meta: {rc}, data: [the route]} (data is empty for
        an unknown id). To change it, pass the fields to change as `route` to update_static_route.

        Example call (get_static_route):
            {"host": "my-console", "site": "Default", "route_id": "000000000000000000000101"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            route_id: Static route _id from list_routing_entries (data[]._id).
        """
        client, registry = deps_fn()
        return await _get_config_record(
            client, registry, host, site, STATIC_ROUTES, route_id, "route_id"
        )

    @mcp.tool(annotations=WRITE)
    async def create_static_route(host: str, site: str, route: dict[str, Any]) -> Any:
        """Create a static route via Classic REST POST rest/routing (the UI's route).

        The body is sent verbatim. A next-hop route: {name, enabled, type: "static-route",
        static-route_type: "nexthop-route", static-route_network: "198.51.100.0/24",
        static-route_nexthop: "10.0.0.2", static-route_distance: 1}; static-route_type may also
        be "interface-route" (with static-route_interface) or "blackhole".

        Returns: the upstream body verbatim, {meta: {rc}, data: [the created route with _id]}.
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (create_static_route):
            {"host": "my-console", "site": "Default", "route": {"name": "Lab", "enabled": true,
             "type": "static-route", "static-route_type": "nexthop-route",
             "static-route_network": "198.51.100.0/24", "static-route_nexthop": "10.0.0.2",
             "static-route_distance": 1}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            route: Native routing body (fields above). Free-form JSON object; no published body
                shape.
        """
        client, registry = deps_fn()
        hint = missing_fields_hint(
            "create_static_route",
            route,
            ("name", "type", "static-route_type", "static-route_network"),
            "type is static-route; static-route_type is nexthop-route, interface-route or "
            "blackhole",
        )
        return await _create_config_record(client, registry, host, site, STATIC_ROUTES, route, hint)

    @mcp.tool(annotations=WRITE)
    async def update_static_route(
        host: str, site: str, route_id: str, route: dict[str, Any]
    ) -> Any:
        """Update a static route via Classic REST PUT rest/routing/{_id}.

        The id is resolved in the route list first (an unknown id fails listing every route,
        no write is sent). Send only the fields to change; the controller keeps the rest.

        Returns: the upstream body verbatim, {meta: {rc}, data: [the updated route]}.
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (update_static_route):
            {"host": "my-console", "site": "Default", "route_id": "000000000000000000000101",
             "route": {"enabled": false}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            route_id: Static route _id from list_routing_entries (data[]._id).
            route: Native routing fields to change, e.g. enabled, name, static-route_nexthop.
                Free-form JSON object; no published body shape.
        """
        client, registry = deps_fn()
        return await _update_config_record(
            client, registry, host, site, STATIC_ROUTES, route_id, "route_id", route
        )

    @mcp.tool(annotations=WRITE)
    async def delete_static_route(host: str, site: str, route_id: str) -> dict[str, Any]:
        """Delete a static route via Classic REST DELETE rest/routing/{_id}.

        Consequence: traffic for the route's prefix follows the remaining routing table at
        once (often the default route); there is no undo.

        The id is resolved in the route list first, so an unknown id is never reported as
        deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body
        verbatim. Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false,
        message, response (the preview with method, path, params (query parameters), body)}.

        Example call (delete_static_route):
            {"host": "my-console", "site": "Default", "route_id": "000000000000000000000101"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            route_id: Static route _id from list_routing_entries (data[]._id).
        """
        client, registry = deps_fn()
        return await _delete_config_record(
            client, registry, host, site, STATIC_ROUTES, route_id, "route_id"
        )

    # ------------------------------------------------------------------ RADIUS accounts

    @mcp.tool(annotations=WRITE)
    async def create_radius_account(
        host: str,
        site: str,
        name: str,
        password: str,
        fields: dict[str, Any] | None = None,
    ) -> Any:
        """Create a local RADIUS user account via v2 POST radius/users/batch_add (the UI's route).

        Sends a one-element batch, [{...fields, name, x_password}], to
        /v2/api/site/{site}/radius/users/batch_add. For a VLAN assignment add vlan with
        tunnel_type 13 and tunnel_medium_type 6 in `fields`. Nothing is defaulted.

        Returns: the upstream body verbatim, a one-element JSON array [the created account
        {_id, name, x_password, group_policy, filter_ids, ...}]; its _id is the id
        list_accounts shows. Additive _warnings on that account (NO_ID_RETURNED,
        NOT_STORED_AS_SENT: field names only) report a write that did not land as sent.
        Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_radius_account):
            {"host": "my-console", "site": "Default", "name": "alice",
             "password": "correct-horse", "fields": {"vlan": 20, "tunnel_type": 13,
             "tunnel_medium_type": 6}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            name: RADIUS user name, e.g. "alice".
            password: RADIUS user password; sent as x_password.
            fields: Optional further native account keys, e.g. vlan, tunnel_type,
                tunnel_medium_type; name and password take precedence. Free-form JSON object.
        """
        client, registry = deps_fn()
        body = {**(fields or {}), "name": name, "x_password": password}
        return await _create_batch_record(client, registry, host, site, RADIUS_ACCOUNTS, body, None)

    @mcp.tool(annotations=WRITE)
    async def update_radius_account(
        host: str, site: str, account_id: str, account: dict[str, Any]
    ) -> Any:
        """Update a local RADIUS user account via v2 POST radius/users/batch_update.

        Consequence: the stored account changes at once; a new x_password or vlan applies to
        the user's next 802.1X or VPN authentication.

        The id is resolved in the v2 account list (GET /v2/api/site/{site}/radius/users)
        first; an unknown id fails listing every account and no write is sent. The route
        replaces the whole account and refuses a partial one, so the stored account is sent
        with `account` laid over it, as a one-element batch [account]: send only the fields
        to change, e.g. x_password for a new password; every other field is kept as stored.

        Returns: the upstream body verbatim, a one-element JSON array [the updated account].
        Additive _warnings on that account (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names
        only) report a write that did not land as sent. Under dry-run policy nothing is sent:
        the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}.

        Example call (update_radius_account):
            {"host": "my-console", "site": "Default", "account_id": "000000000000000000000101",
             "account": {"vlan": 30}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            account_id: RADIUS account _id from list_accounts (data[]._id).
            account: Native account fields to change, e.g. name, x_password, vlan. Free-form
                JSON object; no published body shape.
        """
        client, registry = deps_fn()
        return await _update_batch_record(
            client, registry, host, site, RADIUS_ACCOUNTS, account_id, "account_id", account
        )

    @mcp.tool(annotations=WRITE)
    async def delete_radius_account(host: str, site: str, account_id: str) -> dict[str, Any]:
        """Delete a local RADIUS user account via v2 POST radius/users/batch_delete.

        Consequence: the user can no longer authenticate (802.1X / VPN) with these
        credentials; existing sessions end at their next re-authentication. There is no undo.

        The id is resolved in the v2 account list first, so an unknown id is never reported
        as deleted. The body sent is a one-element batch of ids, [_id].

        Returns {deleted: true, message, response}; response is the upstream body verbatim
        (null: the controller answers with no body). Under dry-run policy nothing is deleted:
        {status: "dry_run", deleted: false, message, response (the preview with method,
        path, params (query parameters), body)}.

        Example call (delete_radius_account):
            {"host": "my-console", "site": "Default", "account_id": "000000000000000000000101"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            account_id: RADIUS account _id from list_accounts (data[]._id).
        """
        client, registry = deps_fn()
        return await _delete_batch_record(
            client, registry, host, site, RADIUS_ACCOUNTS, account_id, "account_id"
        )

    # ------------------------------------------------------------------ AP groups

    @mcp.tool(annotations=READ_ONLY)
    async def list_ap_groups(host: str, site: str) -> Any:
        """List AP groups via v2 GET /v2/api/site/{site}/apgroups (the UI's route).

        Returns: the upstream body verbatim, a JSON array of {_id, external_id, name,
        device_macs, for_wlanconf, attr_no_delete}; device_macs are the member APs.

        Example call (list_ap_groups):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await _list_config_records(client, registry, host, site, AP_GROUPS)

    @mcp.tool(annotations=READ_ONLY)
    async def get_ap_group(host: str, site: str, group_id: str) -> dict[str, Any]:
        """Get one AP group by _id or external_id from the v2 apgroups collection.

        The controller answers GET by id with HTTP 405 (Network 11.0.81), so the collection
        is read and the matching group returned; an unknown id fails listing every group.

        Returns: the AP group object verbatim, {_id, external_id, name, device_macs, ...}. To
        change it, pass the fields to change as `group` to update_ap_group.

        Example call (get_ap_group):
            {"host": "my-console", "site": "Default",
             "group_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group_id: AP group _id or external_id from list_ap_groups.
        """
        client, registry = deps_fn()
        return await _get_ap_group(client, registry, host, site, group_id)

    @mcp.tool(annotations=WRITE)
    async def create_ap_group(host: str, site: str, group: dict[str, Any]) -> Any:
        """Create an AP group via v2 POST /v2/api/site/{site}/apgroups (the UI's route).

        The body is sent verbatim: name and device_macs (the member APs' MACs, may be empty).

        Returns: the upstream body verbatim, the created group {_id, external_id, name,
        device_macs, ...} (HTTP 201).
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (create_ap_group):
            {"host": "my-console", "site": "Default", "group": {"name": "Upstairs",
             "device_macs": ["02:00:5e:00:00:01"]}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group: Native apgroup body: name (string), device_macs (array of AP MACs).
                Free-form JSON object; no published body shape.
        """
        client, registry = deps_fn()
        hint = missing_fields_hint(
            "create_ap_group", group, ("name", "device_macs"), "device_macs lists member APs"
        )
        return await _create_config_record(client, registry, host, site, AP_GROUPS, group, hint)

    @mcp.tool(annotations=WRITE)
    async def update_ap_group(host: str, site: str, group_id: str, group: dict[str, Any]) -> Any:
        """Update an AP group via v2 PUT /v2/api/site/{site}/apgroups/{_id}.

        The group (_id or external_id) is read from the collection first (an unknown id fails
        listing every group, no write is sent) and the fields given are laid over it, so a
        rename keeps the members. device_macs replaces the member list: send every AP to keep.

        Returns: the upstream body verbatim, the updated group object.
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (update_ap_group):
            {"host": "my-console", "site": "Default",
             "group_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "group": {"name": "Floor 2"}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group_id: AP group _id or external_id from list_ap_groups.
            group: Native apgroup fields to change: name, device_macs. Free-form JSON object.
        """
        client, registry = deps_fn()
        return await _update_config_record(
            client, registry, host, site, AP_GROUPS, group_id, "group_id", group, merge=True
        )

    @mcp.tool(annotations=WRITE)
    async def delete_ap_group(host: str, site: str, group_id: str) -> dict[str, Any]:
        """Delete an AP group via v2 DELETE /v2/api/site/{site}/apgroups/{_id}.

        Consequence: the group is gone; WiFi networks broadcast on that group stop using it
        (the controller refuses while one still does, and its error is returned). The APs
        themselves are not changed. There is no undo.

        The id (_id or external_id) is resolved in the collection first, so an unknown id is
        never reported as deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body
        verbatim (null for the HTTP 204 answer). Under dry-run policy nothing is deleted:
        {status: "dry_run", deleted: false, message, response (the preview with method, path,
        params (query parameters), body)}.

        Example call (delete_ap_group):
            {"host": "my-console", "site": "Default",
             "group_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            group_id: AP group _id or external_id from list_ap_groups.
        """
        client, registry = deps_fn()
        return await _delete_config_record(
            client, registry, host, site, AP_GROUPS, group_id, "group_id"
        )

    # ------------------------------------------------------------------ port profiles

    @mcp.tool(annotations=WRITE)
    async def create_port_profile(host: str, site: str, profile: dict[str, Any]) -> Any:
        """Create a switch port profile via Classic REST POST rest/portconf (the UI's route).

        The body is sent verbatim (additive _ keys from a read are dropped): name,
        tagged_vlan_mgmt (auto, block_all, custom) with the matching forward (all, native,
        customize; Network 11.0.81 derives forward from tagged_vlan_mgmt), native_networkconf_id,
        voice_networkconf_id, excluded_networkconf_ids, poe_mode and the other portconf fields
        list_port_profiles shows. The networkconf id fields accept a Classic networkconf _id or
        the Integration id from list_networks (data[].id), which the tool converts to the _id
        before the POST; an unknown value fails listing every network, and nothing is sent.

        Returns: the upstream envelope verbatim, {meta: {rc}, data: [the created profile]},
        each profile plus the additive _resolved_networks key (see list_port_profiles).
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (create_port_profile):
            {"host": "my-console", "site": "Default", "profile": {"name": "Cameras",
             "forward": "native", "tagged_vlan_mgmt": "block_all",
             "native_networkconf_id": "000000000000000000000101", "poe_mode": "auto"}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            profile: Native portconf body (fields above). Free-form JSON object; no published
                body shape.
        """
        client, registry = deps_fn()
        return await _create_port_profile(client, registry, host, site, profile)

    @mcp.tool(annotations=WRITE)
    async def delete_port_profile(host: str, site: str, profile_id: str) -> dict[str, Any]:
        """Delete a switch port profile via Classic REST DELETE rest/portconf/{_id}.

        Consequence: the profile is gone; the controller refuses while a switch port still
        uses it (its error is returned). There is no undo.

        The id is resolved in the profile list first, so an unknown id is never reported as
        deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body
        verbatim. Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false,
        message, response (the preview with method, path, params (query parameters), body)}.

        Example call (delete_port_profile):
            {"host": "my-console", "site": "Default", "profile_id": "000000000000000000000101"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            profile_id: Port profile _id from list_port_profiles (data[]._id).
        """
        client, registry = deps_fn()
        return await _delete_config_record(
            client, registry, host, site, PORT_PROFILES, profile_id, "profile_id"
        )

    # ------------------------------------------------------------------ Dynamic DNS

    @mcp.tool(annotations=WRITE)
    async def create_dynamic_dns(host: str, site: str, ddns: dict[str, Any]) -> Any:
        """Create a Dynamic DNS config via Classic REST POST rest/dynamicdns (the UI's route).

        The body is sent verbatim: service (e.g. dyndns, cloudflare, custom), host_name,
        login, x_password, server (for custom), interface (wan, wan2).

        Returns: the upstream body verbatim, {meta: {rc}, data: [the created config with
        _id]}.
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (create_dynamic_dns):
            {"host": "my-console", "site": "Default", "ddns": {"service": "dyndns",
             "host_name": "home.example.com", "login": "user", "x_password": "secret",
             "interface": "wan"}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            ddns: Native dynamicdns body (fields above). Free-form JSON object; no published
                body shape.
        """
        client, registry = deps_fn()
        hint = missing_fields_hint(
            "create_dynamic_dns",
            ddns,
            ("service", "host_name"),
            "a config names its provider service and the host name it updates",
        )
        return await _create_config_record(client, registry, host, site, DYNAMIC_DNS, ddns, hint)

    @mcp.tool(annotations=WRITE)
    async def delete_dynamic_dns(host: str, site: str, ddns_id: str) -> dict[str, Any]:
        """Delete a Dynamic DNS config via Classic REST DELETE rest/dynamicdns/{_id}.

        Consequence: the gateway stops updating that host name; the DNS record keeps its last
        address. There is no undo.

        The id is resolved in the config list first, so an unknown id is never reported as
        deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body
        verbatim. Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false,
        message, response (the preview with method, path, params (query parameters), body)}.

        Example call (delete_dynamic_dns):
            {"host": "my-console", "site": "Default", "ddns_id": "000000000000000000000101"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            ddns_id: Dynamic DNS config _id from list_dynamic_dns (data[]._id).
        """
        client, registry = deps_fn()
        return await _delete_config_record(
            client, registry, host, site, DYNAMIC_DNS, ddns_id, "ddns_id"
        )
