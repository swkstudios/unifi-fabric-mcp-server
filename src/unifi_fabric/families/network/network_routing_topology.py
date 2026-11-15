"""Network routing (BGP, OSPF), global network settings and switching-topology tools.

These routes have no published Integration API. They are the Network controller's own
web-UI routes under ``/proxy/network/v2/api/site/{site}`` (Network 11.0.81 private-API
inventory, ``tests/fixtures/private_api/inventory_network_11.0.81.json``) and take the
site's short name (``default``), resolved from the caller's site name or UUID.

* Request bodies the inventory records as dynamic (``body_dynamic``) are taken as one
  free-form JSON object and sent verbatim; no required key is invented. Routes the
  inventory records without a body are sent without one.
* None of these collections takes a paging parameter in the inventory, so list reads send
  one GET and return the upstream body verbatim (no drain, no cap).
* Updates read the record (from its collection, or the singleton), merge only the
  requested leaves, write the merged record and read it back, comparing every requested
  leaf type-strictly (``_verified``; ``_readAfterError`` when the read-back failed).
* Updates and deletes resolve the id in its collection first (the controller answers a
  write on an unknown id without an error), failing with every valid id listed.
* POST actions are not on the read-POST allowlist, so they are writes:
  ``UNIFI_WRITE_POLICY=deny`` refuses them and ``dry-run policy`` previews them.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    keep_stored_secrets,
    unmasked_read,
    upstream_error_value,
    validate_id,
)
from ...config import APIKeyConfig
from ...redaction import drop_and_note_masked_fields
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._classic_objects import (
    addressed_body,
    classic_rest,
    resolve_site_slug,
    v2_site,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import (
    deletion_readback_ids,
    deletion_result,
    requested_leaves_verdict,
    safe_read_after,
)
from ...write_body import IDENTITY_FIELDS, require_unmasked_fields, require_update_fields
from .schemas import (  # the family's shapes (family-owned layout)
    _BGP,
    _BGP_ALL,
    _GLOBAL,
    _MCLAG,
    _OSPF,
    _STACK,
    _STATUS_VIEWS,
    _VNET,
)

# --- shared helpers ---


def _choice(value: Any, name: str, choices: Iterable[str]) -> str:
    """``value`` when it is one of ``choices`` (the server's own route grammar), else raise."""
    allowed = tuple(choices)
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{name} must be one of {', '.join(allowed)}; got {value!r}")
    return value


def _paired_id(action: str, value: str | None, name: str, needs: Iterable[str]) -> str | None:
    """Validate an id argument that some actions need and the others must not get."""
    if action in needs:
        if value is None:
            raise ValueError(f"{name} is required for action {action!r}")
        validate_id(value, name)
        return value
    if value is not None:
        raise ValueError(f"{name} is not used with action {action!r}; omit it")
    return None


def _update_body(tool: str, value: Any, name: str) -> dict[str, Any]:
    """The requested update leaves (masked and identity fields dropped), or raise."""
    clean = require_update_fields(drop_and_note_masked_fields(value), f"{tool} {name}")
    return {key: item for key, item in clean.items() if key not in IDENTITY_FIELDS}


def _merge(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge only the requested leaves into the current upstream record."""
    merged = dict(current)
    for key, value in changes.items():
        prior = merged.get(key)
        merged[key] = (
            _merge(prior, value) if isinstance(prior, dict) and isinstance(value, dict) else value
        )
    return merged


async def _site(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str, str]:
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_site_slug(registry, host, site)


def _rows(body: Any, path: str) -> list[dict[str, Any]]:
    """The records of a collection body: a bare JSON array or a ``{data: [...]}`` envelope."""
    rows = body.get("data") if isinstance(body, dict) else body
    if not isinstance(rows, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a JSON array or an object "
            f"with a 'data' array, got {describe_shape(body)}"
        )
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {path}: row {index} expected an object, "
                f"got {describe_shape(row)}"
            )
    return rows


def _singleton(body: Any, path: str) -> dict[str, Any]:
    """The one settings record of a singleton route: an object, or an array of one object."""
    if isinstance(body, dict):
        return body
    if isinstance(body, list) and len(body) == 1 and isinstance(body[0], dict):
        return body[0]
    raise UniFiConnectionError(
        f"GET {path} did not answer one settings record: the body must be an object or an "
        f"array of exactly one object (got {describe_shape(body)})"
    )


def _record_id(record: dict[str, Any], fields: tuple[str, ...]) -> str | None:
    for field in fields:
        value = record.get(field)
        if isinstance(value, str) and value:
            return value
    return None


async def _listed_record(
    client: UniFiClient,
    path: str,
    key: APIKeyConfig | None,
    identifier: str,
    label: str,
    fields: tuple[str, ...] = ("_id", "id"),
    *,
    read_after: bool = False,
) -> tuple[dict[str, Any], str]:
    """``(record, upstream id)`` of the row of collection ``path`` that ``identifier`` names.

    The id is matched against ``fields`` (hex ids ignore case); the write addresses the
    record's own first id field, never the caller's spelling. An unknown id raises listing
    every valid id.
    """
    rows = _rows(await client.get(path, key=key), path)
    wanted = identifier.lower()
    for row in rows:
        if any(isinstance(row.get(f), str) and row[f].lower() == wanted for f in fields):
            resolved = _record_id(row, fields)
            if resolved is not None:
                validate_id(resolved, "id")
                return row, resolved
    choices = sorted(
        f"{upstream_error_value(row.get('name'), client)!r} "
        f"({field}={upstream_error_value(row[field], client)})"
        for row in rows
        for field in fields[:1] + tuple(f for f in fields[1:] if fields[0] not in row)
        if isinstance(row.get(field), str) and row[field]
    )
    raise ValueError(
        f"{label} {identifier!r} not found; valid: {'; '.join(choices) or '(none)'}. "
        + (
            "The write was sent; read-back could not find the record."
            if read_after
            else "No write was sent."
        )
    )


def _with_verdict(response: Any, changes: dict[str, Any], after: Any, error: str | None) -> Any:
    """The write response verbatim plus ``_verified`` (and ``_readAfterError``).

    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    verified, error = requested_leaves_verdict(changes, after, error)
    if not isinstance(response, dict):
        response = {"response": response}
    additions: dict[str, Any] = {"_verified": verified}
    if error is not None:
        additions["_readAfterError"] = error
    return with_context(response, additions)


async def _bgp_write_suffix(
    client: UniFiClient, host_id: str, slug: str, key: APIKeyConfig | None, resolved: str
) -> str:
    """Address the gateway singleton at /config; other listed records use their id route."""
    path = v2_site(host_id, slug, _BGP)
    rows = _rows(await client.get(path, key=key), path)
    for row in rows:
        if any(
            isinstance(row.get(field), str) and row[field].lower() == resolved.lower()
            for field in ("_id", "id")
        ):
            return _BGP
    return f"{_BGP}/{resolved}"


async def _verified_collection_update(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    list_suffix: str,
    write_suffix: str,
    identifier: str,
    changes: dict[str, Any],
    label: str,
    method: Literal["POST", "PUT"] = "PUT",
    requested: dict[str, Any] | None = None,
) -> Any:
    """Read-merge-write one collection record, then verify every requested leaf.

    ``requested`` is the caller's value as given: a leaf passed back as the redaction mask
    keeps the stored value (:func:`client.keep_stored_secrets`).
    """
    key, host_id, slug = await _site(registry, host, site)
    list_path = v2_site(host_id, slug, list_suffix)
    with unmasked_read():  # the stored password is written back as stored
        current, resolved = await _listed_record(client, list_path, key, identifier, label)
    suffix = (
        await _bgp_write_suffix(client, host_id, slug, key, resolved)
        if write_suffix == _BGP
        else f"{write_suffix}/{resolved}"
    )
    path = v2_site(host_id, slug, suffix)
    body = keep_stored_secrets(client, _merge(current, changes), current, requested or {})
    if method == "POST":
        response = await client.post(path, key=key, json=body)
    else:
        response = await client.put(path, key=key, json=body)
    if is_dry_run_preview(response):
        return response

    async def read_after() -> dict[str, Any]:
        record, _ = await _listed_record(client, list_path, key, resolved, label, read_after=True)
        return record

    after, error = await safe_read_after(read_after)
    return _with_verdict(response, changes, after, error)


async def _delete_listed(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    list_suffix: str,
    write_suffix: str,
    identifier: str,
    label: str,
) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    list_path = v2_site(host_id, slug, list_suffix)
    _record, resolved = await _listed_record(client, list_path, key, identifier, label)
    suffix = (
        await _bgp_write_suffix(client, host_id, slug, key, resolved)
        if write_suffix == _BGP
        else f"{write_suffix}/{resolved}"
    )
    response = await client.delete(v2_site(host_id, slug, suffix), key=key)
    result = deletion_result(f"{label} {resolved} deleted.", response)
    if is_dry_run_preview(response):
        return result

    async def read_after() -> set[str]:
        return deletion_readback_ids(
            _rows(await client.get(list_path, key=key), list_path), "_id", "id"
        )

    rows, error = await safe_read_after(read_after)
    if error is not None or rows is None:
        result.update(
            deleted=None,
            message=f"Could not verify deletion of {label} {resolved}.",
            readAfterError=error or "Read-after returned no records",
        )
    else:
        remains = resolved.lower() in {identity.lower() for identity in rows}
        if remains:
            result.update(
                deleted=False, message=f"{label} {resolved} is still listed after delete."
            )
    return result


async def _get(client: UniFiClient, registry: Registry, host: str, site: str, suffix: str) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, suffix), key=key)


async def _post(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    suffix: str,
    body: Any = None,
) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(v2_site(host_id, slug, suffix), key=key, json=body)


async def _network_id(
    client: UniFiClient, key: APIKeyConfig | None, host_id: str, slug: str, network_id: str
) -> str:
    """The Classic ``_id`` of the network ``network_id`` names (``_id`` or Integration id)."""
    _record, resolved = await _listed_record(
        client,
        classic_rest(host_id, slug, "/networkconf"),
        key,
        network_id,
        "network",
        ("_id", "external_id"),
    )
    return resolved


# --- BGP ---


async def get_bgp_status(
    client: UniFiClient, registry: Registry, host: str, site: str, view: str = "config"
) -> Any:
    """GET the BGP configurations (``config``) or BGP neighbours (``neighbors``)."""
    view = _choice(view, "view", _STATUS_VIEWS)
    return await _get(
        client, registry, host, site, _BGP_ALL if view == "config" else "/bgp/neighbors"
    )


async def create_bgp_config(
    client: UniFiClient, registry: Registry, host: str, site: str, config: dict[str, Any]
) -> Any:
    """POST ``config`` verbatim to the site's BGP configurations."""
    return await _post(client, registry, host, site, _BGP, config)


async def update_bgp_config(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    config_id: str,
    config: dict[str, Any],
) -> Any:
    """Merge ``config`` into the listed BGP config, POST it to its id route and verify."""
    validate_id(config_id, "config_id")
    changes = _update_body("update_bgp_config", config, "config")
    return await _verified_collection_update(
        client,
        registry,
        host,
        site,
        list_suffix=_BGP_ALL,
        write_suffix=_BGP,
        identifier=config_id,
        changes=changes,
        label="BGP config",
        method="POST",
        requested=config,
    )


async def delete_bgp_config(
    client: UniFiClient, registry: Registry, host: str, site: str, config_id: str
) -> Any:
    """Resolve ``config_id`` in the BGP config list, then DELETE it."""
    validate_id(config_id, "config_id")
    return await _delete_listed(
        client,
        registry,
        host,
        site,
        list_suffix=_BGP_ALL,
        write_suffix=_BGP,
        identifier=config_id,
        label="BGP config",
    )


# --- OSPF ---


async def get_ospf_status(
    client: UniFiClient, registry: Registry, host: str, site: str, view: str = "config"
) -> Any:
    """GET the OSPF routers (``config``) or OSPF neighbours (``neighbors``)."""
    view = _choice(view, "view", _STATUS_VIEWS)
    return await _get(
        client, registry, host, site, _OSPF if view == "config" else "/ospf/neighbors"
    )


async def create_ospf_router(
    client: UniFiClient, registry: Registry, host: str, site: str, router: dict[str, Any]
) -> Any:
    """POST ``router`` verbatim to the site's OSPF routers."""
    return await _post(client, registry, host, site, _OSPF, router)


async def update_ospf_router(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    router_id: str,
    router: dict[str, Any],
) -> Any:
    """Merge ``router`` into the listed OSPF router, PUT it and verify the leaves."""
    validate_id(router_id, "router_id")
    changes = _update_body("update_ospf_router", router, "router")
    return await _verified_collection_update(
        client,
        registry,
        host,
        site,
        list_suffix=_OSPF,
        write_suffix=_OSPF,
        identifier=router_id,
        changes=changes,
        label="OSPF router",
        requested=router,
    )


async def delete_ospf_router(
    client: UniFiClient, registry: Registry, host: str, site: str, router_id: str
) -> Any:
    """Resolve ``router_id`` in the OSPF router list, then DELETE it."""
    validate_id(router_id, "router_id")
    return await _delete_listed(
        client,
        registry,
        host,
        site,
        list_suffix=_OSPF,
        write_suffix=_OSPF,
        identifier=router_id,
        label="OSPF router",
    )


# --- Global network settings, mDNS, Layer 3 migration, suggestions ---


async def get_global_network_config(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the site's global network configuration; returned verbatim."""
    return await _get(client, registry, host, site, _GLOBAL)


async def update_global_network_config(
    client: UniFiClient, registry: Registry, host: str, site: str, config: dict[str, Any]
) -> Any:
    """Merge ``config`` into the global network configuration, PUT it and verify."""
    changes = _update_body("update_global_network_config", config, "config")
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, _GLOBAL)
    current = _singleton(await client.get(path, key=key), path)
    response = await client.put(path, key=key, json=_merge(current, changes))
    if is_dry_run_preview(response):
        return response

    async def read_after() -> dict[str, Any]:
        return _singleton(await client.get(path, key=key), path)

    after, error = await safe_read_after(read_after)
    return _with_verdict(response, changes, after, error)


async def get_mdns_settings(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the site's LAN mDNS settings; returned verbatim."""
    return await _get(client, registry, host, site, "/lan/mdns")


async def migrate_network_to_layer3(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    network_id: str,
    request: dict[str, Any],
) -> Any:
    """Resolve the network, then POST ``request`` verbatim to its migrate-to-layer3 route."""
    validate_id(network_id, "network_id")
    key, host_id, slug = await _site(registry, host, site)
    resolved = await _network_id(client, key, host_id, slug, network_id)
    body = addressed_body(request, resolved) if isinstance(request, dict) else request
    return await client.post(
        v2_site(host_id, slug, f"/lan/migrate-to-layer3/{resolved}"), key=key, json=body
    )


async def suggest_network_settings(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the controller's suggested settings for a new network; returned verbatim."""
    return await _get(client, registry, host, site, "/network/suggest")


async def generate_vlan_plan(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    request: dict[str, Any] | None = None,
) -> Any:
    """POST to the generate-vlans route, with ``request`` verbatim when given."""
    if request is not None:
        require_unmasked_fields(request, "generate_vlan_plan request")
    return await _post(client, registry, host, site, "/network/generate-vlans", request)


async def import_dhcp_reservations(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    reservations: dict[str, Any] | list[dict[str, Any]],
) -> Any:
    """POST ``reservations`` verbatim to the site's DHCP import route."""
    if isinstance(reservations, list) and not reservations:
        raise ValueError(
            "reservations is an empty list, so there is nothing to import: pass at least one "
            "reservation object. Nothing was sent."
        )
    return await _post(client, registry, host, site, "/dhcp-import", reservations)


async def detach_from_orchestration(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    target: str,
    object_id: str,
) -> Any:
    """POST the detach of a network (resolved first) or of orchestration settings."""
    target = _choice(target, "target", ("network", "settings"))
    validate_id(object_id, "object_id")
    key, host_id, slug = await _site(registry, host, site)
    if target == "network":
        resolved = await _network_id(client, key, host_id, slug, object_id)
        suffix = f"/orchestration/network/{resolved}/detach"
    else:
        suffix = f"/orchestration/{object_id}/settings/detach"
    return await client.post(v2_site(host_id, slug, suffix), key=key, json=None)


async def manage_virtual_network(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    virtual_network: dict[str, Any],
    virtual_network_id: str | None = None,
) -> Any:
    """POST (create) or PUT (update) ``virtual_network`` verbatim.

    The 11.0.81 inventory has no read route for these records, so an update cannot be
    merged or read back: the object is sent as given.
    """
    action = _choice(action, "action", ("create", "update"))
    vnet_id = _paired_id(action, virtual_network_id, "virtual_network_id", ("update",))
    if vnet_id is None:
        clean = require_update_fields(
            drop_and_note_masked_fields(virtual_network),
            "manage_virtual_network virtual_network",
            identity=frozenset(),
        )
        key, host_id, slug = await _site(registry, host, site)
        return await client.post(v2_site(host_id, slug, _VNET), key=key, json=clean)
    virtual_network = _update_body("manage_virtual_network", virtual_network, "virtual_network")
    key, host_id, slug = await _site(registry, host, site)
    return await client.put(
        v2_site(host_id, slug, f"{_VNET}/{vnet_id}"), key=key, json=virtual_network
    )


# --- Loop detection, MC-LAG, switch stacks ---


async def get_loop_detection_status(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the site's loop-detection information; returned verbatim."""
    return await _get(client, registry, host, site, "/loop-detection/info")


async def recover_loop_blocked_ports(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """POST the recover-all-ports action (no body)."""
    return await _post(client, registry, host, site, "/loop-detection/recover-all-ports")


async def manage_mclag_group(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    group_id: str | None = None,
    group: dict[str, Any] | None = None,
) -> Any:
    """Create, update (read-merge-write, verified) or delete one MC-LAG group."""
    action = _choice(action, "action", ("create", "update", "delete"))
    resolved_id = _paired_id(action, group_id, "group_id", ("update", "delete"))
    if action == "delete":
        if group is not None:
            raise ValueError("group is not used with action 'delete'; omit it")
        return await _delete_listed(
            client,
            registry,
            host,
            site,
            list_suffix=_MCLAG,
            write_suffix=_MCLAG,
            identifier=str(resolved_id),
            label="MC-LAG group",
        )
    changes = _update_body("manage_mclag_group", group, "group")
    if action == "create":
        return await _post(client, registry, host, site, _MCLAG, group)
    return await _verified_collection_update(
        client,
        registry,
        host,
        site,
        list_suffix=_MCLAG,
        write_suffix=_MCLAG,
        identifier=str(resolved_id),
        changes=changes,
        label="MC-LAG group",
    )


async def update_switch_stack(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    stack_id: str,
    stack: dict[str, Any],
) -> Any:
    """Merge ``stack`` into the listed switch stack, PUT it and verify the leaves."""
    validate_id(stack_id, "stack_id")
    changes = _update_body("update_switch_stack", stack, "stack")
    return await _verified_collection_update(
        client,
        registry,
        host,
        site,
        list_suffix=_STACK,
        write_suffix=_STACK,
        identifier=stack_id,
        changes=changes,
        label="switch stack",
    )


# --- registration ---
