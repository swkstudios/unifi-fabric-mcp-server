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
  ``UNIFI_READ_ONLY`` refuses them and ``UNIFI_DRY_RUN`` previews them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Literal

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    validate_id,
)
from ..config import APIKeyConfig
from ..redaction import drop_and_note_masked_fields
from ..registry import Registry
from ..selector_args import check_selector
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import IDENTITY_FIELDS, require_unmasked_fields, require_update_fields
from ._classic_objects import addressed_body, classic_rest, resolve_site_slug, v2_site
from ._keys import with_context
from ._results import (
    deletion_readback_ids,
    deletion_result,
    requested_leaves_verdict,
    safe_read_after,
)

_BGP = "/bgp/config"
_BGP_ALL = "/bgp/config/all"
_OSPF = "/ospf/router"
_GLOBAL = "/global/config/network"
_MCLAG = "/mclag-groups"
_STACK = "/stacking"
_VNET = "/visual-programming/virtual-network"
_STATUS_VIEWS = ("config", "neighbors")


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
        f"{row.get('name')!r} ({field}={row[field]})"
        for row in rows
        for field in fields[:1] + tuple(f for f in fields[1:] if fields[0] not in row)
        if isinstance(row.get(field), str) and row[field]
    )
    raise ValueError(
        f"{label} {identifier!r} not found; valid: {'; '.join(choices) or '(none)'}. "
        "No write was sent."
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
) -> Any:
    """Read-merge-write one collection record, then verify every requested leaf."""
    key, host_id, slug = await _site(registry, host, site)
    list_path = v2_site(host_id, slug, list_suffix)
    current, resolved = await _listed_record(client, list_path, key, identifier, label)
    suffix = (
        await _bgp_write_suffix(client, host_id, slug, key, resolved)
        if write_suffix == _BGP
        else f"{write_suffix}/{resolved}"
    )
    path = v2_site(host_id, slug, suffix)
    body = _merge(current, changes)
    if method == "POST":
        response = await client.post(path, key=key, json=body)
    else:
        response = await client.put(path, key=key, json=body)
    if is_dry_run_preview(response):
        return response

    async def read_after() -> dict[str, Any]:
        record, _ = await _listed_record(client, list_path, key, resolved, label)
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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 21 routing, global-network and switching-topology tools."""

    @mcp.tool(name="get_bgp_status", annotations=READ_ONLY)
    async def get_bgp_status_tool(
        host: str, site: str, view: Literal["config", "neighbors"] = "config"
    ) -> Any:
        """Get a site's BGP configurations or BGP neighbour state (Network v2 route).

        With view "config": GET /proxy/network/v2/api/site/{site}/bgp/config/all; with
        view "neighbors": GET .../bgp/neighbors. Returns the upstream body (JSON object or array)
        verbatim (configurations can carry neighbour passwords; they are not masked unless the
        operator sets UNIFI_REDACT_SECRETS).

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            view: "config" (default) or "neighbors", e.g. "neighbors".
        """
        client, registry = deps_fn()
        return await get_bgp_status(client, registry, host, site, view)

    @mcp.tool(name="create_bgp_config", annotations=WRITE)
    async def create_bgp_config_tool(host: str, site: str, config: dict[str, Any]) -> Any:
        """Create a BGP configuration (Network v2 route). Consequence: changes routing.

        POST /proxy/network/v2/api/site/{site}/bgp/config with config sent verbatim. Returns
        the upstream body verbatim. The body shape is not published: send the
        object get_bgp_status (view "config") returns for an existing configuration.
        Never auto-retried; on a timeout, read get_bgp_status before retrying.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, config.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            config: Free-form BGP configuration object, sent verbatim, e.g.
                {"name": "edge-bgp", "enabled": false}.
        """
        client, registry = deps_fn()
        return await create_bgp_config(client, registry, host, site, config)

    @mcp.tool(name="update_bgp_config", annotations=WRITE)
    async def update_bgp_config_tool(
        host: str, site: str, config_id: str, config: dict[str, Any]
    ) -> Any:
        """Update a BGP configuration (Network v2 route). Consequence: changes routing.

        Reads the configuration from GET .../bgp/config/all, merges only the given leaves into it
        and POSTs the whole merged record to /proxy/network/v2/api/site/{site}/bgp/config for the
        gateway singleton, or /bgp/config/{id} for another listed configuration, then reads it back.
        Returns the upstream object verbatim plus _verified (true only when every requested leaf
        reads back equal, type-strict) and _readAfterError when the read-back failed; a non-object
        body (array or scalar) is returned whole under response with those keys beside it. The id,
        _id and site_id in the object are ignored; an object with nothing else to change fails
        before any request.
        An unknown id fails listing every valid id. Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, config_id, config.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            config_id: Configuration _id or id from get_bgp_status, e.g.
                "65f1c0ffee0123456789abcd".
            config: Free-form object of leaves to change, e.g. {"enabled": true}.
        """
        client, registry = deps_fn()
        return await update_bgp_config(client, registry, host, site, config_id, config)

    @mcp.tool(name="delete_bgp_config", annotations=WRITE)
    async def delete_bgp_config_tool(host: str, site: str, config_id: str) -> Any:
        """Delete a BGP configuration (Network v2 route). Consequence: BGP sessions drop.

        Resolves the id in GET .../bgp/config/all first (an unknown id fails listing every valid
        id), then DELETE /proxy/network/v2/api/site/{site}/bgp/config for the gateway singleton,
        or /bgp/config/{id} for another listed configuration, and verify it is absent.
        Returns {deleted, message, response}: deleted is true only when absence is confirmed, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). Irreversible: the configuration is removed.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, config_id.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            config_id: Configuration _id or id from get_bgp_status, e.g.
                "65f1c0ffee0123456789abcd".
        """
        client, registry = deps_fn()
        return await delete_bgp_config(client, registry, host, site, config_id)

    @mcp.tool(name="get_ospf_status", annotations=READ_ONLY)
    async def get_ospf_status_tool(
        host: str, site: str, view: Literal["config", "neighbors"] = "config"
    ) -> Any:
        """Get a site's OSPF routers or OSPF neighbour state (Network v2 route).

        With view "config": GET /proxy/network/v2/api/site/{site}/ospf/router; with
        view "neighbors": GET .../ospf/neighbors. Returns the upstream body (JSON object or array)
        verbatim.

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            view: "config" (default) or "neighbors", e.g. "neighbors".
        """
        client, registry = deps_fn()
        return await get_ospf_status(client, registry, host, site, view)

    @mcp.tool(name="create_ospf_router", annotations=WRITE)
    async def create_ospf_router_tool(host: str, site: str, router: dict[str, Any]) -> Any:
        """Create an OSPF router (Network v2 route). Consequence: changes routing.

        POST /proxy/network/v2/api/site/{site}/ospf/router with router sent verbatim. Returns
        the upstream body verbatim. The body shape is not published: send the
        object get_ospf_status (view "config") returns for an existing router. Never
        auto-retried; on a timeout, read get_ospf_status before retrying.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, router.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            router: Free-form OSPF router object, sent verbatim, e.g.
                {"name": "core-ospf", "enabled": false}.
        """
        client, registry = deps_fn()
        return await create_ospf_router(client, registry, host, site, router)

    @mcp.tool(name="update_ospf_router", annotations=WRITE)
    async def update_ospf_router_tool(
        host: str, site: str, router_id: str, router: dict[str, Any]
    ) -> Any:
        """Update an OSPF router (Network v2 route). Consequence: changes routing.

        Reads the router from GET .../ospf/router, merges only the given leaves into it, PUT
        /proxy/network/v2/api/site/{site}/ospf/router/{id} with the whole merged record and reads it
        back. Returns the upstream object verbatim plus _verified (true only when every requested
        leaf reads back equal, type-strict) and _readAfterError when the read-back failed; a
        non-object body (array or scalar) is returned whole under response with those keys beside
        it. id, _id and site_id in the object are ignored; an object with nothing else to change
        fails before any request. An unknown id fails listing every valid id. Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, router_id, router.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            router_id: Router _id or id from get_ospf_status, e.g.
                "65f1c0ffee0123456789abcd".
            router: Free-form object of leaves to change, e.g. {"enabled": true}.
        """
        client, registry = deps_fn()
        return await update_ospf_router(client, registry, host, site, router_id, router)

    @mcp.tool(name="delete_ospf_router", annotations=WRITE)
    async def delete_ospf_router_tool(host: str, site: str, router_id: str) -> Any:
        """Delete an OSPF router (Network v2 route). Consequence: OSPF adjacencies drop.

        Resolves the id in GET .../ospf/router first (an unknown id fails listing every valid id),
        then DELETE /proxy/network/v2/api/site/{site}/ospf/router/{id}.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). Irreversible: the router is removed.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, router_id.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            router_id: Router _id or id from get_ospf_status, e.g.
                "65f1c0ffee0123456789abcd".
        """
        client, registry = deps_fn()
        return await delete_ospf_router(client, registry, host, site, router_id)

    @mcp.tool(name="get_global_network_config", annotations=READ_ONLY)
    async def get_global_network_config_tool(host: str, site: str) -> Any:
        """Get a site's global network configuration (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/global/config/network. Returns the upstream body
        (JSON object or array) verbatim.

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await get_global_network_config(client, registry, host, site)

    @mcp.tool(name="update_global_network_config", annotations=WRITE)
    async def update_global_network_config_tool(
        host: str, site: str, config: dict[str, Any]
    ) -> Any:
        """Update a site's global network configuration (Network v2 route).

        Consequence: applies to every network of the site. Reads GET .../global/config/network,
        merges only the given leaves into it, PUT
        /proxy/network/v2/api/site/{site}/global/config/network with the whole merged object and
        reads it back. Returns the upstream object verbatim plus _verified (true only when every
        requested leaf reads back equal, type-strict) and _readAfterError when the read-back failed;
        a non-object body (array or scalar) is returned whole under response with those keys beside
        it. An object with nothing to change fails before any request. Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, config.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            config: Free-form object of leaves to change, shaped like get_global_network_config,
                e.g. {"ipv6_enabled": true}.
        """
        client, registry = deps_fn()
        return await update_global_network_config(client, registry, host, site, config)

    @mcp.tool(name="get_mdns_settings", annotations=READ_ONLY)
    async def get_mdns_settings_tool(host: str, site: str) -> Any:
        """Get a site's LAN mDNS (multicast DNS) settings (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/lan/mdns. Returns the upstream body
        (JSON object or array) verbatim.

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await get_mdns_settings(client, registry, host, site)

    @mcp.tool(name="migrate_network_to_layer3", annotations=WRITE)
    async def migrate_network_to_layer3_tool(
        host: str, site: str, network_id: str, request: dict[str, Any]
    ) -> Any:
        """Migrate a network's routing to a Layer 3 switch (Network v2 route).

        Consequence: moves the network's gateway; clients can lose connectivity while it
        moves. Resolves network_id in the Classic networkconf list (an unknown id fails
        listing every valid id), then POST
        /proxy/network/v2/api/site/{site}/lan/migrate-to-layer3/{_id} with request sent
        verbatim. Returns the upstream body (JSON object or array) verbatim. The Network 11.0.81 web
        UI sends the keys cmd, gateway_device and name; their values are not published, so
        nothing is filled in. Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, network_id, request.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            network_id: Network Integration id or Classic _id from list_networks, e.g.
                "65f1c0ffee0123456789abcd".
            request: Free-form migration body, sent verbatim, e.g.
                {"gateway_device": "02:00:5e:00:00:a1", "name": "Office L3"}.
        """
        client, registry = deps_fn()
        return await migrate_network_to_layer3(client, registry, host, site, network_id, request)

    @mcp.tool(name="suggest_network_settings", annotations=READ_ONLY)
    async def suggest_network_settings_tool(host: str, site: str) -> Any:
        """Get the controller's suggested settings for a new network (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/network/suggest (the free VLAN id and
        subnet the web UI pre-fills). Returns the upstream body (JSON object or array) verbatim.

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await suggest_network_settings(client, registry, host, site)

    @mcp.tool(name="generate_vlan_plan", annotations=WRITE)
    async def generate_vlan_plan_tool(
        host: str, site: str, request: dict[str, Any] | None = None
    ) -> Any:
        """Ask the controller to generate a VLAN plan (Network v2 route).

        Consequence: whether the controller only computes the plan or also stores or
        applies it is not published; treat it as a change to the site's networks.

        POST /proxy/network/v2/api/site/{site}/network/generate-vlans. Returns the upstream body
        (JSON object or array) verbatim. The Network 11.0.81 web UI sends no body keys the inventory
        records, so request is free-form and optional: omit it to send no body. This
        POST is not on the read-POST allowlist, so it is classified as a write
        (UNIFI_READ_ONLY refuses it).

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            request: Optional free-form body sent verbatim, e.g. {"purpose": "corporate"}.
        """
        client, registry = deps_fn()
        return await generate_vlan_plan(client, registry, host, site, request)

    @mcp.tool(name="import_dhcp_reservations", annotations=WRITE)
    async def import_dhcp_reservations_tool(
        host: str, site: str, reservations: dict[str, Any] | list[dict[str, Any]]
    ) -> Any:
        """Import DHCP reservations (fixed IPs) into a site (Network v2 route).

        Consequence: creates or changes client IP reservations. POST
        /proxy/network/v2/api/site/{site}/dhcp-import with reservations sent verbatim (object or
        array; the body shape is not published; an empty array fails before any request). Returns
        the upstream body (JSON object or array) verbatim. Never auto-retried; on a timeout, check
        the clients' fixed IPs before retrying.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, reservations.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            reservations: Free-form import body (object or array), e.g.
                [{"mac": "02:00:5e:00:00:a1", "fixed_ip": "192.0.2.20"}].
        """
        client, registry = deps_fn()
        return await import_dhcp_reservations(client, registry, host, site, reservations)

    @mcp.tool(name="detach_from_orchestration", annotations=WRITE)
    async def detach_from_orchestration_tool(
        host: str, site: str, target: Literal["network", "settings"], object_id: str
    ) -> Any:
        """Detach a network or settings from central orchestration (Network v2 route).

        Consequence: the object stops following its orchestration template. target
        "network": object_id is resolved in the Classic networkconf list (an unknown id
        fails listing every valid id), then POST
        /proxy/network/v2/api/site/{site}/orchestration/network/{_id}/detach. target
        "settings": POST .../orchestration/{object_id}/settings/detach. No body is sent.
        Returns the upstream body (JSON object or array) verbatim. Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, target, object_id.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            target: "network" or "settings", e.g. "network".
            object_id: Network id (target network) or orchestration id (target
                settings), e.g. "65f1c0ffee0123456789abcd".
        """
        client, registry = deps_fn()
        return await detach_from_orchestration(client, registry, host, site, target, object_id)

    @mcp.tool(name="manage_virtual_network", annotations=WRITE)
    async def manage_virtual_network_tool(
        host: str,
        site: str,
        action: Literal["create", "update"],
        virtual_network: dict[str, Any],
        virtual_network_id: str | None = None,
    ) -> Any:
        """Create or update a visual-programming virtual network (Network v2 route).

        Consequence: changes the site's network topology. action "create": POST
        /proxy/network/v2/api/site/{site}/visual-programming/virtual-network; action
        "update": PUT .../visual-programming/virtual-network/{virtual_network_id}.
        virtual_network is sent verbatim. Returns the upstream body (JSON object or array) verbatim.
        The 11.0.81 inventory has no read route for these records, so an update is not
        merged or read back: send the complete object. An object with no field fails
        before any request. Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, action, virtual_network.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: "create" or "update", e.g. "create".
            virtual_network: Free-form virtual network object, e.g. {"name": "lab-segment"}.
            virtual_network_id: Required for update, omitted for create, e.g.
                "65f1c0ffee0123456789abcd".
        """
        client, registry = deps_fn()
        return await manage_virtual_network(
            client, registry, host, site, action, virtual_network, virtual_network_id
        )

    @mcp.tool(name="get_loop_detection_status", annotations=READ_ONLY)
    async def get_loop_detection_status_tool(host: str, site: str) -> Any:
        """Get a site's loop-detection status and loop-blocked ports (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/loop-detection/info. Returns the upstream body
        (JSON object or array) verbatim.

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await get_loop_detection_status(client, registry, host, site)

    @mcp.tool(name="recover_loop_blocked_ports", annotations=WRITE)
    async def recover_loop_blocked_ports_tool(host: str, site: str) -> Any:
        """Re-enable every port loop protection blocked on a site (Network v2 route).

        Consequence: physical ports come back up; if the loop is still cabled, it can
        return and disrupt the network. POST
        /proxy/network/v2/api/site/{site}/loop-detection/recover-all-ports with no body;
        Returns the upstream body (JSON object or array) verbatim. Never auto-retried. Read
        get_loop_detection_status first.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await recover_loop_blocked_ports(client, registry, host, site)

    @mcp.tool(name="manage_mclag_group", annotations=WRITE)
    async def manage_mclag_group_tool(
        host: str,
        site: str,
        action: Literal["create", "update", "delete"],
        group_id: str | None = None,
        group: dict[str, Any] | None = None,
    ) -> Any:
        """Create, update or delete an MC-LAG switch group (Network v2 route).

        Consequence: changes switch link aggregation; links can drop. action "create": POST
        /proxy/network/v2/api/site/{site}/mclag-groups with group verbatim. action "update": reads
        GET .../mclag-groups, merges only the given leaves, PUT .../mclag-groups/{id} with the
        merged record and reads it back, adding _verified (type-strict per requested leaf) and
        _readAfterError. action "delete": DELETE .../mclag-groups/{id} (irreversible). Update and
        delete resolve group_id in the list first (an unknown id fails listing every valid id).
        group is required for create and update and omitted for delete; group_id is required for
        update and delete and omitted for create. Returns the upstream body (JSON object or
        array) verbatim for actions "create" and "update"; for action "update" a non-object
        body is returned whole under response with _verified (and _readAfterError) beside it.
        Action "delete" returns {deleted, message, response}: deleted is true, message
        summarizes the delete, and response is the upstream body verbatim (decoded JSON, raw
        text, or null when the body is empty).
        Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body); for
        action "delete" that preview is the response of {status: "dry_run", deleted: false, message,
        response}.

        Required arguments: host, site, action.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: "create", "update" or "delete", e.g. "update".
            group_id: Group _id or id, e.g. "65f1c0ffee0123456789abcd".
            group: Free-form group object (create) or leaves to change (update), e.g.
                {"name": "core-pair"}.
        """
        client, registry = deps_fn()
        return await manage_mclag_group(client, registry, host, site, action, group_id, group)

    @mcp.tool(name="update_switch_stack", annotations=WRITE)
    async def update_switch_stack_tool(
        host: str, site: str, stack_id: str, stack: dict[str, Any]
    ) -> Any:
        """Update a switch stack, e.g. its unit order (Network v2 route).

        Consequence: stack members can renumber or reboot. Reads GET .../stacking, merges only the
        given leaves into the stack, PUT /proxy/network/v2/api/site/{site}/stacking/{id} with the
        whole merged record and reads it back. Returns the upstream object verbatim plus _verified
        (true only when every requested leaf reads back equal, type-strict) and _readAfterError when
        the read-back failed; a non-object body (array or scalar) is returned whole under response
        with those keys beside it. id, _id and site_id in the object are ignored; an object with
        nothing else to change fails before any request. An unknown id fails listing every valid id.
        Never auto-retried.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, stack_id, stack.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            stack_id: Stack _id or id from GET .../stacking, e.g.
                "65f1c0ffee0123456789abcd".
            stack: Free-form object of leaves to change, e.g. {"unit_order": ["02:00:5e:00:00:a1",
                "02:00:5e:00:00:a2"]}.
        """
        client, registry = deps_fn()
        return await update_switch_stack(client, registry, host, site, stack_id, stack)
