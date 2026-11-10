"""Cloud-only Network v2 Matter/Thread routes discovered from Network 11.0.81."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from pydantic import SecretStr

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    upstream_error_value,
    validate_id,
)
from ...config import APIKeyConfig
from ...matching import find_by_id
from ...read_only import guard_request, mark_write_denied
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._pagination import collect_offset, offset_list_result
from ...shared_shapes._results import deletion_result
from ...tool_annotations import READ_ONLY, WRITE
from ..connector.connector import area_write_refusal

BASE = "/v1/connector/consoles/{host_id}/proxy/network/v2/api/site/{site_slug}"


async def _target(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str]:
    check_selector("host", host)
    check_selector("site", site)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return key, BASE.format(host_id=host_id, site_slug=site_slug)


def _write_guard(method: str) -> None:
    # Direct Python callers get the same pre-resolution guards as MCP callers.
    guard_request(method, "network/v2/api/site/{site}/matter/nodes")
    refusal = area_write_refusal("network")
    if refusal is not None:
        raise mark_write_denied(ValueError(refusal))


async def _list(client: UniFiClient, path: str, key: APIKeyConfig | None) -> Any:
    raw = await client.get(path, key=key)
    # These FE routes return complete bare arrays, verified live, and ignore
    # offset/limit. Do not invent paging parameters or a get-by-id API for them.
    if isinstance(raw, list):
        return raw
    # If a controller exposes an offset envelope, drain it with the shared guard.
    if isinstance(raw, dict) and isinstance(raw.get("data"), list):
        if any(field in raw for field in ("offset", "limit", "totalCount", "total")):
            return offset_list_result(await collect_offset(client, path, key=key))
        return raw
    raise UniFiConnectionError(
        f"Unexpected response shape from GET {path}: expected a bare array or data array "
        f"envelope, got {describe_shape(raw)}"
    )


async def list_thread_networks(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    key, base = await _target(registry, host, site)
    return await _list(client, base + "/thread-networks", key)


async def list_matter_nodes(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    key, base = await _target(registry, host, site)
    return await _list(client, base + "/matter/nodes", key)


async def _matter_node_id(
    client: UniFiClient, base: str, key: APIKeyConfig | None, node_id: str
) -> str:
    """Resolve a Matter node id from the native collection before a destructive write."""
    body = await _list(client, base + "/matter/nodes", key)
    rows = body.get("data") if isinstance(body, dict) else body
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {base}/matter/nodes: expected node objects"
        )
    record = find_by_id(rows, node_id, "id", "_id")
    if record is not None:
        native_id = record.get("id", record.get("_id"))
        if not isinstance(native_id, str):
            raise ValueError(
                f"Selected Matter node has invalid native id "
                f"{upstream_error_value(native_id, client)!r}. No write was sent."
            )
        try:
            validate_id(native_id, "node_id")
        except ValueError:
            # Redact the structured value before repr escapes quotes inside it.
            # Re-parsing validate_id's formatted exception loses that structure.
            raise ValueError(
                f"Selected Matter node has invalid native id "
                f"{upstream_error_value(native_id, client)!r}. No write was sent."
            ) from None
        return native_id
    valid = (
        "; ".join(
            f"{upstream_error_value(row.get('name'), client)!r} "
            f"(id={upstream_error_value(row.get('id'), client)}, "
            f"_id={upstream_error_value(row.get('_id'), client)})"
            for row in rows
        )
        or "(none)"
    )
    raise ValueError(
        f"Matter node {node_id!r} not found; valid: {valid}. Get ids from list_matter_nodes. "
        "No write was sent."
    )


async def commission_matter_node(
    client: UniFiClient, registry: Registry, host: str, site: str, setup_code: SecretStr
) -> Any:
    _write_guard("POST")
    if not isinstance(setup_code, SecretStr):
        raise ValueError("setup_code must be a secret string containing the device setup code")
    code = setup_code.get_secret_value()
    # The setup code is a registered route secret (route_secrets.ROUTE_SECRETS): the
    # client binds it into the call's scrub scope before sending. Dry-run previews
    # mask it only with UNIFI_REDACT_SECRETS, also through the generic relay.
    # A successful upstream body is returned verbatim.
    key, base = await _target(registry, host, site)
    return await client.post(base + "/matter/nodes", key=key, json={"setup_code": code})


async def rename_matter_node(
    client: UniFiClient, registry: Registry, host: str, site: str, node_id: str, name: str
) -> Any:
    _write_guard("PUT")
    validate_id(node_id, "node_id")
    if not isinstance(name, str):
        raise ValueError("name must be a string; pass the new Matter node name")
    key, base = await _target(registry, host, site)
    native_id = await _matter_node_id(client, base, key, node_id)
    return await client.put(base + f"/matter/nodes/{native_id}", key=key, json={"name": name})


async def remove_matter_node(
    client: UniFiClient, registry: Registry, host: str, site: str, node_id: str
) -> Any:
    _write_guard("DELETE")
    validate_id(node_id, "node_id")
    key, base = await _target(registry, host, site)
    native_id = await _matter_node_id(client, base, key, node_id)
    response = await client.delete(base + f"/matter/nodes/{native_id}", key=key)
    return deletion_result(f"Matter node {node_id} removed.", response)


_list_thread_networks = list_thread_networks
_list_matter_nodes = list_matter_nodes
_commission_matter_node = commission_matter_node
_rename_matter_node = rename_matter_node
_remove_matter_node = remove_matter_node


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def list_thread_networks(host: str, site: str) -> Any:
        """List Thread networks through the cloud connector, preserving the native body.

        Returns the Network v2 bare array, including all border router and network fields.
        This endpoint ignores offset/limit and returns its complete array. A controller
        returning an offset envelope is drained, with explicit caps marked incomplete.

        Args:
            host: Console name or composite id from list_hosts; for example "Gateway".
            site: Network site name, id or slug from list_local_sites; for example "default".
        """
        client, registry = deps_fn()
        return await _list_thread_networks(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_matter_nodes(host: str, site: str) -> Any:
        """List commissioned Matter nodes through the cloud connector.

        Returns the native bare array, including an empty array when no nodes exist.
        The endpoint ignores offset/limit. A controller returning an offset envelope
        is drained, with explicit caps marked incomplete. No local console transport.

        Args:
            host: Console name or composite id from list_hosts; for example "Gateway".
            site: Network site name, id or slug from list_local_sites; for example "default".
        """
        client, registry = deps_fn()
        return await _list_matter_nodes(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def commission_matter_node(
        host: str, site: str, setup_code: SecretStr, confirm: bool = False
    ) -> Any:
        """Commission a Matter device using its setup code through the cloud connector.

        Consequence: the device joins this console's Matter fabric and becomes a node that
        list_matter_nodes reports and other Matter tools can control.

        Sends the exact setup_code string to POST matter/nodes and returns the native
        body unchanged. The setup code is secret: logs always scrub it; returned errors and
        the dry-run preview mask it only with UNIFI_REDACT_SECRETS. Under dry-run policy
        nothing is sent and the preview is returned instead. Network write opt-out and global
        read-only mode apply before any request. Commissioning requires a device in
        pairing mode.

        Returns the upstream body unchanged. With dry-run policy, returns
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}} without sending a write.

        Args:
            host: Console name or composite id from list_hosts; for example "Gateway".
            site: Network site name, id or slug from list_local_sites; for example "default".
            setup_code: Secret device pairing code copied from its label; for example "34970112332".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _commission_matter_node(client, registry, host, site, setup_code)

    @mcp.tool(annotations=WRITE)
    async def rename_matter_node(
        host: str, site: str, node_id: str, name: str, confirm: bool = False
    ) -> Any:
        """Rename a commissioned Matter node through the cloud connector.

        Sends PUT matter/nodes/{node_id} with {name} and returns the native body
        unchanged. No invented verification or no-op result. Discover the native node
        identifier with list_matter_nodes. Dry-run returns a preview without writing.

        Returns the upstream body unchanged. With dry-run policy, returns
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}} without sending a write.

        Args:
            host: Console name or composite id from list_hosts; for example "Gateway".
            site: Network site name, id or slug from list_local_sites; for example "default".
            node_id: Native Matter node id from list_matter_nodes; for example "999999999999999999".
            name: New display name sent exactly as given; for example "Desk lamp".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _rename_matter_node(client, registry, host, site, node_id, name)

    @mcp.tool(annotations=WRITE)
    async def remove_matter_node(host: str, site: str, node_id: str, confirm: bool = False) -> Any:
        """Remove a commissioned Matter node through the cloud connector.

        Consequence: the node leaves this console's Matter fabric and can no longer be
        controlled here; it must be commissioned again (in pairing mode) to return.

        Sends DELETE matter/nodes/{node_id}. Discover ids with list_matter_nodes.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). With dry-run policy, returns {status: "dry_run", deleted: false, message, response},
        where response is the dry-run preview {status, dryRun, sent: false, message, preview:
        {method, path, params, body}}, without sending a write.

        Args:
            host: Console name or composite id from list_hosts; for example "Gateway".
            site: Network site name, id or slug from list_local_sites; for example "default".
            node_id: Native Matter node id from list_matter_nodes; for example "999999999999999999".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _remove_matter_node(client, registry, host, site, node_id)
