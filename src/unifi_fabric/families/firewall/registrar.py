"""The firewall family registrar: its tool wrappers, in registration order (public #42 layout).

The firewall tools are split out of the network steps, so each family's tools have steps of
their own: the loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>``
below at the place the network step held them, so the ``tools/list`` order is unchanged, and
each keeps the ``origin`` its tools are indexed under (``firewall_proxy``,
``network_dpi_policy``, ``network_services_proxy``; an origin is an index key only and may
span family directories). Each wrapper calls its handler through the handler's module, so a
patched handler still applies. The handlers still live in the network modules: the import of
``..network`` is a kept cross-family import (pinned in ``tests/test_firewall_family.py``)
until the shared code moves to the common package.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ...shared_shapes._results import deletion_result
from ...tool_annotations import READ_ONLY, WRITE
from ..network import firewall_proxy, network_dpi_policy, network_services_proxy


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the firewall_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_policies(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List firewall policies for a site. Returns {data, totalCount}: every page is drained; data holds the policy records verbatim, totalCount is the upstream total (null if none reported), the first page's other envelope fields are kept, and incomplete/incompleteReason mark a capped drain. Offset alone fetches one page (totalCount surfaced so you can advance). limit requests a total, gathered in batches up to 200; _pageSize reports requested, sent, effective and returned sizes. filter is a Network Integration API filter expression forwarded unchanged (e.g. name.like('*guest*'), metadata.origin.eq('USER_DEFINED')); omitted when unset.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset.
                Example: `metadata.origin.eq('USER_DEFINED')`.
        """
        client, registry = deps_fn()
        return await firewall_proxy.list_firewall_policies(
            client, registry, host, site, offset, limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_firewall_policy(
        host: str,
        site: str,
        policy: dict[str, Any],
    ) -> Any:
        """Create a new firewall policy on a site. Returns the created policy object verbatim (under dry-run policy, the dry-run preview).

        The seven required keys of `policy` (name, enabled, loggingEnabled, action, source, destination, ipProtocolScope) are validated locally (a missing key raises ValueError naming it). action.type is ALLOW (also requires allowReturnTraffic), BLOCK or REJECT; ipProtocolScope.ipVersion is IPV4, IPV6 or IPV4_AND_IPV6. There is NO 'index' field: use set_firewall_policy_ordering. Get zone UUIDs from list_firewall_zones_proxy (data[].id). For port-only destination matching: destination.trafficFilter type PORT; address plus port: type IP_ADDRESS with portFilter; a source portFilter matches ephemeral source ports. Parameter schemas hold the full trafficFilter variants. Details: docs/TOOL-USAGE.md#create_firewall_policy.

        Required arguments: host, site, policy.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy: Full policy, schema "Create or update firewall policy". Required: name, enabled,
                loggingEnabled, action{type:ALLOW|BLOCK|REJECT}, source{zoneId}, destination{zoneId},
                ipProtocolScope{ipVersion}.
        """
        client, registry = deps_fn()
        return await firewall_proxy.create_firewall_policy(client, registry, host, site, policy)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> Any:
        """Get a single firewall policy by ID.

        Returns: the firewall policy object, verbatim. To change it, edit it and pass it as `policy` to
        update_firewall_policy (full replace); patch_firewall_policy takes only the fields its schema
        allows, as `fields`.

        Example call (get_firewall_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_firewall_policy(client, registry, host, site, policy_id)

    @mcp.tool(annotations=WRITE)
    async def update_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
        policy: dict[str, Any],
    ) -> Any:
        """Full-replace a firewall policy by ID: get_firewall_policy, edit, send the entire object; omitted optional fields are cleared. Returns the replaced policy object verbatim (under dry-run policy, the dry-run preview).

        In the policy, action.type is ALLOW (requires allowReturnTraffic), BLOCK or REJECT and ipProtocolScope.ipVersion is IPV4, IPV6 or IPV4_AND_IPV6. There is no index field: use set_firewall_policy_ordering. For port-only destination matching: destination.trafficFilter type PORT; address plus port: IP_ADDRESS with portFilter; a source portFilter matches ephemeral source ports. Zone UUIDs come from list_firewall_zones_proxy. Details: docs/TOOL-USAGE.md#update_firewall_policy.

        Required arguments: host, site, policy_id, policy.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
            policy: Complete official firewall policy object. Fetch it with get_firewall_policy;
                omitted optional fields are cleared by this PUT.
        """
        client, registry = deps_fn()
        return await firewall_proxy.update_firewall_policy(
            client, registry, host, site, policy_id, policy
        )

    @mcp.tool(annotations=WRITE)
    async def patch_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
        fields: dict[str, Any],
    ) -> Any:
        """Partially update a firewall policy by ID.

        Returns the upstream response body verbatim: the updated firewall policy object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Example call (patch_firewall_policy):
            {"host": "my-console", "site": "Default",
             "policy_id": "7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f01",
             "fields": {"loggingEnabled": true}}

        Details: docs/TOOL-USAGE.md#patch_firewall_policy.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
            fields: Partial update. Spec "Patch firewall policy" defines ONLY loggingEnabled and
                reportFlowEnabled (booleans). For any other change use update_firewall_policy.
        """
        client, registry = deps_fn()
        return await firewall_proxy.patch_firewall_policy(
            client, registry, host, site, policy_id, fields
        )

    @mcp.tool(annotations=WRITE)
    async def delete_firewall_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> dict[str, Any]:
        """Delete a firewall policy.

        Consequence: the policy stops applying immediately, so traffic it allowed or blocked falls through to the remaining policies; there is no undo.

        Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}.

        Example call (delete_firewall_policy):
            {"host": "my-console", "site": "Default",
             "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await firewall_proxy.delete_firewall_policy(
            client, registry, host, site, policy_id
        )
        return deletion_result(f"Firewall policy {policy_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_policy_ordering(
        host: str,
        site: str,
        source_zone_id: str,
        destination_zone_id: str,
    ) -> Any:
        """Get the ordering of firewall policies for a site filtered by source and destination zone.

        Returns: {"orderedFirewallPolicyIds": {"beforeSystemDefined": [policy id…], "afterSystemDefined": [policy id…]}}, verbatim — the user-defined order for this zone pair. Pass it verbatim (reordered, or unchanged for a no-op) as `ordering` to set_firewall_policy_ordering with the same source_zone_id and destination_zone_id. Ordering is per source/destination zone pair: find the pairs that have policies by calling list_firewall_policies and grouping data[] by source.zoneId / destination.zoneId (its `filter` narrows it, e.g. metadata.origin.eq('USER_DEFINED')).

        Prerequisite — {"tool": "list_firewall_zones_proxy", "arguments": {"host": "my-console", "site": "Default"}, "use": "data[].id of the source and destination zones"}.

        Example call (get_firewall_policy_ordering):
            {"host": "my-console", "site": "Default",
             "source_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
             "destination_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            source_zone_id: REQUIRED source firewall zone UUID, in 8-4-4-4-12 hex form, for
                example 0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01. A zone name such as Internal or External
                is rejected. Sent as query param sourceFirewallZoneId.
                Get it from list_firewall_zones_proxy (data[].id), matching the zone by name.
            destination_zone_id: REQUIRED destination firewall zone UUID, in 8-4-4-4-12 hex form, for
                example 0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01. A zone name such as Internal or External
                is rejected. Sent as query param destinationFirewallZoneId.
                Get it from list_firewall_zones_proxy (data[].id), matching the zone by name.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_firewall_policy_ordering(
            client, registry, host, site, source_zone_id, destination_zone_id
        )

    @mcp.tool(annotations=WRITE)
    async def set_firewall_policy_ordering(
        host: str,
        site: str,
        source_zone_id: str,
        destination_zone_id: str,
        ordering: dict[str, Any],
    ) -> Any:
        """Set the ordering of firewall policies within one source/destination zone pair.

        Returns: the controller's response, verbatim — the resulting order in the same {"orderedFirewallPolicyIds": {"beforeSystemDefined": […], "afterSystemDefined": […]}} shape (published response schema IntegrationFirewallPolicyOrderingDto). Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Full replace of the user-defined order for ONE source/destination zone pair: start from get_firewall_policy_ordering for the same pair, reorder, and send it back. Use [] for an empty side. Afterwards, read back with get_firewall_policy_ordering and compare. If either zone id is missing, upstream returns HTTP 400 (the zone ids are query parameters, never read from the body).

        Example call (set_firewall_policy_ordering):
            {"host": "my-console", "site": "Default",
             "source_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
             "destination_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02",
             "ordering": {"orderedFirewallPolicyIds": {
               "beforeSystemDefined": ["7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f02"],
               "afterSystemDefined": []}}}

        Details: docs/TOOL-USAGE.md#set_firewall_policy_ordering.

        Required arguments: host, site, source_zone_id, destination_zone_id, ordering (see parameter descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            source_zone_id: REQUIRED source firewall zone UUID, in 8-4-4-4-12 hex form, for
                example 0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01. A zone name such as Internal or External
                is rejected. Sent as query param sourceFirewallZoneId.
                Get it from list_firewall_zones_proxy (data[].id), matching the zone by name.
            destination_zone_id: REQUIRED destination firewall zone UUID, in 8-4-4-4-12 hex form, for
                example 0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01. A zone name such as Internal or External
                is rejected. Sent as query param destinationFirewallZoneId.
                Get it from list_firewall_zones_proxy (data[].id), matching the zone by name.
            ordering: Full replacement
                {"orderedFirewallPolicyIds":{"beforeSystemDefined":[uuid…],"afterSystemDefined":[uuid…]}};
                the published spec requires both arrays, but this tool does not check them and
                sends the body as given. Start from get_firewall_policy_ordering output.
        """
        client, registry = deps_fn()
        return await firewall_proxy.set_firewall_policy_ordering(
            client, registry, host, site, source_zone_id, destination_zone_id, ordering
        )

    # --- Firewall Zone Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_zones_proxy(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all firewall zones for a site via connector proxy.

        This is the firewall-zone list; the _proxy suffix is historical. Returns {data: [{id, name, networkIds, metadata: {origin, configurable}}], totalCount}. System-defined zones (metadata.origin SYSTEM_DEFINED) carry the names the controller returns — Internal, External, Gateway, Vpn, Hotspot and Dmz on Network 11.0.81 — so compare zone names case-insensitively ("VPN" matches "Vpn"). Every other tool takes a zone by its id (data[].id), never by name.

        Zones are offset-paginated (native default page size 25); by default every page is drained and the complete list is returned as {data, totalCount}. Pass offset alone for a single manual page. A capped drain is flagged incomplete.

        limit requests a total, gathered automatically in batches up to 200; _pageSize reports requested count, actual sent sizes per request, observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `metadata.origin.eq('USER_DEFINED')`.
        """
        client, registry = deps_fn()
        return await firewall_proxy.list_firewall_zones(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_firewall_zone_proxy(
        host: str,
        site: str,
        zone: dict[str, Any],
    ) -> Any:
        """Create a new firewall zone on a site via connector proxy.

        Returns the upstream response body verbatim: the created firewall zone object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        `zone`: must include {'name': str, 'networkIds': [str]} — both required, validated locally (a missing field raises ValueError naming it) and verified against the live controller. Get network IDs from list_networks.

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/firewall/zones (createFirewallZone);
        schema "Create or update firewall zone") is passed in `zone`. Required keys — name, networkIds.
        - name: string
        - networkIds: array of string (uuid)

        Example call (create_firewall_zone_proxy):
            {"host": "my-console", "site": "Default",
             "zone": {"name": "Hotspot", "networkIds": ["dfb21062-8ea0-4dca-b1d8-1eb3da00e58b"]}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone: Full object to create; spec Create or update firewall zone. Required: name,
                networkIds.
        """
        client, registry = deps_fn()
        return await firewall_proxy.create_firewall_zone(client, registry, host, site, zone)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_zone_proxy(
        host: str,
        site: str,
        zone_id: str,
    ) -> Any:
        """Get a single firewall zone by ID via connector proxy.

        Returns: the firewall zone object, verbatim. To change it, edit it and pass it as `zone` to
        update_firewall_zone_proxy.

        Example call (get_firewall_zone_proxy):
            {"host": "my-console", "site": "Default", "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_firewall_zone(client, registry, host, site, zone_id)

    @mcp.tool(annotations=WRITE)
    async def update_firewall_zone_proxy(
        host: str,
        site: str,
        zone_id: str,
        zone: dict[str, Any],
    ) -> Any:
        """Update a firewall zone by ID via connector proxy.

        Returns the upstream response body verbatim: the updated firewall zone object the API answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 11.0.97, PUT /v1/sites/{siteId}/firewall/zones/{firewallZoneId}
        (updateFirewallZone); schema "Create or update firewall zone") is passed in `zone`. Required
        keys — name, networkIds.
        - name: string
        - networkIds: array of string (uuid)

        Example call (update_firewall_zone_proxy):
            {
              "host": "my-console",
              "site": "Default",
              "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "zone": {"name": "Hotspot", "networkIds": ["dfb21062-8ea0-4dca-b1d8-1eb3da00e58b"]}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
                UUID — not a Protect id.
            zone: FULL replacement object (PUT; omitted fields reset); spec Create or update firewall
                zone. Required: name, networkIds.
        """
        client, registry = deps_fn()
        return await firewall_proxy.update_firewall_zone(
            client, registry, host, site, zone_id, zone
        )

    @mcp.tool(annotations=WRITE)
    async def delete_firewall_zone_proxy(
        host: str,
        site: str,
        zone_id: str,
    ) -> dict[str, Any]:
        """Delete a firewall zone via connector proxy.

        Consequence: the zone is permanently removed; there is no undo.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_firewall_zone_proxy):
            {"host": "my-console", "site": "Default", "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await firewall_proxy.delete_firewall_zone(client, registry, host, site, zone_id)
        return deletion_result(f"Firewall zone {zone_id} deleted.", response)

    # --- ACL Rule Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_acl_rules(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all ACL rules for a site.

        ACL rules include IPv4 network-layer (L3) and MAC access lists, used to filter traffic
        between networks or within a VLAN. Use them only when the user asks for ACL rules; for an
        ordinary firewall rule use zone-based firewall policies (create_firewall_policy).

        Returns {data, totalCount} with every page drained (the API pages at 25 by default).
        Pass offset alone to fetch a single manual page (native envelope preserved).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await firewall_proxy.list_acl_rules(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_acl_rule(
        host: str,
        site: str,
        rule: dict[str, Any],
    ) -> Any:
        """Create a new ACL rule on a site.

        Returns the upstream response body verbatim: the created ACL rule object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it): ``type`` — the discriminator the controller validates first (verified live: an empty body is rejected with ``Missing $.type value``; observed value: 'MAC'). The remaining fields are type-specific and enforced by the controller. `rule`: for a MAC-type rule the live object also carries: name (str), action, enabled (bool), sourceFilter, networkIdFilter. Read an existing rule with get_acl_rule to see the exact shape for the type you want. Note: ACL rules include IPv4 network-layer (L3) and MAC access lists for filtering traffic between networks or within a VLAN. Use them only when the user asks for ACL rules; otherwise use zone-based firewall policies (create_firewall_policy).

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/acl-rules (createAclRule); schema "ACL
        rule update") is passed in `rule`. Required keys — action, enabled, name, type.
        - action: enum[ALLOW|BLOCK]
        - description: string
        - destinationFilter: any
        - enabled: boolean
        - enforcingDeviceFilter: oneOf by type[DEVICES] (ACL rule device filter)
        - index: integer(int32); deprecated, no effect per spec: reorder with set_acl_rule_ordering
        - name: string
        - sourceFilter: any
        - type: string
        Variants by `type` — IPV4 requires action, enabled, name, type; MAC requires action, enabled,
        name, networkIdFilter, type.

        Example call (create_acl_rule):
            {
              "host": "my-console",
              "site": "Default",
              "rule": {
                "type": "IPV4",
                "action": "ALLOW",
                "enabled": true,
                "name": "Allow printer access"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule: Full object to create; spec ACL rule update. Required: action, enabled, name, type.
                'type' selects variant: IPV4|MAC.
        """
        client, registry = deps_fn()
        return await firewall_proxy.create_acl_rule(client, registry, host, site, rule)

    @mcp.tool(annotations=READ_ONLY)
    async def get_acl_rule(
        host: str,
        site: str,
        rule_id: str,
    ) -> Any:
        """Get a single ACL rule by ID.

        Returns: the ACL rule object, verbatim. To change it, edit it and pass it as `rule` to
        update_acl_rule.

        Example call (get_acl_rule):
            {"host": "my-console", "site": "Default", "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
                Protect id.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_acl_rule(client, registry, host, site, rule_id)

    @mcp.tool(annotations=WRITE)
    async def update_acl_rule(
        host: str,
        site: str,
        rule_id: str,
        rule: dict[str, Any],
    ) -> Any:
        """Update an existing ACL rule by ID.

        Returns the upstream response body verbatim: the updated ACL rule object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Request body (Network 11.0.97, PUT /v1/sites/{siteId}/acl-rules/{aclRuleId} (updateAclRule);
        schema "ACL rule update") is passed in `rule`. Required keys — action, enabled, name, type.
        - action: enum[ALLOW|BLOCK]
        - description: string
        - destinationFilter: any
        - enabled: boolean
        - enforcingDeviceFilter: oneOf by type[DEVICES] (ACL rule device filter)
        - index: integer(int32); deprecated, no effect per spec: reorder with set_acl_rule_ordering
        - name: string
        - sourceFilter: any
        - type: string
        Variants by `type` — IPV4 requires action, enabled, name, type; MAC requires action, enabled,
        name, networkIdFilter, type.

        Example call (update_acl_rule):
            {
              "host": "my-console",
              "site": "Default",
              "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "rule": {
                "type": "IPV4",
                "action": "ALLOW",
                "enabled": true,
                "name": "Allow printer access"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
                Protect id.
            rule: FULL replacement object (PUT; omitted fields reset); spec ACL rule update. Required:
                action, enabled, name, type. 'type' selects variant: IPV4|MAC.
        """
        client, registry = deps_fn()
        return await firewall_proxy.update_acl_rule(client, registry, host, site, rule_id, rule)

    @mcp.tool(annotations=WRITE)
    async def delete_acl_rule(
        host: str,
        site: str,
        rule_id: str,
    ) -> dict[str, Any]:
        """Delete an ACL rule.

        Consequence: the rule stops filtering traffic immediately; there is no undo (recreate it from a
        saved copy).

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_acl_rule):
            {"host": "my-console", "site": "Default", "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
                Protect id.
        """
        client, registry = deps_fn()
        response = await firewall_proxy.delete_acl_rule(client, registry, host, site, rule_id)
        return deletion_result(f"ACL rule {rule_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def get_acl_rule_ordering(
        host: str,
        site: str,
    ) -> Any:
        """Get the ordering of ACL rules for a site.

        Returns: {"orderedAclRuleIds": [rule id…]}, verbatim, in evaluation order. Pass it verbatim
        (reordered, or unchanged for a no-op) as `ordering` to set_acl_rule_ordering.

        Example call (get_acl_rule_ordering):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await firewall_proxy.get_acl_rule_ordering(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def set_acl_rule_ordering(
        host: str,
        site: str,
        ordering: dict[str, Any],
    ) -> Any:
        """Set the ordering of ACL rules for a site.

        Returns: the controller's response, verbatim — the resulting order in the same {"orderedAclRuleIds": […]} shape (published response schema "ACL rule ordering"). Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Typical sequence (one tool call per step):
        1. get_acl_rule_ordering(host="my-console", site="Default").
        2. set_acl_rule_ordering(host="my-console", site="Default", ordering={…}).
        3. get_acl_rule_ordering(host="my-console", site="Default") — read back and compare.

        Example call (set_acl_rule_ordering):
            {
              "host": "my-console",
              "site": "Default",
              "ordering": {
                "orderedAclRuleIds": [
                  "5c2b9e10-3d4f-4a6b-9c8d-7e6f5a4b3c02",
                  "5c2b9e10-3d4f-4a6b-9c8d-7e6f5a4b3c01"
                ]
              }
            }

        Details: docs/TOOL-USAGE.md#set_acl_rule_ordering.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            ordering: Full replacement {"orderedAclRuleIds":[uuid…]} in evaluation order (schema "ACL
                rule ordering"). Start from get_acl_rule_ordering; ids from list_acl_rules.
        """
        client, registry = deps_fn()
        return await firewall_proxy.set_acl_rule_ordering(client, registry, host, site, ordering)

    return {
        "list_firewall_policies": list_firewall_policies,
        "create_firewall_policy": create_firewall_policy,
        "get_firewall_policy": get_firewall_policy,
        "update_firewall_policy": update_firewall_policy,
        "patch_firewall_policy": patch_firewall_policy,
        "delete_firewall_policy": delete_firewall_policy,
        "get_firewall_policy_ordering": get_firewall_policy_ordering,
        "set_firewall_policy_ordering": set_firewall_policy_ordering,
        "list_firewall_zones_proxy": list_firewall_zones_proxy,
        "create_firewall_zone_proxy": create_firewall_zone_proxy,
        "get_firewall_zone_proxy": get_firewall_zone_proxy,
        "update_firewall_zone_proxy": update_firewall_zone_proxy,
        "delete_firewall_zone_proxy": delete_firewall_zone_proxy,
        "list_acl_rules": list_acl_rules,
        "create_acl_rule": create_acl_rule,
        "get_acl_rule": get_acl_rule,
        "update_acl_rule": update_acl_rule,
        "delete_acl_rule": delete_acl_rule,
        "get_acl_rule_ordering": get_acl_rule_ordering,
        "set_acl_rule_ordering": set_acl_rule_ordering,
    }


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the network_dpi_policy lane's firewall tools, split from the network step;
    they keep their place in the ``tools/list`` order."""

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def list_firewall_app_blocks(host: str, site: str) -> Any:
        """Read application blocks. Returns the complete application-block array verbatim
        (nonobjects use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_list_firewall_app_blocks(client, registry, host, site)

    @mcp.tool(
        annotations=WRITE,
    )
    async def set_firewall_app_blocks(host: str, site: str, blocks: list[dict[str, Any]]) -> Any:
        """Replace application blocks with the complete returned array. Consequence: replaces
        the configured app blocks, removing omitted entries. Returns upstream body and
        _redactedFieldsNotSent when masked fields are omitted (nonobjects use result). Under
        dry-run policy sends no mutation and returns {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            blocks: Complete list of free-form JSON objects from list_firewall_app_blocks.
                Preserve existing entries and private fields. An empty list removes all blocks.
                Captured fields include name, enabled, source_type, source_networks,
                source_devices, target_type, app_ids and app_category_ids.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_set_firewall_app_blocks(
            client, registry, host, site, blocks
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def preview_firewall_group(host: str, site: str, group: dict[str, Any]) -> Any:
        """Preview a firewall group URL. Consequence: submits the URL to the controller preview
        action, classified as a write. Returns upstream body and _redactedFieldsNotSent when
        masked fields are omitted (nonobjects use result). Under dry-run policy sends no mutation
        and returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group: Free-form JSON object; FE fields url (for example
                'https://example.invalid/list.txt') and group_type (controller string).
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_preview_firewall_group(
            client, registry, host, site, group
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def update_predefined_firewall_policy(
        host: str, site: str, policy_id: str, policy: dict[str, Any]
    ) -> Any:
        """Update a predefined firewall policy (PUT /v1/sites/{siteId}/firewall/policies/{id}).

        Read-merge-write and type-strict requested-leaf verification. Returns the upstream
        write body with _verified and possible _readAfterError; nonobjects use result. Masked
        fields are omitted and reported in _redactedFieldsNotSent. Under dry-run policy sends no
        mutation and returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; no read-back or verification.

        This is the full PUT of the Integration API. A policy whose metadata.origin is
        SYSTEM_DEFINED is refused by the controller (Network 11.0.89: HTTP 400
        system-defined-firewall-policy-update-forbidden, returned whole with a hint); change
        only its loggingEnabled or reportFlowEnabled with patch_firewall_policy instead.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            policy_id: Official UUID from list_firewall_policies or get_firewall_policy,
                for example 'bbbbbbbb-0000-4000-8000-000000000001'; not a private v2 _id.
            policy: Nonempty partial official policy object, for example {'enabled': False}.
                Fields use the published Network 11.0.97 shape; see its properties.
                Read-only id, index and metadata are not sent; all unrequested
                writable fields are preserved.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_update_predefined_firewall_policy(
            client, registry, host, site, policy_id, policy
        )

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def get_firewall_zone_matrix(host: str, site: str) -> Any:
        """Read the private firewall-zone matrix. Returns the upstream body unchanged
        (nonobjects use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_get_firewall_zone_matrix(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def batch_delete_acl_rules(host: str, site: str, ids: list[str]) -> Any:
        """Batch-delete ACL rules (v2 POST acl-rules/batch-delete, one call). Consequence: permanently removes every listed record; there is no undo. Each id is resolved against the v2 list first (an unknown id fails with the valid ids and sends nothing), then the list is read back. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim; deleted is false and message names the ids still listed when the read-back still has any, or says the removal is unverified when the read-back failed. Under dry-run policy sends nothing and returns {status: "dry_run", deleted: false, message, response}, where response is {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            ids: List of ACL rule id strings to delete, for example
                ["0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a90"], the ids the list and create tools
                return (the private _id is accepted too). Each id must be non-empty with no
                surrounding whitespace.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._batch_delete_acl_rules(client, registry, host, site, ids)

    @mcp.tool(
        annotations=WRITE,
    )
    async def batch_delete_firewall_policies(host: str, site: str, ids: list[str]) -> Any:
        """Batch-delete firewall policies (DELETE firewall/policies/{id} per id, then read back). Consequence: permanently removes every listed record; there is no undo. The v2 batch route cannot be addressed with Integration ids, so each id goes to the Integration DELETE, then each id is read back. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. With several differing bodies response is the list of them in id order. When a read-back still finds an id, deleted is false and message names it; when the read-back failed, readAfterError says why. A failing DELETE raises, naming the ids already deleted. Under dry-run policy sends nothing and returns {status: "dry_run", deleted: false, message, response}, where response is {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} (a list of them for several ids).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            ids: List of firewall policy ids to delete, for example
                ["0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a90"], the ids the list and create tools
                return. Each id must be letters, digits, hyphen or underscore only.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._batch_delete_firewall_policies(
            client, registry, host, site, ids
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def batch_delete_firewall_zones(host: str, site: str, ids: list[str]) -> Any:
        """Batch-delete firewall zones (v2 POST firewall/zone/batch-delete, one call). Consequence: permanently removes every listed record; there is no undo. Each id is resolved against the v2 list first (an unknown id fails with the valid ids and sends nothing), then the list is read back. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim; deleted is false and message names the ids still listed when the read-back still has any, or says the removal is unverified when the read-back failed. Under dry-run policy sends nothing and returns {status: "dry_run", deleted: false, message, response}, where response is {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            ids: List of firewall zone id strings to delete, for example
                ["0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a90"], the ids the list and create tools
                return (the private _id is accepted too). Each id must be non-empty with no
                surrounding whitespace.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._batch_delete_firewall_zones(
            client, registry, host, site, ids
        )


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy firewall tool wrappers, split from the network
    step; they keep their place in the ``tools/list`` order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_rules(
        host: str,
        site: str,
    ) -> Any:
        """List classic L3/L4 firewall rules for a site (distinct from Integration API policies).

        Legacy, read-only: classic rules predate zone-based firewalling, and the Network 11.0.81
        web UI no longer reads this route. For the current firewall use list_firewall_policies
        (and get_firewall_policy, create_firewall_policy, update_firewall_policy).

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_firewall_rules(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_firewall_rule(
        host: str,
        site: str,
        rule: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Create a classic L3/L4 firewall rule for a site.

        This is an immediate, destructive Network write. It can change which traffic is
        allowed through the site's firewall. ``confirm`` is accepted for compatibility
        and ignored; the write runs whether it is true or false.

        This uses the private Early Access Site Manager route because the current official
        Network specification publishes only zone-based firewall policies. Prefer
        create_firewall_policy on zone-based Network releases.

        Returns the controller's response verbatim, typically {meta: {rc}, data: [...]}.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}} instead of the upstream body.

        Required arguments: host, site, rule (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Site Manager site name or ObjectId, scoped to host. Get names and ids from
                list_sites (data[].meta.name or data[].siteId).
            rule: Free-form classic firewall-rule request body, forwarded unchanged for the
                controller to validate. Observed fields include name, action, enabled,
                ruleset, rule_index, protocol, src_address, dst_address,
                src_networkconf_id, dst_networkconf_id and dst_port.
            confirm: Accepted and ignored. The write always runs. Example: false.
        """
        del confirm
        client, registry = deps_fn()
        return await network_services_proxy.create_firewall_rule(client, registry, host, site, rule)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_rule(
        host: str,
        site: str,
        rule_id: str,
    ) -> Any:
        """Get a single classic firewall rule by ID.

        Legacy, read-only: for the current zone-based firewall use get_firewall_policy (ids from
        list_firewall_policies).

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_firewall_rule):
            {"host": "my-console", "site": "Default", "rule_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: Legacy firewall rule _id (classic REST). Get it from list_firewall_rules (_id).
                Not a firewall policy UUID.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_firewall_rule(client, registry, host, site, rule_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_groups(
        host: str,
        site: str,
    ) -> Any:
        """List firewall groups (IP/port sets referenced by firewall rules) for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_firewall_groups(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_group(
        host: str,
        site: str,
        group_id: str,
    ) -> Any:
        """Get a single firewall group by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_firewall_group):
            {"host": "my-console", "site": "Default", "group_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            group_id: Legacy firewall group _id (classic REST). Get it from list_firewall_groups (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_firewall_group(
            client, registry, host, site, group_id
        )

    return {
        "list_firewall_rules": list_firewall_rules,
        "create_firewall_rule": create_firewall_rule,
        "get_firewall_rule": get_firewall_rule,
        "list_firewall_groups": list_firewall_groups,
        "get_firewall_group": get_firewall_group,
    }
