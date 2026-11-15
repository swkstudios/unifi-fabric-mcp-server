"""The network family registrar: its tool wrappers, in registration order (the family-owned layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from inspect import Parameter, getdoc, signature
from types import SimpleNamespace
from typing import Any, Literal, cast

from fastmcp import FastMCP
from pydantic import SecretStr

from ..._read_only_audit import derive_write_tools
from ...client import UniFiClient, path_segment, validate_selector
from ...macs import colon_mac, is_mac, normalize_mac
from ...read_only import guard_action
from ...registry import Registry
from ...shared_shapes._classic_objects import resolve_site_slug, v2_site
from ...shared_shapes._payload import missing_fields_hint
from ...shared_shapes._results import deletion_result
from ...shared_shapes._shared import _validate_optional_site
from ...shared_shapes._site_config_shared import _delete_config_record, _update_config_record
from ...tool_annotations import READ_ONLY, WRITE, for_tool
from ...write_body import require_unmasked_fields
from . import (
    matter,
    network,
    network_clients_guests,
    network_controller_admin,
    network_controller_insights,
    network_device_operations,
    network_dpi_policy,
    network_mobile_wan,
    network_nat_qos_traffic,
    network_proav_sandbox,
    network_routing_topology,
    network_security_diagnostics,
    network_services_proxy,
    network_switching_power,
    network_wifi_radio,
    site_admin,
    site_config,
)
from .schemas import (
    DefaultsKind,
    EnrichedKind,
    EsimAction,
    GuestTarget,
    IconTarget,
    LoadBalancingView,
    LteManager,
    ObservabilityView,
    ParamValue,
    StatsView,
    UpsAction,
    WarningsSource,
    WifiReportTarget,
)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def get_network_application_info(
        host: str,
    ) -> Any:
        """Get the UniFi Network application version reported by a console.

        Returns the upstream application-info ({applicationVersion, ...}) object verbatim, exactly as
        the API answers it.

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await network.get_network_application_info(client, registry, host)

    @mcp.tool(annotations=READ_ONLY)
    async def list_local_sites(
        host: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List sites managed by one UniFi Network application.

        Every site managed by that one Network application (the local sites of one console).

        Returns {data, totalCount}: every page is drained; data holds the site records verbatim and
        totalCount is the upstream total (null when none was reported). The first page's other envelope
        fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
        stopped short.

        By default every page is drained and the complete list is returned. Pass
        offset alone to fetch a single page manually (native envelope preserved).
        A capped drain returns the sites gathered so far with incomplete=true rather
        than truncating silently. filter: optional UniFi Integration API filter.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional UniFi Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter. Omitted entirely when unset.
                Example: `name.eq('Default')`."""
        client, registry = deps_fn()
        return await network.list_local_sites(
            client,
            registry,
            host,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_networks(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all networks/VLANs for a site.

        Returns {data, totalCount}: every page is drained; data holds the network records verbatim and totalCount is the upstream total (null when none was reported). The first page's other envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped drain stopped short.

        Networks are offset-paginated (native default page size 25); by default every page is drained and the complete list is returned as {data, totalCount}. Pass offset alone for a single manual page. filter: optional Network Integration API filter expression, forwarded unchanged as the upstream `filter` query parameter for server-side filtering (e.g. `vlanId.eq(100)`, `name.like('*guest*')`, `metadata.origin.eq('USER_DEFINED')`); omitted entirely when unset. A capped drain is flagged incomplete.

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
                upstream `filter` query parameter (e.g. `vlanId.eq(100)`, `name.like('*guest*')`,
                `metadata.origin.eq('USER_DEFINED')`). Omitted entirely when unset.
                Example: `metadata.origin.eq('USER_DEFINED')`.
        """
        client, registry = deps_fn()
        return await network.list_networks(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_network(
        host: str,
        site: str,
        network_config: dict[str, Any],
    ) -> Any:
        """Create a new network/VLAN on a site. Returns the created network object verbatim (under dry-run policy, the dry-run preview).

        `network_config` is sent verbatim; a missing `management` raises ValueError (the discriminator the controller validates first). Field names are camelCase as in the spec: the IPv4 block is ipv4Configuration (lower-case v); there is no 'purpose' field. For management='GATEWAY' the controller also requires name, vlanId (1 only for the default network, else 2-4009), enabled, internetAccessEnabled, isolationEnabled, cellularBackupEnabled and ipv4Configuration (hostIpAddress + prefixLength, required autoScaleEnabled, optional DHCP). Optional zoneId (from list_firewall_zones_proxy). Copy a working ipv4Configuration from get_network.

        Network auto-exclusion: UniFi silently adds every new network to excluded_networkconf_ids of ALL custom-tagged port profiles (tagged_vlan_mgmt 'custom'), blackholing the VLAN at the host uplink. The response then carries a _warnings entry (D12_AUTO_EXCLUSION) naming each profile and the network's Classic _id; run allow_network_on_port_profile on each (either id works).

        Details: docs/TOOL-USAGE.md#create_network.

        Required arguments: host, site, network_config.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_config: Full object to create; spec Create or update Network. Required: enabled,
                management, name, vlanId. 'management' selects variant: GATEWAY|SWITCH|UNMANAGED.
        """
        client, registry = deps_fn()
        created = await network.create_network(client, registry, host, site, network_config)
        return await network_services_proxy.annotate_auto_exclusions(
            client, registry, host, site, created
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_network(
        host: str,
        site: str,
        network_id: str,
    ) -> Any:
        """Get a single network/VLAN by ID.

        Returns: the network object, verbatim. To change it, edit it and pass it as `network_config` to
        update_network.

        Example call (get_network):
            {
              "host": "my-console",
              "site": "Default",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
        """
        client, registry = deps_fn()
        return await network.get_network(client, registry, host, site, network_id)

    @mcp.tool(annotations=WRITE)
    async def update_network(
        host: str,
        site: str,
        network_id: str,
        network_config: dict[str, Any],
    ) -> Any:
        """Update an existing network/VLAN.

        Returns the upstream response body verbatim: the updated network object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Example call (update_network):
            {
              "host": "my-console",
              "site": "Default",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "network_config": {
                "management": "GATEWAY",
                "cellularBackupEnabled": true,
                "enabled": true,
                "internetAccessEnabled": true,
                "ipv4Configuration": {
                  "autoScaleEnabled": true,
                  "hostIpAddress": "192.0.2.1",
                  "prefixLength": 24
                },
                "isolationEnabled": true,
                "name": "Office VLAN",
                "vlanId": 20
              }
            }

        Details: docs/TOOL-USAGE.md#update_network.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
            network_config: FULL replacement object (PUT; omitted fields reset); spec Create or update
                Network. Required: enabled, management, name, vlanId. 'management' selects variant:
                GATEWAY|SWITCH|UNMANAGED.
        """
        client, registry = deps_fn()
        return await network.update_network(
            client, registry, host, site, network_id, network_config
        )

    @mcp.tool(annotations=WRITE)
    async def delete_network(
        host: str,
        site: str,
        network_id: str,
        force: bool | None = None,
    ) -> dict[str, Any]:
        """Delete a network/VLAN.

        Consequence: removes the VLAN and disconnects all clients on that network; there is no undo.

        Network 11.0.97 DELETE /v1/sites/{siteId}/networks/{networkId} (deleteNetwork). The spec's optional `force` query parameter is sent only when given.

        Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}.

        Example call (delete_network):
            {"host": "my-console", "site": "Default",
             "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
            force: Optional spec query parameter `force` (boolean, upstream default false); true asks
                the controller to delete a network that is still referenced. Omitted when unset.
        """
        client, registry = deps_fn()
        response = await network.delete_network(
            client, registry, host, site, network_id, force=force
        )
        return deletion_result(f"Network {network_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def get_network_references(
        host: str,
        site: str,
        network_id: str,
    ) -> Any:
        """Get all resources referencing a network — useful before deleting to check dependencies.

        Returns {referenceResources: [...]}, one entry per resource type that references the
        network; each entry is returned as {resourceType, referenceCount, references: [...]}
        and each reference as {referenceId}. resourceType is one of CLIENT, DEVICE,
        STATIC_ROUTE, OSPF_ROUTE, NEXT_AI, WIFI, NAT_RULE or SD_WAN (the pinned enum);
        referenceCount is how many resources of that type reference it, and referenceId is
        the id of one of them. The body is passed through as the console sent it.

        The console may return HTTP 500 for some networks; this is an upstream condition.

        Example call (get_network_references):
            {
              "host": "my-console",
              "site": "Default",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
                a Protect id.
        """
        client, registry = deps_fn()
        return await network.get_network_references(client, registry, host, site, network_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_lags(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List Link Aggregation Groups (LAGs) on a site.

        Returns {data, totalCount}: every page is drained; data holds the LAG records verbatim and
        totalCount is the upstream total (null when none was reported). The first page's other envelope
        fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
        stopped short.

        Drains all pages by default; pass offset alone for a single manual page. A
        capped drain is flagged incomplete rather than truncated silently.

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
            filter: optional UniFi Integration API filter expression.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_lags(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_lag(
        host: str,
        site: str,
        lag_id: str,
    ) -> Any:
        """Get one Link Aggregation Group.

        Returns the upstream LAG object verbatim, exactly as the API answers it.

        Example call (get_lag):
            {"host": "my-console", "site": "Default", "lag_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            lag_id: LAG UUID. Get it from list_lags (data[].id).
        """
        client, registry = deps_fn()
        return await network.get_lag(client, registry, host, site, lag_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_mc_lag_domains(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List Multi-Chassis Link Aggregation (MC-LAG) domains on a site.

        Returns {data, totalCount}: every page is drained; data holds the MC-LAG domain records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        Drains all pages by default; pass offset alone for a single manual page. A
        capped drain is flagged incomplete rather than truncated silently.

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
            filter: optional UniFi Integration API filter expression.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_mc_lag_domains(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_mc_lag_domain(
        host: str,
        site: str,
        mc_lag_domain_id: str,
    ) -> Any:
        """Get one Multi-Chassis Link Aggregation domain.

        Returns the upstream MC-LAG domain object verbatim, exactly as the API answers it.

        Example call (get_mc_lag_domain):
            {
              "host": "my-console",
              "site": "Default",
              "mc_lag_domain_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            mc_lag_domain_id: MC-LAG domain UUID. Get it from list_mc_lag_domains (data[].id).
        """
        client, registry = deps_fn()
        return await network.get_mc_lag_domain(client, registry, host, site, mc_lag_domain_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_switch_stacks(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List switch stacks on a site.

        Returns {data, totalCount}: every page is drained; data holds the switch stack records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        Drains all pages by default; pass offset alone for a single manual page. A
        capped drain is flagged incomplete rather than truncated silently.

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
            filter: optional UniFi Integration API filter expression.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_switch_stacks(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_switch_stack(
        host: str,
        site: str,
        switch_stack_id: str,
    ) -> Any:
        """Get one switch stack.

        Returns the upstream switch stack object verbatim, exactly as the API answers it.

        Example call (get_switch_stack):
            {
              "host": "my-console",
              "site": "Default",
              "switch_stack_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            switch_stack_id: Switch stack UUID. Get it from list_switch_stacks (data[].id).
        """
        client, registry = deps_fn()
        return await network.get_switch_stack(client, registry, host, site, switch_stack_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_integration_device_tags(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List the Network Integration device-tag collection for a site.

        These device tags are used for WiFi Broadcast assignments, distinct from the UI
        device-tag collection exposed by list_device_tags. By default, drain all pages.
        A limit requests that many records across pages; an offset selects one native page.
        Returns {data, totalCount} with every page drained by default, plus _pageSize
        metadata describing requested and returned counts when limit is set.
        With offset, returns the native upstream page envelope.

        Args:
            host: Console name or ID from list_hosts.
            site: Network site name or UUID from list_local_sites.
            offset: Optional zero-based offset for one native page. Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional upstream filter expression. Filterable properties are id (eq,
                ne, in, notIn), name (eq, ne, in, notIn, like), and deviceIds (contains,
                containsAny, containsAll, containsExactly). Example: `name.eq('Guest')`.
        """
        client, registry = deps_fn()
        return await network.list_integration_device_tags(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_wifi_broadcasts(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all WiFi broadcast SSIDs for a site.

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
            filter: optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g. `enabled.eq(true)`,
                `name.like('*Guest*')`); omitted entirely when unset.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network.list_wifi_broadcasts(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_wifi_broadcast(
        host: str,
        site: str,
        broadcast: dict[str, Any],
    ) -> Any:
        """Create a new WiFi broadcast SSID on a site.

        Returns the upstream response body verbatim: the created WiFi broadcast object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it): ``type`` — the discriminator the controller validates first (observed value: 'STANDARD'). The remaining fields are type-specific and enforced by the controller. `broadcast`: its parameter description lists the keys each ``type`` requires ("Variants by type"; STANDARD and IOT_OPTIMIZED differ). Field names are camelCase. For an open SSID use securityConfiguration: {type: "OPEN"} and an explicit network reference: network: {type: "SPECIFIC", networkId: UUID from list_networks}. The spec permits omitting network, but the live controller requires it for OPEN broadcasts. An access point carries a limited number of SSIDs: when the controller refuses with HTTP 400 too-many-wifi-broadcasts, the error keeps its whole body and adds a hint to scope the SSID with broadcastingDeviceFilter. Creating it with enabled false does not avoid that limit.

        Details: docs/TOOL-USAGE.md#create_wifi_broadcast.

        Required arguments: host, site, broadcast (see parameter descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast: Full object to create; spec Wifi broadcast create or update. 'type' selects
                variant: IOT_OPTIMIZED|STANDARD.
        """
        client, registry = deps_fn()
        return await network.create_wifi_broadcast(client, registry, host, site, broadcast)

    @mcp.tool(annotations=READ_ONLY)
    async def get_wifi_broadcast(
        host: str,
        site: str,
        broadcast_id: str,
    ) -> Any:
        """Get a single WiFi broadcast SSID by ID.

        Returns: the WiFi broadcast object, verbatim. To change it, edit it and pass it as `broadcast`
        to update_wifi_broadcast.

        Example call (get_wifi_broadcast):
            {
              "host": "my-console",
              "site": "Default",
              "broadcast_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
                Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await network.get_wifi_broadcast(client, registry, host, site, broadcast_id)

    @mcp.tool(annotations=WRITE)
    async def update_wifi_broadcast(
        host: str,
        site: str,
        broadcast_id: str,
        broadcast: dict[str, Any],
    ) -> Any:
        """Update an existing WiFi broadcast SSID.

        Returns the upstream response body verbatim: the updated WiFi broadcast object the API
        answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).


        For an open SSID use securityConfiguration: {type: "OPEN"} and an explicit network
        reference: network: {type: "SPECIFIC", networkId: UUID from list_networks}. Retain that
        reference in the full replacement object; the live controller requires it for OPEN.

        Full request shapes are in the parameter schema; detailed examples and workflows:
        docs/TOOL-USAGE.md#update_wifi_broadcast.

        Required arguments: host, site, broadcast_id, broadcast (see parameter descriptions for
        identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
                Network-app UUID — not a Protect id.
            broadcast: FULL replacement object (PUT; omitted fields reset); spec Wifi broadcast create
                or update. 'type' selects variant: IOT_OPTIMIZED|STANDARD.
        """
        client, registry = deps_fn()
        return await network.update_wifi_broadcast(
            client, registry, host, site, broadcast_id, broadcast
        )

    @mcp.tool(annotations=WRITE)
    async def delete_wifi_broadcast(
        host: str,
        site: str,
        broadcast_id: str,
        force: bool | None = None,
    ) -> dict[str, Any]:
        """Delete a WiFi broadcast SSID.

        Consequence: the SSID stops broadcasting and its connected clients are disconnected; there is no undo.

        Network 11.0.97 DELETE /v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId} (deleteWifiBroadcast). The spec's optional `force` query parameter is sent only when given.

        Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}.

        Example call (delete_wifi_broadcast):
            {"host": "my-console", "site": "Default",
             "broadcast_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
                Network-app UUID — not a Protect id.
            force: Optional spec query parameter `force` (boolean, upstream default false); true asks
                the controller to delete a broadcast that is still referenced. Omitted when unset.
        """
        client, registry = deps_fn()
        response = await network.delete_wifi_broadcast(
            client, registry, host, site, broadcast_id, force=force
        )
        return deletion_result(f"WiFi broadcast {broadcast_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def list_wan_interfaces(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List WAN interfaces for a site.

        Returns: {data: [wan…], totalCount, _health}. data is the Integration WAN list, entries verbatim (every page drained; incomplete/incompleteReason when a capped drain stopped short; with offset alone, that single page in its native envelope, plus _health, and a page the upstream answers as a bare array is returned as that array, without _health); totalCount is the upstream total of that list (null when the upstream reports none). The additive _health is the Classic /stat/health body verbatim ({meta: {rc}, data: [...]}, every subsystem; the WAN health entries are its data[] entries with subsystem "wan"). When the stat/health read fails, the additive _wanHealthError carries the reason (and _health is the body received, if any) — the interfaces are still returned. To change one, pass the native Classic networkconf fields to change (e.g. wan_load_balance_weight, wan_failover_priority, wan_dns1) as `wan` to update_wan_interface (wan_id = its data[] id).

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
        """
        client, registry = deps_fn()
        return await network.list_wan_interfaces(
            client, registry, host, site, offset=offset, limit=limit
        )

    @mcp.tool(annotations=WRITE)
    async def update_wan_interface(
        host: str,
        site: str,
        wan_id: str,
        wan: dict[str, Any],
    ) -> Any:
        """Update a WAN interface configuration.

        A WAN interface is a Classic REST networkconf record of purpose wan, written with PUT /proxy/network/api/s/{site}/rest/networkconf/{_id} (the route the controller's own UI uses; the published Integration API serves WANs GET-only, PUT answers HTTP 404 "No endpoint" on Network 11.0.81). The id is resolved among the site's wan records first; an unknown id fails listing every WAN with both ids. Send only the fields to change: the Classic PUT merges them into the stored record.

        Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the updated networkconf record]}. Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_wan_interface):
            {"host": "my-console", "site": "Default",
             "wan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "wan": {"wan_load_balance_weight": 50}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            wan_id: WAN interface id. Get it from list_wan_interfaces (data[].id); the Classic
                networkconf _id also works. Network-app UUID — not a Protect id.
            wan: Native Classic networkconf fields to change, e.g. name, wan_type, wan_dns1,
                wan_load_balance_weight, wan_failover_priority, wan_vlan_enabled. Sent unchanged
                (empty-string list placeholders dropped); an absent or null purpose is sent as
                wan, another is sent as given (an upstream error then gets a hint).
                A purpose-only update is refused. Network 11.1.47 passthrough VLANs:
                tagged_networkconf_ids (array of VLAN Only network _ids, sent with
                setting_preference manual; an empty array clears them), and the WAN's own VLAN in
                wan_vlan_enabled, wan_vlan and wan_vlan_networkconf_id.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network.update_wan_interface(client, registry, host, site, wan_id, wan)

    return {
        "get_network_application_info": get_network_application_info,
        "list_local_sites": list_local_sites,
        "list_networks": list_networks,
        "create_network": create_network,
        "get_network": get_network,
        "update_network": update_network,
        "delete_network": delete_network,
        "get_network_references": get_network_references,
        "list_lags": list_lags,
        "get_lag": get_lag,
        "list_mc_lag_domains": list_mc_lag_domains,
        "get_mc_lag_domain": get_mc_lag_domain,
        "list_switch_stacks": list_switch_stacks,
        "get_switch_stack": get_switch_stack,
        "list_wifi_broadcasts": list_wifi_broadcasts,
        "create_wifi_broadcast": create_wifi_broadcast,
        "get_wifi_broadcast": get_wifi_broadcast,
        "update_wifi_broadcast": update_wifi_broadcast,
        "delete_wifi_broadcast": delete_wifi_broadcast,
        "list_wan_interfaces": list_wan_interfaces,
        "update_wan_interface": update_wan_interface,
    }


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register N10 WiFi-radio tools as typed FastMCP functions."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="get_radio_ai_isolation_matrix", annotations=READ_ONLY)
    async def radio_ai_isolation(host: str, site: str, radio_band: str | None = None) -> Any:
        """Read the radio-AI isolation matrix (per-AP RF isolation used by channel AI).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radio_band: Optional radio band filter, e.g. "na".
        """
        return await network_wifi_radio.get_radio_ai_isolation_matrix(
            *deps(), host, site, radio_band
        )

    @mcp.tool(name="preview_radio_ai_optimization", annotations=WRITE)
    async def radio_ai_preview(
        host: str,
        site: str,
        calculation_id: str,
        radios: list[dict[str, Any]],
        method: str,
        dry_run: bool = False,
    ) -> Any:
        """Create radio-AI preview. Consequence: creates controller calculation state.

        POSTs calculation_id, radios and method to radio-ai/optimize/preview.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, calculation_id, radios, method.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            calculation_id: Required calculation UUID, e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            radios: Required non-empty plan array, e.g. [{"mac":"02:00:5e:00:00:a1"}].
                Shape: {mac:string}[]; keys the server reads: none, each entry is sent as given
            method: Required optimization method, e.g. "balanced".
            dry_run: Preview without POST, e.g. true.
        """
        return await network_wifi_radio.preview_radio_ai_optimization(
            *deps(), host, site, calculation_id, radios, method, dry_run=dry_run
        )

    @mcp.tool(name="apply_radio_ai_optimization", annotations=WRITE)
    async def radio_ai_apply(
        host: str,
        site: str,
        radios: list[dict[str, Any]],
        calculation_id: str | None = None,
        dry_run: bool = False,
    ) -> Any:
        """Apply radio-AI plan. Consequence: channels may change and clients may roam.

        With calculation_id POSTs radio-ai/optimize/apply/{calculation_id}; without it
        POSTs radios to radio-ai/optimize/apply-last. Never auto-retried.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, radios.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radios: Required non-empty radio array, e.g. [{"mac":"02:00:5e:00:00:a1"}].
                Shape: {mac:string}[]; keys the server reads: none, each entry is sent as given
            calculation_id: Optional preview UUID, e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            dry_run: Preview without POST, e.g. true.
        """
        return await network_wifi_radio.apply_radio_ai_optimization(
            *deps(), host, site, radios, calculation_id, dry_run=dry_run
        )

    @mcp.tool(name="get_radio_history", annotations=READ_ONLY)
    async def radio_history(
        host: str,
        site: str,
        view: Literal["timeline", "timestamps", "at"],
        start: int | None = None,
        end: int | None = None,
        access_point: str | None = None,
    ) -> Any:
        """Read AP radio history (timeline, timestamps, or the snapshot at start).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        View "at" takes only start; end or access_point with it fails before any request.
        _warnings lists each epoch argument with its unit (EPOCH_MILLISECONDS).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, view.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            view: Required history view, e.g. "timeline".
            start: Required epoch milliseconds, e.g. 1710000000000.
            end: Required for range views, epoch milliseconds, e.g. 1710003600000.
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await network_wifi_radio.get_radio_history(
            *deps(), host, site, view, start, end, access_point
        )

    @mcp.tool(name="get_wifi_connectivity", annotations=READ_ONLY)
    async def wifi_connectivity(
        host: str,
        site: str,
        start: int,
        end: int,
        access_point: str | None = None,
        client_mac: str | None = None,
        radio_band: str | None = None,
    ) -> Any:
        """Read WiFi connectivity for a time range, optionally per AP, client or band.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        _warnings lists each epoch argument with its unit (EPOCH_MILLISECONDS).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, start, end.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            start: Required epoch milliseconds, e.g. 1710000000000.
            end: Required epoch milliseconds, e.g. 1710003600000.
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
            client_mac: Optional client MAC, e.g. "02:00:5e:00:00:b2".
            radio_band: Optional band, e.g. "na".
        """
        return await network_wifi_radio.get_wifi_connectivity(
            *deps(), host, site, start, end, access_point, client_mac, radio_band
        )

    @mcp.tool(name="control_wifi_doctor_optimization", annotations=WRITE)
    async def wifi_doctor(
        host: str, site: str, action: Literal["start", "stop"], dry_run: bool = False
    ) -> Any:
        """Start or stop WiFi Doctor. Consequence: may change radio behavior and client service.

        POSTs wifi-doctor/optimization/{action}. Never auto-retried.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, action.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            action: Required action, e.g. "start".
            dry_run: Preview without POST, e.g. true.
        """
        return await network_wifi_radio.control_wifi_doctor_optimization(
            *deps(), host, site, action, dry_run=dry_run
        )

    @mcp.tool(name="get_wifi_stats", annotations=READ_ONLY)
    async def wifi_stats(
        host: str,
        site: str,
        view: Literal["details", "radios"],
        start: int,
        end: int,
        access_point: str | None = None,
    ) -> Any:
        """Read WiFi statistics (details or per-radio) for a time range.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        _warnings lists each epoch argument with its unit (EPOCH_MILLISECONDS).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, view, start, end.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            view: Required view, e.g. "details".
            start: Required epoch milliseconds, e.g. 1710000000000.
            end: Required epoch milliseconds, e.g. 1710003600000.
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await network_wifi_radio.get_wifi_stats(
            *deps(), host, site, view, start, end, access_point
        )

    @mcp.tool(name="get_wifi_tethering_scan", annotations=READ_ONLY)
    async def tethering_scan(host: str, site: str, gateway_mac: str) -> Any:
        """Read the WiFi networks a gateway saw in its tethering scan.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, gateway_mac.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            gateway_mac: Required gateway MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await network_wifi_radio.get_wifi_tethering_scan(*deps(), host, site, gateway_mac)

    @mcp.tool(name="get_wifiman_settings", annotations=READ_ONLY)
    async def wifiman_settings(host: str, site: str) -> Any:
        """Read the site WiFiman settings.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await network_wifi_radio.get_wifiman_settings(*deps(), host, site)

    @mcp.tool(name="get_wlan_capabilities", annotations=READ_ONLY)
    async def wlan_capabilities(host: str, site: str) -> Any:
        """Read the site WLAN capabilities (supported bands, security and features).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await network_wifi_radio.get_wlan_capabilities(*deps(), host, site)

    @mcp.tool(name="list_available_wifi_channels", annotations=READ_ONLY)
    async def available_channels(host: str, site: str) -> Any:
        """List the WiFi channels available per band (Classic stat/current-channel).

        Returns the upstream Classic envelope verbatim (meta and data); an array is wrapped as
        result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await network_wifi_radio.list_available_wifi_channels(*deps(), host, site)

    @mcp.tool(name="get_access_point_neighbors", annotations=READ_ONLY)
    async def ap_neighbors(host: str, site: str, access_point: str) -> Any:
        """Read the neighbouring APs an access point hears.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, access_point.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            access_point: Required AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await network_wifi_radio.get_access_point_neighbors(
            *deps(), host, site, access_point
        )

    @mcp.tool(name="start_spectrum_scan", annotations=WRITE)
    async def spectrum_scan(host: str, site: str, access_point: str, dry_run: bool = False) -> Any:
        """Start spectrum scan. Consequence: may interrupt service on selected AP.

        Sends Classic cmd/devmgr {"cmd": "spectrum-scan", "mac": ...}; success needs
        meta.rc "ok", otherwise the full upstream meta is raised. Never auto-retried.
        Returns the upstream Classic envelope verbatim (meta and data).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, access_point.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            access_point: Required free AP MAC, e.g. "02:00:5e:00:00:a1".
            dry_run: Preview without POST, e.g. true.
        """
        return await network_wifi_radio.start_spectrum_scan(
            *deps(), host, site, access_point, dry_run=dry_run
        )

    @mcp.tool(name="get_spectrum_scan_results", annotations=READ_ONLY)
    async def spectrum_results(host: str, site: str, access_point: str | None = None) -> Any:
        """Read spectrum scan results, for every AP or one access_point.

        Returns the upstream Classic envelope verbatim (meta and data); an array is wrapped as
        result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await network_wifi_radio.get_spectrum_scan_results(*deps(), host, site, access_point)

    @mcp.tool(name="start_wifi_quick_scan", annotations=WRITE)
    async def quick_scan(host: str, site: str, radio_band: str, dry_run: bool = False) -> Any:
        """Start WiFi quick scan. Consequence: may interrupt radio service while scanning.

        POSTs {"band": radio_band} to quick-scan. Never auto-retried.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, radio_band.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radio_band: Required radio band: ng (2.4 GHz), na (5 GHz) or 6e (6 GHz), e.g. "na".
            dry_run: Preview without POST, e.g. true.
        """
        return await network_wifi_radio.start_wifi_quick_scan(
            *deps(), host, site, radio_band, dry_run=dry_run
        )

    @mcp.tool(name="get_wifi_quick_scan_status", annotations=READ_ONLY)
    async def quick_scan_status(host: str, site: str, radio_band: str | None = None) -> Any:
        """Read the WiFi quick-scan status for one radio band.

        GET quick-scan/status?band={radio_band}, one band per call as the web app reads it
        (the console answers HTTP 400 without a band), e.g. {"in_progress": false}.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radio_band: Optional band; observed values include ng, na and 6e, e.g. "na".
        """
        return await network_wifi_radio.get_wifi_quick_scan_status(*deps(), host, site, radio_band)

    @mcp.tool(name="get_wifi_uplink_scan_status", annotations=READ_ONLY)
    async def wifi_uplink_scan_status(host: str, site: str) -> Any:
        """Read the WiFi-uplink quick-scan status (SSIDs a gateway can tether to).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await network_wifi_radio.get_wifi_uplink_scan_status(*deps(), host, site)

    @mcp.tool(name="configure_wifi_wan", annotations=WRITE)
    async def wifi_wan(
        host: str,
        site: str,
        is_wifi_tethering: bool,
        enabled: bool,
        port: int,
        uplink_ssid: str,
        uplink_security: Literal[
            "OPEN", "WPA2_PERSONAL", "WPA3_PERSONAL", "WPA2_ENTERPRISE", "WPA3_ENTERPRISE"
        ],
        uplink_band: Literal["RADIO_NG", "RADIO_NA", "RADIO_6E"],
        x_uplink_password: str | None = None,
        uplink_identity: str | None = None,
        wan_id: str | None = None,
        dry_run: bool = False,
    ) -> Any:
        """Configure a WAN for WiFi tethering. Consequence: can disconnect the site's WAN.

        Reads the site's Classic networkconf records, picks the WAN record (wan_id, or the only one), merges these fields over it and PUTs the whole record with purpose "wan". Returns the upstream envelope verbatim plus _readAfter (the WAN record read back) and _verified (requested fields match, type-strict); _readAfterError is added when the read-back fails. A non-object write body is returned whole under response with those keys beside it. x_uplink_password passes through unless UNIFI_REDACT_SECRETS. Several WANs without wan_id fail listing valid records. dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and preview (method, path, params, body: the merged record) without writing or verifying. Provide host (console name or id from list_hosts) and site (Network site name or UUID from list_local_sites).

        Required arguments: host, site, is_wifi_tethering, enabled, port, uplink_ssid, uplink_security, uplink_band.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            is_wifi_tethering: Required tethering state, e.g. true.
            enabled: Required WAN state, e.g. true.
            port: Required WAN port number, e.g. 9.
            uplink_ssid: Required upstream WiFi SSID, e.g. "example-uplink".
            uplink_security: Required security mode, e.g. "WPA2_PERSONAL".
            uplink_band: Required WiFi band, e.g. "RADIO_NA".
            x_uplink_password: Passphrase, required unless OPEN, e.g. "example-passphrase".
            uplink_identity: Identity, required for enterprise security, e.g. "example-uplink".
            wan_id: WAN id (Integration id or Classic _id) when the site has several WANs,
                e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            dry_run: Preview the merged PUT without writing, e.g. true.
        """
        return await network_wifi_radio.configure_wifi_wan(
            *deps(),
            host,
            site,
            is_wifi_tethering,
            enabled,
            port,
            uplink_ssid,
            uplink_security,
            uplink_band,
            x_uplink_password,
            uplink_identity,
            wan_id,
            dry_run=dry_run,
        )


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 21 NAT, QoS, content-filtering and traffic tools."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="list_nat_rules", annotations=READ_ONLY)
    async def list_nat_rules(host: str, site: str) -> Any:
        """List a site's NAT rules (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/nat; the upstream body is returned verbatim
        (the route takes no paging parameter). Rule ids (_id) feed update_nat_rule and
        delete_nat_rule.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await network_nat_qos_traffic.list_nat_rules(*deps(), host, site)

    @mcp.tool(name="create_nat_rule", annotations=WRITE)
    async def create_nat_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Create a NAT rule (Network v2 route). Consequence: changes how the gateway
        translates traffic for the site.

        POST /proxy/network/v2/api/site/{site}/nat with rule sent verbatim; the upstream
        body is returned verbatim. The request body is free-form: no field list is
        published, so copy the shape list_nat_rules returns. Never auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule: Required free-form NAT rule object in the shape list_nat_rules returns,
                e.g. {"description": "web", "enabled": false}.
        """
        return await network_nat_qos_traffic.create_nat_rule(*deps(), host, site, rule)

    @mcp.tool(name="update_nat_rule", annotations=WRITE)
    async def update_nat_rule(host: str, site: str, rule_id: str, rule: dict[str, Any]) -> Any:
        """Update a NAT rule (Network v2 route). Consequence: changes live gateway NAT.

        Reads the rule from list_nat_rules (an unknown id fails listing every valid id),
        merges only the given leaves into it, PUTs the merged rule to
        /proxy/network/v2/api/site/{site}/nat/{_id} and reads it back: the upstream body
        is returned plus _verified (every requested leaf matched, type-strict) and
        _readAfterError when the read-back failed. An empty rule is refused before any
        request.

        Returns the upstream PUT body plus _verified (true only when every requested leaf
        read back equal, type-strict) and _readAfterError when the read-back failed; a
        non-object PUT body is kept under response.
        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule_id, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule_id: Required NAT rule _id from list_nat_rules,
                e.g. "000000000000000000000107".
            rule: Required free-form fields to change, e.g. {"enabled": false}.
        """
        return await network_nat_qos_traffic.update_nat_rule(*deps(), host, site, rule_id, rule)

    @mcp.tool(name="delete_nat_rule", annotations=WRITE)
    async def delete_nat_rule(host: str, site: str, rule_id: str) -> Any:
        """Delete a NAT rule (Network v2 route). Consequence: permanently removes the rule.

        Resolves rule_id in list_nat_rules first (an unknown id fails listing every valid
        id and nothing is deleted), then DELETE
        /proxy/network/v2/api/site/{site}/nat/{_id}. Returns deleted, message and the
        upstream response verbatim. Never auto-retried.

        Returns deleted, message and response (the upstream body verbatim).
        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, rule_id.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule_id: Required NAT rule _id from list_nat_rules,
                e.g. "000000000000000000000107".
        """
        return await network_nat_qos_traffic.delete_nat_rule(*deps(), host, site, rule_id)

    @mcp.tool(name="list_qos_rules", annotations=READ_ONLY)
    async def list_qos_rules(host: str, site: str) -> Any:
        """List a site's QoS rules (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/qos-rules; the upstream body is returned
        verbatim (no paging parameter). Rule ids (_id) feed update_qos_rule,
        delete_qos_rule and reorder_qos_rules.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await network_nat_qos_traffic.list_qos_rules(*deps(), host, site)

    @mcp.tool(name="create_qos_rule", annotations=WRITE)
    async def create_qos_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Create a QoS rule (Network v2 route). Consequence: shapes or prioritises live
        traffic.

        POST /proxy/network/v2/api/site/{site}/qos-rules with rule sent verbatim; the
        upstream body is returned verbatim. The request body is free-form: no field list
        is published, so copy the shape list_qos_rules returns. Never auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule: Required free-form QoS rule object in the shape list_qos_rules returns,
                e.g. {"name": "voip", "enabled": false}.
        """
        return await network_nat_qos_traffic.create_qos_rule(*deps(), host, site, rule)

    @mcp.tool(name="update_qos_rule", annotations=WRITE)
    async def update_qos_rule(host: str, site: str, rule_id: str, rule: dict[str, Any]) -> Any:
        """Update a QoS rule (Network v2 route). Consequence: changes live traffic shaping.

        Reads the rule from list_qos_rules (an unknown id fails listing every valid id),
        merges only the given leaves, PUTs the merged rule to
        /proxy/network/v2/api/site/{site}/qos-rules/{_id} and reads it back: the upstream
        body is returned plus _verified (type-strict, every requested leaf) and
        _readAfterError when the read-back failed. An empty rule is refused before any
        request.

        Returns the upstream PUT body plus _verified (true only when every requested leaf
        read back equal, type-strict) and _readAfterError when the read-back failed; a
        non-object PUT body is kept under response.
        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, rule_id, rule.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            rule_id: Required QoS rule _id from list_qos_rules,
                e.g. "000000000000000000000107".
            rule: Required free-form fields to change, e.g. {"enabled": false}.
        """
        return await network_nat_qos_traffic.update_qos_rule(*deps(), host, site, rule_id, rule)

    @mcp.tool(name="delete_qos_rule", annotations=WRITE)
    async def delete_qos_rule(
        host: str, site: str, body: dict[str, Any] | list[str | dict[str, Any]]
    ) -> Any:
        """Delete QoS rules (Network v2 batch-delete route). Consequence: permanently removes the rules.

        POST /proxy/network/v2/api/site/{site}/qos-rules/batch-delete with body sent verbatim (the controller has no single-rule DELETE route). The body is free-form: no field list is published. When body is a JSON array of id strings, each id is resolved in list_qos_rules first and an unknown id fails listing every valid id (nothing is sent). Returns deleted, message and the upstream response verbatim. Never auto-retried.

        Returns deleted, message and response (the upstream body verbatim). Under dry-run policy nothing is sent and the tool returns {status: "dry_run", deleted: false, message, response}, where response is the dry-run preview (status, dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, body.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Required free-form batch-delete body (an empty list fails before any
                request), e.g. ["000000000000000000000107"].
        """
        return await network_nat_qos_traffic.delete_qos_rule(*deps(), host, site, body)

    @mcp.tool(name="reorder_qos_rules", annotations=WRITE)
    async def reorder_qos_rules(
        host: str, site: str, body: dict[str, Any] | list[str | dict[str, Any]]
    ) -> Any:
        """Reorder QoS rules (Network v2 route). Consequence: changes which rule matches
        live traffic first.

        PUT /proxy/network/v2/api/site/{site}/qos-rules/batch-reorder with body sent
        verbatim; the upstream body is returned verbatim. The body is free-form: no field
        list is published, so build it from the rule ids list_qos_rules returns. Never
        auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, body.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Required free-form reorder body (an empty list fails before any request),
                e.g. ["000000000000000000000108", "000000000000000000000107"].
        """
        return await network_nat_qos_traffic.reorder_qos_rules(*deps(), host, site, body)

    @mcp.tool(name="list_content_filters", annotations=READ_ONLY)
    async def list_content_filters(host: str, site: str) -> Any:
        """List a site's content-filtering profiles (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/content-filtering; the upstream body is
        returned verbatim (no paging parameter). Profile ids (_id) feed
        update_content_filter and delete_content_filter.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await network_nat_qos_traffic.list_content_filters(*deps(), host, site)

    @mcp.tool(name="create_content_filter", annotations=WRITE)
    async def create_content_filter(host: str, site: str, content_filter: dict[str, Any]) -> Any:
        """Create a content-filtering profile (Network v2 route). Consequence: can block
        web categories for the clients and networks it targets.

        POST /proxy/network/v2/api/site/{site}/content-filtering/create with
        content_filter sent verbatim; the upstream body is returned verbatim. The body is
        free-form: copy the shape list_content_filters returns; category names come from
        list_content_filter_categories. Never auto-retried.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, content_filter.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            content_filter: Required free-form profile object,
                e.g. {"name": "kids", "enabled": false}.
        """
        return await network_nat_qos_traffic.create_content_filter(
            *deps(), host, site, content_filter
        )

    @mcp.tool(name="update_content_filter", annotations=WRITE)
    async def update_content_filter(
        host: str, site: str, filter_id: str, content_filter: dict[str, Any]
    ) -> Any:
        """Update a content-filtering profile (Network v2 route). Consequence: changes which web categories are blocked.

        Reads the profile from list_content_filters (an unknown id fails listing every valid id), merges only the given leaves, PUTs the merged profile to /proxy/network/v2/api/site/{site}/content-filtering/{_id} and reads it back: the upstream body is returned plus _verified (type-strict) and _readAfterError when the read-back failed. An empty update is refused before any request.

        Returns the upstream PUT body plus _verified (true only when every requested leaf read back equal, type-strict) and _readAfterError when the read-back failed; a non-object PUT body is kept under response. Under dry-run policy nothing is sent and the tool returns a dry-run preview: status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, filter_id, content_filter.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            filter_id: Required profile _id from list_content_filters,
                e.g. "000000000000000000000107".
            content_filter: Required free-form fields to change, e.g. {"enabled": false}.
        """
        return await network_nat_qos_traffic.update_content_filter(
            *deps(), host, site, filter_id, content_filter
        )

    @mcp.tool(name="delete_content_filter", annotations=WRITE)
    async def delete_content_filter(host: str, site: str, filter_id: str) -> Any:
        """Delete a content-filtering profile (Network v2 route). Consequence: permanently removes the profile and stops its blocking.

        Resolves filter_id in list_content_filters first (an unknown id fails listing every valid id and nothing is deleted), then DELETE /proxy/network/v2/api/site/{site}/content-filtering/{_id}. Returns deleted, message and the upstream response verbatim. Never auto-retried.

        Returns deleted, message and response (the upstream body verbatim). Under dry-run policy nothing is sent and the tool returns {status: "dry_run", deleted: false, message, response}, where response is the dry-run preview (status, dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, filter_id.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            filter_id: Required profile _id from list_content_filters,
                e.g. "000000000000000000000107".
        """
        return await network_nat_qos_traffic.delete_content_filter(*deps(), host, site, filter_id)

    @mcp.tool(name="list_content_filter_categories", annotations=READ_ONLY)
    async def list_content_filter_categories(host: str, site: str) -> Any:
        """List the content-filtering categories a profile can block (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/content-filtering/categories; the upstream
        body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await network_nat_qos_traffic.list_content_filter_categories(*deps(), host, site)

    @mcp.tool(name="get_traffic_stats", annotations=READ_ONLY)
    async def get_traffic_stats(host: str, site: str, params: dict[str, Any] | None = None) -> Any:
        """Read the site's traffic statistics over a time window (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/traffic with params forwarded as the query
        string unchanged; the upstream body is returned verbatim. The query keys are
        free-form: the web UI sends start and end (milliseconds), and includeUnidentified.
        An upstream HTTP 400 with a missing window adds a hint.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            params: Optional free-form query parameters, e.g. {"start": 1710000000000,
                "end": 1710003600000, "includeUnidentified": true}. The console
                expects a window in milliseconds; integer window fields add _warnings to
                object results.
        """
        return await network_nat_qos_traffic.get_traffic_stats(*deps(), host, site, params)

    @mcp.tool(name="get_latest_traffic_flow_stats", annotations=READ_ONLY)
    async def get_latest_traffic_flow_stats(
        host: str, site: str, period: str | None = "DAY", top: int | None = None
    ) -> Any:
        """Read the latest traffic-flow statistics (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/traffic-flow-latest-statistics with period
        (default DAY; explicit null omits it) and top when given, the two
        keys the web UI sends. The upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            period: Observed periods include HOUR, DAY, WEEK and MONTH; default
                "DAY", the web UI's default, e.g. "HOUR".
            top: Optional number of top entries sent as given, e.g. 10.
        """
        return await network_nat_qos_traffic.get_latest_traffic_flow_stats(
            *deps(), host, site, period, top
        )

    @mcp.tool(name="query_traffic_flows", annotations=READ_ONLY)
    async def query_traffic_flows(
        host: str,
        site: str,
        body: dict[str, Any] | None = None,
        window: str | None = None,
        direction: str | list[str] | None = None,
        action: str | list[str] | None = None,
        risk: str | list[str] | None = None,
        threat_signature: str | int | list[str | int] | None = None,
    ) -> Any:
        """Query traffic flows: a Network v2 read-POST allowlisted by live read evidence (2026-10-26, 50+ calls, configuration unchanged), so it works in read-only and dry-run modes. POST /proxy/network/v2/api/site/{site}/traffic-flows. Body keys override typed selectors; the window becomes epoch-ms timestampFrom/timestampTo; direction, action, risk and threat_signature become lists. Without pageSize, every page reported by has_next/total_page_count is drained from pageNumber (default 0). A body pageSize above 5000 is sent as 5000 per page (larger causes HTTP 400); at or below, as given; each integer pageSize returns that many records or fewer at the end, from pageNumber * pageSize. Upstream errors pass through. No window or page-count cap applies (not even UNIFI_PAGINATE_MAX_PAGES); large queries can use substantial controller memory and time. _nextPage {offset, pageSize} resumes at the first unreturned record: pass it as body.pageNumber, optionally with a new body.pageSize. _pageSize {requested, sent, effective, returned} reports sizes.

        Returns a single page verbatim, or for several pages the last page's envelope with gathered data and _pages; repeated/empty pages claiming more return gathered data with incomplete/incompleteReason, and a later failure names its zero-based page, status and upstream error.

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Optional free-form query body; its keys take precedence over selectors.
                Explicit timestamps use epoch ms, e.g. {"timestampFrom": 1710000000000}.
            window: Duration converted to epoch-millisecond bounds, e.g. "5m".
            direction: Shape: string|string[]; sent as an array.
                Observed values local, outgoing, incoming (2026-10-26).
                Any value is forwarded for the console to validate, e.g. "outgoing".
            action: Shape: string|string[]; sent as an array.
                Observed values allowed, blocked (2026-10-26).
                Any value is forwarded for the console to validate, e.g. "blocked".
            risk: Shape: string|string[]; sent as an array.
                Observed values low, medium, high (2026-10-26).
                Any value is forwarded for the console to validate, e.g. "high".
            threat_signature: Shape: string|integer|(string|integer)[]; sent as the body key
                ips_signature_id (the key the Network 11.1.47 web app filters flows by IPS
                signature with), as an array. Values are the console's IPS signature ids, as
                listed under ips_signatures by GET traffic-flows/filter-data; any value is
                forwarded for the console to validate, e.g. 2027750.
        """
        return await network_nat_qos_traffic.query_traffic_flows(
            *deps(),
            host,
            site,
            network_nat_qos_traffic._traffic_flow_body(
                body, window, direction, action, risk, threat_signature
            ),
        )

    @mcp.tool(name="export_traffic_flows", annotations=WRITE)
    async def export_traffic_flows(host: str, site: str, body: dict[str, Any] | None = None) -> Any:
        """Export traffic flows (Network v2 route; a read-type POST, classed as a write). Consequence: none intended (an export); classed as a write because the POST is not on the read-POST allowlist.

        POST /proxy/network/v2/api/site/{site}/traffic-flows/export with body sent verbatim (free-form; no field list is published). The export is returned whole: JSON verbatim (paged JSON is drained as query_traffic_flows does), text as {contentType, sizeBytes, body}, any other content base64-encoded as {contentType, sizeBytes, bodyBase64}. No size or window cap. A body pageSize above 5000 (the largest page the console accepts; it answers a larger one with HTTP 400) is sent as pageSize 5000 and paged JSON is gathered until the requested total or the end, starting at record pageNumber * pageSize; every integer pageSize returns _pages and _pageSize with requested, sent, effective, returned. sent lists each physical request size and effective is the observed console size. Resume by passing _nextPage {offset, pageSize} as body.pageNumber; body.pageSize can change without moving the continuation's record offset. A pageSize at or below 5000 is sent as given, and an upstream error for it is returned as received.

        Returns a single page without pageSize verbatim; a gathered result is the last page's envelope with data holding the requested records, plus _pages, and incomplete with incompleteReason when the drain stopped short. A non-JSON export returns contentType, sizeBytes and body (text) or bodyBase64. Under dry-run policy nothing is sent and the tool returns a dry-run preview: status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            body: Optional free-form export body,
                e.g. {"timestampFrom": 1710000000000, "timestampTo": 1710003600000}.
        """
        return await network_nat_qos_traffic.export_traffic_flows(*deps(), host, site, body)

    @mcp.tool(name="query_app_traffic_rates", annotations=WRITE)
    async def query_app_traffic_rates(
        host: str,
        site: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Query per-application traffic rates (Network v2 route; a read-type POST, classed
        as a write). Consequence: none intended (a query); classed as a write because the
        POST is not on the read-POST allowlist.

        POST /proxy/network/v2/api/site/{site}/app-traffic-rate with params forwarded as
        the query string and body sent verbatim; an omitted body is sent as {} (the route
        requires a body, and the web app sends {} when it filters no app or client). The
        upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).
        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides
        the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            params: Optional free-form query parameters, e.g.
                {"start": 1710000000000, "end": 1710003600000,
                "includeUnidentified": true}. The pinned Network 11.0.81 UI uses these
                fields, with no period parameter or period enum.
            body: Optional free-form request body filtering apps or clients, e.g.
                {"client_macs": ["02:00:5e:00:53:01"]}; omit it to send {} (no filter).
        """
        return await network_nat_qos_traffic.query_app_traffic_rates(
            *deps(), host, site, params, body
        )

    @mcp.tool(name="get_poe_info", annotations=READ_ONLY)
    async def get_poe_info(host: str, site: str, params: dict[str, Any] | None = None) -> Any:
        """Read the site's PoE budget and per-port power information (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/poe-info with params forwarded as the query
        string unchanged. The console expects params.mac in lowercase colon form; a missing
        mac on HTTP 400 adds a hint. The upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array, as sent).

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            params: Optional free-form query parameters, e.g. {"mac": "02:00:5e:00:00:a1"}.
        """
        return await network_nat_qos_traffic.get_poe_info(*deps(), host, site, params)

    @mcp.tool(name="get_topology_snapshot", annotations=READ_ONLY)
    async def get_topology_snapshot(
        host: str,
        site: str,
        view: Literal["live", "timeline", "timestamps", "at"] = "live",
        start: int | None = None,
        end: int | None = None,
        at: int | None = None,
    ) -> Any:
        """Read the site's network topology snapshot or its history (Network v2 routes).

        With view "live": GET .../topology/snapshot/live. With "timeline" or "timestamps": GET
        .../topology/snapshot/history/{view}?start=&end= (start and end required). With
        "at": GET .../topology/snapshot/history/at/{at} (at required). All under
        /proxy/network/v2/api/site/{site}. Epochs are Unix MILLISECONDS, sent as given;
        the result carries an additive _warnings entry naming the unit. The upstream body
        is returned verbatim.

        Returns the upstream body verbatim (a JSON object or array) plus _warnings for
        history views.

        Required arguments: host, site.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name or UUID from list_local_sites, e.g. "Default".
            view: Snapshot view, e.g. "timeline".
            start: Range start, epoch milliseconds, e.g. 1710000000000.
            end: Range end, epoch milliseconds, e.g. 1710003600000.
            at: Instant for view "at", epoch milliseconds, e.g. 1710000000000.
        """
        return await network_nat_qos_traffic.get_topology_snapshot(
            *deps(), host, site, view, start, end, at
        )


def register_4(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the network clients, guests, DHCP and hotspot tools."""

    @mcp.tool(name="authorize_guest", annotations=WRITE)
    async def _authorize_guest(
        host: str,
        site: str,
        client: str,
        time_limit_minutes: int | None = None,
        data_limit_mbytes: int | None = None,
        rx_rate_limit_kbps: int | None = None,
        tx_rate_limit_kbps: int | None = None,
        ap_mac: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Authorize a guest client on the guest portal (onto the network now). Undo with revoke_guest_access.

        Consequence: the guest gets network access past the portal at once, within the limits sent (or the site's guest defaults) until they expire or the guest is revoked.

        A CONNECTED client uses the official action AUTHORIZE_GUEST_ACCESS (Network 11.0.97 POST /v1/sites/{siteId}/clients/{clientId}/actions; 422 api.client.not-guest if not on a guest network). A MAC not connected (pre-authorizing) or a call with ap_mac uses Classic cmd/stamgr authorize-guest (the official action needs a connected client and has no ap_mac). Limits map 1:1 (time_limit_minutes -> timeLimitMinutes/minutes, data_limit_mbytes -> dataUsageLimitMBytes/bytes, rx_rate_limit_kbps -> rxRateLimitKbps/down, tx_rate_limit_kbps -> txRateLimitKbps/up); only those passed are sent.

        Returns the upstream body verbatim with _route and _reason added to objects; Classic requires rc "ok". Under dry-run policy nothing is sent: the preview, unchanged.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (authorize_guest):
            {"host": "my-console", "site": "Default", "client": "02:00:00:00:00:01",
             "time_limit_minutes": 60}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Guest MAC (any form, e.g. "02:00:00:00:00:01") or connected client UUID.
            time_limit_minutes: Minutes of access, e.g. 60 (official range 1-1000000).
            data_limit_mbytes: Data cap in MB, e.g. 1024 (official range 1-1048576).
            rx_rate_limit_kbps: Download limit in kbps, e.g. 10000 (official 2-100000).
            tx_rate_limit_kbps: Upload limit in kbps, e.g. 2000 (official 2-100000).
            ap_mac: Classic only: the AP MAC the guest is associated with; selects Classic,
                e.g. "02:00:00:00:00:aa".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.authorize_guest(
            c,
            registry,
            host,
            site,
            client,
            time_limit_minutes=time_limit_minutes,
            data_limit_mbytes=data_limit_mbytes,
            rx_rate_limit_kbps=rx_rate_limit_kbps,
            tx_rate_limit_kbps=tx_rate_limit_kbps,
            ap_mac=ap_mac,
        )

    @mcp.tool(name="revoke_guest_access", annotations=WRITE)
    async def _revoke_guest_access(
        host: str,
        site: str,
        guest: str,
        target_type: GuestTarget = "client",
        confirm: bool = False,
    ) -> Any:
        """Revoke a guest's portal authorization (the guest is disconnected). Consequence: the guest loses network access at once and must pass the portal again (or be re-authorized with authorize_guest).

        target_type "client" (default): a CONNECTED guest (MAC or UUID) uses the official action UNAUTHORIZE_GUEST_ACCESS; a MAC not connected uses Classic cmd/stamgr unauthorize-guest. "guest_session": guest is a session _id from list_hotspot_authorizations, ended with Classic cmd/hotspot terminate (the only route addressing a session). Session and client ids are both UUIDs on Network 11.x, hence the explicit selector. The official action answers 422 api.client.not-guest for a non-guest. Classic requires rc "ok". Under dry-run policy it returns {status: "dry_run", deleted: false, message, response (the dry-run preview)}; nothing is sent.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (revoke_guest_access):
            {"host": "my-console", "site": "Default", "guest": "02:00:00:00:00:01"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            guest: Guest MAC (any form) or connected client UUID; for target_type
                guest_session, the session _id from list_hotspot_authorizations, e.g.
                "02:00:00:00:00:01" (client) or "00000000-0000-0000-0000-000000000001".
            target_type: "client" (default) or "guest_session", e.g. "client".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.revoke_guest_access(
            c, registry, host, site, guest, target_type
        )

    @mcp.tool(name="get_local_client", annotations=READ_ONLY)
    async def _get_local_client(
        host: str,
        site: str,
        client: str,
        include_traffic_usage: bool | None = None,
        include_unifi_devices: bool | None = None,
        include_matter_thread_clients: bool | None = None,
    ) -> Any:
        """Get the controller's record of one client by MAC (v2 clients/local/{mac}).

        Route: v2 only (no official route has these fields): the record the Network web
        app opens for a client, with fingerprint, network, uplink, usergroup, tags, note
        flag and fixed-IP state. The collection route clients/local answers HTTP 404 on
        Network 11.0.81, so this reads one client; list connected clients with
        list_clients. A client id (UUID) is turned into its MAC with the official client
        GET first.

        Returns the upstream object verbatim.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (get_local_client):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            include_traffic_usage: Sent as includeTrafficUsage=true/false when given, e.g.
                true.
            include_unifi_devices: Sent as includeUnifiDevices=true/false when given, e.g.
                false.
            include_matter_thread_clients: Sent as includeMatterThreadClients=true/false
                when given, e.g. false.
        """
        c, registry = deps_fn()
        return await network_clients_guests.get_local_client(
            c,
            registry,
            host,
            site,
            client,
            include_traffic_usage=include_traffic_usage,
            include_unifi_devices=include_unifi_devices,
            include_matter_thread_clients=include_matter_thread_clients,
        )

    @mcp.tool(name="list_client_traffic_controls", annotations=READ_ONLY)
    async def _list_client_traffic_controls(host: str, site: str) -> Any:
        """List how many traffic rules apply to each client (v2 clients/traffic-control).

        Route: v2 only. Returns the upstream object verbatim:
        {applied_traffic_rule_count: {client MAC: count}}.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (list_client_traffic_controls):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        c, registry = deps_fn()
        return await network_clients_guests.list_client_traffic_controls(c, registry, host, site)

    @mcp.tool(name="get_client_insights", annotations=READ_ONLY)
    async def _get_client_insights(
        host: str,
        site: str,
        client: str,
        view: network_clients_guests.InsightView,
        start: int | None = None,
        end: int | None = None,
    ) -> Any:
        """Get a client insight view (v2 client/{mac}/view).

        Views: 24hr-activity ({historical_activity: [{timestamp, activity_seconds}]}),
        24hr-satisfaction ({historical_scores: [{timestamp, satisfaction}]}), ap-stats
        ({ap_stats: [{device_mac, device_name, session_time_seconds}],
        total_session_time_seconds}; needs start and end) and traffic-insights
        ({traffic_overview: {24hr_bytes, 24hr_wan_bytes}}). Route: v2 only.

        Start / end are epoch SECONDS and are sent as epoch milliseconds (the web app's
        unit; ap-stats answers HTTP 500 to seconds). Returns the upstream object verbatim
        (plus _warnings when a time looks like milliseconds or is negative).

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (get_client_insights):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff",
             "view": "ap-stats", "start": 1760000000, "end": 1760003600}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            view: One of 24hr-activity, 24hr-satisfaction, ap-stats, traffic-insights,
                e.g. "ap-stats".
            start: Window start, epoch seconds, e.g. 1760000000 (ap-stats needs it).
            end: Window end, epoch seconds, e.g. 1760003600 (ap-stats needs it).
        """
        c, registry = deps_fn()
        return await network_clients_guests.get_client_insights(
            c, registry, host, site, client, view, start=start, end=end
        )

    @mcp.tool(name="get_client_observability", annotations=READ_ONLY)
    async def _get_client_observability(
        host: str,
        site: str,
        client: str,
        view: ObservabilityView,
        start: int | None = None,
        end: int | None = None,
        timestamp: int | None = None,
    ) -> Any:
        """Get a client observability view (v2 observability/client/{mac}/...).

        Views: logs-all (client connection logs: {data, page_number, total_element_count, total_page_count}; the route takes no page parameter, so a multi-page answer adds a _warnings entry), timeline (array of timeline entries), timestamps (array of epoch-ms times that have a topology snapshot) and topology (the client's path at one time: {client, hops, isp, timestamp}; needs timestamp). Route: v2 only.

        Start, end and timestamp are epoch SECONDS and are sent as epoch milliseconds (the web app's unit). logs-all, timeline and timestamps require start and end; topology takes timestamp (pick one from the timestamps view, divided by 1000). Start or end with topology, or timestamp with any other view, fails before any request. Missing windows are forwarded. Returns the upstream body verbatim (objects also carry _warnings when a time looks like milliseconds or is negative).

        Example call (get_client_observability):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff",
             "view": "timeline", "start": 1760000000, "end": 1760003600}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            view: One of logs-all, timeline, timestamps, topology, e.g. "timeline".
            start: Window start, epoch seconds; required for logs-all, timeline and
                timestamps, e.g. 1760000000.
            end: Window end, epoch seconds; required for logs-all, timeline and
                timestamps, e.g. 1760003600.
            timestamp: topology only: the snapshot time, epoch seconds, e.g. 1760003000.
        """
        c, registry = deps_fn()
        return await network_clients_guests.get_client_observability(
            c, registry, host, site, client, view, start=start, end=end, timestamp=timestamp
        )

    @mcp.tool(name="set_client_icon", annotations=WRITE)
    async def _set_client_icon(
        host: str,
        site: str,
        target_id: str,
        icon: dict[str, Any] | None = None,
        target_type: IconTarget = "client",
        confirm: bool = False,
    ) -> Any:
        """Set or remove the custom (AI-generated) icon of a client or Matter node. Consequence: changes only the icon the UI shows (removal restores the default); connectivity is unaffected.

        Icon given: PUT v2 clients/{mac}/ai-icon (or matter/nodes/{id}/ai-icon) with the icon object as body, returned verbatim. icon omitted: DELETE on the same route restores the default icon. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. v2 only (no official route). No published schema: the web app sends {icon_id, icon_set_id, request_id, selected_index, assets: [{url, width, height}]}; an empty body answers 400 "Validation failure". A MAC that is neither connected nor known (stat/alluser) is refused before any request, listing valid clients; the upstream answers 404 api.err.ClientNotFound only for a known MAC with no v2 record.

        Under dry-run policy nothing is sent: a PUT returns the preview unchanged; a DELETE returns {status: "dry_run", deleted: false, message, response (the dry-run preview)}.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (set_client_icon):
            {"host": "my-console", "site": "Default", "target_id": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            target_id: Client MAC (any form) or connected client UUID; for target_type
                matter_node the Matter node id, e.g. "aa:bb:cc:dd:ee:ff".
            icon: Free-form icon object to set; omit to restore the default icon, e.g.
                the web app icon generator's object with keys icon_id, icon_set_id,
                request_id, selected_index and assets ([{url, width, height}]).
            target_type: "client" (default) or "matter_node", e.g. "client".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.set_client_icon(
            c, registry, host, site, target_id, icon, target_type
        )

    @mcp.tool(name="set_client_fingerprint_override", annotations=WRITE)
    async def _set_client_fingerprint_override(
        host: str,
        site: str,
        client: str,
        override: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Override (or restore) the device type the controller detected for a client. Consequence: the controller reports the overridden type in place of its fingerprint detection until the override is removed.

        Override given: PUT v2 station/{mac}/fingerprint_override with {dev_id_override: fingerprint device id, mac (added from the client if absent), plus optional search_query, dev_type, dev_vendor, dev_model}; returns the PUT body verbatim. override omitted: DELETE on the same route restores automatic detection. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. Current state: fingerprint.has_override / dev_id_override in list_dhcp_leases or get_local_client. v2 only (no official route).

        Under dry-run policy nothing is sent: a PUT returns the preview unchanged; a DELETE returns {status: "dry_run", deleted: false, message, response (the dry-run preview)}.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (set_client_fingerprint_override):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff",
             "override": {"dev_id_override": 4}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client: Client MAC (any form) or connected client UUID, e.g. "aa:bb:cc:dd:ee:ff".
            override: Body {dev_id_override, ...} (free-form); omit to restore detection,
                e.g. {"dev_id_override": 4}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.set_client_fingerprint_override(
            c, registry, host, site, client, override
        )

    @mcp.tool(name="report_incorrect_wifi_experience", annotations=WRITE)
    async def _report_incorrect_wifi_experience(
        host: str,
        site: str,
        target_type: WifiReportTarget,
        target: str,
        reason: str,
        comment: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Report that a client's or AP's WiFi experience score is wrong (sends feedback
        to Ubiquiti; cannot be withdrawn).

        Consequence: the feedback report is sent to Ubiquiti and cannot be withdrawn; client,
        AP and score are not changed by it.

        POST v2 station/{mac}/wifi_experience/incorrect (target_type client) or
        device/{mac}/wifi_experience/incorrect (target_type ap) with {reason, comment}.
        The web app offers the reasons DROPPED_CONNECTIVITY, POOR_LATENCY and
        POOR_THROUGHPUT; reason is sent as given. Route: v2 only (no official route).
        Returns the upstream body verbatim; under dry-run policy the dry-run preview.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.

        Example call (report_incorrect_wifi_experience):
            {"host": "my-console", "site": "Default", "target_type": "client",
             "target": "aa:bb:cc:dd:ee:ff", "reason": "POOR_LATENCY"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            target_type: "client" or "ap", e.g. "client".
            target: Client MAC (any form) or connected client UUID; for ap, the AP MAC,
                e.g. "aa:bb:cc:dd:ee:ff".
            reason: e.g. "POOR_LATENCY" (web app: DROPPED_CONNECTIVITY, POOR_LATENCY,
                POOR_THROUGHPUT).
            comment: Optional free-text comment, e.g. "Calls drop in the kitchen".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.report_incorrect_wifi_experience(
            c, registry, host, site, target_type, target, reason, comment
        )

    @mcp.tool(name="list_dhcp_leases", annotations=READ_ONLY)
    async def _list_dhcp_leases(host: str, site: str, network_id: str | None = None) -> Any:
        """List active DHCP leases, for the site or one network (v2 active-leases).

        Route: v2 only (no official route). Returns the upstream object verbatim:
        {dhcp_lease_info: [{mac, ip, hostname, display_name, network_id, client_type,
        status, lease_expiration_time, use_fixedip, fixed_ip, fingerprint, ...}]}.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (list_dhcp_leases):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            network_id: Optional Classic networkconf _id to list that network's leases only,
                e.g. "000000000000000000000108". It is sent untranslated in the v2 path, so
                the Integration id from list_networks (data[].id) is not a substitute.
        """
        c, registry = deps_fn()
        return await network_clients_guests.list_dhcp_leases(c, registry, host, site, network_id)

    @mcp.tool(name="list_dhcp_excluded_ips", annotations=READ_ONLY)
    async def _list_dhcp_excluded_ips(host: str, site: str, network_id: str | None = None) -> Any:
        """List addresses excluded from DHCP, for the site or one network (v2 excluded-ips).

        Route: v2 only (no official route). Returns the upstream object verbatim:
        {excluded_ip_client_info: [...], unidentified_excluded_ip_info: [...]}.

        Bare-list returns use the FastMCP {result: [...]} envelope; upstream core shapes
        remain verbatim.

        Example call (list_dhcp_excluded_ips):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            network_id: Optional Classic networkconf _id to scope the list, e.g.
                "000000000000000000000108". It is sent untranslated in the v2 path, so the
                Integration id from list_networks (data[].id) is not a substitute.
        """
        c, registry = deps_fn()
        return await network_clients_guests.list_dhcp_excluded_ips(
            c, registry, host, site, network_id
        )

    @mcp.tool(name="list_dhcp_options", annotations=READ_ONLY)
    async def _list_dhcp_options(host: str, site: str) -> Any:
        """List custom DHCP option definitions (Classic rest/dhcpoption).

        Route: Classic only (the Network 11.0.81 web app has no newer route). Returns the
        Classic envelope {meta: {rc}, data: [option...]} verbatim; each option carries _id,
        name, code, type, width and signed. Change one with update_dhcp_option (option_id
        = its _id).

        Example call (list_dhcp_options):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        c, registry = deps_fn()
        return await network_clients_guests.list_dhcp_options(c, registry, host, site)

    @mcp.tool(name="create_dhcp_option", annotations=WRITE)
    async def _create_dhcp_option(
        host: str, site: str, option: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Define a custom DHCP option (Classic POST rest/dhcpoption).

        Request body: no published schema; the controller's fields are name (letters, digits, - and _; a 31-character name was rejected with api.err.InvalidValue), code (the option number; the web app allows 7-254 except reserved codes; stored as an integer), type (text, ipaddress, integer, boolean, hexarray, macaddress), width (8, 16 or 32 for integers) and signed. The body is sent as given. Networks then reference the option by name. Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [option]} verbatim; the new _id is data[0]._id. Under dry-run policy the dry-run preview is returned and nothing sent.

        Dry-run returns {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (create_dhcp_option):
            {"host": "my-console", "site": "Default",
             "option": {"name": "tftp-server", "code": "150", "type": "ipaddress"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            option: Free-form option body: name, code, type, width, signed, e.g.
                {"name": "tftp-server", "code": "150", "type": "ipaddress"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.create_dhcp_option(c, registry, host, site, option)

    @mcp.tool(name="update_dhcp_option", annotations=WRITE)
    async def _update_dhcp_option(
        host: str, site: str, option_id: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a custom DHCP option by _id (Classic PUT rest/dhcpoption/{id}).

        The id is resolved in list_dhcp_options first: an unknown id fails listing every valid _id and nothing is written. Request body: no published schema; pass only the fields to change (name, code, type, width, signed). The controller rejects a partial PUT (HTTP 400 api.err.Invalid), so the record read for the id check is sent back with your fields laid over it. Empty strings in list-valued fields are dropped. An empty update fails before any request. Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [option]} verbatim. Under dry-run policy the dry-run preview is returned and nothing is sent.

        Dry-run returns {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent. Object results add _verified after a type-strict, leaf-by-leaf re-read: true, false with _unverifiedFields naming each differing leaf, or null with _readAfterError when the re-read fails. A non-object write body is returned whole under response with the same verdict keys beside it. Dry-run skips the re-read.

        Example call (update_dhcp_option):
            {"host": "my-console", "site": "Default", "option_id": "000000000000000000000107",
             "fields": {"name": "tftp-backup"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            option_id: DHCP option _id from list_dhcp_options, e.g.
                "000000000000000000000107".
            fields: Free-form fields to change, e.g. {"name": "tftp-backup"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.update_dhcp_option(
            c, registry, host, site, option_id, fields
        )

    @mcp.tool(name="delete_dhcp_option", annotations=WRITE)
    async def _delete_dhcp_option(
        host: str, site: str, option_id: str, confirm: bool = False
    ) -> Any:
        """Delete a custom DHCP option by _id (Classic DELETE rest/dhcpoption/{id}).

        Consequence: networks stop handing out this option; there is no undo. The id is
        resolved in list_dhcp_options first (the controller answers a DELETE on an unknown
        id with HTTP 200): an unknown id fails listing every valid _id and nothing is
        deleted. Route: Classic only.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy the tool returns {status: "dry_run", deleted: false, message,
        response},
        where response is {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_dhcp_option):
            {"host": "my-console", "site": "Default", "option_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            option_id: DHCP option _id from list_dhcp_options, e.g.
                "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.delete_dhcp_option(c, registry, host, site, option_id)

    @mcp.tool(name="get_hotspot_settings", annotations=READ_ONLY)
    async def _get_hotspot_settings(host: str, site: str) -> Any:
        """Get the guest portal (hotspot) settings (Classic /api/stat/s/{site}/hotspotconfig).

        Route: Classic only (v2 hotspot/info has only show_hotspot_manager). Returns the
        Classic envelope {meta: {rc}, data: [config]} verbatim: auth, voucher_enabled,
        password_enabled, payment_enabled, radius_enabled, facebook_enabled, tos, title,
        welcome text, colours, logo and background settings, languages and the country
        list.

        Example call (get_hotspot_settings):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        c, registry = deps_fn()
        return await network_clients_guests.get_hotspot_settings(c, registry, host, site)

    @mcp.tool(name="list_hotspot_payments", annotations=READ_ONLY)
    async def _list_hotspot_payments(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        within: int | None = None,
    ) -> Any:
        """List guest portal payment transactions (Classic stat/payment).

        Route: Classic only. start / end are epoch SECONDS and are sent as epoch
        milliseconds (the web app's unit); within (hours back) is sent as given. Only the
        parameters you pass are sent. Returns the Classic envelope {meta: {rc}, data:
        [payment...]} verbatim (plus _warnings when a time looks like milliseconds).

        Example call (list_hotspot_payments):
            {"host": "my-console", "site": "Default", "start": 1757000000, "end": 1760000000}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            start: Window start, epoch seconds, e.g. 1757000000.
            end: Window end, epoch seconds, e.g. 1760000000.
            within: Hours back from now, e.g. 720.
        """
        c, registry = deps_fn()
        return await network_clients_guests.list_hotspot_payments(
            c, registry, host, site, start=start, end=end, within=within
        )

    @mcp.tool(name="list_hotspot_authorizations", annotations=READ_ONLY)
    async def _list_hotspot_authorizations(
        host: str, site: str, start: int | None = None, end: int | None = None
    ) -> Any:
        """List guest authorization history (Classic stat/authorization).

        Route: Classic only (community-documented route, served on Network 11.0.81). start
        / end are epoch SECONDS, sent as given; only the parameters you pass are sent.
        Returns the Classic envelope {meta: {rc}, data: [authorization...]} verbatim,
        plus _warnings when a time is negative or looks like milliseconds.

        Example call (list_hotspot_authorizations):
            {"host": "my-console", "site": "Default", "start": 1757000000, "end": 1760000000}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            start: Window start, epoch seconds, e.g. 1757000000.
            end: Window end, epoch seconds, e.g. 1760000000.
        """
        c, registry = deps_fn()
        return await network_clients_guests.list_hotspot_authorizations(
            c, registry, host, site, start=start, end=end
        )

    @mcp.tool(name="get_hotspot_guest_webhook_delivery", annotations=READ_ONLY)
    async def _get_hotspot_guest_webhook_delivery(host: str, site: str) -> Any:
        """Get the last delivery attempt of the hotspot guest-data webhook.

        Needs Network 11.1.47 or later. GET
        /proxy/network/v2/api/site/{site}/hotspot/guest-data-webhook/last-delivery. The
        webhook posts collected guest data (such as the guest email) to the URL set in the
        hotspot settings. Returns the upstream body verbatim: the Network 11.1.47 web
        application reads attemptedAtSeconds (epoch seconds), delivered (boolean), httpStatus
        and error from it. A console that has never attempted a delivery answers HTTP 204, which
        returns null (shown as {"result": null}); an older Network application answers 404.

        Example call (get_hotspot_guest_webhook_delivery):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        c, registry = deps_fn()
        return await network_clients_guests.get_hotspot_guest_webhook_delivery(
            c, registry, host, site
        )

    @mcp.tool(name="create_hotspot_package", annotations=WRITE)
    async def _create_hotspot_package(
        host: str, site: str, package: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a guest portal billing package (Classic POST rest/hotspotpackage).

        Request body: no published schema; sent as given. Fields: name, amount, currency, hours (paid duration), trial_duration_minutes and trial_reset (free trial), charged_as, index, limit_overwrite, limit_up, limit_down, limit_quota and the payment_fields_* switches. Live on Network 11.0.81 with payments not configured, a trial package {name, amount: 0, currency, trial_duration_minutes, trial_reset} was accepted, while paid packages (amount > 0 with hours) answered HTTP 400 api.err.InvalidHotspotPackageDuration. Guests see packages only when the portal has payments enabled (get_hotspot_settings payment_enabled). Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [package]} verbatim; the new _id is data[0]._id (list them with list_hotspot_packages). Under dry-run policy the dry-run preview is returned and nothing is sent.

        Dry-run returns {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (create_hotspot_package):
            {"host": "my-console", "site": "Default",
             "package": {"name": "Trial", "amount": 0, "currency": "USD",
                         "trial_duration_minutes": 30, "trial_reset": 24}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            package: Free-form package body, e.g. {"name": "Trial", "amount": 0,
                "currency": "USD", "trial_duration_minutes": 30, "trial_reset": 24}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.create_hotspot_package(c, registry, host, site, package)

    @mcp.tool(name="update_hotspot_package", annotations=WRITE)
    async def _update_hotspot_package(
        host: str, site: str, package_id: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a guest portal billing package by _id (Classic PUT rest/hotspotpackage/{id}).

        The id is resolved in list_hotspot_packages first: an unknown id fails listing every valid _id and nothing is written. Request body: no published schema; pass only the fields to change. The controller rejects a partial Classic PUT, so the record read for the id check is sent back with your fields laid over it. Empty strings in list-valued fields are dropped. An empty update fails before any request. Route: Classic only.

        Returns the Classic envelope {meta: {rc}, data: [package]} verbatim. Under dry-run policy the dry-run preview is returned and nothing is sent.

        Dry-run returns {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent. Object results add _verified after a type-strict, leaf-by-leaf re-read: true, false with _unverifiedFields naming each differing leaf, or null with _readAfterError when the re-read fails. A non-object write body is returned whole under response with the same verdict keys beside it. Dry-run skips the re-read.

        Example call (update_hotspot_package):
            {"host": "my-console", "site": "Default", "package_id": "000000000000000000000107",
             "fields": {"amount": 6}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            package_id: Package _id from list_hotspot_packages, e.g.
                "000000000000000000000107".
            fields: Free-form fields to change, e.g. {"amount": 6}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.update_hotspot_package(
            c, registry, host, site, package_id, fields
        )

    @mcp.tool(name="delete_hotspot_package", annotations=WRITE)
    async def _delete_hotspot_package(
        host: str, site: str, package_id: str, confirm: bool = False
    ) -> Any:
        """Delete a guest portal billing package by _id (Classic DELETE rest/hotspotpackage/{id}).

        Consequence: guests can no longer buy this package; there is no undo. The id is
        resolved in list_hotspot_packages first (the controller answers a DELETE on an
        unknown id with HTTP 200): an unknown id fails listing every valid _id and nothing
        is deleted. Route: Classic only.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy the tool returns {status: "dry_run", deleted: false, message,
        response},
        where response is {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_hotspot_package):
            {"host": "my-console", "site": "Default", "package_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            package_id: Package _id from list_hotspot_packages, e.g.
                "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.delete_hotspot_package(
            c, registry, host, site, package_id
        )

    @mcp.tool(name="delete_guest_portal_file", annotations=WRITE)
    async def _delete_guest_portal_file(
        host: str, site: str, file_id: str, confirm: bool = False
    ) -> Any:
        """Delete an uploaded guest portal file (logo or background image) by _id
        (Classic DELETE rest/portalfile/{id}).

        Consequence: the portal stops showing the file; there is no undo. The id is
        resolved in the Classic rest/portalfile list first (the controller answers a DELETE
        on an unknown id with HTTP 200): an unknown id fails listing every file and
        nothing is deleted. Route: Classic only.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy the tool returns {status: "dry_run", deleted: false, message,
        response},
        where response is {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_guest_portal_file):
            {"host": "my-console", "site": "Default", "file_id": "000000000000000000000107"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            file_id: Portal file _id from the Classic rest/portalfile list, e.g.
                "000000000000000000000107".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.delete_guest_portal_file(
            c, registry, host, site, file_id
        )

    @mcp.tool(name="reset_guest_access_settings", annotations=WRITE)
    async def _reset_guest_access_settings(
        host: str, site: str, body: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Reset the guest portal (guest access) settings to their defaults
        (v2 POST settings/guest-access/reset).

        Consequence: every customized portal setting (authentication, texts, colours,
        images, terms) returns to the default; there is no undo, so read
        get_hotspot_settings first if you may want to restore them. Request body: none
        published; the web app sends {} (sent when body is omitted). Route: v2 only.

        Returns the upstream body verbatim; under dry-run policy the dry-run preview.

        Dry-run returns {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}}; nothing is sent.

        Example call (reset_guest_access_settings):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            body: Optional free-form request body; omitted, {} is sent like the web app,
                e.g. {}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        c, registry = deps_fn()
        return await network_clients_guests.reset_guest_access_settings(
            c, registry, host, site, body
        )


def register_5(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 24 switching, power and infrastructure-history tools."""

    @mcp.tool(name="list_energy_saving_policies", annotations=READ_ONLY)
    async def list_energy_saving_policies_tool(host: str, site: str) -> Any:
        """List a site's energy-saving policies (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/energy-saving-policies. Returns the upstream body
        verbatim. The route takes no paging parameter.
        A JSON array result (the usual v2 shape) arrives wrapped as {"result": [...]};
        an object result is returned as sent.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_switching_power.list_energy_saving_policies(
            client, registry, host, site
        )

    @mcp.tool(name="create_energy_saving_policy", annotations=WRITE)
    async def create_energy_saving_policy_tool(host: str, site: str, policy: dict[str, Any]) -> Any:
        """Create an energy-saving policy (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/energy-saving-policies with policy sent
        verbatim. Returns the upstream body verbatim. Never auto-retried.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, policy (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            policy: Policy object in the shape list_energy_saving_policies returns, e.g.
                {"name": "night-saver", "enabled": false}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.create_energy_saving_policy(
            client, registry, host, site, policy
        )

    @mcp.tool(name="update_energy_saving_policy", annotations=WRITE)
    async def update_energy_saving_policy_tool(
        host: str, site: str, policy_id: str, policy: dict[str, Any]
    ) -> Any:
        """Update an energy-saving policy (Network v2 route).

        PUT /proxy/network/v2/api/site/{site}/energy-saving-policies/{id}.

        Reads the record from its list, merges the given leaves into its writable fields, PUTs the merged record and reads it back. Controller-generated list metadata is not copied into PUT. Returns the upstream PUT body verbatim plus _verified (true only when every requested leaf reads back equal, type-strict) and _readAfterError when the read-back failed; a non-object body (array or scalar) is returned whole under response with those keys beside it. id, _id and site_id in the object are ignored; an object with nothing else to change fails before any request. An unknown id fails listing every valid id.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, policy_id, policy (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            policy_id: Policy _id or id from list_energy_saving_policies, e.g.
                "000000000000000000000107".
            policy: Leaves to change, e.g. {"enabled": true}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.update_energy_saving_policy(
            client, registry, host, site, policy_id, policy
        )

    @mcp.tool(name="delete_energy_saving_policy", annotations=WRITE)
    async def delete_energy_saving_policy_tool(host: str, site: str, policy_id: str) -> Any:
        """Delete an energy-saving policy (Network v2 route).

        Consequence: the policy is permanently removed and the site's devices stop following
        it; there is no undo.

        Resolves the id in list_energy_saving_policies first (an unknown id fails listing every
        valid id), then DELETE /proxy/network/v2/api/site/{site}/energy-saving-policies/{id}.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, policy_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            policy_id: Policy _id or id from list_energy_saving_policies, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_switching_power.delete_energy_saving_policy(
            client, registry, host, site, policy_id
        )

    @mcp.tool(name="list_port_automations", annotations=READ_ONLY)
    async def list_port_automations_tool(host: str, site: str) -> Any:
        """List a site's port automations (Network 11.1 v2 route).

        A port automation applies a port profile to a switch port when the device plugged in
        matches a vendor or MAC OUI.

        GET /proxy/network/v2/api/site/{site}/port-automations. Returns the upstream body
        verbatim (a JSON array, empty when none exist). The route takes no paging parameter.
        Needs a Network application of 11.1.47 or later; an older console answers 404.
        A JSON array result (the usual v2 shape) arrives wrapped as {"result": [...]};
        an object result is returned as sent.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_switching_power.list_port_automations(client, registry, host, site)

    @mcp.tool(name="get_port_automation", annotations=READ_ONLY)
    async def get_port_automation_tool(host: str, site: str, automation_id: str) -> Any:
        """Get one port automation (Network 11.1 v2 route).

        The controller serves no single-record route, so this reads GET
        /proxy/network/v2/api/site/{site}/port-automations and returns the record whose id
        matches, verbatim. An unknown id fails naming every valid id. The record carries name,
        enabled, port_profile_id, match (vendor_ids and mac_ouis) and scope (switch_macs,
        device_tag_ids and an optional port_range), exactly as the Network 11.1.47 web
        application stores it, plus the identifier the controller assigned. match lists the
        numeric vendor identifiers and the six-digit hexadecimal MAC prefixes that select
        devices; scope narrows the rule to chosen switches, to the members of device tags, and
        to a contiguous span of physical ports; port_profile_id names the profile applied to a
        port when a selected device is detected there. Nothing is changed by this read.

        Returns the matching port automation record verbatim (a JSON object).

        Required arguments: host, site, automation_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            automation_id: Port automation id (the id field of a record), e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_switching_power.get_port_automation(
            client, registry, host, site, automation_id
        )

    @mcp.tool(name="create_port_automation", annotations=WRITE)
    async def create_port_automation_tool(host: str, site: str, automation: dict[str, Any]) -> Any:
        """Create a port automation (Network 11.1 v2 route).

        Consequence: once enabled, a matching device plugged into an in-scope switch port moves
        that port to the profile's network, which can change what the device can reach.

        POST /proxy/network/v2/api/site/{site}/port-automations with automation sent
        verbatim. Returns the upstream body verbatim. Never auto-retried; on a timeout, list
        the automations before retrying.

        Request body (observed in the Network 11.1.47 web application; the controller
        publishes no spec): name (string, 1 to 128 characters), enabled (boolean),
        port_profile_id (port profile _id from list_port_profiles), match (object: vendor_ids,
        up to 64 non-negative integers; mac_ouis, up to 64 six-hex-digit OUIs; at least one of
        the two is required), scope (object: switch_macs, up to 128 switch MACs; device_tag_ids,
        up to 64 device tag ids; optional port_range {from_port, to_port}, 1 to 60; empty
        switch_macs and device_tag_ids mean every switch).

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, automation (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            automation: Automation object in the shape list_port_automations returns, e.g.
                {"name": "Phones", "enabled": true, "port_profile_id": "PORT_PROFILE_ID",
                "match": {"vendor_ids": [], "mac_ouis": ["00:11:22"]},
                "scope": {"switch_macs": [], "device_tag_ids": [],
                "port_range": {"from_port": 1, "to_port": 24}}}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.create_port_automation(
            client, registry, host, site, automation
        )

    @mcp.tool(name="update_port_automation", annotations=WRITE)
    async def update_port_automation_tool(
        host: str, site: str, automation_id: str, automation: dict[str, Any]
    ) -> Any:
        """Update a port automation (Network 11.1 v2 route).

        Consequence: changes which devices get which port profile on in-scope switch ports.

        PUT /proxy/network/v2/api/site/{site}/port-automations/{id}. Never auto-retried.

        Reads the record from its list, merges only the given leaves into it, PUTs the whole merged
        record and reads it back. Returns the upstream PUT body verbatim plus _verified (true only
        when every requested leaf reads back equal, type-strict) and _readAfterError when the
        read-back failed; a non-object body (array or scalar) is returned whole under response with
        those keys beside it. id, _id and site_id in the object are ignored; an object with nothing
        else to change fails before any request. An unknown id fails listing every valid id.
        The body fields are those create_port_automation lists.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, automation_id, automation (see each parameter's
        description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            automation_id: Port automation id from list_port_automations, e.g.
                "000000000000000000000107".
            automation: Leaves to change, e.g. {"enabled": false}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.update_port_automation(
            client, registry, host, site, automation_id, automation
        )

    @mcp.tool(name="delete_port_automation", annotations=WRITE)
    async def delete_port_automation_tool(host: str, site: str, automation_id: str) -> Any:
        """Delete a port automation (Network 11.1 v2 route).

        Consequence: the automation is permanently removed; ports it already configured keep
        their current profile. There is no undo.

        Resolves the id in list_port_automations first (an unknown id fails listing every valid
        id), then DELETE /proxy/network/v2/api/site/{site}/port-automations/{id}.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty).

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, automation_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            automation_id: Port automation id from list_port_automations, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_switching_power.delete_port_automation(
            client, registry, host, site, automation_id
        )

    @mcp.tool(name="list_power_supervisors", annotations=READ_ONLY)
    async def list_power_supervisors_tool(host: str, site: str) -> Any:
        """List a site's PoE power supervisors (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/power-supervisors. Returns the upstream body
        verbatim. The route takes no paging parameter.
        A JSON array result (the usual v2 shape) arrives wrapped as {"result": [...]};
        an object result is returned as sent.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_switching_power.list_power_supervisors(client, registry, host, site)

    @mcp.tool(name="create_power_supervisor", annotations=WRITE)
    async def create_power_supervisor_tool(host: str, site: str, supervisor: dict[str, Any]) -> Any:
        """Create a PoE power supervisor (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/power-supervisors with supervisor sent
        verbatim. Returns the upstream body verbatim. An enabled supervisor can
        power-cycle the PoE port it watches. Never auto-retried; on a timeout, list the
        supervisors before retrying.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, supervisor (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            supervisor: Supervisor object, e.g. {"client_mac": "02:00:5e:00:00:a1",
                "control_mode": "manual", "settings": {"enabled": false}}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.create_power_supervisor(
            client, registry, host, site, supervisor
        )

    @mcp.tool(name="update_power_supervisor", annotations=WRITE)
    async def update_power_supervisor_tool(
        host: str, site: str, supervisor_id: str, supervisor: dict[str, Any]
    ) -> Any:
        """Update a PoE power supervisor (Network v2 route).

        PUT /proxy/network/v2/api/site/{site}/power-supervisors/{id}. Never auto-retried.

        Reads the record from its list, merges only the given leaves into it, PUTs the whole merged
        record and reads it back. Returns the upstream PUT body verbatim plus _verified (true only
        when every requested leaf reads back equal, type-strict) and _readAfterError when the
        read-back failed; a non-object body (array or scalar) is returned whole under response with
        those keys beside it. id, _id and site_id in the object are ignored; an object with nothing
        else to change fails before any request. An unknown id fails listing every valid id.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, supervisor_id, supervisor (see each parameter's
        description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            supervisor_id: Supervisor _id or id from list_power_supervisors, e.g.
                "000000000000000000000107".
            supervisor: Leaves to change, e.g. {"control_mode": "manual"}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.update_power_supervisor(
            client, registry, host, site, supervisor_id, supervisor
        )

    @mcp.tool(name="delete_power_supervisor", annotations=WRITE)
    async def delete_power_supervisor_tool(host: str, site: str, supervisor_id: str) -> Any:
        """Delete a PoE power supervisor (Network v2 route).

        Consequence: the supervisor and its configuration are permanently removed and it no
        longer manages the PoE power it supervised; there is no undo.

        Resolves the id in list_power_supervisors first (an unknown id fails listing every valid
        id), then DELETE /proxy/network/v2/api/site/{site}/power-supervisors/{id}.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, supervisor_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            supervisor_id: Supervisor _id or id from list_power_supervisors, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_switching_power.delete_power_supervisor(
            client, registry, host, site, supervisor_id
        )

    @mcp.tool(name="create_power_supervisor_link", annotations=WRITE)
    async def create_power_supervisor_link_tool(host: str, site: str, link: dict[str, Any]) -> Any:
        """Create a power-supervisor link (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/power-supervisors/links with link sent
        verbatim. Returns the upstream body verbatim. Never auto-retried.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, link (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            link: Link object, e.g. {"supervisor_id": "000000000000000000000107",
                "enabled": false}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.create_power_supervisor_link(
            client, registry, host, site, link
        )

    @mcp.tool(name="update_power_supervisor_link", annotations=WRITE)
    async def update_power_supervisor_link_tool(
        host: str, site: str, link_id: str, link: dict[str, Any]
    ) -> Any:
        """Update a power-supervisor link (Network v2 route).

        Reads the link from GET .../power-supervisors/links, then PUT /proxy/network/v2/api/site/{site}/power-supervisors/links/{id}. Never auto-retried.

        Reads the record from its list, merges only the given leaves into it, PUTs the whole merged record and reads it back. Returns the upstream PUT body verbatim plus _verified (true only when every requested leaf reads back equal, type-strict) and _readAfterError when the read-back failed; a non-object body (array or scalar) is returned whole under response with those keys beside it. id, _id and site_id in the object are ignored; an object with nothing else to change fails before any request. An unknown id fails listing every valid id.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, link_id, link (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            link_id: Link _id or id from fabric_connector_get with path
                network/v2/api/site/{site}/power-supervisors/links, e.g.
                "000000000000000000000107".
            link: Leaves to change, e.g. {"enabled": false}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.update_power_supervisor_link(
            client, registry, host, site, link_id, link
        )

    @mcp.tool(name="delete_power_supervisor_link", annotations=WRITE)
    async def delete_power_supervisor_link_tool(host: str, site: str, link_id: str) -> Any:
        """Delete a power-supervisor link (Network v2 route).

        Consequence: the link is permanently removed, so its supervisor no longer acts on
        the linked port or device; there is no undo.

        Resolves the id in GET .../power-supervisors/links first (an unknown id fails listing every
        valid id), then DELETE /proxy/network/v2/api/site/{site}/power-supervisors/links/{id}.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, link_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            link_id: Link _id or id from fabric_connector_get with path
                network/v2/api/site/{site}/power-supervisors/links, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_switching_power.delete_power_supervisor_link(
            client, registry, host, site, link_id
        )

    @mcp.tool(name="query_power_supervisor_logs", annotations=WRITE)
    async def query_power_supervisor_logs_tool(
        host: str, site: str, supervisor_id: str, query: dict[str, Any]
    ) -> Any:
        """Query one PoE power supervisor's system logs (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/power-supervisors/{id}/system-logs with
        query sent verbatim. Returns the upstream body verbatim. This POST is not on
        the read-POST allowlist, so it is classified as a write (UNIFI_WRITE_POLICY=deny hides the
        tool;
        family:network=deny also hides the tool). Consequence: none intended
        (a query); it only reads logs.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, supervisor_id, query (see each parameter's description).

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides
        the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            supervisor_id: Supervisor _id or id from list_power_supervisors, e.g.
                "000000000000000000000107".
            query: Query body, e.g. {"limit": 25}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.query_power_supervisor_logs(
            client, registry, host, site, supervisor_id, query
        )

    @mcp.tool(name="get_port_history", annotations=READ_ONLY)
    async def get_port_history_tool(
        host: str, site: str, at: int, device_id: str | None = None
    ) -> Any:
        """Get the switch-port history snapshot at a time (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/ports/history/at/{at}, or
        .../ports/history/{device_id}/at/{at} for one device. Returns the upstream body
        verbatim. at is epoch SECONDS and is sent as epoch milliseconds (the route's
        unit); _warnings is added when it is negative or looks like epoch milliseconds.

        Required arguments: host, site, at (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            at: Epoch-seconds timestamp (sent as milliseconds), e.g. 1760000000.
            device_id: Optional device id, e.g. "000000000000000000000107"; omit for every
                device of the site.
        """
        client, registry = deps_fn()
        return await network_switching_power.get_port_history(
            client, registry, host, site, at, device_id
        )

    @mcp.tool(name="query_switch_mac_tables", annotations=WRITE)
    async def query_switch_mac_tables_tool(
        host: str,
        site: str,
        query: dict[str, Any] = network_switching_power._QUERY_DEFAULT,
        queries: list[dict[str, Any]] | None = None,
    ) -> Any:
        """Query the MAC tables of switch ports (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/ports/mac-tables with queries sent as a JSON array, one {mac, ports} item per switch, as the web app sends it (an object body answers HTTP 400). Use queries for the array body. The legacy query takes precedence when present: a {mac, ports} object is sent as the one-item array [query]; any other value is forwarded unchanged and the controller judges it. An empty queries list or a non-object array item is refused before any request. Returns the upstream body verbatim (per switch, each port's mac_table). This POST is not on the read-POST allowlist, so it is classified as a write (UNIFI_WRITE_POLICY=deny hides the tool; family:network=deny also hides the tool). Consequence: none intended (a query); it only reads the MAC tables.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, and either queries (UI array) or query (legacy object).

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            query: Legacy free-form object, taking precedence over queries; a {mac, ports}
                object is sent as [query]. Shape: {mac:string,ports:integer[]}, e.g.
                {"mac": "02:00:5e:00:53:01", "ports": [1, 2]}. Use queries for the UI array.
            queries: Shape: {mac:string,ports:integer[]}[]. One item per switch, with
                free-form object keys forwarded, e.g.
                [{"mac": "02:00:5e:00:53:01", "ports": [1, 2]}].
        """
        client, registry = deps_fn()
        if query is not network_switching_power._QUERY_UNSET:
            if network_switching_power._is_switch_query(query):
                # The documented legacy object names one switch: the route deserializes a
                # list, so it goes through the array path (sent as [query]).
                return await network_switching_power.query_switch_mac_tables(
                    client, registry, host, site, query
                )
            key, host_id, slug = await resolve_site_slug(registry, host, site)
            return await client.post(
                v2_site(host_id, slug, "/ports/mac-tables"), key=key, json=query
            )
        return await network_switching_power.query_switch_mac_tables(
            client, registry, host, site, queries
        )

    @mcp.tool(name="list_port_anomalies", annotations=READ_ONLY)
    async def list_port_anomalies_tool(host: str, site: str) -> Any:
        """List the site's switch-port anomalies (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/ports/port-anomalies. Returns the upstream body
        verbatim. The route takes no paging parameter.
        A JSON array result (the usual v2 shape) arrives wrapped as {"result": [...]};
        an object result is returned as sent.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_switching_power.list_port_anomalies(client, registry, host, site)

    @mcp.tool(name="query_port_system_logs", annotations=WRITE)
    async def query_port_system_logs_tool(host: str, site: str, query: dict[str, Any]) -> Any:
        """Query the site's switch-port system logs (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/ports/system-logs with query sent verbatim.
        Returns the upstream body verbatim. This POST is not on the read-POST
        allowlist, so it is classified as a write (UNIFI_WRITE_POLICY=deny hides the tool;
        family:network=deny also hides the tool).
        Consequence: none intended (a query); it only reads logs.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, query (see each parameter's description).

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides
        the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            query: Query body, e.g. {"limit": 25}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.query_port_system_logs(
            client, registry, host, site, query
        )

    @mcp.tool(name="list_wireless_links", annotations=READ_ONLY)
    async def list_wireless_links_tool(host: str, site: str, device_id: str | None = None) -> Any:
        """List wireless (mesh and bridge) links for the site or one device (Network v2).

        GET /proxy/network/v2/api/site/{site}/device/wireless-links, or
        .../device/{device_id}/wireless-links for one device. Returns the upstream body
        verbatim.
        A JSON array result (the usual v2 shape) arrives wrapped as {"result": [...]};
        an object result is returned as sent.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device_id: Optional device id, e.g. "000000000000000000000107"; omit for every
                device of the site.
        """
        client, registry = deps_fn()
        return await network_switching_power.list_wireless_links(
            client, registry, host, site, device_id
        )

    @mcp.tool(name="get_device_tx_retries", annotations=READ_ONLY)
    async def get_device_tx_retries_tool(
        host: str, site: str, device_id: str, params: dict[str, Any] | None = None
    ) -> Any:
        """Get one device's 24-hour transmit retries (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/device/{device_id}/24hr-tx-retries with
        params forwarded as the query string. Returns the upstream body verbatim.
        A JSON array result (the usual v2 shape) arrives wrapped as {"result": [...]};
        an object result is returned as sent.

        Required arguments: host, site, device_id (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device_id: Device id, e.g. "000000000000000000000107".
            params: Optional query parameters sent as given, e.g. {"radio": "na"}. Free-form object.
        """
        client, registry = deps_fn()
        return await network_switching_power.get_device_tx_retries(
            client, registry, host, site, device_id, params
        )

    @mcp.tool(name="get_infrastructure_history", annotations=READ_ONLY)
    async def get_infrastructure_history_tool(host: str, site: str, at: int) -> Any:
        """Get the site's infrastructure history snapshot at a time (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/infrastructure/history/at/{at}. Returns
        the upstream body verbatim. at is epoch SECONDS and is sent as epoch milliseconds
        (the route's unit); _warnings is added when it is negative or looks like epoch
        milliseconds.

        Required arguments: host, site, at (see each parameter's description).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            at: Epoch-seconds timestamp (sent as milliseconds), e.g. 1760000000.
        """
        client, registry = deps_fn()
        return await network_switching_power.get_infrastructure_history(
            client, registry, host, site, at
        )


def register_6(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 18 Network controller administration tools."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="reboot_unifi_os_console", annotations=WRITE)
    async def reboot_unifi_os_console_tool(host: str, confirm: bool = False) -> Any:
        """Ask the Network application to reboot a UniFi OS console (POST /proxy/network/api/system/reboot).

        Required argument: host. Known limitation: UniFi OS serves its console reboot at the
        console root, POST /api/system/reboot, which the Fabric connector does not relay, and
        the Network application this path reaches has no such route (checked in Network
        11.0.99). Expect an upstream error and no reboot; the error is returned verbatim.
        Consequence: if a console did serve it, this restarts the entire console, temporarily
        interrupting every application it runs and disconnecting managed devices and clients.
        The operation is destructive and non-idempotent. Returns the upstream response body
        unchanged; an upstream error is returned as received, with the route hint above.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried. Writes are allowed by default; family:network=deny disables this tool.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            confirm: Accepted and ignored for compatibility; e.g. false.
        """
        del confirm
        return await network_controller_admin.reboot_unifi_os_console(*deps(), host)

    @mcp.tool(name="cancel_controller_backup", annotations=WRITE)
    async def cancel_controller_backup_tool(host: str, site: str, backup_id: str) -> Any:
        """Cancel a running controller backup (Classic cmd/backup cancel-backup).

        Required arguments: host, site, backup_id.

        POST /proxy/network/api/s/{site}/cmd/backup {"cmd": "cancel-backup", "backup_id"}.
        Consequence: the running backup stops and leaves no backup file.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            backup_id: Id of the running backup the controller reported, e.g.
                "000000000000000000000107".
        """
        return await network_controller_admin.cancel_controller_backup(
            *deps(), host, site, backup_id
        )

    @mcp.tool(name="delete_controller_backup", annotations=WRITE)
    async def delete_controller_backup_tool(
        host: str, site: str, filename: str, device_id: str | None = None
    ) -> Any:
        """Delete a stored controller backup file (Classic cmd/backup delete-backup).

        Required arguments: host, site, filename.

        POST /proxy/network/api/s/{site}/cmd/backup {"cmd": "delete-backup", "filename",
        "device_id" when given}. Consequence: the backup file is removed permanently and
        cannot be restored afterwards.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            filename: Backup file name as the controller lists it, e.g.
                "autobackup_11.0.81_20261001_0000_1759276800000.unf".
            device_id: Optional console device id the backup belongs to, e.g.
                "000000000000000000000107".
        """
        return await network_controller_admin.delete_controller_backup(
            *deps(), host, site, filename, device_id
        )

    @mcp.tool(name="restore_controller_backup", annotations=WRITE)
    async def restore_controller_backup_tool(
        host: str, site: str, filename: str | None = None, body: dict[str, Any] | None = None
    ) -> Any:
        """Restore the Network application from a backup (Classic cmd/backup restore).

        Required arguments: host, site.

        With filename, first POST cmd/backup {"cmd": "choose-backup", "filename"} (the
        controller's backup-selection step; its body is returned under _chooseBackup),
        then POST cmd/backup {"cmd": "restore", **body}. The 11.0.81 front end builds the
        restore body at runtime, so body is free-form and sent as given. Consequence:
        replaces the controller's whole configuration with the backup and restarts the
        Network application; clients and devices may disconnect.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            filename: Optional backup file to select first, e.g.
                "autobackup_11.0.81_20261001_0000_1759276800000.unf".
            body: Optional free-form restore body (never "cmd"), e.g. {}.
        """
        return await network_controller_admin.restore_controller_backup(
            *deps(), host, site, filename, body
        )

    @mcp.tool(name="import_site_configuration", annotations=WRITE)
    async def import_site_configuration_tool(
        host: str, site: str, backup_id: str, site_desc: str
    ) -> Any:
        """Import an exported site into the controller (Classic cmd/backup import-site).

        Required arguments: host, site, backup_id, site_desc.

        POST /proxy/network/api/s/{site}/cmd/backup {"cmd": "import-site", "backup_id",
        "site_desc"}. Consequence: creates a site from the export and may adopt its
        devices.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            backup_id: Id of the uploaded site export, e.g. "000000000000000000000107".
            site_desc: Name for the imported site, e.g. "Branch Office".
        """
        return await network_controller_admin.import_site_configuration(
            *deps(), host, site, backup_id, site_desc
        )

    @mcp.tool(name="send_test_email", annotations=WRITE)
    async def send_test_email_tool(
        host: str,
        site: str,
        email: str,
        smtp_host: str | None = None,
        port: int | None = None,
        sender: str | None = None,
        use_auth: bool | None = None,
        use_sender: bool | None = None,
        use_ssl: bool | None = None,
        username: str | None = None,
        x_password: str | None = None,
    ) -> Any:
        """Send a test email through SMTP settings (Classic cmd/cfgmgr test_mail).

        Required arguments: host, site, email.

        POST /proxy/network/api/s/{site}/cmd/cfgmgr {"cmd": "test_mail", "email", and the
        SMTP keys given: host (smtp_host), port, sender, use_auth, use_sender, use_ssl,
        username, x_password}. x_password is a credential: scrubbed from logs, and from
        errors only under UNIFI_REDACT_SECRETS.
        Consequence: the controller sends one email.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            email: Recipient address, e.g. "admin@example.com".
            smtp_host: Optional SMTP server (sent as host), e.g. "smtp.example.com".
            port: Optional SMTP port, e.g. 587.
            sender: Optional From address, e.g. "unifi@example.com".
            use_auth: Optional SMTP authentication flag, e.g. true.
            use_sender: Optional use-sender flag, e.g. true.
            use_ssl: Optional TLS flag, e.g. true.
            username: Optional SMTP user, e.g. "unifi@example.com".
            x_password: Optional SMTP password, e.g. "example-smtp-password".
        """
        return await network_controller_admin.send_test_email(
            *deps(),
            host,
            site,
            email,
            smtp_host,
            port,
            sender,
            use_auth,
            use_sender,
            use_ssl,
            username,
            x_password,
        )

    @mcp.tool(name="get_remote_access_turn_credentials", annotations=WRITE)
    async def get_remote_access_turn_credentials_tool(host: str, site: str) -> Any:
        """Get remote-access TURN credentials (Classic cmd/cloudaccess).

        Required arguments: host, site.

        POST /proxy/network/api/s/{site}/cmd/cloudaccess {"cmd": "get-turn-credentials"}.
        The credentials are returned verbatim (masked only under UNIFI_REDACT_SECRETS).
        This POST is not on the read-POST allowlist, so it is classified as a write.
        Consequence: the controller issues TURN credentials.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await network_controller_admin.get_remote_access_turn_credentials(
            *deps(), host, site
        )

    @mcp.tool(name="set_cloud_access_registration", annotations=WRITE)
    async def set_cloud_access_registration_tool(
        host: str,
        site: str,
        action: Literal["register", "unregister"],
        ubic_username: str | None = None,
        ubic_password: str | None = None,
        ubic_2fa_token: str | None = None,
        mfa_cookie: str | None = None,
        poll_login: bool | None = None,
    ) -> Any:
        """Register or unregister cloud remote access (Classic cmd/cloudaccess).

        Required arguments: host, site, action.

        POST /proxy/network/api/s/{site}/cmd/cloudaccess {"cmd": action, and the account
        keys given}. ubic_password, ubic_2fa_token and mfa_cookie are credentials.
        Consequence: unregister ends cloud remote access to this controller.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: Command to send, e.g. "register".
            ubic_username: Optional Ubiquiti account user, e.g. "admin@example.com".
            ubic_password: Optional Ubiquiti account password, e.g. "example-password".
            ubic_2fa_token: Optional 2FA code, e.g. "123456".
            mfa_cookie: Optional MFA cookie from an earlier reply, e.g. "example-cookie".
            poll_login: Optional poll-login flag, e.g. true.
        """
        return await network_controller_admin.set_cloud_access_registration(
            *deps(),
            host,
            site,
            action,
            ubic_username,
            ubic_password,
            ubic_2fa_token,
            mfa_cookie,
            poll_login,
        )

    @mcp.tool(name="refresh_sso_session", annotations=WRITE)
    async def refresh_sso_session_tool(
        host: str,
        site: str,
        sso_username: str | None = None,
        sso_password: str | None = None,
        sso_2fa_token: str | None = None,
        mfa_cookie: str | None = None,
        poll_login: bool | None = None,
    ) -> Any:
        """Refresh the controller's Ubiquiti SSO session (Classic cmd/productinfo).

        Required arguments: host, site.

        POST /proxy/network/api/s/{site}/cmd/productinfo/refresh-sso {"cmd":
        "refresh-sso", and the keys given}. sso_password, sso_2fa_token and mfa_cookie are
        credentials. Consequence: replaces the controller's SSO session.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            sso_username: Optional SSO user, e.g. "admin@example.com".
            sso_password: Optional SSO password, e.g. "example-password".
            sso_2fa_token: Optional 2FA code, e.g. "123456".
            mfa_cookie: Optional MFA cookie from an earlier reply, e.g. "example-cookie".
            poll_login: Optional poll-login flag, e.g. true.
        """
        return await network_controller_admin.refresh_sso_session(
            *deps(), host, site, sso_username, sso_password, sso_2fa_token, mfa_cookie, poll_login
        )

    @mcp.tool(name="link_ubiquiti_sso_account", annotations=WRITE)
    async def link_ubiquiti_sso_account_tool(
        host: str,
        site: str,
        command: str,
        ubic_username: str | None = None,
        x_ubic_password: str | None = None,
        ubic_2fa_token: str | None = None,
        mfa_cookie: str | None = None,
        poll_login: bool | None = None,
    ) -> Any:
        """Link the signed-in admin to a Ubiquiti SSO account (Classic self/ubic_sso).

        Required arguments: host, site, command.

        POST /proxy/network/api/s/{site}/self/ubic_sso {"cmd": command, and the keys
        given}. The 11.0.81 front end chooses the command name at runtime, so command is
        sent as given. x_ubic_password, ubic_2fa_token and mfa_cookie are credentials.
        Consequence: changes how this admin signs in.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            command: Command name the SSO form sends (lower-case), e.g. "link".
            ubic_username: Optional Ubiquiti account user, e.g. "admin@example.com".
            x_ubic_password: Optional account password, e.g. "example-password".
            ubic_2fa_token: Optional 2FA code, e.g. "123456".
            mfa_cookie: Optional MFA cookie from an earlier reply, e.g. "example-cookie".
            poll_login: Optional poll-login flag, e.g. true.
        """
        return await network_controller_admin.link_ubiquiti_sso_account(
            *deps(),
            host,
            site,
            command,
            ubic_username,
            x_ubic_password,
            ubic_2fa_token,
            mfa_cookie,
            poll_login,
        )

    @mcp.tool(name="update_my_admin_profile", annotations=WRITE)
    async def update_my_admin_profile_tool(host: str, profile: dict[str, Any]) -> Any:
        """Update the calling admin's own profile (Classic PUT api/self).

        Required arguments: host, profile.

        Reads GET /proxy/network/api/self, merges only the given leaves into the named
        top-level keys (the front end sends ui_settings), PUTs those keys and reads back.
        Returns the upstream PUT body verbatim plus _verified (true only when every
        requested leaf reads back equal, type-strict) and _readAfterError when the
        read-back failed; a non-object body is returned whole under response with those
        keys beside it. An object with nothing to change fails before any request.
        Consequence: changes this admin's own settings.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            profile: Leaves to change, e.g. {"ui_settings": {"preferences": {"theme": "dark"}}}.
                Free-form object.
        """
        return await network_controller_admin.update_my_admin_profile(*deps(), host, profile)

    @mcp.tool(name="resend_mfa_code", annotations=WRITE)
    async def resend_mfa_code_tool(
        host: str, mfa_type: str, mfa_id: str, body: dict[str, Any] | None = None
    ) -> Any:
        """Resend an MFA code for an SSO sign-in (Network v2 route).

        Required arguments: host, mfa_type, mfa_id.

        POST /proxy/network/v2/api/mfa/{mfa_type}/{mfa_id}/send {"cmd": "resend-mfa-code",
        **body}; the 11.0.81 front end builds the two path segments and the rest of the
        body from the MFA challenge of a refresh_sso_session reply. Returns the upstream
        body verbatim. Consequence: a new code is sent to the account.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            mfa_type: First path segment, the challenge's MFA type, e.g. "email".
            mfa_id: Second path segment, the challenge's MFA id, e.g. "example-mfa-id".
            body: Optional free-form extra body keys (never "cmd"), e.g.
                {"mfa_cookie": "example-cookie"}.
        """
        return await network_controller_admin.resend_mfa_code(*deps(), host, mfa_type, mfa_id, body)

    @mcp.tool(name="set_controller_system_parameter", annotations=WRITE)
    async def set_controller_system_parameter_tool(
        host: str, site: str, key: str, value: ParamValue
    ) -> Any:
        """Set one controller system parameter (Classic cmd/system set-param).

        Required arguments: host, site, key, value.

        POST /proxy/network/api/s/{site}/cmd/system {"cmd": "set-param", "key", "value"},
        both sent as given. Consequence: changes controller-wide behaviour.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            key: Parameter name, e.g. "debug.mgmt".
            value: Parameter value, e.g. "warn".
        """
        return await network_controller_admin.set_controller_system_parameter(
            *deps(), host, site, key, value
        )

    @mcp.tool(name="generate_support_file", annotations=WRITE)
    async def generate_support_file_tool(
        host: str, site: str, mac: str, body: dict[str, Any] | None = None
    ) -> Any:
        """Start generating a device support file (Network v2 route).

        Required arguments: host, site, mac.

        The MAC is checked against GET .../stat/device-basic first (an unknown MAC fails
        listing the site's device MACs), then POST
        /proxy/network/v2/api/site/{site}/support/{mac}/generation with body as given (the
        front end builds it at runtime; free-form). Returns the upstream body verbatim.
        Poll get_support_file, then fetch it with download=true. Consequence: the device
        collects diagnostics.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            mac: Device MAC, e.g. "02:00:5e:00:00:a1".
            body: Optional free-form body, e.g. {}.
        """
        return await network_controller_admin.generate_support_file(*deps(), host, site, mac, body)

    @mcp.tool(name="get_support_file", annotations=READ_ONLY)
    async def get_support_file_tool(host: str, site: str, mac: str, download: bool = False) -> Any:
        """Get a device support file's status, or download it (Network v2 route).

        Required arguments: host, site, mac.

        GET /proxy/network/v2/api/site/{site}/support/{mac}: Returns the upstream status
        body verbatim, an object or an array as sent (an unknown MAC is the upstream's own
        error). With download=true,
        GET .../support/{mac}/download: Returns content_base64 (the file), contentType
        (the upstream Content-Type) and sizeBytes.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            mac: Device MAC, e.g. "02:00:5e:00:00:a1".
            download: Download the file instead of the status, e.g. true.
        """
        return await network_controller_admin.get_support_file(*deps(), host, site, mac, download)

    @mcp.tool(name="check_controller_firmware_update", annotations=WRITE)
    async def check_controller_firmware_update_tool(host: str, site: str) -> Any:
        """Ask the controller to check for a Network application update (Classic).

        Required arguments: host, site.

        POST /proxy/network/api/s/{site}/cmd/productinfo {"cmd": "check-firmware-update"}.
        This POST is not on the read-POST allowlist, so it is classified as a write.
        Consequence: refreshes the controller's update state; installs nothing.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await network_controller_admin.check_controller_firmware_update(*deps(), host, site)

    @mcp.tool(name="manage_firmware_cache", annotations=WRITE)
    async def manage_firmware_cache_tool(
        host: str,
        site: str,
        action: Literal["download", "remove"],
        device: str,
        version: str,
    ) -> Any:
        """Download or remove a cached device firmware (Classic cmd/firmware).

        Required arguments: host, site, action, device, version.

        POST /proxy/network/api/s/{site}/cmd/firmware {"cmd": action, "device",
        "version"}, both sent as given. Consequence: changes the controller's firmware
        cache; no device is upgraded.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: Command to send, e.g. "download".
            device: Device model the firmware is for, e.g. "U7PG2".
            version: Firmware version, e.g. "6.6.77.15402".
        """
        return await network_controller_admin.manage_firmware_cache(
            *deps(), host, site, action, device, version
        )

    @mcp.tool(name="get_latest_firmware_versions", annotations=READ_ONLY)
    async def get_latest_firmware_versions_tool(
        host: str, site: str, filter: str | None = None, time: str | None = None
    ) -> Any:
        """Report the devices' current firmware and update availability (official APIs).

        Required arguments: host, site.

        Returns the site's drained Integration device list verbatim (data[].firmwareVersion,
        data[].firmwareUpdatable, totalCount) plus _siteManagerDevices: Site Manager GET
        /v1/devices for this console, verbatim (data[].devices[].version, firmwareStatus,
        updateAvailable). incomplete=true with incompleteReason when either drain stopped
        short.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            filter: Optional Integration device filter, sent as given, e.g.
                "firmwareUpdatable.eq(true)". Example: `name.eq('Office Switch')`.
            time: Optional Site Manager last-processed RFC3339 time, e.g.
                "2026-10-01T00:00:00Z".
        """
        return await network_controller_admin.get_latest_firmware_versions(
            *deps(), host, site, filter, time
        )


def register_7(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
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
        return await network_routing_topology.get_bgp_status(client, registry, host, site, view)

    @mcp.tool(name="create_bgp_config", annotations=WRITE)
    async def create_bgp_config_tool(host: str, site: str, config: dict[str, Any]) -> Any:
        """Create a BGP configuration (Network v2 route). Consequence: changes routing.

        POST /proxy/network/v2/api/site/{site}/bgp/config with config sent verbatim. Returns
        the upstream body verbatim. The body shape is not published: send the
        object get_bgp_status (view "config") returns for an existing configuration.
        Never auto-retried; on a timeout, read get_bgp_status before retrying.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
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
        return await network_routing_topology.create_bgp_config(
            client, registry, host, site, config
        )

    @mcp.tool(name="update_bgp_config", annotations=WRITE)
    async def update_bgp_config_tool(
        host: str, site: str, config_id: str, config: dict[str, Any]
    ) -> Any:
        """Update a BGP configuration (Network v2 route). Consequence: changes routing.

        Reads the configuration from GET .../bgp/config/all, merges only the given leaves into it and POSTs the whole merged record to /proxy/network/v2/api/site/{site}/bgp/config for the gateway singleton, or /bgp/config/{id} for another listed configuration, then reads it back. Returns the upstream object verbatim plus _verified (true only when every requested leaf reads back equal, type-strict) and _readAfterError when the read-back failed; a non-object body (array or scalar) is returned whole under response with those keys beside it. The id, _id and site_id in the object are ignored; an object with nothing else to change fails before any request. An unknown id fails listing every valid id. Never auto-retried.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview: status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, config_id, config.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            config_id: Configuration _id or id from get_bgp_status, e.g.
                "000000000000000000000107".
            config: Free-form object of leaves to change, e.g. {"enabled": true}.
        """
        client, registry = deps_fn()
        return await network_routing_topology.update_bgp_config(
            client, registry, host, site, config_id, config
        )

    @mcp.tool(name="delete_bgp_config", annotations=WRITE)
    async def delete_bgp_config_tool(host: str, site: str, config_id: str) -> Any:
        """Delete a BGP configuration (Network v2 route). Consequence: BGP sessions drop.

        Resolves the id in GET .../bgp/config/all first (an unknown id fails listing every valid id), then DELETE /proxy/network/v2/api/site/{site}/bgp/config for the gateway singleton, or /bgp/config/{id} for another listed configuration, and verify it is absent. Returns {deleted, message, response}: deleted is true only when absence is confirmed, response is the upstream body verbatim. Irreversible: the configuration is removed.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run", deleted: false, message, response}, where response is the dry-run preview (status, dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, config_id.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            config_id: Configuration _id or id from get_bgp_status, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_routing_topology.delete_bgp_config(
            client, registry, host, site, config_id
        )

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
        return await network_routing_topology.get_ospf_status(client, registry, host, site, view)

    @mcp.tool(name="create_ospf_router", annotations=WRITE)
    async def create_ospf_router_tool(host: str, site: str, router: dict[str, Any]) -> Any:
        """Create an OSPF router (Network v2 route). Consequence: changes routing.

        POST /proxy/network/v2/api/site/{site}/ospf/router with router sent verbatim. Returns
        the upstream body verbatim. The body shape is not published: send the
        object get_ospf_status (view "config") returns for an existing router. Never
        auto-retried; on a timeout, read get_ospf_status before retrying.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
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
        return await network_routing_topology.create_ospf_router(
            client, registry, host, site, router
        )

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

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, router_id, router.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            router_id: Router _id or id from get_ospf_status, e.g.
                "000000000000000000000107".
            router: Free-form object of leaves to change, e.g. {"enabled": true}.
        """
        client, registry = deps_fn()
        return await network_routing_topology.update_ospf_router(
            client, registry, host, site, router_id, router
        )

    @mcp.tool(name="delete_ospf_router", annotations=WRITE)
    async def delete_ospf_router_tool(host: str, site: str, router_id: str) -> Any:
        """Delete an OSPF router (Network v2 route). Consequence: OSPF adjacencies drop.

        Resolves the id in GET .../ospf/router first (an unknown id fails listing every valid id),
        then DELETE /proxy/network/v2/api/site/{site}/ospf/router/{id}.
        Returns {deleted, message, response}: deleted is true only when absence is confirmed;
        message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty). Irreversible: the router is removed.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body).

        Required arguments: host, site, router_id.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            router_id: Router _id or id from get_ospf_status, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_routing_topology.delete_ospf_router(
            client, registry, host, site, router_id
        )

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
        return await network_routing_topology.get_global_network_config(
            client, registry, host, site
        )

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

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
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
        return await network_routing_topology.update_global_network_config(
            client, registry, host, site, config
        )

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
        return await network_routing_topology.get_mdns_settings(client, registry, host, site)

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

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, network_id, request.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            network_id: Network Integration id or Classic _id from list_networks, e.g.
                "000000000000000000000107".
            request: Free-form migration body, sent verbatim, e.g.
                {"gateway_device": "02:00:5e:00:00:a1", "name": "Office L3"}.
        """
        client, registry = deps_fn()
        return await network_routing_topology.migrate_network_to_layer3(
            client, registry, host, site, network_id, request
        )

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
        return await network_routing_topology.suggest_network_settings(client, registry, host, site)

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
        (UNIFI_WRITE_POLICY=deny refuses it).

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
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
        return await network_routing_topology.generate_vlan_plan(
            client, registry, host, site, request
        )

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

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
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
        return await network_routing_topology.import_dhcp_reservations(
            client, registry, host, site, reservations
        )

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

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, target, object_id.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            target: "network" or "settings", e.g. "network".
            object_id: Network id (target network) or orchestration id (target
                settings), e.g. "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_routing_topology.detach_from_orchestration(
            client, registry, host, site, target, object_id
        )

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

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
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
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_routing_topology.manage_virtual_network(
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
        return await network_routing_topology.get_loop_detection_status(
            client, registry, host, site
        )

    @mcp.tool(name="recover_loop_blocked_ports", annotations=WRITE)
    async def recover_loop_blocked_ports_tool(host: str, site: str) -> Any:
        """Re-enable every port loop protection blocked on a site (Network v2 route).

        Consequence: physical ports come back up; if the loop is still cabled, it can
        return and disrupt the network. POST
        /proxy/network/v2/api/site/{site}/loop-detection/recover-all-ports with no body;
        Returns the upstream body (JSON object or array) verbatim. Never auto-retried. Read
        get_loop_detection_status first.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_routing_topology.recover_loop_blocked_ports(
            client, registry, host, site
        )

    @mcp.tool(name="manage_mclag_group", annotations=WRITE)
    async def manage_mclag_group_tool(
        host: str,
        site: str,
        action: Literal["create", "update", "delete"],
        group_id: str | None = None,
        group: dict[str, Any] | None = None,
    ) -> Any:
        """Create, update or delete an MC-LAG switch group (Network v2 route). Consequence: changes switch link aggregation; links can drop. Never auto-retried.

        action "create": POST /proxy/network/v2/api/site/{site}/mclag-groups with group verbatim. "update": reads GET .../mclag-groups, merges only the given leaves, PUT .../mclag-groups/{id} and reads it back. "delete": DELETE .../mclag-groups/{id} (irreversible). Update and delete resolve group_id in the list first (an unknown id fails listing every valid id). group is required for create/update and omitted for delete; group_id is required for update/delete and omitted for create.

        Returns the upstream body verbatim for create and update; update adds _verified (type-strict per requested leaf) and _readAfterError, and a non-object body is kept under response. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. Under dry-run policy nothing is sent: the dry-run preview (for delete, the response of {status: "dry_run", deleted: false, message, response}).

        Required arguments: host, site, action.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: "create", "update" or "delete", e.g. "update".
            group_id: Group _id or id, e.g. "000000000000000000000107".
            group: Free-form group object (create) or leaves to change (update), e.g.
                {"name": "core-pair"}.
        """
        client, registry = deps_fn()
        return await network_routing_topology.manage_mclag_group(
            client, registry, host, site, action, group_id, group
        )

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

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, sent: false, message and preview (method, path, params, body).

        Required arguments: host, site, stack_id, stack.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            stack_id: Stack _id or id from GET .../stacking, e.g.
                "000000000000000000000107".
            stack: Free-form object of leaves to change, e.g. {"unit_order": ["02:00:5e:00:00:a1",
                "02:00:5e:00:00:a2"]}.
        """
        client, registry = deps_fn()
        return await network_routing_topology.update_switch_stack(
            client, registry, host, site, stack_id, stack
        )


def register_8(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
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
        return await matter._list_thread_networks(client, registry, host, site)

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
        return await matter._list_matter_nodes(client, registry, host, site)

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
        return await matter._commission_matter_node(client, registry, host, site, setup_code)

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
        return await matter._rename_matter_node(client, registry, host, site, node_id, name)

    @mcp.tool(annotations=WRITE)
    async def remove_matter_node(host: str, site: str, node_id: str, confirm: bool = False) -> Any:
        """Remove a commissioned Matter node through the cloud connector.

        Consequence: the node leaves this console's Matter fabric and can no longer be
        controlled here; it must be commissioned again (in pairing mode) to return.

        Sends DELETE matter/nodes/{node_id}. Discover ids with list_matter_nodes.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. With dry-run policy, returns {status: "dry_run", deleted: false, message, response},
        where response is the dry-run preview {status, dryRun, sent: false, message, preview:
        {method, path, params, body}}, without sending a write.

        Args:
            host: Console name or composite id from list_hosts; for example "Gateway".
            site: Network site name, id or slug from list_local_sites; for example "default".
            node_id: Native Matter node id from list_matter_nodes; for example "999999999999999999".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await matter._remove_matter_node(client, registry, host, site, node_id)


def register_9(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_dns_policies(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all DNS policies for a site.

        Returns {data, totalCount}: every page is drained; data holds the DNS policy records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        DNS policies are offset-paginated (native default page size 25); by default every
        page is drained and the complete list is returned as {data, totalCount}. Pass
        offset alone for a single manual page. A capped drain is flagged incomplete.

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
                `domain.like('*example*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `type.eq('A_RECORD')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_dns_policies(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_dns_policy(
        host: str,
        site: str,
        policy: dict[str, Any],
    ) -> Any:
        """Create a new DNS policy on a site.

        Returns the upstream response body verbatim: the created DNS policy object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it): ``type`` — the discriminator the controller validates first (verified live: an empty body is rejected with ``Missing $.type value``). The remaining fields are type-specific and enforced by the controller.

        Example call (create_dns_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy": {
                "type": "AAAA_RECORD",
                "domain": "example.com",
                "enabled": true,
                "ipv6Address": "cafe::babe",
                "ttlSeconds": 14400
              }
            }

        Details: docs/TOOL-USAGE.md#create_dns_policy.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy: Full object to create; spec Create or update DNS policy. Required: enabled, type.
                'type' selects variant:
                AAAA_RECORD|A_RECORD|CNAME_RECORD|FORWARD_DOMAIN|MX_RECORD|SRV_RECORD|TXT_RECORD.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_dns_policy(client, registry, host, site, policy)

    @mcp.tool(annotations=READ_ONLY)
    async def get_dns_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> Any:
        """Get a single DNS policy by ID.

        Returns: the DNS policy object, verbatim. To change it, edit it and pass it as `policy` to
        update_dns_policy.

        Example call (get_dns_policy):
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
            policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
                not a Protect id.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_dns_policy(client, registry, host, site, policy_id)

    @mcp.tool(annotations=WRITE)
    async def update_dns_policy(
        host: str,
        site: str,
        policy_id: str,
        policy: dict[str, Any],
    ) -> Any:
        """Update a DNS policy by ID.

        Returns the upstream response body verbatim: the updated DNS policy object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Example call (update_dns_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "policy": {
                "type": "AAAA_RECORD",
                "domain": "example.com",
                "enabled": true,
                "ipv6Address": "cafe::babe",
                "ttlSeconds": 14400
              }
            }

        Details: docs/TOOL-USAGE.md#update_dns_policy.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
                not a Protect id.
            policy: FULL replacement object (PUT; omitted fields reset); spec Create or update DNS
                policy. Required: enabled, type.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_dns_policy(
            client, registry, host, site, policy_id, policy
        )

    @mcp.tool(annotations=WRITE)
    async def delete_dns_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> dict[str, Any]:
        """Delete a DNS policy.

        Consequence: the record or forwarding rule stops being served immediately; there is no undo.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_dns_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
                not a Protect id.
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_dns_policy(
            client, registry, host, site, policy_id
        )
        return deletion_result(f"DNS policy {policy_id} deleted.", response)

    # --- Traffic Matching List Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_traffic_matching_lists(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all traffic matching lists for a site.

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
                Example: `name.eq('Business Apps')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_traffic_matching_lists(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_traffic_matching_list(
        host: str,
        site: str,
        traffic_list: dict[str, Any],
    ) -> Any:
        """Create a new traffic matching list on a site.

        Returns the upstream response body verbatim: the created traffic matching list object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it): a top-level ``type`` — the discriminator the controller validates first (verified live: an empty body is rejected with ``Missing $.type value``; observed value: 'PORTS').

        Example call (create_traffic_matching_list):
            {
              "host": "my-console",
              "site": "Default",
              "traffic_list": {
                "type": "IPV4_ADDRESSES",
                "items": [{"type": "IP_ADDRESS", "value": "192.0.2.5"}],
                "name": "Allowed address list"
              }
            }

        Details: docs/TOOL-USAGE.md#create_traffic_matching_list.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            traffic_list: Full object to create; spec Create or update traffic matching list. Required:
                name, type. 'type' selects variant: IPV4_ADDRESSES|IPV6_ADDRESSES|PORTS.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_traffic_matching_list(
            client, registry, host, site, traffic_list
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_traffic_matching_list(
        host: str,
        site: str,
        list_id: str,
    ) -> Any:
        """Get a single traffic matching list by ID.

        Returns: the traffic matching list object, verbatim. To change it, edit it and pass it as
        `traffic_list` to update_traffic_matching_list.

        Example call (get_traffic_matching_list):
            {"host": "my-console", "site": "Default", "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
                Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_traffic_matching_list(
            client, registry, host, site, list_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_traffic_matching_list(
        host: str,
        site: str,
        list_id: str,
        traffic_list: dict[str, Any],
    ) -> Any:
        """Update a traffic matching list by ID.

        Returns the upstream response body verbatim: the updated traffic matching list object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Example call (update_traffic_matching_list):
            {
              "host": "my-console",
              "site": "Default",
              "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "traffic_list": {
                "type": "IPV4_ADDRESSES",
                "items": [{"type": "IP_ADDRESS", "value": "192.0.2.5"}],
                "name": "Allowed address list"
              }
            }

        Details: docs/TOOL-USAGE.md#update_traffic_matching_list.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
                Network-app UUID — not a Protect id.
            traffic_list: FULL replacement object (PUT; omitted fields reset); spec Create or update
                traffic matching list. Required: name, type. 'type' selects variant:
                IPV4_ADDRESSES|IPV6_ADDRESSES|PORTS.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_traffic_matching_list(
            client, registry, host, site, list_id, traffic_list
        )

    @mcp.tool(annotations=WRITE)
    async def delete_traffic_matching_list(
        host: str,
        site: str,
        list_id: str,
    ) -> dict[str, Any]:
        """Delete a traffic matching list.

        Consequence: the list is permanently removed; there is no undo.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_traffic_matching_list):
            {"host": "my-console", "site": "Default", "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
                Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_traffic_matching_list(
            client, registry, host, site, list_id
        )
        return deletion_result(f"Traffic matching list {list_id} deleted.", response)

    # --- VPN Server Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_vpn_servers(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List VPN servers for a site.

        Returns {data, totalCount}: every page is drained; data holds the VPN server records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        VPN servers are offset-paginated (native default page size 25); by default every
        page is drained and the complete list is returned as {data, totalCount}. Pass
        offset alone for a single manual page. A capped drain is flagged incomplete.

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
        return await network_services_proxy.list_vpn_servers(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_site_to_site_tunnels(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List site-to-site VPN tunnels for a site.

        Returns: {data: [tunnel…], totalCount} with every page drained, entries verbatim (pass
        offset alone to fetch a single manual page, native envelope preserved). To change one,
        pass the native Classic networkconf fields to change (e.g. enabled, name) as `tunnel` to
        update_site_to_site_tunnel (tunnel_id = its data[] id).

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
        return await network_services_proxy.list_site_to_site_tunnels(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    # --- RADIUS Profile Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_radius_profiles(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List RADIUS profiles for a site.

        Returns {data, totalCount}: every page is drained; data holds the RADIUS profile records
        verbatim and totalCount is the upstream total (null when none was reported). The first page's
        other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short.

        RADIUS profiles are offset-paginated (native default page size 25); by default
        every page is drained and the complete list is returned as {data, totalCount}.
        Pass offset alone for a single manual page. A capped drain is flagged incomplete.

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
        return await network_services_proxy.list_radius_profiles(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    # --- Hotspot Voucher Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_hotspot_vouchers(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all hotspot/guest vouchers for a site (there is no `list_vouchers` — this is it).

        Returns {data, totalCount}: every page is drained; data holds the voucher records verbatim and totalCount is the upstream total (null when none was reported). The first page's other envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped drain stopped short.

        This is the voucher-listing tool; the family is `list_hotspot_vouchers`, `create_hotspot_vouchers`, `get_hotspot_voucher`, `delete_hotspot_voucher` — all prefixed `hotspot_`. There is no shorter `list_vouchers`/`get_voucher` alias.

        Vouchers are offset-paginated (native page size 100) and batches routinely exceed that; by default every page is drained and all records are returned as {data, totalCount}. Pass offset alone for a single manual page. A capped drain is flagged incomplete.

        limit requests a total, gathered automatically in batches up to 1000; _pageSize reports requested count, actual sent sizes per request, observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 1000; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 1000, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `name.eq('Conference')`.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_hotspot_vouchers(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_hotspot_vouchers(
        host: str,
        site: str,
        voucher_config: dict[str, Any],
    ) -> Any:
        """Generate hotspot vouchers for a site.

        Returns the upstream response body verbatim: the voucher-creation object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        `voucher_config`: required fields (validated locally — a missing field raises ValueError naming it — and verified against the live controller): ``name`` and ``timeLimitMinutes`` (voucher validity window, minutes). Optional: count, quota, bandwidth limits, etc.

        Example call (create_hotspot_vouchers):
            {"host": "my-console", "site": "Default",
             "voucher_config": {"name": "Conference", "timeLimitMinutes": 1440}}

        Details: docs/TOOL-USAGE.md#create_hotspot_vouchers.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            voucher_config: Full object to create; spec Hotspot voucher creation request. Required:
                name, timeLimitMinutes.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_hotspot_vouchers(
            client, registry, host, site, voucher_config
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_hotspot_voucher(
        host: str,
        site: str,
        voucher_id: str,
    ) -> Any:
        """Get a single hotspot voucher by ID.

        Returns the upstream voucher object verbatim, exactly as the API answers it.

        Example call (get_hotspot_voucher):
            {
              "host": "my-console",
              "site": "Default",
              "voucher_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            voucher_id: Hotspot voucher UUID. Get it from list_hotspot_vouchers (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_hotspot_voucher(
            client, registry, host, site, voucher_id
        )

    @mcp.tool(annotations=WRITE)
    async def delete_hotspot_voucher(
        host: str,
        site: str,
        voucher_id: str,
    ) -> dict[str, Any]:
        """Delete a single hotspot voucher.

        Consequence: the voucher can no longer be redeemed; there is no undo.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_hotspot_voucher):
            {
              "host": "my-console",
              "site": "Default",
              "voucher_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            voucher_id: Hotspot voucher UUID. Get it from list_hotspot_vouchers (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_hotspot_voucher(
            client, registry, host, site, voucher_id
        )
        return deletion_result(f"Hotspot voucher {voucher_id} deleted.", response)

    @mcp.tool(annotations=WRITE)
    async def bulk_delete_hotspot_vouchers(
        host: str,
        site: str,
        filter_params: dict[str, Any],
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Bulk delete hotspot vouchers matching filter criteria.

        Consequence: every voucher matching the filter is permanently removed and can no longer be
        redeemed; there is no undo.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim.
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (bulk_delete_hotspot_vouchers):
            {
              "host": "my-console",
              "site": "Default",
              "filter_params": {"filter": "name.eq('Conference')"}
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            filter_params: Query parameters sent with the DELETE; must contain `filter`, which selects
                the vouchers to delete (Network 11.0.97 DELETE /v1/sites/{siteId}/hotspot/vouchers),
                e.g. {"filter": "name.eq('Conference')"}. Filter syntax as list_hotspot_vouchers.
                Free-form JSON object; no fixed body shape is published.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is
                sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        response = await network_services_proxy.bulk_delete_hotspot_vouchers(
            client, registry, host, site, filter_params
        )
        return deletion_result("Hotspot vouchers deleted.", response)

    # --- Supporting Resources Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_device_tags(
        host: str,
        site: str,
    ) -> Any:
        """List all device tags defined in a site (the tags the Network UI shows).

        Reads the v2 route the controller's own UI uses, GET
        /proxy/network/v2/api/site/{site}/device-tags; the published Integration device-tag list
        is a separate collection that answers empty on Network 11.0.81 while the UI has tags.

        Returns: the v2 API's bare JSON array of tags, verbatim, the whole list in one response
        (each entry {_id, name, member_device_macs, ...}). To change one, pass it as `tag` to
        update_device_tag (tag_id = its _id): either the entry itself, edited (rename it, or set
        member_device_macs to the desired members; the tool sends the additions and removals
        and drops _id), or a native v2 update body {name, device_mac_additions,
        device_mac_removals}.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_device_tags(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_countries(
        host: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all countries with ISO codes available on a console.

        Returns {data, totalCount} with every page drained (about 250 entries; the API pages at
        25 by default). Pass offset alone to fetch a single manual page (native envelope
        preserved).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
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
                Example: `code.eq('US')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_countries(
            client, registry, host, offset=offset, limit=limit, filter=filter
        )

    return {
        "list_dns_policies": list_dns_policies,
        "create_dns_policy": create_dns_policy,
        "get_dns_policy": get_dns_policy,
        "update_dns_policy": update_dns_policy,
        "delete_dns_policy": delete_dns_policy,
        "list_traffic_matching_lists": list_traffic_matching_lists,
        "create_traffic_matching_list": create_traffic_matching_list,
        "get_traffic_matching_list": get_traffic_matching_list,
        "update_traffic_matching_list": update_traffic_matching_list,
        "delete_traffic_matching_list": delete_traffic_matching_list,
        "list_vpn_servers": list_vpn_servers,
        "list_site_to_site_tunnels": list_site_to_site_tunnels,
        "list_radius_profiles": list_radius_profiles,
        "list_hotspot_vouchers": list_hotspot_vouchers,
        "create_hotspot_vouchers": create_hotspot_vouchers,
        "get_hotspot_voucher": get_hotspot_voucher,
        "delete_hotspot_voucher": delete_hotspot_voucher,
        "bulk_delete_hotspot_vouchers": bulk_delete_hotspot_vouchers,
        "list_device_tags": list_device_tags,
        "list_countries": list_countries,
    }


def register_10(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_port_forwards(
        host: str,
        site: str,
    ) -> Any:
        """List all port forwarding rules for a site.

        Returns: the controller envelope {meta, data: [rule…]}, entries verbatim. To change one, edit
        its data[] entry and pass it as `payload` to update_port_forward (forward_id = its _id).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_port_forwards(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_port_forward(
        host: str,
        site: str,
        payload: dict[str, Any],
    ) -> Any:
        """Create a port forwarding rule via the Classic REST API. Returns the controller's envelope {meta: {rc}, data: [...]} verbatim (meta relayed, never interpreted). Under dry-run policy nothing is sent: the bare preview.

        `payload`: pass name, dst_port, fwd and fwd_port; proto is optional (the controller defaults it, typically 'tcp_udp'). Sent as given: this endpoint has no published schema and is observed to accept a body without those fields and create a broken rule, so include them; an upstream error gets a hint naming any missing. Read the current object first for edits.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_port_forward):
            {
              "host": "my-console",
              "site": "Default",
              "payload": {
                "enabled": true,
                "name": "SSH",
                "pfwd_interface": "wan",
                "src": "any",
                "dst_port": "2222",
                "fwd": "192.0.2.10",
                "fwd_port": "22",
                "proto": "tcp",
                "log": false
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            payload: spec: free-form (classic REST portforward), sent as given. Pass name,
                dst_port, fwd (target IP), fwd_port; proto optional (tcp|udp|tcp_udp).
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_port_forward(
            client, registry, host, site, payload
        )

    @mcp.tool(annotations=WRITE)
    async def update_port_forward(
        host: str,
        site: str,
        forward_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a port forwarding rule by ID.

        The id is resolved in list_port_forwards first: an unknown id fails listing every valid _id, and
        nothing is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/portforward/{id}
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (update_port_forward):
            {
              "host": "my-console",
              "site": "Default",
              "forward_id": "000000000000000000000107",
              "payload": {"enabled": false}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            forward_id: Port-forward rule _id (classic REST portforward). Get it from list_port_forwards
                (_id).
            payload: spec: free-form (classic REST portforward). Fields to change (snake_case, e.g.
                dst_port, fwd, fwd_port, enabled). Read current via list_port_forwards.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_port_forward(
            client, registry, host, site, forward_id, payload
        )

    @mcp.tool(annotations=WRITE)
    async def delete_port_forward(
        host: str,
        site: str,
        forward_id: str,
    ) -> dict[str, Any]:
        """Delete a port forwarding rule by ID.

        Consequence: inbound connections on the forwarded port stop reaching the internal host; there is no undo.

        The id is resolved in list_port_forwards first (the controller answers a DELETE on an unknown id with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

        Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}.

        Example call (delete_port_forward):
            {"host": "my-console", "site": "Default", "forward_id": "000000000000000000000107"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            forward_id: Port-forward rule _id (classic REST portforward). Get it from list_port_forwards
                (_id).
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_port_forward(
            client, registry, host, site, forward_id
        )
        return deletion_result(f"Port forward {forward_id} deleted.", response)

    # --- Traffic Rule Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_traffic_rules(
        host: str,
        site: str,
    ) -> Any:
        """List traffic matching rules (QoS, application, IP group matching). Legacy.

        Legacy: reads traffic rules carried over from earlier Network versions on the v2
        trafficrules route. The Network 11.0.99 web app no longer shows them, and the console
        does not implement creating, changing or deleting them (HTTP 501
        api.err.NotImplemented). For new rules use create_firewall_policy, create_qos_rule or
        create_traffic_route. A console without the route answers with an upstream error,
        returned to the caller.

        Returns: the v2 API's bare JSON array of rules, verbatim (the same shape as
        list_traffic_routes).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_traffic_rules(client, registry, host, site)

    return {
        "list_port_forwards": list_port_forwards,
        "create_port_forward": create_port_forward,
        "update_port_forward": update_port_forward,
        "delete_port_forward": delete_port_forward,
        "list_traffic_rules": list_traffic_rules,
    }


def register_11(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
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
        return await site_config._list_config_records(
            client, registry, host, site, site_config.USER_GROUPS
        )

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
        return await site_config._get_config_record(
            client, registry, host, site, site_config.USER_GROUPS, group_id, "group_id"
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
        return await site_config._create_config_record(
            client, registry, host, site, site_config.USER_GROUPS, group, hint
        )

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
            client, registry, host, site, site_config.USER_GROUPS, group_id, "group_id", group
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
            client, registry, host, site, site_config.USER_GROUPS, group_id, "group_id"
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
        return await site_config._set_client_user_group(api, registry, host, site, client, group)

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
        return await site_config._get_config_record(
            client, registry, host, site, site_config.STATIC_ROUTES, route_id, "route_id"
        )

    @mcp.tool(annotations=WRITE)
    async def create_static_route(host: str, site: str, route: dict[str, Any]) -> Any:
        """Create a static route via Classic REST POST rest/routing (the UI's route).

        The body is sent verbatim. A next-hop route: {name, enabled, type: "static-route", static-route_type: "nexthop-route", static-route_network: "198.51.100.0/24", static-route_nexthop: "10.0.0.2", static-route_distance: 1}; static-route_type may also be "interface-route" (with static-route_interface) or "blackhole".

        Returns: the upstream body verbatim, {meta: {rc}, data: [the created route with _id]}. Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

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
        return await site_config._create_config_record(
            client, registry, host, site, site_config.STATIC_ROUTES, route, hint
        )

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
            client, registry, host, site, site_config.STATIC_ROUTES, route_id, "route_id", route
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
            client, registry, host, site, site_config.STATIC_ROUTES, route_id, "route_id"
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

        Sends a one-element batch, [{...fields, name, x_password}], to /v2/api/site/{site}/radius/users/batch_add. For a VLAN assignment add vlan with tunnel_type 13 and tunnel_medium_type 6 in `fields`. Nothing is defaulted.

        Returns: the upstream body verbatim, a one-element JSON array [the created account {_id, name, x_password, group_policy, filter_ids, ...}]; its _id is the id list_accounts shows. Additive _warnings on that account (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_radius_account):
            {"host": "my-console", "site": "Default", "name": "alice", "password": "correct-horse",
             "fields": {"vlan": 20, "tunnel_type": 13, "tunnel_medium_type": 6}}

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
        return await site_config._create_batch_record(
            client, registry, host, site, site_config.RADIUS_ACCOUNTS, body, None
        )

    @mcp.tool(annotations=WRITE)
    async def update_radius_account(
        host: str, site: str, account_id: str, account: dict[str, Any]
    ) -> Any:
        """Update a local RADIUS user account via v2 POST radius/users/batch_update.

        Consequence: the stored account changes at once; a new x_password or vlan applies to the user's next 802.1X or VPN authentication.

        The id is resolved in the v2 account list (GET /v2/api/site/{site}/radius/users) first; an unknown id fails listing every account and no write is sent. The route replaces the whole account and refuses a partial one, so the stored account is sent with `account` laid over it, as a one-element batch [account]: send only the fields to change, e.g. x_password for a new password; every other field is kept as stored.

        Returns: the upstream body verbatim, a one-element JSON array [the updated account]. Additive _warnings on that account (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

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
        return await site_config._update_batch_record(
            client,
            registry,
            host,
            site,
            site_config.RADIUS_ACCOUNTS,
            account_id,
            "account_id",
            account,
        )

    @mcp.tool(annotations=WRITE)
    async def delete_radius_account(host: str, site: str, account_id: str) -> dict[str, Any]:
        """Delete a local RADIUS user account via v2 POST radius/users/batch_delete.

        Consequence: the user can no longer authenticate (802.1X / VPN) with these credentials; existing sessions end at their next re-authentication. There is no undo.

        The id is resolved in the v2 account list first, so an unknown id is never reported as deleted. The body sent is a one-element batch of ids, [_id].

        Returns {deleted: true, message, response}; response is the upstream body verbatim (null: the controller answers with no body). Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message, response (the dry-run preview {method, path, params, body})}.

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
        return await site_config._delete_batch_record(
            client, registry, host, site, site_config.RADIUS_ACCOUNTS, account_id, "account_id"
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
        return await site_config._list_config_records(
            client, registry, host, site, site_config.AP_GROUPS
        )

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
        return await site_config._get_ap_group(client, registry, host, site, group_id)

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
        return await site_config._create_config_record(
            client, registry, host, site, site_config.AP_GROUPS, group, hint
        )

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
            client,
            registry,
            host,
            site,
            site_config.AP_GROUPS,
            group_id,
            "group_id",
            group,
            merge=True,
        )

    @mcp.tool(annotations=WRITE)
    async def delete_ap_group(host: str, site: str, group_id: str) -> dict[str, Any]:
        """Delete an AP group via v2 DELETE /v2/api/site/{site}/apgroups/{_id}.

        Consequence: the group is gone; WiFi networks broadcast on that group stop using it (the controller refuses while one still does, and its error is returned). The APs themselves are not changed. There is no undo.

        The id (_id or external_id) is resolved in the collection first, so an unknown id is never reported as deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim (null for the HTTP 204 answer). Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message, response (the dry-run preview {method, path, params, body})}.

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
            client, registry, host, site, site_config.AP_GROUPS, group_id, "group_id"
        )

    # ------------------------------------------------------------------ port profiles

    @mcp.tool(annotations=WRITE)
    async def create_port_profile(host: str, site: str, profile: dict[str, Any]) -> Any:
        """Create a switch port profile via Classic POST rest/portconf (the UI's route). The body is sent verbatim (additive _ keys from a read are dropped): name, tagged_vlan_mgmt (auto, block_all, custom) with the matching forward (all, native, customize), native_networkconf_id, voice_networkconf_id, excluded_networkconf_ids, poe_mode and the other portconf fields list_port_profiles shows. Networkconf id fields accept a Classic _id or the Integration id from list_networks, converted before the POST; an unknown value fails listing every network, nothing sent.

        Returns {meta: {rc}, data: [the created profile]} verbatim (profile plus _resolved_networks). Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) flag a write that did not land as sent. Under dry-run policy nothing is sent: the bare preview.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

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
        return await site_config._create_port_profile(client, registry, host, site, profile)

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
            client, registry, host, site, site_config.PORT_PROFILES, profile_id, "profile_id"
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
        return await site_config._create_config_record(
            client, registry, host, site, site_config.DYNAMIC_DNS, ddns, hint
        )

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
            client, registry, host, site, site_config.DYNAMIC_DNS, ddns_id, "ddns_id"
        )


def register_12(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    def tool(fn: Callable[..., Any]) -> Any:
        # FastMCP exposes the prose before ``Args:`` as the tool description. Make
        # each required parameter visible there as well as in its detailed Args entry.
        # This keeps the catalog usable for clients that display only descriptions.
        required = [
            name
            for name, parameter in signature(fn).parameters.items()
            if parameter.default is Parameter.empty
        ]
        # Each tool states its own result in its docstring: no shared result line is added
        # here (one would contradict the tools that drain, wrap or add keys).
        doc = getdoc(fn)
        if required and doc:
            prose, marker, args = doc.partition("\n\nArgs:\n")
            required_line = f"Required inputs: {', '.join(required)}."
            fn.__doc__ = (
                f"{prose.rstrip()}\n\n{required_line}{marker}{args}"
                if marker
                else f"{doc.rstrip()}\n\n{required_line}"
            )
        # Derive hints from the complete implementation call graph at registration.
        writes = derive_write_tools([SimpleNamespace(name=fn.__name__, fn=fn)])
        return mcp.tool(annotations=for_tool(writes=fn.__name__ in writes))(fn)

    @tool
    async def get_network_config_defaults(
        host: str, kind: DefaultsKind, site: str | None = None
    ) -> Any:
        """Get the default object the Network app uses when it creates a configuration item.

        Shows the field values a new item starts with (for example a new LAN's DHCP
        settings or a new firewall policy's action). Returns the upstream body verbatim: an
        object, or an array for wlan, wifiai and firewall_zone. Kinds and routes (GET /v2/api/...):
        port_profile, wan, lan, wlan, firewall_policy, firewall_zone, connectivity, doh,
        element_adopt, global_switch, ips_advanced_filtering, netflow, ntp, usg (gateway
        timeouts), wifiai, ssl_inspection_profile, ssl_inspection_setting and
        system_log_setting are per site (site required); log_levels and super_mgmt
        (data retention) are console-wide (site not used).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            kind: Defaults kind from the list above; for example "lan".
            site: Network site name or id, required for per-site kinds; for example
                "Default".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_defaults(client, registry, host, kind, site)

    @tool
    async def get_controller_stats(
        host: str,
        view: StatsView = "recent_series",
        schema: str | None = None,
        period: str | None = None,
        start: int | None = None,
        end: int | None = None,
        bucket: str | None = None,
        filter: str | None = None,
        projection: list[str] | None = None,
        nested_projection: list[str] | None = None,
        no_gaps: bool | None = None,
    ) -> Any:
        """Query the controller's time-series statistics service, as the web app's graphs do. Returns the upstream body verbatim. View recent_series (GET /v2/api/stats/recent/series) answers an array of {siteId, deviceMac?, series: [...]}; it needs schema and exactly one of period or start (end optional), else the console may return 400. View series (GET /v2/api/stats/series) reads history over an explicit window: schema, bucket, start, end and filter (a missing one adds a hint to the console's error). View source answers the statistics backend ("MODERN" or "LEGACY"). start and end are sent exactly as given; negative or millisecond-like values add _warnings (an array result becomes {result, _warnings}). Only passed arguments are sent. filter uses the service's own grammar: a one-term and(...) is rejected (400 InvalidStatQuery); a single term without and(...) or and(...) with two or three terms works (Network 11.0.81).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            view: recent_series, series or source; for example "series".
            schema: Series schema, such as wanBySiteByDevice, wirelessBySiteByDevice,
                systemBySiteByDevice, clientCountBySite or portBySiteByDevice; for example
                "clientCountBySite".
            period: HOUR, DAY, WEEK or MONTH; for example "DAY".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            bucket: OF_5_MINUTES, OF_1_HOUR, OF_8_HOURS or OF_1_MONTH; for example
                "OF_5_MINUTES".
            filter: Filter expression sent as given; for example
                "deviceMac.eq('02:00:5e:00:53:01')".
            projection: Value fields, sent as values(...); for example ["rxBytes",
                "txBytes"].
                Shape: string[]
            nested_projection: Nested groupings, sent as nested(...); for example
                ["byNetworkGroup"].
                Shape: string[]
            no_gaps: Fill empty buckets, sent as noGaps; for example true.
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_stats(
            client,
            registry,
            host,
            view,
            schema=schema,
            period=period,
            start=start,
            end=end,
            bucket=bucket,
            filter=filter,
            projection=projection,
            nested_projection=nested_projection,
            no_gaps=no_gaps,
        )

    @tool
    async def get_sites_overview(
        host: str,
        search_text: str | None = None,
        sort_by_field: str | None = None,
        sort_direction: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
        confirm: bool = False,
    ) -> Any:
        """Get every Network site on one console with its device, client and health counts.

        Reads POST /v2/api/sites/overview (a read-only query sent as a POST, so read-only mode refuses it). Consequence: none intended; it changes nothing. Each site carries id, name, description, counts (total/offline/wifi/wired/gateway devices, wifi/wired/guest clients, pending updates, critical notifications, LAN/WAN/WiFi configurations) and percentages (wan_uptime, successful_association). Every page is drained by default. Returns the first page's envelope as the upstream sent it (for example total_page_count, total_element_count, page_number) with data holding the sites of every page, plus _count (sites) and _pages (pages read); _incomplete and _incompleteReason are added when the drain stopped short (a UNIFI_PAGINATE_MAX_PAGES cap, a page without the paged envelope, or a page answered under another number). A first page without a data array is returned as received. Pass page alone (0-based) for that one page verbatim. page_size alone is window 0: exactly page_size sites from the first; _nextPage counts page_size windows, so resume with page=_nextPage and the same page_size. page with page_size returns that window of sites. _pageSize reports the requested count, sent (every pageSize sent, in request order), the effective console page size and the returned count. _nextPage is absent when no site follows the window or the call stopped short (_incomplete). For counts across every console use list_sites. With dry-run policy, returns {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends nothing.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            search_text: Filter sites by text, sent as searchText; for example "branch".
            sort_by_field: Field to sort by, sent as sortByField; for example "name".
            sort_direction: ASCENDING or DESCENDING; for example "ASCENDING".
            page: Zero-based page. With page_size, returns exactly page_size records starting
                at record page * page_size, gathered across console pages whatever the console
                page size; resume with _nextPage and the same page_size. Without page_size, one
                request returns that console page verbatim. For example 0.
            page_size: Number of sites. Alone, window 0 (the first page_size sites); with
                page, the size of the window. Fewer if the collection ends. Omit to drain all.
                Example: 1000.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_overview(
            client,
            registry,
            host,
            search_text=search_text,
            sort_by_field=sort_by_field,
            sort_direction=sort_direction,
            page=page,
            page_size=page_size,
        )

    @tool
    async def get_network_ui_data(host: str) -> Any:
        """Get the Network app's UI bootstrap data (Classic GET /api/ui-data).

        Returns the Classic envelope {meta: {rc}, data: [...]} verbatim; data holds
        front-end service keys (map, payment and image providers) and LTE pricing.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_ui_data(client, registry, host)

    @tool
    async def get_sdn_status(host: str, site: str) -> Any:
        """Get the controller's UniFi cloud (SDN) connection status.

        Returns the Classic envelope verbatim; data[0] has enabled, connected,
        has_sso_auth, is_udm, is_cloud_key and ubic_env (Classic GET stat/sdn).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_sdn(client, registry, host, site)

    @tool
    async def list_installed_applications(host: str) -> Any:
        """List the UniFi OS applications the Network app sees as installed on the console.

        Returns the array verbatim, one {name} per application
        (GET /v2/api/system/installed-applications). For versions and run state see
        get_host (reportedState.controllers).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_apps(client, registry, host)

    @tool
    async def get_console_general_info(host: str) -> Any:
        """Get whether remote (cloud) access and cloud backup are enabled on the console.

        Returns {cloud_access_enabled, cloud_backup_enabled} verbatim (GET
        /v2/api/unifi-core/general-info). A body that is not a JSON object arrives as {result:
        ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_general_info(client, registry, host)

    @tool
    async def get_first_system_event(host: str, event_type: str) -> Any:
        """Get the first recorded system event of one type, such as when setup completed.

        Returns the upstream body of GET /v2/api/system/event/{event_type}/first verbatim; null when
        the console has none. A body that is not a JSON object arrives as {result: ...}. An
        unknown type answers HTTP 400.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            event_type: System event type; for example "SETUP_COMPLETED".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_first_event(
            client, registry, host, event_type
        )

    @tool
    async def list_timezones(host: str) -> Any:
        """List every timezone the controller accepts, with its UTC offset.

        Returns the array verbatim, one {timezone, offset} per zone
        (GET /v2/api/timezones). Use a timezone value in site and schedule settings.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_timezones(client, registry, host)

    @tool
    async def list_ups_devices(host: str) -> Any:
        """List the consoles that can pair with a UniFi UPS for safe shutdown, with state.

        Returns the array verbatim (GET /v2/api/ups/consoles): console_mac, name, model,
        state (paired, unpaired, upgrade_needed, token_invalid, offline), ups_mac (null
        when not paired), square_wave_incompatible and icon. Pair or unpair with
        set_ups_pairing.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_ups(client, registry, host)

    @tool
    async def set_ups_pairing(
        host: str,
        action: UpsAction,
        console_mac: str,
        ups_mac: str | None = None,
        username: str | None = None,
        password: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Pair a console with a UniFi UPS for safe shutdown, or unpair it.

        Consequence: pair links the console to the UPS so the UPS can signal it to shut down
        safely on power loss; unpair removes that link and with it the shutdown signal.

        Action pair sends {console_mac, username, password, ups_mac} to
        POST /v2/api/ups/pair: the console logs in to the UPS with the UI account given.
        action unpair sends {console_mac} to POST /v2/api/ups/unpair. Only the
        arguments you pass are sent; the console reports a missing one. Returns the
        upstream body verbatim, whatever its type: a 204 response does not prove an unpair;
        an unpair can answer a bare true, and a
        body that is not a JSON object arrives as {result: ...}. The
        password is a credential: UNIFI_REDACT_SECRETS masks it. With dry-run policy,
        returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}} and sends nothing.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            action: "pair" or "unpair"; for example "unpair".
            console_mac: console_mac from list_ups_devices; for example
                "02:00:5e:00:53:01".
            ups_mac: MAC of the UPS to pair with (pair); for example "02:00:5e:00:53:02".
            username: UI account username or email for the UPS (pair); for example
                "admin@example.com".
            password: UI account password for the UPS (pair); for example "example-pass".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_ups_pairing(
            client,
            registry,
            host,
            action,
            console_mac,
            ups_mac=ups_mac,
            username=username,
            password=password,
        )

    @tool
    async def list_vendor_ids(host: str, site: str) -> Any:
        """List the device vendor ids the controller's client fingerprinting knows.

        Returns the array of vendor id strings verbatim (GET /v2/api/site/{site}/vendor-ids).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_vendor_ids(client, registry, host, site)

    @tool
    async def list_device_models(host: str, site: str, model_id: str | None = None) -> Any:
        """List the UniFi device model catalogue, or get one model by id.

        Returns the upstream body verbatim (GET /v2/api/site/{site}/models[/{model_id}]): without
        model_id the catalogue object, whose model_list entries carry id, model_name,
        model_fullName, model_abbreviation, model_sysid, sku and image ids; with model_id that
        model's object. A body that is not a JSON object arrives as {result: ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            model_id: Model id from model_list[].id; for example "UDMPRO".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_models(
            client, registry, host, site, model_id
        )

    @tool
    async def get_device_fingerprint(host: str, source: int) -> Any:
        """Get the client fingerprint definitions (id to name maps) of one source.

        Returns the upstream body of GET /v2/api/fingerprint_devices/{source} verbatim.
        The web app reads
        sources 0 (custom: dev_ids, vendor_ids, os_name_ids, family_ids, dev_type_ids,
        os_class_ids, ctag_ids), 1 (built-in maps) and 2 (extended dev_ids, several MB);
        source -1 answers HTTP 404 on Network 11.0.81. Use it to name the dev_id and
        vendor ids that client records carry.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            source: Fingerprint source id; for example 1.
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_fingerprint(client, registry, host, source)

    @tool
    async def list_site_features(
        host: str,
        site: str,
        include_system_features: bool | None = None,
        feature: str | None = None,
    ) -> Any:
        """List the site's features with enabled state and limitations, or check one.

        Returns the upstream body verbatim. Without feature it is the array from GET
        .../described-features: name, enabled, feature_exists and limitations (device MACs
        and ports a feature cannot use); include_system_features true adds the system
        features, as the web app does. With feature it is the object from GET
        .../features/{feature}/exists, which carries feature_exists.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            include_system_features: Also list system features; for example true.
            feature: One feature name from the list; for example "ips".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_features(
            client,
            registry,
            host,
            site,
            include_system_features=include_system_features,
            feature=feature,
        )

    @tool
    async def get_site_dashboard(
        host: str,
        site: str,
        history_seconds: int | None = None,
        radio_activity_ap_mac: str | None = None,
    ) -> Any:
        """Get the site dashboard the Network web app opens with.

        Returns the upstream body of GET /v2/api/site/{site}/aggregated-dashboard verbatim. Without
        history_seconds it has internet, isp_metrics, wan_activity, radio_activity, wifi_channels,
        wifi_technology, most active APs and clients, traffic identification and upgradable devices.
        With history_seconds (as the web app sends) it also has gateway, system_status, speed_test,
        cybersecure, wifi_connectivity, wifi_activity, wan_history and degradation_status. A body
        that is not a JSON object arrives as {result: ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            history_seconds: History window in seconds, sent as historySeconds; for
                example 86400.
            radio_activity_ap_mac: Limit radio activity to one AP, sent as
                radio_activity.access_point_mac; for example "02:00:5e:00:53:01".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_dashboard(
            client,
            registry,
            host,
            site,
            history_seconds=history_seconds,
            radio_activity_ap_mac=radio_activity_ap_mac,
        )

    @tool
    async def list_site_warnings(host: str, site: str, source: WarningsSource = "all") -> Any:
        """List the site's warnings from both places the controller keeps them.

        Returns, for source network, the body of GET /v2/api/site/{site}/warnings verbatim:
        rogue_clients, rogue_dhcps, missing_windows_defender_firewall_rules. For source
        controller, the Classic GET stat/widget/warnings envelope verbatim: firmware update
        state, end-of-life, LTS and unsupported device counts, LTE subscription problems
        and controller_low_disk_space. For source all (default), {network, controller}
        holding those two bodies.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            source: all, network or controller; for example "all".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_warnings(
            client, registry, host, site, source
        )

    @tool
    async def get_cybersecure_summary(host: str, site: str, period: str) -> Any:
        """Get the CyberSecure (IPS/IDS) summary for one period.

        Returns the upstream body of GET /v2/api/site/{site}/cybersecure/summary?period=...
        verbatim: ips_enabled, has_subscription, enterprise, is_activating, signatures,
        signature_capacity, threats, scanned_bytes, updated_timestamp. A body that is not a JSON
        object arrives as {result: ...}. The console requires period.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            period: HOUR, DAY, WEEK or MONTH; for example "DAY".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_cybersecure(
            client, registry, host, site, period
        )

    @tool
    async def get_site_degradation_status(host: str, site: str) -> Any:
        """Get whether the Network application runs in degraded (safe) mode.

        Returns {safe_mode} verbatim (GET /v2/api/site/{site}/degradation-status). A body that is
        not a JSON object arrives as {result: ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_degradation(client, registry, host, site)

    @tool
    async def get_observability_site_health(
        host: str, site: str, start: int | None = None, end: int | None = None
    ) -> Any:
        """Get the site's WAN health and traffic history.

        Returns the upstream body of GET /v2/api/site/{site}/observability/sitehealth
        verbatim: wan_activity (total and per-WAN history of rx/tx rate, latency, packet
        loss and client count) and wan_history (per WAN uptime, ISP, health and downtime
        history). Without start and end the console picks its default window. When start
        or end is negative or looks like epoch milliseconds, an object result gains an
        additive _warnings list and an array result is returned as {result, _warnings}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_site_health(
            client, registry, host, site, start=start, end=end
        )

    @tool
    async def get_observability_people(host: str, site: str) -> Any:
        """List the people the site knows, each with the client MACs assigned to them.

        Returns the array verbatim (GET /v2/api/site/{site}/observability/people): id,
        name and client_macs per person.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_people(client, registry, host, site)

    @tool
    async def list_ulp_user_groups(host: str, site: str) -> Any:
        """List the UniFi Identity users and groups the site can reference.

        Returns {users, groups} verbatim (GET /v2/api/site/{site}/ulp/users_groups); each user has
        unique_id, full_name and group_ids. A body that is not a JSON object arrives as {result:
        ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_ulp(client, registry, host, site)

    @tool
    async def list_network_anomalies(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        scale: str | None = None,
    ) -> Any:
        """List the client connectivity anomalies the controller detected.

        Returns the Classic envelope {meta, data} of GET stat/anomalies verbatim. When
        start or end is negative or looks like epoch milliseconds, the envelope gains an
        additive _warnings list. Only the arguments you pass are sent.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            scale: Aggregation scale; for example "hourly".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_anomalies(
            client, registry, host, site, start=start, end=end, scale=scale
        )

    @tool
    async def get_site_dpi_usage(
        host: str,
        start: int,
        end: int,
        bucket: str | None = None,
        filter: str | None = None,
    ) -> Any:
        """Get which applications use the bandwidth, per site, over a time window.

        Reads GET /v2/api/stats/series with schema applicationTrafficBySite. Returns the
        upstream body verbatim (a JSON array arrives as {result: [...]}): per site, per time
        bucket, rxOtherBytes, txOtherBytes and
        byApplication[] of {applicationId, categoryId, rxBytes, txBytes, activityS}. Names
        for the ids come from list_dpi_applications and list_dpi_categories; category totals
        are the sum of the applications with one categoryId. The series covers every site
        of the console unless filter narrows it. When start or end is negative or looks like
        epoch milliseconds, an object result gains an additive _warnings list and an array
        result is returned as {result, _warnings}. For one client at a time use
        get_client_dpi_usage.
        Simulated only: no recorded live console answer yet.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            bucket: Bucket size, sent as given: OF_5_MINUTES, OF_1_HOUR, OF_8_HOURS or
                OF_1_MONTH; omit it to let the console choose; for example "OF_1_HOUR".
            filter: Filter expression in the statistics service's grammar, sent as given; for
                example "siteId.eq('00000000-0000-4000-8000-0000000000aa')".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_site_dpi(
            client, registry, host, start, end, bucket=bucket, filter=filter
        )

    @tool
    async def get_client_dpi_usage(
        host: str,
        start: int,
        end: int,
        bucket: str | None = None,
        filter: str | None = None,
    ) -> Any:
        """Get which applications each client uses, over a time window.

        Reads GET /v2/api/stats/series with schema applicationTrafficBySiteByClient. Returns
        the upstream body verbatim (a JSON array arrives as {result: [...]}): one row per
        client (siteId, clientId) with, per
        time bucket, byApplication[] of {applicationId, categoryId, rxBytes, txBytes,
        activityS}. Names for the ids come from list_dpi_applications and
        list_dpi_categories. When start or end is negative or looks like epoch milliseconds,
        an object result gains an additive _warnings list and an array result is returned as
        {result, _warnings}. For the site as a whole use get_site_dpi_usage.
        Simulated only: no recorded live console answer yet.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            bucket: Bucket size, sent as given: OF_5_MINUTES, OF_1_HOUR, OF_8_HOURS or
                OF_1_MONTH; omit it to let the console choose; for example "OF_1_HOUR".
            filter: Filter expression in the statistics service's grammar, sent as given; for
                example "siteId.eq('00000000-0000-4000-8000-0000000000aa')".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_client_dpi(
            client, registry, host, start, end, bucket=bucket, filter=filter
        )

    @tool
    async def get_client_wifi_experience(host: str, site: str, client_ip: str) -> Any:
        """Get one wireless client's Wi-Fi experience (the web app's per-client WiFiman view).

        Returns the upstream body verbatim (a body that is not a JSON object arrives as
        {result: ...}) from GET /v2/api/site/{site}/wifiman/{client_ip}:
        channel, channel_width, link rates, signal, noise, wifi_experience, wlan_band,
        radio_protocol, nearest_neighbors[], statistics[] (experience over time) and
        uplink_devices[]. Band codes ("2.4g", "5g", "6g") differ from the "ng", "na" and "6e"
        of the Classic client record. An IP that is not a wireless client answers HTTP 404
        (api.err.ClientNotFound). The settings route is get_wifiman_settings.
        Simulated only: no recorded live console answer yet.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            client_ip: The client's IPv4 or IPv6 address, as in the ip field of
                list_active_clients_stats; for example "192.168.1.50". Anything else is
                refused before any request.
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_wifi_experience(
            client, registry, host, site, client_ip
        )

    @tool
    async def suggest_service_port(
        host: str, site: str, service: str | None = None, protocol: str | None = None
    ) -> Any:
        """Suggest free ports for a service on the gateway, as the web app does for VPN servers.

        Returns the upstream body verbatim (a body that is not a JSON object arrives as
        {result: ...}) from GET /v2/api/site/{site}/network/port-suggest,
        for example {available_ports: [1194]} for openvpn. It is a different route from
        suggest_network_settings, which suggests network settings. Only the arguments you
        pass are sent. Without service the console still answers HTTP 200 with a free port
        (Network 11.1.47 answered {available_ports: [1024]}), so pass service for the port of
        a specific service; if a console answers an error, a hint is added to it.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            service: The service to suggest ports for, sent as given: openvpn or wireguard;
                for example "openvpn".
            protocol: Optional transport protocol, sent as given; the web app sends "udp" with
                wireguard; for example "udp".
        """
        client, registry = deps_fn()
        return await network_controller_insights._impl_port_suggest(
            client, registry, host, site, service, protocol
        )


def register_13(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the network tools of the network_dpi_policy lane; its firewall tools
    register in ``families/firewall`` right after them."""

    @mcp.tool(
        annotations=WRITE,
    )
    async def reset_dpi_counters(host: str, site: str) -> Any:
        """Erase DPI history and counters using v2 DELETE /dpi. Consequence: permanently erases
        DPI history and counters. Returns the upstream body unchanged (nonobjects use result).
        Under dry-run policy sends no mutation and returns {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_reset_dpi_counters(client, registry, host, site)

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def list_policy_engine_rules(host: str, site: str) -> Any:
        """List policy-engine objects, distinct from Integration firewall policies. Returns the
        complete unpaged array unchanged (nonobjects use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_list_policy_engine_rules(client, registry, host, site)

    @mcp.tool(
        annotations=WRITE,
    )
    async def create_policy_engine_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Create a private policy-engine object. Returns the upstream body unchanged; masked
        fields are reported in _redactedFieldsNotSent (nonobjects use result). Under
        dry-run policy sends no mutation and returns {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule: Free-form JSON object, for example {'name': 'Test', 'enabled': False,
                'targets': [], 'secure': {'enabled': False}}; preserve private fields.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_create_policy_engine_rule(
            client, registry, host, site, rule
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def update_policy_engine_rule(
        host: str, site: str, rule_id: str, rule: dict[str, Any]
    ) -> Any:
        """Update a policy-engine rule (Network v2 PUT /object-oriented-network-config/{id}).

        Read-merge-write and type-strict requested-leaf verification. Returns the upstream
        write body with _verified and possible _readAfterError; nonobjects use result. Masked
        fields are omitted and reported in _redactedFieldsNotSent. Under dry-run policy sends no
        mutation and returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; no read-back or verification.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule_id: Native id or _id from list_policy_engine_rules, for example 'test-rule'.
            rule: Nonempty free-form partial update object; unrequested fields are preserved, with a
                changed field such as {'name': 'Test updated', 'enabled': False}.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_update_policy_engine_rule(
            client, registry, host, site, rule_id, rule
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def delete_policy_engine_rule(host: str, site: str, rule_id: str) -> Any:
        """Delete one policy-engine object. Consequence: removes the selected policy and its
        enforcement. The id is resolved in the collection list first; an unknown id lists the valid
        ids and sends no write. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. Under dry-run policy sends no mutation and returns {status:
        "dry_run", deleted: false, message, response}, where response is the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule_id: Native id or _id from list_policy_engine_rules, for example 'test-rule'.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_delete_policy_engine_rule(
            client, registry, host, site, rule_id
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def preview_policy_engine_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Preview an object-oriented policy using the Network 11.1.11 private endpoint.
        Consequence: submits the policy to the controller preview action, classified as a write.
        Write class: UNIFI_WRITE_POLICY=deny hides it, and discovery mode runs it through
        call_write_tool.
        Requires Network 11.1.11 or later; 11.0.89 answered 405 and the 11.0.99 route table lacks
        it. The 11.1.11 frontend
        references POST /object-oriented-network-config/preview, but that endpoint is not
        live-verified.
        Returns upstream body and _redactedFieldsNotSent when masked fields are omitted
        (nonobjects use result). Under dry-run policy sends no mutation and returns {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule: Free-form policy JSON object, for example {'name': 'Test',
                'enabled': False, 'targets': [], 'secure': {'enabled': False}}.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_preview_policy_engine_rule(
            client, registry, host, site, rule
        )

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def list_network_members_groups(host: str, site: str) -> Any:
        """List network member groups. Returns the complete unpaged array unchanged (nonobjects
        use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_list_network_members_groups(
            client, registry, host, site
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def create_network_members_group(host: str, site: str, group: dict[str, Any]) -> Any:
        """Create a network member group. Returns upstream body and _redactedFieldsNotSent when
        masked fields are omitted (nonobjects use result). Under dry-run policy sends no mutation
        and returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group: Free-form group object. type is USERS or CLIENTS (live-verified: any other value,
                including IPV4, is rejected with HTTP 400), for example {'name': 'Test',
                'members': ['aa:bb:cc:dd:ee:01'], 'type': 'CLIENTS'}. Other fields pass through.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_create_network_members_group(
            client, registry, host, site, group
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def update_network_members_group(
        host: str, site: str, group_id: str, group: dict[str, Any]
    ) -> Any:
        """Update a network member group (v2 PUT /network-members-group/{id}).

        Read-merge-write and type-strict requested-leaf verification. Returns the upstream
        write body with _verified and possible _readAfterError; nonobjects use result. Masked
        fields are omitted and reported in _redactedFieldsNotSent. Under dry-run policy sends no
        mutation and returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; no read-back or verification.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group_id: Native id from list_network_members_groups, for example 'test-group'.
            group: Nonempty free-form partial update object. type is USERS or CLIENTS, for example
                {'name': 'Test', 'members': ['aa:bb:cc:dd:ee:01'], 'type': 'CLIENTS'}; preserve
                private fields.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_update_network_members_group(
            client, registry, host, site, group_id, group
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def delete_network_members_group(host: str, site: str, group_id: str) -> Any:
        """Delete one network member group. Consequence: removes the selected member group; policies
        referencing it may be affected. The id is resolved in the collection list first; an unknown
        id lists the valid ids and sends no write. Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. Under dry-run policy sends no mutation and
        returns {status: "dry_run", deleted: false, message, response}, where response is the
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group_id: Native id from list_network_members_groups, for example 'test-group'.
        """
        client, registry = deps_fn()
        return await network_dpi_policy._impl_delete_network_members_group(
            client, registry, host, site, group_id
        )


def register_14(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the N11 security, diagnostics and IP/Thread topology tools."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="list_ssl_inspection_catalog", annotations=READ_ONLY)
    async def ssl_catalog(
        host: str,
        site: str,
        catalog: Literal[
            "categories",
            "file-extensions",
            "search-engines",
            "profile-defaults",
            "profile-usage",
            "setting-defaults",
        ],
    ) -> Any:
        """Read one SSL inspection reference catalog.

        Required arguments: host, site, catalog. Each catalog is one Network v2 GET under
        ssl-inspection/: categories, file-extensions, search-engines, profiles/defaults,
        profiles/usage or setting/defaults. Returns the upstream body verbatim (a JSON array arrives
        as {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            catalog: Required catalog to read, e.g. "categories".
        """
        return await network_security_diagnostics.list_ssl_inspection_catalog(
            *deps(), host, site, catalog
        )

    @mcp.tool(name="list_ssl_inspection_certificates", annotations=READ_ONLY)
    async def ssl_certificates(host: str, site: str, active_only: bool = False) -> Any:
        """List SSL inspection CA certificates, or only the active one.

        Required arguments: host, site. Returns the upstream body verbatim (a complete bare array,
        served as {result: [...]}). An offset envelope is drained to {data, totalCount}, with
        incomplete and incompleteReason when the drain stops short. Certificate material is returned
        as the upstream sends it.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            active_only: Read certificates/active instead of the list, e.g. true.
        """
        return await network_security_diagnostics.list_ssl_inspection_certificates(
            *deps(), host, site, active_only
        )

    @mcp.tool(name="create_ssl_inspection_certificate", annotations=WRITE)
    async def ssl_certificate_create(
        host: str,
        site: str,
        mode: Literal["upload", "generate"],
        certificate: dict[str, Any],
    ) -> Any:
        """Upload or generate an SSL inspection CA certificate.

        Required arguments: host, site, mode, certificate. mode "upload" POSTs
        ssl-inspection/certificates and "generate" POSTs ssl-inspection/certificates/generate.
        certificate is a free-form JSON object sent exactly as given: the route inventory records
        the body as dynamic, so no field is required or added by this tool. Private key and
        passphrase fields are route secrets: logs always scrub them; errors and previews mask them
        only under UNIFI_REDACT_SECRETS. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}). With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun,
        sent: false, message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            mode: Required upload or generate, e.g. "generate".
            certificate: Required free-form JSON object sent as the request body, as the
                Network UI builds it, e.g. {"name": "example-ca"}.
        """
        return await network_security_diagnostics.create_ssl_inspection_certificate(
            *deps(), host, site, mode, certificate
        )

    @mcp.tool(name="delete_ssl_inspection_certificate", annotations=WRITE)
    async def ssl_certificate_delete(host: str, site: str, certificate_id: str) -> Any:
        """Delete an SSL inspection CA certificate.

        Consequence: irreversible; clients that trust this CA lose it for inspection. Required
        arguments: host, site, certificate_id. The id is resolved in the certificate list first: an
        unknown id fails listing the valid ids and sends no DELETE. Returns {deleted, message,
        response} with the upstream body. With dry-run policy, returns {status: "dry_run", deleted:
        false, message, response} with the preview (method, path, params, body) under response.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            certificate_id: Required certificate id, e.g. "000000000000000000000105".
        """
        return await network_security_diagnostics.delete_ssl_inspection_certificate(
            *deps(), host, site, certificate_id
        )

    @mcp.tool(name="activate_ssl_inspection_certificate", annotations=WRITE)
    async def ssl_certificate_activate(host: str, site: str, certificate_id: str) -> Any:
        """Make an SSL inspection CA certificate the active one.

        Consequence: inspected TLS sessions are re-signed with this CA; clients that do not trust it
        see certificate errors. Required arguments: host, site, certificate_id. The id is resolved
        in the certificate list first. Sent once and never retried. Returns the upstream body
        verbatim. With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent:
        false, message,
        preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            certificate_id: Required certificate id, e.g. "000000000000000000000105".
        """
        return await network_security_diagnostics.activate_ssl_inspection_certificate(
            *deps(), host, site, certificate_id
        )

    @mcp.tool(name="list_ssl_inspection_profiles", annotations=READ_ONLY)
    async def ssl_profiles(host: str, site: str) -> Any:
        """List SSL inspection profiles.

        Required arguments: host, site. Returns the upstream body verbatim (a complete bare array,
        served as {result: [...]}). An offset envelope is drained to {data, totalCount}, with
        incomplete and incompleteReason when the drain stops short.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await network_security_diagnostics.list_ssl_inspection_profiles(*deps(), host, site)

    @mcp.tool(name="create_ssl_inspection_profile", annotations=WRITE)
    async def ssl_profile_create(host: str, site: str, profile: dict[str, Any]) -> Any:
        """Create an SSL inspection profile.

        Required arguments: host, site, profile. profile is a free-form JSON object sent exactly as
        given (the route inventory records the body as dynamic); read list_ssl_inspection_catalog
        with catalog "profile-defaults" for the fields. Returns the upstream body verbatim (a JSON
        array arrives as {result: [...]}). With dry-run policy, returns a dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            profile: Required free-form profile object, shaped like the profile-defaults
                catalog, e.g. {"name": "example-profile"}.
        """
        return await network_security_diagnostics.create_ssl_inspection_profile(
            *deps(), host, site, profile
        )

    @mcp.tool(name="update_ssl_inspection_profile", annotations=WRITE)
    async def ssl_profile_update(
        host: str, site: str, profile_id: str, changes: dict[str, Any]
    ) -> Any:
        """Update an SSL inspection profile by read-merge-write, verified by a read-back.

        Required arguments: host, site, profile_id, changes. Reads the profile list, deep-merges
        changes over the stored profile and PUTs the merged object, then reads it back. An empty
        changes object is refused before any request. Returns the upstream write body (a non-object
        body under response) plus _readAfter, _verified (true only when every requested leaf matches
        type-strictly), _unverifiedFields when false and _readAfterError when the read-back failed;
        when UNIFI_REDACT_SECRETS is enabled, fields holding the redaction mask are not sent
        and are listed in _redactedFieldsNotSent.
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            profile_id: Required profile id, e.g. "000000000000000000000106".
            changes: Required fields to change, e.g. {"name": "example-profile-2"}.
                Free-form object.
        """
        return await network_security_diagnostics.update_ssl_inspection_profile(
            *deps(), host, site, profile_id, changes
        )

    @mcp.tool(name="delete_ssl_inspection_profile", annotations=WRITE)
    async def ssl_profile_delete(host: str, site: str, profile_id: str) -> Any:
        """Delete an SSL inspection profile.

        Consequence: irreversible; rules using the profile lose it. Required arguments: host, site,
        profile_id. The id is resolved in the profile list first: an unknown id fails listing the
        valid ids and sends no DELETE. Returns {deleted, message, response} with the upstream body.
        With dry-run policy, returns {status: "dry_run", deleted: false, message, response} with the
        preview (method, path, params, body) under response.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            profile_id: Required profile id, e.g. "000000000000000000000106".
        """
        return await network_security_diagnostics.delete_ssl_inspection_profile(
            *deps(), host, site, profile_id
        )

    @mcp.tool(name="get_ssl_inspection_settings", annotations=READ_ONLY)
    async def ssl_settings(host: str, site: str) -> Any:
        """Read the site SSL inspection setting.

        Required arguments: host, site. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await network_security_diagnostics.get_ssl_inspection_settings(*deps(), host, site)

    @mcp.tool(name="update_ssl_inspection_settings", annotations=WRITE)
    async def ssl_settings_update(host: str, site: str, changes: dict[str, Any]) -> Any:
        """Update the SSL inspection setting by read-merge-write, verified by a read-back.

        Consequence: enabling inspection intercepts client TLS traffic. Required arguments: host,
        site, changes. Reads the setting, deep-merges changes and PUTs the merged object, then reads
        it back. An empty changes object is refused before any request. Returns the upstream write
        body (a non-object body under response) plus _readAfter, _verified (true only when every
        requested leaf matches type-strictly), _unverifiedFields when false and _readAfterError when
        the read-back failed; when UNIFI_REDACT_SECRETS is enabled, fields holding the redaction
        mask are not sent and are listed in _redactedFieldsNotSent. With dry-run policy, returns
        a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path,
        params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            changes: Required fields to change, e.g. {"enabled": false}. Free-form object.
        """
        return await network_security_diagnostics.update_ssl_inspection_settings(
            *deps(), host, site, changes
        )

    @mcp.tool(name="list_ips_categories", annotations=READ_ONLY)
    async def ips_categories(host: str, site: str, memory_optimized: bool | None = None) -> Any:
        """List the IPS threat categories available on the site.

        Required arguments: host, site. memory_optimized is sent as the memoryOptimized query
        parameter only when given. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            memory_optimized: Optional memoryOptimized filter, e.g. true.
        """
        return await network_security_diagnostics.list_ips_categories(
            *deps(), host, site, memory_optimized
        )

    @mcp.tool(name="get_ips_signature_status", annotations=READ_ONLY)
    async def ips_signature_status(host: str, site: str) -> Any:
        """Read the IPS (Suricata) signature status.

        Required arguments: host, site. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await network_security_diagnostics.get_ips_signature_status(*deps(), host, site)

    @mcp.tool(name="update_ips_signatures", annotations=WRITE)
    async def ips_signature_update(host: str, site: str) -> Any:
        """Start an IPS (Suricata) signature upgrade on the gateway.

        Consequence: the gateway downloads and loads new signatures; inspection can pause while the
        engine reloads. Required arguments: host, site. Sent once and never retried; read
        get_ips_signature_status for progress. Returns the upstream body verbatim (a JSON array
        arrives as {result: [...]}). With dry-run policy, returns a dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await network_security_diagnostics.update_ips_signatures(*deps(), host, site)

    @mcp.tool(name="get_system_log_settings", annotations=READ_ONLY)
    async def log_settings(host: str, site: str) -> Any:
        """Read the system-log (syslog / activity log) setting.

        Required arguments: host, site. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await network_security_diagnostics.get_system_log_settings(*deps(), host, site)

    @mcp.tool(name="update_system_log_settings", annotations=WRITE)
    async def log_settings_update(host: str, site: str, changes: dict[str, Any]) -> Any:
        """Update the system-log setting by read-merge-write, verified by a read-back.

        Required arguments: host, site, changes. Reads the setting, deep-merges changes and PUTs the
        merged object, then reads it back. An empty changes object is refused before any request.
        Returns the upstream write body (a non-object body under response) plus _readAfter,
        _verified (true only when every requested leaf matches type-strictly), _unverifiedFields
        when false and _readAfterError when the read-back failed; when UNIFI_REDACT_SECRETS is
        enabled, fields holding the redaction mask are not sent and are listed in
        _redactedFieldsNotSent. With dry-run policy, returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            changes: Required fields to change, e.g. {"debug_logging": true}. Free-form object.
        """
        return await network_security_diagnostics.update_system_log_settings(
            *deps(), host, site, changes
        )

    @mcp.tool(name="mark_critical_logs_read", annotations=WRITE)
    async def critical_logs_read(host: str, site: str, body: dict[str, Any] | None = None) -> Any:
        """Mark every critical system-log entry as read.

        Required arguments: host, site. body is an optional free-form JSON object sent exactly as
        given (the route inventory records the body as dynamic). Returns the upstream body verbatim
        (a JSON array arrives as {result: [...]}). With dry-run policy, returns a dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            body: Optional free-form JSON object sent as the request body, e.g. {}.
        """
        return await network_security_diagnostics.mark_critical_logs_read(*deps(), host, site, body)

    @mcp.tool(name="acknowledge_critical_alert", annotations=WRITE)
    async def critical_alert_acknowledge(host: str, site: str, alert_id: str) -> Any:
        """Mark ONE critical system-log alert as read (acknowledge it). Not run on a console.

        The route and its PUT method are bound in Ubiquiti's Network 11.0.99 server code (a
        PutMapping on the system-log controller; no request body; HTTP 204). The Network web
        app never calls it (it only calls mark-all-as-read), so no console has answered it yet.
        Consequence: the alert and the alerts aggregated with it (Ubiquiti's handler marks the
        whole group read) stop counting as unread in the Network app; alerts in other groups are
        untouched (mark_critical_logs_read marks every one). Required arguments:
        host, site, alert_id. Sends PUT /v2/api/site/{site}/system-log/critical/{alert_id}/
        mark-as-read with an empty JSON object, once and never retried. Returns the upstream
        body verbatim (a JSON array arrives as {result: [...]}). With dry-run policy, returns a
        dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method,
        path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            alert_id: Required id of one critical alert, from the id field of an entry returned
                by get_system_log with class "critical", e.g. "0000000000000000000000aa".
        """
        return await network_security_diagnostics.acknowledge_critical_alert(
            *deps(), host, site, alert_id
        )

    @mcp.tool(name="control_packet_capture", annotations=WRITE)
    async def packet_capture(
        host: str,
        site: str,
        action: Literal["start", "stop"],
        capture_id: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> Any:
        """Start or stop a gateway packet capture.

        Consequence: a capture runs on the gateway and uses its CPU and storage. Required arguments:
        host, site, action. start POSTs pcap-start with {cmd: "pcap-start"} plus options (free-form,
        sent as given); stop POSTs pcap-stop/{capture_id} with {cmd: "pcap-stop"}. Sent once and
        never retried. Returns the upstream body verbatim (a JSON array arrives as {result: [...]}).
        With dry-run policy, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            action: Required start or stop, e.g. "start".
            capture_id: Capture id for stop, from the start result, e.g. "capture-0001".
            options: Optional free-form start fields merged under cmd, e.g. {}.
        """
        return await network_security_diagnostics.control_packet_capture(
            *deps(), host, site, action, capture_id, options
        )

    @mcp.tool(name="get_packet_capture_status", annotations=READ_ONLY)
    async def packet_capture_status(host: str, site: str, capture_id: str) -> Any:
        """Read a packet capture's status.

        Required arguments: host, site, capture_id. Returns the upstream body verbatim (a JSON array
        arrives as {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            capture_id: Required capture id from control_packet_capture, e.g. "capture-0001".
        """
        return await network_security_diagnostics.get_packet_capture_status(
            *deps(), host, site, capture_id
        )

    @mcp.tool(name="control_ping_test", annotations=WRITE)
    async def ping_test(
        host: str,
        site: str,
        action: Literal["start", "stop"],
        target: str,
        options: dict[str, Any] | None = None,
    ) -> Any:
        """Start or stop a ping test run by the console.

        Consequence: the device sends ICMP traffic until the test ends or is stopped. Required
        arguments: host, site, action, target. POSTs ping-start/{target} or ping-stop/{target};
        target is the path segment the Network UI uses for the test and is sent as one encoded
        segment. options is a free-form body sent as given. Sent once and never retried. Returns the
        upstream body verbatim. With dry-run policy, returns a dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            action: Required start or stop, e.g. "start".
            target: Required test path segment, e.g. "02:00:5e:00:00:a1".
            options: Optional free-form JSON body sent as given, e.g. {}.
        """
        return await network_security_diagnostics.control_ping_test(
            *deps(), host, site, action, target, options
        )

    @mcp.tool(name="get_ping_test_results", annotations=READ_ONLY)
    async def ping_results(host: str, site: str, target: str) -> Any:
        """Read a ping test's results.

        Required arguments: host, site, target. Returns the upstream body verbatim (a JSON array
        arrives as {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            target: Required test path segment used to start it, e.g. "02:00:5e:00:00:a1".
        """
        return await network_security_diagnostics.get_ping_test_results(*deps(), host, site, target)

    @mcp.tool(name="get_unified_ip_thread_topology", annotations=READ_ONLY)
    async def ip_thread_topology(host: str, site: str) -> Any:
        """Project Matter nodes, Thread networks and the live IP topology into one view.

        Required arguments: host, site. Reads matter/nodes, thread-networks and
        topology/snapshot/live. Returns each body verbatim under _matterNodes, _threadNetworks and
        _topologySnapshot, with _sources (path and outcome of each GET), _join (matterNodes,
        threadBorderRouters, summary, notes) and _warnings (Thread timestamps are epoch
        milliseconds). The join maps each Matter node by client_id (node_id when absent) to a
        topology vertex, then to a Thread border router by normalized MAC, and gives every row a
        joinState. A border router is linked to a Matter node only through a matched vertex; an
        unlinked router is never reported as a Matter node. A failed source is reported in _sources
        and the others are still joined.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await network_security_diagnostics.get_unified_ip_thread_topology(
            *deps(), host, site
        )


def register_15(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 18 ProAV, Shadow Mode, sandbox, digital-twin and insight tools."""

    @mcp.tool(name="get_proav_matrix", annotations=READ_ONLY)
    async def get_proav_matrix_tool(host: str, site: str, kind: Literal["audio", "video"]) -> Any:
        """Read a site's ProAV audio or video routing matrix (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/proav/{kind}/matrix; the upstream body is
        returned verbatim. The route takes no paging parameter.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, kind.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Which matrix to read, "audio" or "video", e.g. "video".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.get_proav_matrix(client, registry, host, site, kind)

    @mcp.tool(name="get_proav_snapshot", annotations=READ_ONLY)
    async def get_proav_snapshot_tool(host: str, site: str, snapshot_id: str) -> Any:
        """Read one ProAV snapshot (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/proav/snapshot/{snapshot_id}; the upstream
        body is returned verbatim. The inventory records only a path placeholder for the
        snapshot identifier, so it is passed through as one path segment.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, snapshot_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            snapshot_id: Snapshot identifier (letters, digits, - and _), e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.get_proav_snapshot(
            client, registry, host, site, snapshot_id
        )

    @mcp.tool(name="create_proav_group", annotations=WRITE)
    async def create_proav_group_tool(
        host: str, site: str, kind: Literal["audio", "video"], group: dict[str, Any]
    ) -> Any:
        """Create a ProAV audio or video group (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/proav/{kind}/group with group sent verbatim;
        the upstream body is returned verbatim. Never auto-retried. The group body is
        free-form: the route inventory records no body keys, so none is required here.
        Consequence: changes which ProAV endpoints share a stream.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, kind, group.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Group type, "audio" or "video", e.g. "video".
            group: Free-form group object as the Network UI sends it, e.g.
                {"name": "lobby-wall"}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.create_proav_group(
            client, registry, host, site, kind, group
        )

    @mcp.tool(name="update_proav_group", annotations=WRITE)
    async def update_proav_group_tool(
        host: str,
        site: str,
        kind: Literal["audio", "video"],
        group_id: str,
        group: dict[str, Any],
    ) -> Any:
        """Replace a ProAV audio or video group (Network v2 route).

        PUT /proxy/network/v2/api/site/{site}/proav/{kind}/group/{group_id} with group sent
        verbatim as the complete group; the upstream body is returned verbatim. No route
        reads a single group, so nothing is merged or read back. An empty group is refused
        before any request. Consequence: changes live ProAV stream routing.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, kind, group_id, group.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Group type, "audio" or "video", e.g. "audio".
            group_id: Group id, e.g. "000000000000000000000107".
            group: Free-form complete group object, e.g. {"name": "lobby-wall"}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.update_proav_group(
            client, registry, host, site, kind, group_id, group
        )

    @mcp.tool(name="delete_proav_group", annotations=WRITE)
    async def delete_proav_group_tool(
        host: str, site: str, kind: Literal["audio", "video"], group_id: str
    ) -> Any:
        """Delete a ProAV audio or video group (Network v2 route).

        DELETE /proxy/network/v2/api/site/{site}/proav/{kind}/group/{group_id}; returns
        deleted, message and the upstream body as response. Never auto-retried.
        Consequence: the group is removed permanently and its streams stop.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, message and preview with method, path, params, body).

        Returns deleted, message and response (the upstream body).

        Required arguments: host, site, kind, group_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Group type, "audio" or "video", e.g. "video".
            group_id: Group id, e.g. "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.delete_proav_group(
            client, registry, host, site, kind, group_id
        )

    @mcp.tool(name="set_tv_wall_calibration", annotations=WRITE)
    async def set_tv_wall_calibration_tool(
        host: str,
        site: str,
        action: Literal["set", "unset"],
        calibration: dict[str, Any] | None = None,
    ) -> Any:
        """Set or clear the ProAV video TV-wall calibration (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/proav/video/set-tv-wall-calibration (action
        "set") or .../unset-tv-wall-calibration (action "unset") with calibration sent
        verbatim (free-form: the inventory records no body keys; omitted sends no body).
        The upstream body is returned verbatim. Never auto-retried. Consequence: changes
        what the physical displays of the TV wall show.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, action.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: "set" or "unset", e.g. "set".
            calibration: Free-form calibration object as the Network UI sends it, e.g.
                {"rows": 2, "columns": 2}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.set_tv_wall_calibration(
            client, registry, host, site, action, calibration
        )

    @mcp.tool(name="get_shadow_mode_status", annotations=READ_ONLY)
    async def get_shadow_mode_status_tool(
        host: str, site: str, view: Literal["info", "managed_group"] = "info"
    ) -> Any:
        """Read Shadow Mode state (Network v2 route).

        With view "info": GET /proxy/network/v2/api/site/{site}/shadowmode/info; with
        view "managed_group": GET .../shadowmode/managed/group (the managed adoption group).
        The upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            view: "info" (default) or "managed_group", e.g. "managed_group".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.get_shadow_mode_status(
            client, registry, host, site, view
        )

    @mcp.tool(name="control_shadow_mode_adoption", annotations=WRITE)
    async def control_shadow_mode_adoption_tool(
        host: str,
        site: str,
        action: Literal["begin", "complete", "rollback"],
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Begin, complete or roll back Shadow Mode managed adoption (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/shadowmode/managed/begin-adoption,
        complete-adoption or rollback with body sent verbatim (free-form: the inventory
        records no body keys; omitted sends no body). The upstream body is returned
        verbatim. Never auto-retried. Consequence: devices change which controller manages
        them; complete and rollback can disconnect devices while they re-provision.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, action.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: "begin", "complete" or "rollback", e.g. "begin".
            body: Free-form request object as the Network UI sends it, e.g.
                {"devices": ["02:00:5e:00:00:a1"]}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.control_shadow_mode_adoption(
            client, registry, host, site, action, body
        )

    @mcp.tool(name="list_test_configs", annotations=READ_ONLY)
    async def list_test_configs_tool(host: str, site: str) -> Any:
        """List a site's sandbox test configs (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/test-configs; the upstream body is returned
        verbatim. The route takes no paging parameter.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.list_test_configs(client, registry, host, site)

    @mcp.tool(name="create_test_config", annotations=WRITE)
    async def create_test_config_tool(host: str, site: str, test_config: dict[str, Any]) -> Any:
        """Create a sandbox test config (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/test-configs with test_config sent verbatim
        (free-form: the inventory records no body keys); the upstream body is returned
        verbatim. Never auto-retried. Consequence: stores a staged configuration; nothing
        is applied until apply_test_config.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, test_config.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            test_config: Free-form test-config object as the Network UI sends it, e.g.
                {"name": "vlan-trial"}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.create_test_config(
            client, registry, host, site, test_config
        )

    @mcp.tool(name="delete_test_config", annotations=WRITE)
    async def delete_test_config_tool(host: str, site: str, test_config_id: str) -> Any:
        """Delete a sandbox test config (Network v2 route).

        Reads GET .../test-configs to resolve test_config_id (_id or id; an unknown id
        fails listing every valid id), then DELETE
        /proxy/network/v2/api/site/{site}/test-configs/{id}; returns deleted, message and
        the upstream body as response. Consequence: the staged config is removed
        permanently.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, message and preview with method, path, params, body).

        Returns deleted, message and response (the upstream body).

        Required arguments: host, site, test_config_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            test_config_id: Test-config id from list_test_configs, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.delete_test_config(
            client, registry, host, site, test_config_id
        )

    @mcp.tool(name="apply_test_config", annotations=WRITE)
    async def apply_test_config_tool(
        host: str,
        site: str,
        test_config_id: str,
        action: Literal["apply", "commit"] = "apply",
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Apply or commit a sandbox test config (Network v2 route).

        Resolves test_config_id in GET .../test-configs (an unknown id fails listing every
        valid id), then POST /proxy/network/v2/api/site/{site}/test-configs/{id}/apply or
        .../commit with body sent verbatim (free-form; omitted sends no body). The upstream
        body is returned verbatim. Never auto-retried. Consequence: the staged
        configuration goes live on the site's devices and can interrupt traffic.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, test_config_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            test_config_id: Test-config id from list_test_configs, e.g.
                "000000000000000000000107".
            action: "apply" (default) or "commit", e.g. "commit".
            body: Free-form request object as the Network UI sends it, e.g.
                {"duration": 300}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.apply_test_config(
            client, registry, host, site, test_config_id, action, body
        )

    @mcp.tool(name="get_port_forward_statistics", annotations=READ_ONLY)
    async def get_port_forward_statistics_tool(host: str, site: str) -> Any:
        """Read port-forward rule statistics (Network Classic route).

        GET /proxy/network/api/s/{site}/stat/portforward; success is HTTP 2xx with
        meta.rc "ok" (anything else raises with the full upstream body). The upstream
        {meta, data} body is returned verbatim. Rules themselves: list_port_forwards.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.get_port_forward_statistics(client, registry, host, site)

    @mcp.tool(name="get_digital_twin_layout", annotations=READ_ONLY)
    async def get_digital_twin_layout_tool(host: str, site: str) -> Any:
        """Read a site's digital-twin topology layout (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/digital-twin/layout; the upstream body is
        returned verbatim.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.get_digital_twin_layout(client, registry, host, site)

    @mcp.tool(name="update_digital_twin_layout", annotations=WRITE)
    async def update_digital_twin_layout_tool(host: str, site: str, layout: dict[str, Any]) -> Any:
        """Update a site's digital-twin topology layout (Network v2 route).

        Reads GET .../digital-twin/layout, merges only the given leaves over it (when no
        layout object exists yet the given layout is the whole body), PUTs it to
        /proxy/network/v2/api/site/{site}/digital-twin/layout and reads it back: the
        upstream body plus _verified (every requested leaf matched, type-strict) and
        _readAfterError when the read-back failed. An empty layout is refused before any
        request. Consequence: replaces the saved layout other operators see.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body plus _verified and, when the read-back failed, _readAfterError;
        a non-object write body is returned whole under response with those keys beside it.

        Required arguments: host, site, layout.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            layout: Free-form layout leaves to set, e.g. {"zoom": 1.5}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.update_digital_twin_layout(
            client, registry, host, site, layout
        )

    @mcp.tool(name="delete_digital_twin_layout", annotations=WRITE)
    async def delete_digital_twin_layout_tool(host: str, site: str) -> Any:
        """Delete a site's saved digital-twin topology layout (Network v2 route).

        DELETE /proxy/network/v2/api/site/{site}/digital-twin/layout; returns deleted,
        message and the upstream body as response. Never auto-retried. Consequence: the
        saved layout is removed permanently.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, message and preview with method, path, params, body).

        Returns deleted, message and response (the upstream body).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.delete_digital_twin_layout(client, registry, host, site)

    @mcp.tool(name="get_5g_topology", annotations=READ_ONLY)
    async def get_5g_topology_tool(host: str, site: str, device: str, at: int) -> Any:
        """Read a 5G device's topology snapshot at a point in time (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/observability/5g/{device}/topology/at/{at},
        the route the Network 11.0.89 web app reads for a site whose internet connection is
        a 5G device (it sends the device MAC). The upstream body is returned verbatim plus
        an additive _warnings entry naming the epoch unit. at is epoch MILLISECONDS and is
        sent as given. A console that serves no 5G topology for the device answers an HTML
        404; the error keeps it and adds a hint.

        Returns the upstream body plus _warnings (the epoch unit of at).

        Required arguments: host, site, device, at.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: The 5G device's MAC (what the web app sends) or id, e.g.
                "02:00:5e:00:00:a1".
            at: Point in time, epoch milliseconds, e.g. 1760000000000.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.get_5g_topology(client, registry, host, site, device, at)

    @mcp.tool(name="get_multicast_insights", annotations=WRITE)
    async def get_multicast_insights_tool(
        host: str,
        site: str,
        view: Literal["client", "clients", "history"],
        client_mac: str | None = None,
        query_params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Read multicast insights (Network v2 routes).

        With view "client": GET /proxy/network/v2/api/site/{site}/insights/multicast/ client/{client_mac}. With view "clients" or "history": POST .../insights/multicast/clients or .../history, sending query_params as the query string and body verbatim as JSON. These routes are present in the Network 11.0.81 UI; the 2026-10-26 development-controller capture returned HTTP 404 for both POST views (controller version was not recorded). A firmware exposing these routes is required; the earliest supported version is unverified. Those POSTs are not on the read-POST allowlist, so this tool is a write: UNIFI_WRITE_POLICY=deny hides the whole tool, including the client GET view. Consequence: none intended; the POST is classed as a write.

        Under dry-run policy the POST views return a dry-run preview without sending a POST: status "dry_run", dryRun, sent=false, message and preview (method, path, params, body). The client GET view still reads normally.

        Network 11.1.47 answered HTTP 404 for the clients view (checked 2026-11-13); the history view was not checked.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, view.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            view: "client", "clients" or "history", e.g. "history".
            client_mac: Client MAC, required for view "client" only, e.g.
                "02:00:5e:00:00:a1".
            query_params: Free-form query parameters (string, number or boolean
                values), e.g. {"start": 1760000000000, "end": 1760003600000}.
            body: Optional free-form query body for clients/history, e.g. {"client_macs": []}.
        """
        client, registry = deps_fn()
        return await network_proav_sandbox.get_multicast_insights(
            client, registry, host, site, view, client_mac, query_params, body
        )


def register_16(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    def tool(fn: Callable[..., Any]) -> Any:
        # Annotations derived from the implementation call graph, never hand-set.
        writes = derive_write_tools([SimpleNamespace(name=fn.__name__, fn=fn)])
        return mcp.tool(annotations=for_tool(writes=fn.__name__ in writes))(fn)

    @tool
    async def get_lte_subscription_status(
        host: str,
        site: str,
        macs: list[str],
        ubic_username: str | None = None,
        ubic_password: str | None = None,
        ubic_2fa_token: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Check the UniFi LTE (cellular backup) subscription of one or more LTE devices.

        Required: host, site and macs (a non-empty list of device MACs from list_devices; an empty list fails before any request). Sends Classic POST api/s/{site}/cmd/lte with cmd check-subscription and the keys the Network web app sends: macs, ubic_username, x_ubic_password (from ubic_password) and ubic_2fa_token; only the arguments you pass are sent. Each MAC must be a device of the site (read first; an unknown MAC fails listing the devices). Returns the Classic envelope {meta, data} verbatim; success requires meta.rc "ok". Consequence: none; it changes nothing, but it is a POST, so read-only mode refuses it. The password and token are credentials: masked in errors and results only under UNIFI_REDACT_SECRETS. With dry-run policy returns a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends nothing.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            macs: Non-empty list of LTE device MACs; for example ["02:00:5e:00:53:01"].
            ubic_username: UI account username or email; for example "admin@example.com".
            ubic_password: UI account password, sent as x_ubic_password; for example
                "example-pass".
            ubic_2fa_token: UI account 2FA code; for example "123456".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_subscription(
            client,
            registry,
            host,
            site,
            macs,
            ubic_username=ubic_username,
            ubic_password=ubic_password,
            ubic_2fa_token=ubic_2fa_token,
        )

    @tool
    async def activate_lte_trial(
        host: str, site: str, params: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Activate the UniFi LTE trial subscription on a site.

        Required: host and site. Sends Classic POST api/s/{site}/cmd/lte with cmd
        activate-trial. The Network 11.0.81 web app builds the rest of this body
        dynamically, so params is free-form and sent as given beside cmd (none by
        default); the controller reports a missing or unknown key. Returns the Classic
        envelope {meta, data} verbatim; success requires meta.rc "ok". With dry-run policy
        returns a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview:
        {method, path, params, body}} and sends nothing.

        Consequence: starts the account's one-time LTE trial period; it cannot be undone.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            params: Free-form command fields sent beside cmd; for example
                {"mac": "02:00:5e:00:53:01"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_trial(client, registry, host, site, params)

    @tool
    async def authorize_lte_device(
        host: str,
        site: str,
        mac: str,
        ubic_username: str | None = None,
        ubic_password: str | None = None,
        ubic_2fa_token: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Authorize a UniFi LTE device against the UI account that holds its subscription.

        Required: host, site and mac (the LTE device MAC from list_devices; it must be a
        device of the site). Sends Classic POST api/s/{site}/cmd/lte with cmd auth-device
        and the keys the Network web app sends: mac, ubic_username, x_ubic_password (from
        ubic_password) and ubic_2fa_token; only the arguments you pass are sent. Returns
        the Classic envelope {meta, data} verbatim; success requires meta.rc "ok". The
        password and token are credentials: masked in errors and results only under
        UNIFI_REDACT_SECRETS. With dry-run policy returns a dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing.

        Consequence: binds the device's cellular subscription to the UI account given.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            mac: LTE device MAC; for example "02:00:5e:00:53:01".
            ubic_username: UI account username or email; for example "admin@example.com".
            ubic_password: UI account password, sent as x_ubic_password; for example
                "example-pass".
            ubic_2fa_token: UI account 2FA code; for example "123456".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_authorize(
            client,
            registry,
            host,
            site,
            mac,
            ubic_username=ubic_username,
            ubic_password=ubic_password,
            ubic_2fa_token=ubic_2fa_token,
        )

    @tool
    async def set_lte_apn_profile(
        host: str, site: str, mac: str, profile: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Set the cellular APN profile of a UniFi LTE device.

        Required: host, site, mac (the LTE device MAC from list_devices; it must be a device of the
        site) and profile. Sends Classic POST api/s/{site}/cmd/lte with cmd lte-set-profile, mac and
        the profile fields. The Network 11.0.81 web app builds the profile fields dynamically, so
        profile is free-form and sent as given (a mac key inside it fails before any request: the
        device is the mac argument). APN credentials in it are masked in errors and results
        only under UNIFI_REDACT_SECRETS. Returns the Classic envelope {meta, data} verbatim;
        success requires meta.rc "ok". With dry-run policy returns a dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.

        Consequence: the modem reconnects with the new APN; a wrong APN drops cellular
        connectivity until it is corrected.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            mac: LTE device MAC; for example "02:00:5e:00:53:01".
            profile: Free-form APN profile fields; for example {"apn": "internet"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_apn(client, registry, host, site, mac, profile)

    @tool
    async def verify_sim_pin(
        host: str,
        site: str,
        pin: str,
        mac: str | None = None,
        manager: LteManager = "lte",
        params: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Unlock a PIN-locked SIM card by sending its PIN.

        Required: host, site and pin. manager lte (default) sends Classic POST
        api/s/{site}/cmd/lte with cmd lte-verify-pin and {mac, pin}, the keys the Network
        11.0.81 web app sends; manager mbb sends cmd/mbb with cmd verify-pin, whose other
        keys the web app builds dynamically: pass them in params (free-form, sent as
        given; a pin key, or a mac key together with the mac argument, fails before any
        request). mac, when given, must be a device of the site (from list_devices). Returns
        the Classic envelope {meta, data} verbatim; success requires meta.rc "ok". The PIN
        is a credential: masked in errors and results only under
        UNIFI_REDACT_SECRETS. With dry-run policy returns a dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing.

        Consequence: each wrong PIN uses one of the SIM's few attempts; the last one locks
        the SIM until its PUK is entered.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            pin: SIM PIN; for example "1234".
            mac: Device MAC; for example "02:00:5e:00:53:01".
            manager: lte or mbb; for example "lte".
            params: Free-form extra command fields; for example {"slot": 1}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_pin(
            client, registry, host, site, pin, mac=mac, manager=manager, params=params
        )

    @tool
    async def update_lte_device(
        host: str, site: str, params: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a UniFi LTE device's cellular settings through the LTE command manager.

        Required: host, site and params. Sends Classic POST api/s/{site}/cmd/lte with cmd
        update-device. The Network 11.0.81 web app builds this body dynamically, so params
        is free-form and sent as given beside cmd; the controller reports a missing or
        unknown key. Returns the Classic envelope {meta, data} verbatim; success requires
        meta.rc "ok". With dry-run policy returns a dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}} and sends nothing.

        Consequence: the device applies the new cellular settings and may reconnect.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            params: Free-form command fields; for example {"mac": "02:00:5e:00:53:01"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_update_device(client, registry, host, site, params)

    @tool
    async def manage_esim_profile(
        host: str, site: str, action: EsimAction, params: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Add or delete an eSIM profile on a UniFi mobile-broadband device.

        Required: host, site, action and params. action add sends Classic POST
        api/s/{site}/cmd/mbb with cmd esim-add; action delete sends cmd esim-delete. The
        Network 11.0.81 web app builds the rest of the body dynamically, so params is
        free-form and sent as given beside cmd. eSIM activation codes in it are masked in
        errors and results only under UNIFI_REDACT_SECRETS. Returns the
        Classic envelope {meta, data} verbatim; success requires meta.rc "ok". With
        dry-run policy returns a dry-run preview {status: "dry_run", dryRun, sent: false, message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: delete erases the eSIM profile from the device; a carrier profile
        usually cannot be downloaded again without a new activation code.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            action: add or delete; for example "add".
            params: Free-form command fields; for example {"mac": "02:00:5e:00:53:01"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_esim(client, registry, host, site, action, params)

    @tool
    async def get_inactive_sim_slot(
        host: str, site: str, params: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Read the SIM card in the inactive slot of a dual-SIM mobile-broadband device.

        Required: host and site. Sends Classic POST api/s/{site}/cmd/mbb with cmd
        read-inactive-slot-sim-card. The Network 11.0.81 web app builds the rest of the
        body dynamically, so params is free-form and sent as given beside cmd. Returns the
        Classic envelope {meta, data} verbatim; success requires meta.rc "ok". Consequence:
        none intended; the command reads the SIM and switches no slot, but it is a POST, so
        read-only mode refuses it. With dry-run policy returns a dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides
        the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            params: Free-form command fields; for example {"mac": "02:00:5e:00:53:01"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_inactive_slot(client, registry, host, site, params)

    @tool
    async def reset_mobile_data_usage(
        host: str, site: str, params: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Reset the mobile data usage counter of a UniFi mobile-broadband device.

        Required: host and site. Sends Classic POST api/s/{site}/cmd/mbb with cmd
        reset-usage. The Network 11.0.81 web app builds the rest of the body dynamically,
        so params is free-form and sent as given beside cmd. Returns the Classic envelope
        {meta, data} verbatim; success requires meta.rc "ok". With dry-run policy returns a
        dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path,
        params, body}} and sends nothing.

        Consequence: the accumulated usage count is cleared and cannot be restored.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            params: Free-form command fields; for example {"mac": "02:00:5e:00:53:01"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_reset_usage(client, registry, host, site, params)

    @tool
    async def set_lte_failover(
        host: str, site: str, body: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Enable LTE failover for the site's LAN as the Network web app does.

        Required: host, site and body. Sends PUT
        /v2/api/site/{site}/lan/enable-lte-failover with body as given: the Network
        11.0.81 web app builds it dynamically, so it is free-form and the controller
        reports a missing or unknown key. Returns the upstream body verbatim (an object,
        or an array body as result). With dry-run policy returns a dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing.

        Consequence: WAN traffic fails over to the cellular link when the primary WAN
        drops, which can use metered mobile data.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            body: Free-form request body; for example {"enabled": true}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_failover(client, registry, host, site, body)

    @tool
    async def get_wan_load_balancing(
        host: str, site: str, view: LoadBalancingView = "configuration"
    ) -> Any:
        """Get the site's multi-WAN load-balancing configuration or live status.

        Required: host and site. view configuration (default) reads
        GET /v2/api/site/{site}/wan/load-balancing/configuration; view status reads
        .../load-balancing/status. Returns the upstream body verbatim (an object, or an
        array body as result). Change the configuration with update_wan_load_balancing.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            view: configuration or status; for example "status".
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_lb_get(client, registry, host, site, view)

    @tool
    async def update_wan_load_balancing(
        host: str,
        site: str,
        configuration: dict[str, Any],
        test_config_id: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Change the site's multi-WAN load-balancing configuration and verify it.

        Required: host, site and configuration (the fields to change). Reads the current
        configuration (GET /v2/api/site/{site}/wan/load-balancing/configuration), merges
        configuration over it (objects merge, other values replace) and PUTs the result,
        then reads it back. Returns the PUT response verbatim (a non-object response under
        response) plus _verified (true, false, or null when the read-back failed),
        _unverifiedFields when false, _readAfterError and _redactedFieldsNotSent (with
        UNIFI_REDACT_SECRETS on, the fields that held the redaction mask, left out of the PUT).
        An empty configuration is refused before any request. With dry-run policy returns a
        dry-run preview {status: "dry_run", dryRun, sent:
        false, message, preview: {method, path, params, body}} and sends nothing.

        Consequence: WAN traffic is redistributed across the gateway's uplinks at once.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            configuration: Fields to change, free-form; for example {"mode": "failover"}.
            test_config_id: Sent as the testConfigId query parameter; for example
                "example-test-config".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_lb_update(
            client, registry, host, site, configuration, test_config_id=test_config_id
        )

    @tool
    async def list_wan_network_groups(host: str, site: str, uptime: bool | None = None) -> Any:
        """List the site's WAN network groups (WAN, WAN2, LTE) and optionally their uptime.

        Required: host and site. Reads GET /v2/api/site/{site}/wan/networkgroups; uptime
        true adds ?uptime=true as the Network web app sends. Returns the upstream body
        verbatim (an object, or an array body as result). A group name is the wan_group of
        get_wan_insights.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            uptime: Include uptime, sent as uptime=true or false; for example true.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_groups(client, registry, host, site, uptime=uptime)

    @tool
    async def get_wan_insights(
        host: str,
        site: str,
        wan_group: str,
        view: network_mobile_wan.InsightView = "overview",
        period: str | None = None,
    ) -> Any:
        """Get one WAN's insights: overview, health history or speed-test history.

        Required: host, site and wan_group (a group from list_wan_network_groups). view
        overview reads GET /v2/api/site/{site}/wan/{wan_group}/insights/overview; history
        and speed_tests read .../insights/history and .../insights/speed-tests (the site's
        speed-test history for that WAN) with ?period= when period is given. Returns the
        upstream body verbatim (an object, or an array body as result).

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            wan_group: WAN network group; for example "WAN".
            view: overview, history or speed_tests; for example "speed_tests".
            period: History period: HOUR, DAY, WEEK or MONTH; for example "DAY".
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_insights(
            client, registry, host, site, wan_group, view=view, period=period
        )

    @tool
    async def list_wan_slas(host: str, site: str) -> Any:
        """List the site's WAN SLA definitions (latency, loss and jitter targets).

        Required: host and site. Reads GET /v2/api/site/{site}/wan-slas. Returns the
        upstream body verbatim (an object, or an array body as result). Each record's _id
        selects it in update_wan_sla and delete_wan_sla.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_sla_list(client, registry, host, site)

    @tool
    async def create_wan_sla(
        host: str, site: str, sla: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a WAN SLA definition.

        Required: host, site and sla. Sends POST /v2/api/site/{site}/wan-slas with sla as
        given: the Network 11.0.81 web app builds this body dynamically, so it is
        free-form; copy the shape of a list_wan_slas record. Returns the upstream body
        verbatim (an object, or an array body as result). With dry-run policy returns a
        dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path,
        params, body}} and sends nothing.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            sla: Free-form SLA definition; for example {"name": "Branch SLA"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_sla_create(client, registry, host, site, sla)

    @tool
    async def update_wan_sla(
        host: str, site: str, sla_id: str, changes: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Change a WAN SLA definition and verify it.

        Required: host, site, sla_id (an _id from list_wan_slas; an unknown id fails
        listing them) and changes. Reads the SLA from GET /v2/api/site/{site}/wan-slas,
        merges changes over it, PUTs the result to .../wan-slas/{_id} (its _id and id in
        the upstream spelling) and reads the list back. Returns the PUT response verbatim
        (a non-object response under response) plus _verified (true, false, or null when
        the read-back failed), _unverifiedFields when false, _readAfterError and
        _redactedFieldsNotSent (with UNIFI_REDACT_SECRETS on, the fields that held the
        redaction mask, left out of the PUT). An empty changes
        object is refused before any request. With dry-run policy returns a dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            sla_id: SLA _id; for example "0000000000000000000000aa".
            changes: Fields to change; for example {"name": "Branch SLA"}. Free-form object.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_sla_update(
            client, registry, host, site, sla_id, changes
        )

    @tool
    async def delete_wan_sla(host: str, site: str, sla_id: str, confirm: bool = False) -> Any:
        """Delete a WAN SLA definition.

        Required: host, site and sla_id (an _id from list_wan_slas). The list is read
        first, so an unknown id fails listing the SLAs and sends no DELETE. Sends
        DELETE /v2/api/site/{site}/wan-slas/{_id}. Returns {deleted, message, response}
        with the upstream body verbatim under response. With dry-run policy returns
        {status: "dry_run", deleted: false, message, response}, where response is the dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}}, and sends nothing.

        Consequence: the SLA definition is removed and cannot be restored.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            sla_id: SLA _id; for example "0000000000000000000000aa".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_sla_delete(client, registry, host, site, sla_id)

    @tool
    async def get_enriched_configuration(host: str, site: str, kind: EnrichedKind = "wan") -> Any:
        """Get the site's WAN, LAN or WLAN configuration enriched with usage details.

        Required: host and site. Reads GET
        /v2/api/site/{site}/{kind}/enriched-configuration (kind wan, lan or wlan), the list
        the Network web app shows on its WAN, network and WiFi pages. Returns the upstream
        body verbatim (an object, or an array body as result).

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            kind: wan, lan or wlan; for example "lan".
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_enriched(client, registry, host, site, kind)

    @tool
    async def list_gateway_routes(host: str, site: str) -> Any:
        """List the gateway's active route table (static, connected and dynamic routes).

        Required: host and site. Reads GET /v2/api/site/{site}/routes. Returns the upstream
        body verbatim (an object, or an array body as result). Policy-based traffic routes
        are list_traffic_routes.

        Args:
            host: Console name or id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await network_mobile_wan._impl_routes(client, registry, host, site)


def register_17(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
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

        Sends the Classic POST api/s/{site}/cmd/devmgr command build-ssh-session (action build), ssh-sdp-answer (sdp_answer) or close-ssh-session (close); any other action is sent as the cmd as given and the controller judges it. The Network web app builds the rest of the body at run time and its keys were not recovered from the 11.0.81 bundle, so params is free-form and sent as given beside cmd (no key is added). Returns the Classic envelope {meta, data} verbatim; success requires meta.rc "ok", otherwise the error carries the full upstream body. With dry-run policy, returns the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends nothing. Consequence: build opens a shell channel to the device; close ends it. Other action names execute arbitrary devmgr commands with the consequences of that command; the SSH aliases do not restrict the command set.

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
        return await network_device_operations._impl_ssh(
            client, registry, host, site, action, params
        )

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
        return await network_device_operations._impl_clear(
            client, registry, host, site, device, port_idx, unit_id
        )

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
        return await network_device_operations._impl_clone(
            client, registry, host, site, device, source_device, clone_dry_run
        )

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
        return await network_device_operations._impl_outlet(
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
        return await network_device_operations._impl_recover(
            client, registry, host, site, device, port_idx, unit_id, rps
        )

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
        return await network_device_operations._impl_self_test(client, registry, host, site, device)

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
        return await network_device_operations._impl_alignment(
            client, registry, host, site, device, enabled
        )

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
        return await network_device_operations._impl_priority(
            client, registry, host, site, device, enabled, prefer1, prefer2
        )

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
        return await network_device_operations._impl_rearrange(
            client, registry, host, site, device, enabled
        )

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
        return await network_device_operations._impl_vpn(client, registry, host, site, params)

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
        return await network_device_operations._impl_locate(
            client, registry, host, site, device, port_idx, enabled, unit_id
        )

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
        return await network_device_operations._impl_ubb(client, registry, host, site, device)

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
                selector = network_device_operations._check_device_arg(device)
            network_device_operations._check_object(body, "body")
            require_unmasked_fields(body, "reset_switch_port body")
            guard_action("POST")
            key, host_id, slug = await network_device_operations._site(registry, host, site)
            if port_id is None:
                if is_mac(selector):
                    selector = colon_mac(normalize_mac(selector))
                else:
                    record = await network_device_operations._find_device(
                        client, key, host_id, slug, selector
                    )
                    selector = network_device_operations._mac_of(record)
            segment = path_segment(selector, "port_id" if port_id is not None else "device")
            return await client.post(
                v2_site(host_id, slug, f"/ports/{segment}/reset"), key=key, json=body
            )
        return await network_device_operations._impl_reset_port(
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
        return await network_device_operations._impl_adopt_info(
            client, registry, host, site, device_ref
        )

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
        (free-form). Returns the upstream body verbatim; an HTTP 207 partial failure (a non-empty
        errors list) raises, with the complete body in the error. The estimate is a read sent
        as a POST. The whole tool, including the GET mode, is hidden under UNIFI_WRITE_POLICY=deny.
        With dry-run policy the POST returns the dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}} and sends nothing. Consequence: none on devices; nothing is upgraded.

        Required arguments: host, site (see each parameter's description).

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides
        the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            time_estimate: True to POST the time estimate instead; for example false.
            estimate_body: Body of the time-estimate POST; for example
                {"macs": ["02:00:5e:00:53:01"]}. Free-form object.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await network_device_operations._impl_rolling(
            client, registry, host, site, time_estimate, estimate_body
        )

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
        return await network_device_operations._impl_candidates(
            client, registry, host, site, device
        )

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
        return await network_device_operations._impl_replace(
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
        return await network_device_operations._impl_battery(
            client, registry, host, site, device, battery_ids, action
        )

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
        return await network_device_operations._impl_battery_update(
            client, registry, host, site, device, battery_ids, url
        )

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
        return await network_device_operations._impl_tag_assign(
            client, registry, host, site, assignment_id, body
        )

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
        return await network_device_operations._impl_bulk(
            client, registry, host, site, object_type, payload
        )


def register_18(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the site administration MCP tools."""

    @mcp.tool(annotations=WRITE)
    async def create_site(
        host: str,
        site: str,
        description: str,
    ) -> Any:
        """Create a new Network site on a console that hosts several sites.

        Classic REST POST network/api/s/{site}/cmd/sitemgr with {"cmd": "add-site", "desc":
        description} (the controller UI's request; no published spec): the command is sent
        through an existing site of the console (e.g. "Default"). A UniFi OS
        gateway console has no multi-site support and answers HTTP 400 api.err.NotImplemented
        (Network 11.0.81); multi-site consoles (UniFi OS Server, Cloud Key) create the site.
        Not yet live-tested on a multi-site console.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the new site {_id,
        name (its URL slug), desc}]} (under dry-run policy, the dry-run preview {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query
        parameters), body}} instead).

        Example call (create_site):
            {
              "host": "my-console",
              "site": "Default",
              "description": "Branch office"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: An existing Network site to send the command through (name or UUID, resolved
                server-side), e.g. "Default". Get it from list_local_sites (name or id).
            description: Display name of the new site, e.g. "Branch office".
        """
        client, registry = deps_fn()
        return await site_admin._create_site(client, registry, host, site, description)

    @mcp.tool(annotations=WRITE)
    async def rename_site(
        host: str,
        site: str,
        description: str,
    ) -> Any:
        """Rename a Network site (change its display name).

        Consequence: tools and clients that select the site by its old display name must use
        the new one; the site's id and URL slug do not change.

        Classic REST POST network/api/s/{site}/cmd/sitemgr with {"cmd": "update-site", "desc":
        description} (the controller UI's request; no published spec): it renames the site the
        URL addresses. Verified on Network 11.0.81 with the current name (accepted, rc ok).

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead). Read
        list_local_sites afterwards to see the new name.

        Example call (rename_site):
            {
              "host": "my-console",
              "site": "Default",
              "description": "Head office"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            description: The new display name, e.g. "Head office".
        """
        client, registry = deps_fn()
        return await site_admin._rename_site(client, registry, host, site, description)

    @mcp.tool(annotations=WRITE)
    async def delete_site(
        host: str,
        site: str,
        site_to_delete: str,
    ) -> dict[str, Any]:
        """Delete a Network site and everything configured in it. Consequence: the site and its configuration (networks, WiFi, firewall rules, client records, device settings) are removed; move its devices to another site first. There is no undo.

        The site is resolved in the console's site list (network/api/self/sites) by _id, URL name or display name; an unknown or ambiguous value fails listing the sites and nothing is sent. Then Classic POST network/api/s/{site}/cmd/sitemgr with {"cmd": "delete-site", "site": SITE_ID} (the UI's request; no published spec), sent through another existing site (e.g. "Default"). The controller judges what may be deleted (not the default site). A UniFi OS gateway console has one site; not yet live-tested on a multi-site console. Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the dry-run preview)}.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (delete_site):
            {"host": "my-console", "site": "Default", "site_to_delete": "Branch office"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Another existing Network site to send the command through (name or UUID,
                resolved server-side), e.g. "Default". Get it from list_local_sites (name or id).
            site_to_delete: The site to delete: its _id, URL name or display name, from
                list_local_sites or list_sites, e.g. "Branch office".
        """
        client, registry = deps_fn()
        return await site_admin._delete_site(client, registry, host, site, site_to_delete)


def register_19(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_users(
        host: str,
        site: str,
    ) -> Any:
        """List DHCP fixed-IP reservations and client aliases for a site.

        Returns the Classic REST envelope {meta: {rc}, data: [entry]} verbatim; entries carry name, note, fixed_ip, use_fixedip, network_id.

        Required arguments: host, site.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_users(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_user(
        host: str,
        site: str,
        user_id: str,
    ) -> Any:
        """Get a single DHCP/client-alias entry by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [client-alias/DHCP user
        entry]} verbatim. To change it, edit data[0] and pass it as `payload` to update_user.

        Example call (get_user):
            {"host": "my-console", "site": "Default", "user_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            user_id: Network client-alias/DHCP user _id (classic REST user). Get it from list_users
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_user(client, registry, host, site, user_id)

    @mcp.tool(annotations=WRITE)
    async def update_user(
        host: str,
        site: str,
        user_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a DHCP/client-alias entry by ID.

        The id is resolved in list_users first: an unknown id fails listing every valid _id, and nothing
        is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/user/{id} (classic/v2
        controller API). Pass the controller's native payload; read the current object first with the
        matching list/get tool and send back the edited object.

        Example call (update_user):
            {
              "host": "my-console",
              "site": "Default",
              "user_id": "000000000000000000000107",
              "payload": {"name": "Printer", "note": "2nd floor"}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            user_id: Network client-alias/DHCP user _id (classic REST user). Get it from list_users
                (_id).
            payload: spec: free-form (classic REST user). Fields to change: name, note, fixed_ip,
                use_fixedip, network_id (classic networkconf _id).
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_user(
            client, registry, host, site, user_id, payload
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_traffic_routes(
        host: str,
        site: str,
    ) -> Any:
        """List static/policy traffic routes for a site.

        Returns the v2 API's bare JSON array of routes, verbatim (a list result: structured content
        {result: [...]}).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_traffic_routes(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_traffic_route(
        host: str,
        site: str,
        payload: dict[str, Any],
    ) -> Any:
        """Create a traffic route on a site (policy-based routing / WAN load-balancing). Returns the created route verbatim (under dry-run policy, the dry-run preview).

        `payload` is sent as given; the controller requires (verified live; an upstream error gets a hint naming any missing) network_id (source network UUID from list_networks, or 'ANY'), matching_target ('INTERNET'|'ALL' or a traffic matching list id from list_traffic_matching_lists) and target_devices (the devices/networks it applies to). Optional: matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'), description. This v2 endpoint uses snake_case ('network_id' is accepted, 'networkId' is not). No published schema: send the native payload.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (create_traffic_route):
            {
              "host": "my-console",
              "site": "Default",
              "payload": {
                "network_id": "ANY",
                "matching_target": "INTERNET",
                "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
                "description": "Route via WAN2"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            payload: spec: free-form (Network v2 trafficroutes, snake_case), sent as given. The
                controller requires network_id (list_networks UUID or 'ANY'), matching_target,
                target_devices.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_traffic_route(
            client, registry, host, site, payload
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_traffic_route(
        host: str,
        site: str,
        route_id: str,
    ) -> Any:
        """Get a single traffic route by ID.

        Returns: the traffic route object, verbatim. To change it, edit it and pass it as `payload` to
        update_traffic_route.

        Example call (get_traffic_route):
            {"host": "my-console", "site": "Default", "route_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_traffic_route(
            client, registry, host, site, route_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_traffic_route(
        host: str,
        site: str,
        route_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a traffic route by ID.

        The id is resolved in list_traffic_routes first: an unknown id fails listing every valid _id, and nothing is written.

        Returns the upstream response body verbatim: the updated traffic route object the API answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} instead).

        Request body: no published schema for PUT network/v2/api/site/{site}/trafficroutes/{id}; send the native payload, edited from a prior read.

        Example call (update_traffic_route):
            {
              "host": "my-console",
              "site": "Default",
              "route_id": "000000000000000000000107",
              "payload": {
                "description": "IoT via WAN2",
                "enabled": false,
                "matching_target": "INTERNET",
                "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}]
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
            payload: spec: free-form (Network v2 trafficroutes, snake_case). FULL replacement object;
                start from get_traffic_route output.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_traffic_route(
            client, registry, host, site, route_id, payload
        )

    @mcp.tool(annotations=WRITE)
    async def delete_traffic_route(
        host: str,
        site: str,
        route_id: str,
    ) -> dict[str, Any]:
        """Delete a traffic route by ID.

        Consequence: matching traffic stops following the route and uses the default routing; there is no undo.

        The id is resolved in list_traffic_routes first (the controller answers a DELETE on an unknown id with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

        Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}.

        Example call (delete_traffic_route):
            {"host": "my-console", "site": "Default", "route_id": "000000000000000000000107"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_traffic_route(
            client, registry, host, site, route_id
        )
        return deletion_result(f"Traffic route {route_id} deleted.", response)

    @mcp.tool(annotations=READ_ONLY)
    async def list_settings(
        host: str,
        site: str,
    ) -> Any:
        """List all controller setting groups for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [setting group…]}
        verbatim; data[] holds one object per key (mgmt, super_smtp, guest_access, etc.).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_settings(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_setting(
        host: str,
        site: str,
        setting_key: str,
    ) -> Any:
        """Get a controller setting group by key.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [setting group]} verbatim. To change it, edit data[0] and pass it as `payload` to update_setting.

        There is no schema endpoint, so reading a group is how you discover what it accepts: the returned object lists every settable field and its current (valid) value. Inspect it before calling update_setting — the controller silently drops any field or enum value it does not recognise, so match an existing field's shape exactly. Common keys and notable enum fields (grounded in live responses): mdns (mode, enabled_for), ntp (setting_preference), doh (state), ips (ips_mode), global_nat (mode), ssl_inspection (state), dashboard (layout_preference), locale (timezone), country (code), guest_access (auth), super_mgmt (data_retention_setting_preference). Fields prefixed 'x_' hold credentials/secrets and are returned verbatim (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site, setting_key (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            setting_key: setting group identifier (e.g. 'mgmt', 'super_smtp', 'guest_access').
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_setting(client, registry, host, site, setting_key)

    @mcp.tool(annotations=WRITE)
    async def update_setting(
        host: str,
        site: str,
        setting_key: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a controller setting group by key. Call get_setting(setting_key) first: it lists every settable field and its valid value.

        The controller silently drops unrecognised fields or enum values (HTTP 200, unchanged); this tool walks the payload leaf by leaf (a nested object is a partial update) and reports each rejected leaf by dotted path (e.g. radius.port) in _unverifiedFields and _verificationNote.

        Returns the PUT envelope {meta: {rc}, data: [setting group]} verbatim plus _verified: true only when the read-after confirms every leaf (type-strict: true is not 1), false with _unverifiedFields when a leaf was rejected or changed, null with _readAfterError when the read-after failed (the write was still sent). If every field already holds the sent value, no PUT is made: the GET envelope plus _note "no change needed". Under dry-run policy nothing is sent: the bare preview.

        No published schema for PUT network/api/s/{site}/rest/setting/{setting_key}; send the native payload edited from get_setting.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_setting):
            {"host": "my-console", "site": "Default", "setting_key": "mgmt",
             "payload": {"led_enabled": false}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            setting_key: Classic setting group key, e.g. 'mgmt', 'super_smtp', 'guest_access'. Get keys
                from list_settings (data[].key). Keys a Network 11.0.81 site reports: auto_speedtest,
                connectivity, country, dashboard, device_supervision, doh, dpi, element_adopt,
                ether_lighting, global_nat, global_network, global_switch, guest_access,
                igmp_snooping, ips, ips_suppression, ipsec, lcm, locale, magic_site_to_site_vpn, mdns,
                mgmt, netflow, network_optimization, ntp, openvpn, peer_to_peer,
                provider_capabilities, radio_ai, radius, rsyslogd, snmp, ssl_inspection,
                super_cloudaccess, super_fabric_system_log, super_fwupdate, super_identity,
                super_mail, super_mgmt, super_smtp, super_stats, teleport, traffic_flow, ugw, usg,
                usg_geo (super_* groups are console-wide). Groups holding credentials in x_-prefixed
                fields: connectivity, element_adopt, guest_access, magic_site_to_site_vpn, mgmt,
                openvpn, radius, snmp, super_cloudaccess, super_fwupdate, super_smtp.
            payload: spec: free-form (classic REST setting). Call get_setting(setting_key) first and
                change only fields it returns; unknown fields/enums are reported separately in
                verification metadata.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_setting(
            client, registry, host, site, setting_key, payload
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_dynamic_dns(
        host: str,
        site: str,
    ) -> Any:
        """List Dynamic DNS provider configurations for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_dynamic_dns(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_dynamic_dns(
        host: str,
        site: str,
        ddns_id: str,
    ) -> Any:
        """Get a single Dynamic DNS configuration by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [Dynamic DNS entry]}
        verbatim. To change it, edit data[0] and pass it as `payload` to update_dynamic_dns.

        Returned verbatim, including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Example call (get_dynamic_dns):
            {"host": "my-console", "site": "Default", "ddns_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            ddns_id: Dynamic DNS entry _id (classic REST dynamicdns). Get it from list_dynamic_dns
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_dynamic_dns(client, registry, host, site, ddns_id)

    @mcp.tool(annotations=WRITE)
    async def update_dynamic_dns(
        host: str,
        site: str,
        ddns_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a Dynamic DNS configuration by ID.

        The id is resolved in list_dynamic_dns first: an unknown id fails listing every valid _id, and nothing is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]} verbatim (meta is relayed as received, never interpreted). Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema for PUT network/api/s/{site}/rest/dynamicdns/{id}; send the native payload, edited from a prior read.

        Example call (update_dynamic_dns):
            {"host": "my-console", "site": "Default", "ddns_id": "000000000000000000000107",
             "payload": {"service": "dyndns", "host_name": "home.example.com"}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            ddns_id: Dynamic DNS entry _id (classic REST dynamicdns). Get it from list_dynamic_dns
                (_id).
            payload: spec: free-form (classic REST dynamicdns). Native fields: service (e.g.
                dyndns, cloudflare, custom), host_name, login, x_password, server (for custom),
                interface (wan, wan2). Read the current object via get_dynamic_dns and send it
                back edited.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_dynamic_dns(
            client, registry, host, site, ddns_id, payload
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_port_profiles(
        host: str,
        site: str,
    ) -> Any:
        """List switch port profiles (speed, VLAN, PoE config) for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [profile…]}, each profile
        verbatim (networkconf id fields stay bare Classic _ids). A profile that references networks
        also carries an additive _resolved_networks key mapping excluded_networkconf_ids /
        native_networkconf_id / voice_networkconf_id to {id, name, vlan} (id there is the Classic
        networkconf _id); it is not a controller field and update_port_profile ignores it.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_port_profiles(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_port_profile(
        host: str,
        site: str,
        profile_id: str,
    ) -> Any:
        """Get a single switch port profile by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [port profile]}
        verbatim, plus an additive _resolved_networks key on the profile mapping its networkconf ids
        to {id, name, vlan}. To change it, edit data[0] and pass it as `payload` to
        update_port_profile (the _resolved_networks key is dropped before the write).

        Example call (get_port_profile):
            {"host": "my-console", "site": "Default", "profile_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_port_profile(
            client, registry, host, site, profile_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_port_profile(
        host: str,
        site: str,
        profile_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a switch port profile by ID. WARNING -- SHARED PROFILE, WIDE BLAST RADIUS: this edits a shared Ethernet Port Profile (Classic /rest/portconf), not one switch or port. One write changes STP/PoE/storm-control/VLAN for EVERY port on EVERY switch using it; never present it as a per-port or per-device STP-priority or PoE-mode writer (no such route exists via this API). Check the profile's assignments and blast radius before writing.

        The id is resolved in list_port_profiles first (an unknown id fails listing every valid _id; nothing written). No published schema for PUT network/api/s/{site}/rest/portconf/{id}: send the native payload edited from a prior read.

        Returns the PUT envelope {meta: {rc}, data: [port profile]} verbatim (profile plus _resolved_networks). Under dry-run policy nothing is sent: the bare preview.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_port_profile):
            {"host": "my-console", "site": "Default", "profile_id": "000000000000000000000107",
             "payload": {"poe_mode": "auto"}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
            payload: spec: free-form (classic REST portconf). Fields to change, e.g. speed,
                native_networkconf_id, op_mode, poe_mode. Read current via get_port_profile; its
                additive _resolved_networks key is dropped before the write.
                native_networkconf_id, voice_networkconf_id and excluded_networkconf_ids accept a
                Classic networkconf _id or the Integration id from list_networks (data[].id), which
                the tool converts to the _id before the PUT (a value the profile already holds
                passes unchanged); an unknown value fails listing every network (name, _id, id),
                and no PUT is sent.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_port_profile(
            client, registry, host, site, profile_id, payload
        )

    @mcp.tool(annotations=WRITE)
    async def allow_network_on_port_profile(
        host: str,
        site: str,
        profile_id: str,
        network_id: str,
        confirm: bool = False,
    ) -> Any:
        """Allow (un-exclude) a VLAN network on a switch port profile: the remediation for create_network's D12_AUTO_EXCLUSION warning (run it on every profile named there). Validates network_id, fresh-reads the profile, removes the network from excluded_networkconf_ids and PUTs.

        `confirm` is accepted and ignored: this is a live PUT to a SHARED port profile (its exclusion list affects every switch port using it) and runs at once. The read-then-PUT is not atomic against concurrent edits. network_id is the Integration id (list_networks data[].id) or the Classic networkconf _id (mapped through /rest/networkconf external_id); an unknown id fails before any write, listing every network (name, vlan, _id, id).

        Returns the PUT envelope {meta: {rc}, data: [profile]} verbatim (profile plus _resolved_networks) plus _tagged_networks (resulting tagged VLANs with names) and _network ({_id, id, name, vlan}); _profileNote only when the PUT response data holds no profile. Under dry-run policy nothing is sent: the bare preview. No published spec for network/api/s/{site}/rest/portconf.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
            network_id: Network (networkconf) id to (un)exclude. Get it from list_networks (data[].id)
                or list_port_profiles (_resolved_networks).
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is
                sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await network_services_proxy.allow_network_on_port_profile(
            client, registry, host, site, profile_id, network_id, confirm=confirm
        )

    @mcp.tool(annotations=WRITE)
    async def exclude_network_on_port_profile(
        host: str,
        site: str,
        profile_id: str,
        network_id: str,
        confirm: bool = False,
    ) -> Any:
        """Exclude (untag) a VLAN network from a switch port profile; inverse of allow_network_on_port_profile. Validates network_id, fresh-reads the profile, adds the network's _id to excluded_networkconf_ids and PUTs.

        `confirm` is accepted and ignored: this is a live PUT to a SHARED port profile (its exclusion list affects every switch port using it) and runs at once. The read-then-PUT is not atomic against concurrent edits. network_id is the Integration id (list_networks data[].id) or the Classic networkconf _id (mapped through /rest/networkconf external_id); an unknown id fails before any write, listing every network (name, vlan, _id, id).

        Returns the PUT envelope {meta: {rc}, data: [profile]} verbatim (profile plus _resolved_networks) plus _tagged_networks (resulting tagged VLANs with names) and _network ({_id, id, name, vlan}); _profileNote only when the PUT response data holds no profile. Under dry-run policy nothing is sent: the bare preview. No published spec for network/api/s/{site}/rest/portconf.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
            network_id: Network (networkconf) id to (un)exclude. Get it from list_networks (data[].id)
                or list_port_profiles (_resolved_networks).
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is
                sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await network_services_proxy.exclude_network_on_port_profile(
            client, registry, host, site, profile_id, network_id, confirm=confirm
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_routing_entries(
        host: str,
        site: str,
    ) -> Any:
        """List static routing table entries for a site.

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
        return await network_services_proxy.list_routing_entries(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_wlan_configs(
        host: str,
        site: str,
    ) -> Any:
        """List per-SSID WLAN configurations (security, band steering, rate limits) for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_passphrase credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_wlan_configs(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_wlan_config(
        host: str,
        site: str,
        wlan_id: str,
    ) -> Any:
        """Get a single WLAN (SSID) configuration by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [WLAN configuration]}
        verbatim. To change it, edit data[0] and pass it as `payload` to update_wlan_config.

        Returned verbatim, including x_passphrase credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Example call (get_wlan_config):
            {"host": "my-console", "site": "Default", "wlan_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            wlan_id: Classic WLAN config _id (wlanconf). Get it from list_wlan_configs (_id). Not a wifi
                broadcast UUID.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_wlan_config(client, registry, host, site, wlan_id)

    @mcp.tool(annotations=WRITE)
    async def update_wlan_config(
        host: str,
        site: str,
        wlan_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a WLAN (SSID) configuration by ID.

        The id is resolved in list_wlan_configs first: an unknown id fails listing every valid _id, and
        nothing is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/wlanconf/{id}
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (update_wlan_config):
            {
              "host": "my-console",
              "site": "Default",
              "wlan_id": "000000000000000000000107",
              "payload": {"enabled": false}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            wlan_id: Classic WLAN config _id (wlanconf). Get it from list_wlan_configs (_id). Not a wifi
                broadcast UUID.
            payload: spec: free-form (classic REST wlanconf). Fields to change, e.g. x_passphrase,
                security, enabled. Read current via get_wlan_config.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_wlan_config(
            client, registry, host, site, wlan_id, payload
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_wlan_groups(
        host: str,
        site: str,
    ) -> Any:
        """List WLAN groups for a site.

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
        return await network_services_proxy.list_wlan_groups(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_wlan_group(
        host: str,
        site: str,
        group_id: str,
    ) -> Any:
        """Get a single WLAN group by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Reads the Classic REST /rest/wlangroup collection and returns that envelope
        {meta: {rc}, data: [group]} with data narrowed to the group whose _id matches; an unknown id
        fails listing the valid groups (name and _id). The controller rejects
        GET /rest/wlangroup/{id} with HTTP 400 api.err.InvalidObject for every id, including
        the built-in Default group, so the collection route is the supported read. The
        matching entry is returned unchanged.

        Example call (get_wlan_group):
            {"host": "my-console", "site": "Default", "group_id": "000000000000000000000001"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            group_id: Classic WLAN group _id. Get it from list_wlan_groups (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_wlan_group(client, registry, host, site, group_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_channel_plan(
        host: str,
        site: str,
    ) -> Any:
        """Get RF channel assignments and DFS status for a site.

        Returns the controller's Classic REST envelope {meta: {rc}, data: [channel plan…]} verbatim;
        an empty data array means the controller has no channel plan stored (for example,
        auto-channel optimization has not run).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_channel_plan(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_rogue_aps(
        host: str,
        site: str,
        rogue_only: bool = False,
    ) -> Any:
        """List neighboring APs detected by the site's radios.

        Returns ALL neighboring APs (most will have is_rogue=false and are benign neighbors).
        Only a small subset with is_rogue=true are confirmed rogue APs. Set rogue_only=true to
        filter to confirmed rogues only.

        Returns: the controller's Classic REST /stat/rogueap envelope {meta: {rc}, data: [ap…]}
        verbatim (with rogue_only, data is narrowed to is_rogue=true entries); entries carry BSSID,
        SSID, channel, signal strength, is_rogue flag, and detection time.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rogue_only: When true, return only confirmed rogue APs (is_rogue=true). Default false
                returns every neighboring AP, most of them benign.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_rogue_aps(
            client, registry, host, site, rogue_only=rogue_only
        )

    return {
        "list_users": list_users,
        "get_user": get_user,
        "update_user": update_user,
        "list_traffic_routes": list_traffic_routes,
        "create_traffic_route": create_traffic_route,
        "get_traffic_route": get_traffic_route,
        "update_traffic_route": update_traffic_route,
        "delete_traffic_route": delete_traffic_route,
        "list_settings": list_settings,
        "get_setting": get_setting,
        "update_setting": update_setting,
        "list_dynamic_dns": list_dynamic_dns,
        "get_dynamic_dns": get_dynamic_dns,
        "update_dynamic_dns": update_dynamic_dns,
        "list_port_profiles": list_port_profiles,
        "get_port_profile": get_port_profile,
        "update_port_profile": update_port_profile,
        "allow_network_on_port_profile": allow_network_on_port_profile,
        "exclude_network_on_port_profile": exclude_network_on_port_profile,
        "list_routing_entries": list_routing_entries,
        "list_wlan_configs": list_wlan_configs,
        "get_wlan_config": get_wlan_config,
        "update_wlan_config": update_wlan_config,
        "list_wlan_groups": list_wlan_groups,
        "get_wlan_group": get_wlan_group,
        "get_channel_plan": get_channel_plan,
        "list_rogue_aps": list_rogue_aps,
    }


def register_20(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy tool wrappers that follow its firewall run, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_accounts(
        host: str,
        site: str,
    ) -> Any:
        """List local RADIUS user accounts for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_accounts(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_account(
        host: str,
        site: str,
        account_id: str,
    ) -> Any:
        """Get a single RADIUS account by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Example call (get_account):
            {"host": "my-console", "site": "Default", "account_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            account_id: RADIUS account _id (classic REST account). Get it from list_accounts (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_account(client, registry, host, site, account_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_hotspot_packages(
        host: str,
        site: str,
    ) -> Any:
        """List guest portal billing packages for a site.

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
        return await network_services_proxy.list_hotspot_packages(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_hotspot_package(
        host: str,
        site: str,
        package_id: str,
    ) -> Any:
        """Get a single hotspot billing package by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_hotspot_package):
            {"host": "my-console", "site": "Default", "package_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            package_id: Hotspot package _id (classic REST hotspotpackage). Get it from
                list_hotspot_packages (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_hotspot_package(
            client, registry, host, site, package_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_scheduled_tasks(
        host: str,
        site: str,
    ) -> Any:
        """List scheduled tasks (firmware upgrade schedules, speed tests) for a site.

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
        return await network_services_proxy.list_scheduled_tasks(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_scheduled_task(
        host: str,
        site: str,
        task_id: str,
    ) -> Any:
        """Get a single scheduled task by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_scheduled_task):
            {"host": "my-console", "site": "Default", "task_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            task_id: Scheduled task _id (classic REST scheduletask). Get it from list_scheduled_tasks
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_scheduled_task(
            client, registry, host, site, task_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_dpi_categories(
        host: str,
        site: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List DPI (Deep Packet Inspection) app categories available for traffic rules.

        Returns {data, totalCount}: every page is drained; data holds the DPI category records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        Categories include Social Media, Streaming Video, Gaming, etc.
        By default every page is drained and the complete catalogue is returned as
        {data, totalCount}. Pass offset alone to fetch a single page manually. A
        capped drain returns the categories gathered so far with incomplete=true
        rather than truncating silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Optional. DPI data is host-level, so a site does not narrow the result; when
                given it must name a site on the console (an unknown site is rejected with the
                valid site names).
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
                Example: `name.eq('Business')`."""
        client, registry = deps_fn()
        await _validate_optional_site(registry, host, site)
        return await network_services_proxy.list_dpi_categories(
            client, registry, host, offset, limit, filter=filter
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_dpi_applications(
        host: str,
        site: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List DPI applications available for traffic rules.

        Returns {data, totalCount}: every page is drained; data holds the DPI application records
        verbatim and totalCount is the upstream total (null when none was reported). The first page's
        other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short.

        Companion to list_dpi_categories; use application IDs in traffic rule configurations.
        By default every page is drained and the complete catalogue is returned as
        {data, totalCount}. Pass offset alone to fetch a single page manually. A
        capped drain returns the applications gathered so far with incomplete=true
        rather than truncating silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Optional. DPI data is host-level, so a site does not narrow the result; when
                given it must name a site on the console (an unknown site is rejected with the
                valid site names).
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
                Example: `name.eq('Zoom')`."""
        client, registry = deps_fn()
        await _validate_optional_site(registry, host, site)
        return await network_services_proxy.list_dpi_applications(
            client, registry, host, offset, limit, filter=filter
        )

    return {
        "list_accounts": list_accounts,
        "get_account": get_account,
        "list_hotspot_packages": list_hotspot_packages,
        "get_hotspot_package": get_hotspot_package,
        "list_scheduled_tasks": list_scheduled_tasks,
        "get_scheduled_task": get_scheduled_task,
        "list_dpi_categories": list_dpi_categories,
        "list_dpi_applications": list_dpi_applications,
    }
