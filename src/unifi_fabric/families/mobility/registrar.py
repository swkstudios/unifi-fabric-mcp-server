"""The mobility family registrar: its tool wrappers, in registration order (the family-owned
layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from ...shared_shapes._shared import _nullable_default
from ...tool_annotations import READ_ONLY, WRITE
from . import mobility


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the mobility tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_workspaces(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List UniFi Mobility workspaces visible to the authenticated API key.

        Returns the upstream body verbatim ({data, total, offset, limit, httpStatusCode, traceId}) plus
        _count; incomplete / incompleteReason when total exceeds the rows returned. With several keys:
        {data, _count, _key_labels, byKey} plus errors.

        A workspace is a mobility "cloud site" (workspace_id, workspace_name, is_owner,
        status). Returned verbatim. Not query-paginated by the API. Mobility identity is
        workspace-based and independent of the console host/site model.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to cover
                every configured key: results are merged, each record carries an additive _keyLabel, and
                a key that fails is reported under errors.
        """
        client, _ = deps_fn()
        return await mobility.list_mobility_workspaces(client, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_admins(
        workspace_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List the admins of a Mobility workspace (mobility permissions only).

        Returns the upstream body verbatim ({data, total, offset, limit, httpStatusCode, traceId}) plus
        _count; incomplete / incompleteReason when total exceeds the rows returned.

        Each admin carries name, email, status, is_owner and a permissions object
        exposing the umr (Mobile Routing) level (ALL/VIEW_ONLY/NONE); permissions is
        null for a pending invite. Returned verbatim.

        Example call (list_mobility_admins):
            {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.list_mobility_admins(client, workspace_id, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_devices(
        workspace_id: str,
        key_label: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List the UMR devices in a Mobility workspace.

        Returns {data, _count} plus the first page's other envelope fields (httpStatusCode,
        traceId); total (the upstream total, never computed) only when the upstream sent an
        integer one; incomplete / incompleteReason when the drain stopped short.

        Each device is the lightweight summary (id, name, model, state,
        firmware_version, mac_address). Offset-paginated by the API (limit/offset, 200
        max); every page is drained. Pass offset alone to fetch a single manual page (the
        upstream page body verbatim).

        Example call (list_mobility_devices):
            {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is gathered
                across pages of at most 200 starting at offset. Omit offset and limit to drain
                all.
                Example: `25`."""
        client, _ = deps_fn()
        return await mobility.list_mobility_devices(
            client, workspace_id, key_label=key_label, offset=offset, limit=limit
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_mobility_device(
        workspace_id: str,
        device_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get full detail for one UMR device in a Mobility workspace.

        Returns the upstream response object verbatim: the complete DeviceDetail
        (WAN/cellular/WiFi/VPN/subscription/GPS, counts, and the summary fields) under data,
        beside every other envelope field the API sends.

        Example call (get_mobility_device):
            {
              "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.get_mobility_device(
            client, workspace_id, device_id, key_label=key_label
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_mobility_clients(
        workspace_id: str,
        device_id: str,
        key_label: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List the clients associated with a UMR device.

        Returns {data, _count} plus the first page's other envelope fields (httpStatusCode,
        traceId); total (the upstream total, never computed) only when the upstream sent an
        integer one; incomplete / incompleteReason when the drain stopped short.

        Each client carries mac, name, type (WIRED/WIRELESS), connection_status,
        ip_address, is_blocked and (wireless only) a wifi_experience score.
        Offset-paginated by the API (limit/offset, 200 max); every page is drained. Pass
        offset alone to fetch a single manual page (the upstream page body verbatim).

        Example call (list_mobility_clients):
            {
              "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is gathered
                across pages of at most 200 starting at offset. Omit offset and limit to drain
                all.
                Example: `25`."""
        client, _ = deps_fn()
        return await mobility.list_mobility_clients(
            client, workspace_id, device_id, key_label=key_label, offset=offset, limit=limit
        )

    @mcp.tool(annotations=WRITE)
    async def update_mobility_device_name(
        workspace_id: str,
        device_id: str,
        name: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Rename a UMR device (guarded write; mutates live config). PUT /v1/mobility/workspaces/{workspaceID}/devices/{deviceID} with {"name": name} (1-32 chars). Guarded, in order: family:mobility=deny refuses first (writes are on by default), read-before, no-op ("no_op" when already named this), write, read-after.

        Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null} (the whole map null with readAfterError when the read-after fails), device (read-after GET body), response (PUT body; null for the documented 204)}, or {status: "no_op", reason, device}. Under dry-run policy nothing is sent: {status: "dry_run", device (the body read first), response (the dry-run preview)}; no read-after.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_mobility_device_name):
            {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "name": "Van 12"}

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            name: New device name, 1-32 chars (spec UpdateDeviceNameReq.name).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.update_mobility_device_name(
            client, workspace_id, device_id, name, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def update_mobility_device_network(
        workspace_id: str,
        device_id: str,
        host_address: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_mode: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_range_start: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_range_stop: str | None = Field(default_factory=lambda: mobility._UNSET),
        dhcp_lease_time: int | None = Field(default_factory=lambda: mobility._UNSET),
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Update a UMR device's LAN/DHCP settings (guarded write; mutates live config). PUT /v1/mobility/workspaces/{workspaceID}/devices/{deviceID}.

        Partial: only provided fields apply (WAN/IPv6/InternetSource are not configurable here); at least one is required. The Mobility docs differ on PUT semantics; if the console does full replacement, unsent LAN/DHCP fields can reset. dhcp_mode is 'dhcp' or 'none'; IPs must be dotted-quad IPv4 (a leading-zero octet is refused before any request); dhcp_lease_time is seconds (0 = infinite). explicit null is forwarded; omitted stays unchanged. Guarded, in order: family:mobility=deny refuses first (add it to UNIFI_WRITE_EXCEPTIONS to make Mobility read-only), read-before, no-op on the observable host_address, write, read-after.

        Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null} (the whole map null with readAfterError when the read-after fails), device (read-after GET body), response (PUT body; null for the documented 204)}, or {status: "no_op", reason, device}. Under dry-run policy nothing is sent: {status: "dry_run", device (the body read first), response (the dry-run preview)}; no read-after.

        Required arguments: workspace_id, device_id.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            host_address: Optional new LAN gateway IPv4 (spec UpdateNetworkReq).
            dhcp_mode: Optional 'dhcp' or 'none'.
            dhcp_range_start: Optional DHCP pool start IPv4.
            dhcp_range_stop: Optional DHCP pool end IPv4.
            dhcp_lease_time: Optional lease seconds (>=0; 0 = infinite).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        host_address = _nullable_default(host_address, mobility._UNSET)
        dhcp_mode = _nullable_default(dhcp_mode, mobility._UNSET)
        dhcp_range_start = _nullable_default(dhcp_range_start, mobility._UNSET)
        dhcp_range_stop = _nullable_default(dhcp_range_stop, mobility._UNSET)
        dhcp_lease_time = _nullable_default(dhcp_lease_time, mobility._UNSET)
        client, _ = deps_fn()
        return await mobility.update_mobility_device_network(
            client,
            workspace_id,
            device_id,
            host_address=host_address,
            dhcp_mode=dhcp_mode,
            dhcp_range_start=dhcp_range_start,
            dhcp_range_stop=dhcp_range_stop,
            dhcp_lease_time=dhcp_lease_time,
            confirm=confirm,
            key_label=key_label,
        )

    @mcp.tool(annotations=WRITE)
    async def update_mobility_device_wireless(
        workspace_id: str,
        device_id: str,
        ssid: str,
        password: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Update a UMR device's WiFi SSID and password (guarded write; mutates live config). PUT .../devices/{deviceID}/wireless.

        Both fields required (ssid 1-32 chars; password a WPA2-PSK secret of 8-63 chars). Guarded, in order: family:mobility=deny refuses first, read-before, write, read-after. No no-op short-circuit (the password is unobservable). The password is not echoed back; under dry-run policy the preview body shows it (masked as ***REDACTED*** only when UNIFI_REDACT_SECRETS is on).

        Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null} (the whole map null with readAfterError when the read-after fails), device (read-after GET body), response (PUT body; null for the documented 204)}; never no_op. Under dry-run policy nothing is sent: {status: "dry_run", device (the body read first), response (the dry-run preview)}; no read-after.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_mobility_device_wireless):
            {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "ssid": "Fleet-WiFi",
             "password": "correct-horse-9"}

        Args:
            workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
            device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
                Mobility id — not a Network device UUID.
            ssid: New SSID, 1-32 chars (spec UpdateWirelessReq.ssid).
            password: New WPA2-PSK, 8-63 chars (spec UpdateWirelessReq.password).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await mobility.update_mobility_device_wireless(
            client, workspace_id, device_id, ssid, password, confirm=confirm, key_label=key_label
        )

    return {
        "list_mobility_workspaces": list_mobility_workspaces,
        "list_mobility_admins": list_mobility_admins,
        "list_mobility_devices": list_mobility_devices,
        "get_mobility_device": get_mobility_device,
        "list_mobility_clients": list_mobility_clients,
        "update_mobility_device_name": update_mobility_device_name,
        "update_mobility_device_network": update_mobility_device_network,
        "update_mobility_device_wireless": update_mobility_device_wireless,
    }
