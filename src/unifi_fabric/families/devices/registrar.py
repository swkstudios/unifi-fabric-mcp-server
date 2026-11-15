"""The devices family registrar: its tool wrappers, in registration order (the family-owned layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import StrictInt

from ...shared_shapes._results import deletion_result
from ...tool_annotations import READ_ONLY, WRITE
from . import (
    device_commands,
    device_mgmt,
    device_radios,
    scheduled_tasks,
    switch_port_overrides,
    wifi_diagnosis,
)
from .schemas import PortOverrideChange, RadioChanges


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all device management MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_site_devices(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all adopted devices for a site via connector proxy.

        Returns {data, totalCount}: every page is drained; data holds the device records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short.

        By default every page is drained and the complete device list is returned.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually (the
                API's totalCount is surfaced so you can advance).
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain every page.
                Example: `25`.
            filter: optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `state.eq('ONLINE')`, `model.eq('U6 Pro')`); omitted entirely when unset. A capped
                drain returns the devices gathered so far with incomplete=true rather than
                truncating silently.
                Example: `name.eq('Office Switch')`.
        """
        client, registry = deps_fn()
        return await device_mgmt._list_site_devices(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def adopt_device(
        host: str,
        site: str,
        device: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Adopt a device onto a site.

        Consequence: the site's controller takes over and provisions the device, which may restart
        while it applies its new configuration.

        Returns the upstream response body verbatim: the adopted device object the API answers with
        .

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/devices (adoptDevice); schema
        "IntegrationDeviceAdoptionRequestDto") is passed in `device`. Required keys —
        ignoreDeviceLimit, macAddress.
        - ignoreDeviceLimit: boolean
        - macAddress: string

        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#adopt_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device: Request body; spec IntegrationDeviceAdoptionRequestDto. Required:
                ignoreDeviceLimit, macAddress.
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await device_mgmt._adopt_device(client, registry, host, site, device)

    @mcp.tool(annotations=READ_ONLY)
    async def get_device(
        host: str,
        site: str,
        device_id: str,
    ) -> Any:
        """Get details for a single adopted device.

        Returns the upstream device object verbatim, exactly as the API answers it.

        Example call (get_device):
            {
              "host": "my-console",
              "site": "Default",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: Adopted device UUID or MAC (AA:BB:CC:DD:EE:FF, AABBCCDDEEFF, aa-bb-...). Get
                it from list_site_devices (data[].id). Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await device_mgmt._get_device(client, registry, host, site, device_id)

    @mcp.tool(annotations=WRITE)
    async def unadopt_device(
        host: str,
        site: str,
        device_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Unadopt (remove) a device from a site.

        Consequence: removes the device's association with the site; it must be re-adopted to be
        managed again.

        Returns {deleted: true, message, response}, with the upstream DELETE body in response (JSON,
        text or null). Under dry-run policy nothing is sent; returns {status: "dry_run", deleted:
        false, message, response: {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}}. Never automatically retried.

        Example: docs/TOOL-USAGE.md#unadopt_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        response = await device_mgmt._unadopt_device(client, registry, host, site, device_id)
        return deletion_result(f"Device {device_id} unadopted.", response)

    @mcp.tool(annotations=WRITE)
    async def execute_device_action(
        host: str,
        site: str,
        device_id: str,
        action: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Execute an action on an adopted device via the Network Integration actions route (POST /v1/sites/{siteId}/devices/{deviceId}/actions, Network 11.0.97).

        Consequence: RESTART reboots the device, offline (and its clients or downstream devices interrupted) until it comes back.

        `action` is {"action": "RESTART"}; RESTART is the only variant in the published schema, and the controller rejects any other value with HTTP 400 api.request.unknown-type-id (verified live). For the locate LED use locate_device, for firmware upgrade_device (both Classic cmd/devmgr); adopt a pending device with adopt_device or approve_pending_device. Returns the upstream action-result object verbatim. Not auto-retried on HTTP 429: a retry could repeat the action. Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#execute_device_action.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            action: Action body; spec Device action request. Required: action. 'action' selects
                variant: RESTART.
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await device_mgmt._execute_device_action(
            client, registry, host, site, device_id, action
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_device_statistics(
        host: str,
        site: str,
        device_id: str,
    ) -> Any:
        """Get latest statistics for a device.

        Returns the upstream latest-statistics object verbatim, exactly as the API answers it.

        Example call (get_device_statistics):
            {
              "host": "my-console",
              "site": "Default",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: Adopted device UUID or MAC (AA:BB:CC:DD:EE:FF, AABBCCDDEEFF, aa-bb-...). Get
                it from list_site_devices (data[].id). Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await device_mgmt._get_device_statistics(client, registry, host, site, device_id)

    @mcp.tool(annotations=WRITE)
    async def execute_port_action(
        host: str,
        site: str,
        device_id: str,
        port_idx: int,
        action: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Execute a device port action (POST /v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions, Network 11.0.97).

        Consequence: POWER_CYCLE cuts port PoE power; the device reboots and is offline until it comes back.

        OPERATIONAL-ACTION-ONLY, NOT A CONFIG WRITER: it performs a transient action and persists no port configuration. `action` ({'action': str}) is forwarded verbatim; only {'action': 'POWER_CYCLE'} is valid (the spec's one value): it powers a PoE-capable port off and on. The controller rejects any other value (e.g. 'set-poe-mode') with HTTP 400 'unknown-type-id', leaving the port unchanged (verified live). Never use it for PoE mode, STP, VLAN or other persistent settings: there is no per-port config writer on this API, and a shared Ethernet Port Profile (update_port_profile) has a wide blast radius. Not auto-retried on HTTP 429. Returns the upstream body verbatim. Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}, _consequence}.

        Example call (execute_port_action):
            {"host": "my-console", "site": "Default",
             "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "port_idx": 1,
             "action": {"action": "POWER_CYCLE"}}

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            port_idx: 1-based physical switch port number.
            action: Port action body; required field action must be "POWER_CYCLE".
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await device_mgmt._execute_port_action(
            client, registry, host, site, device_id, port_idx, action
        )

    @mcp.tool(annotations=WRITE)
    async def restart_device(
        host: str,
        site: str,
        device_id: str,
        confirm: bool = False,
        reboot_type: str | None = None,
    ) -> Any:
        """Restart an adopted device.

        Consequence: the device reboots and is offline (and its clients or downstream devices interrupted) until it comes back.

        Omit reboot_type to use the Integration restart: {"action": "RESTART"} to POST /v1/sites/{siteId}/devices/{deviceId}/actions (Network 11.0.97; its only variant). Set reboot_type soft or hard to use Classic cmd/devmgr with {cmd: restart, macs: [mac], reboot_type}; hard also power-cycles PoE ports, interrupting powered downstream devices. Transport failure leaves the outcome unknown; read back before retrying. Returns the upstream body verbatim. Not auto-retried on HTTP 429. Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#restart_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
            reboot_type: Optional Classic reboot type, e.g. "hard" or "soft"; omitted
                selects the existing Integration RESTART route.
        """
        client, registry = deps_fn()
        return await device_mgmt._restart_device(
            client, registry, host, site, device_id, reboot_type
        )

    @mcp.tool(annotations=WRITE)
    async def locate_device(
        host: str,
        site: str,
        device_id: str,
        enabled: bool = True,
        confirm: bool = False,
    ) -> Any:
        """Toggle the locate LED on an adopted device.

        Consequence: the LED flashes until locate is turned off (enabled=false).

        Locate is not in the published Integration device-action schema (only RESTART), so this uses the Classic device manager: POST network/api/s/{site}/cmd/devmgr with {"cmd": "set-locate", "mac": ...} (enabled=true) or {"cmd": "unset-locate", "mac": ...} (enabled=false). A device UUID is resolved to its MAC with the Integration device GET. Returns the Classic envelope {meta: {rc}, data: [...]} verbatim (verified live). Not auto-retried on HTTP 429: a retry could repeat the action. Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#locate_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            enabled: true = start locate LED blink, false = stop.
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await device_mgmt._locate_device(client, registry, host, site, device_id, enabled)

    @mcp.tool(annotations=WRITE)
    async def upgrade_device(
        host: str,
        site: str,
        device_id: str,
        confirm: bool = False,
        firmware_url: str | None = None,
    ) -> Any:
        """Trigger a firmware upgrade on an adopted device.

        Consequence: the device installs the firmware and reboots, and is offline until it comes back. On an MC-LAG pair, check that the peer switch is online first: the Network 11.1.47 web app blocks an upgrade while the peer is offline, and this server adds no such check.

        Upgrade is not in the published Integration device-action schema (only RESTART), so this uses the Classic device manager: POST network/api/s/{site}/cmd/devmgr with {"cmd": "upgrade", "mac": ...}, upgrading to the controller's cached latest firmware. With firmware_url, POST cmd/devmgr/upgrade-external sends {url: firmware_url, macs: [mac]}; choose compatible firmware, since an incorrect image can prevent booting. That route is source-defined and needs live testing. A device UUID is resolved to its MAC with the Integration device GET. Returns the Classic envelope {meta: {rc}, data: [...]} verbatim. Transport failure leaves the outcome unknown; read back before retrying. Not auto-retried on HTTP 429. Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#upgrade_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
            firmware_url: Optional http or https firmware image URL; empty selects the standard
                upgrade.
                Omit to use the controller cached latest firmware.
        """
        client, registry = deps_fn()
        return await device_mgmt._upgrade_device(
            client, registry, host, site, device_id, firmware_url
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_pending_devices(
        host: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List devices pending adoption on a console.

        Returns {data, totalCount} with every page drained (the API pages at 25 by default).
        limit alone requests a total gathered from the start in pages of at most 200 (_pageSize
        reports the sizes); pass offset to fetch a single manual page (native envelope preserved).
        Pending devices are identified by data[].macAddress (pass it to approve_pending_device to
        adopt, or to forget_device to remove it from the pending list).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            offset: Optional zero-based offset for fetching one page manually (limit, if given, is
                its page size). Omit both offset and limit to drain every page.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain every page.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `model.eq('U6 Pro')`). Omitted entirely when unset.
                Example: `model.eq('U7-Pro')`.
        """
        client, registry = deps_fn()
        return await device_mgmt._list_pending_devices(
            client, registry, host, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_device_tag(
        host: str,
        site: str,
        tag: dict[str, Any],
    ) -> Any:
        """Create a device tag on a site (groups devices by MAC in the UniFi UI). Write: modifies live config.

        Uses the controller UI's v2 route, POST /proxy/network/v2/api/site/{site}/device-tags (the Integration API serves tags GET-only; POST answers 405 on Network 11.0.81). The body is sent verbatim; pass name and member_device_macs (HTTP 500 without it, with a hint; pass [] for an empty tag). An existing name is not refused: the same name and members return the existing tag; the same name with other members creates a second tag the controller renames "NAME - CONSOLE NAME". Check list_device_tags first.

        Returns the upstream body verbatim, the created tag {_id, name, member_device_macs}. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (create_device_tag):
            {"host": "my-console", "site": "Default",
             "tag": {"name": "Cameras", "member_device_macs": ["aa:bb:cc:dd:ee:ff"]}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tag: Native v2 tag body, sent as given. Pass name (string) and member_device_macs
                (array of device MAC strings, lower-case colon form as the controller stores
                them; [] for none).
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await device_mgmt._create_device_tag(client, registry, host, site, tag)

    @mcp.tool(annotations=WRITE)
    async def update_device_tag(
        host: str,
        site: str,
        tag_id: str,
        tag: dict[str, Any],
    ) -> Any:
        """Update a device tag: rename it or add and remove member devices.

        Uses the controller UI's v2 route, PUT /proxy/network/v2/api/site/{site}/device-tags/{_id} (the Integration API has no tag update; 404 "No endpoint" on Network 11.0.81). `tag` is either the native update body, sent verbatim, which needs device_mac_additions and device_mac_removals (HTTP 500 without them, with a hint; pass [] for no change), or a list_device_tags entry edited in place: its member_device_macs (the desired members) becomes additions and removals against the current members and its _id is dropped, because the controller rejects both fields on update (HTTP 400 "Unrecognized field").

        Returns the upstream body verbatim, the updated tag {_id, name, member_device_macs}. Under dry-run policy nothing is sent: the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_device_tag):
            {
              "host": "my-console",
              "site": "Default",
              "tag_id": "Cameras",
              "tag": {
                "name": "Outdoor cameras",
                "device_mac_additions": [],
                "device_mac_removals": []
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tag_id: The tag's v2 _id or its name (exact, then case-insensitive, then
                edge-whitespace stripped). Get it from list_device_tags ([]._id; the result is a
                bare array) or from create_device_tag's result (_id). Resolved against the site's
                tags first; an unknown or ambiguous value fails listing every tag as name (_id).
            tag: Native v2 update body (device_mac_additions and device_mac_removals, arrays of
                device MAC strings, [] for none; optional name, the new name), or an edited
                list_device_tags entry {_id, name, member_device_macs} (member_device_macs = the
                desired members). Not both forms at once.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await device_mgmt._update_device_tag(client, registry, host, site, tag_id, tag)

    @mcp.tool(annotations=WRITE)
    async def delete_device_tag(
        host: str,
        site: str,
        tag_id: str,
    ) -> dict[str, Any]:
        """Delete a device tag. Permanently removes the tag from the site.

        Consequence: the tag is removed from the site and from every member device; there is no undo.

        Uses the controller UI's v2 route, DELETE /proxy/network/v2/api/device-tags/{_id} (no site segment; the Integration API has no tag delete). The tag is resolved in the site first, because the controller answers a DELETE for an unknown id with HTTP 200 and would report a deletion that never happened. Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}. The dry-run preview contains method, path, params (query parameters), and body.

        Example call (delete_device_tag):
            {"host": "my-console", "site": "Default",
             "tag_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tag_id: The tag's v2 _id or its name (exact, then case-insensitive, then
                edge-whitespace stripped). Get it from list_device_tags ([]._id; the result is a
                bare array) or from create_device_tag's result (_id). Resolved against the site's
                tags first; an unknown or ambiguous value fails listing every tag as name (_id).
        """
        client, registry = deps_fn()
        return await device_mgmt._delete_device_tag(client, registry, host, site, tag_id)

    @mcp.tool(annotations=WRITE)
    async def approve_pending_device(
        host: str,
        site: str,
        device_id: str,
        ignore_device_limit: bool,
        confirm: bool = False,
    ) -> Any:
        """Approve (adopt) a pending device onto a site.

        Consequence: the site's controller takes over and provisions the device, which may restart while it applies its new configuration.

        Uses the published adoptDevice route (Network 11.0.97, POST /v1/sites/{siteId}/devices), the same as adopt_device, with body {"macAddress": device_id, "ignoreDeviceLimit": ignore_device_limit}. Both keys are required by the spec, so the caller chooses ignore_device_limit (no default). Returns the upstream body (the adopted device details) verbatim. Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}} in place of the upstream body; physical previews carry an additive _consequence warning.

        Example call (approve_pending_device):
            {"host": "my-console", "site": "Default", "device_id": "02:00:5e:00:00:a1",
             "ignore_device_limit": false}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: The pending device's MAC address (any separator style). Get it from
                list_pending_devices (data[].macAddress); pending devices have no id field.
            ignore_device_limit: Required. Sent as the spec's required ignoreDeviceLimit; true
                adopts even when the console's device limit is reached, false respects the limit.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately
                when made unless the operator opted in to dry-run policy (then nothing
                is sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await device_mgmt._approve_pending_device(
            client, registry, host, site, device_id, ignore_device_limit
        )

    @mcp.tool(annotations=WRITE)
    async def forget_device(
        host: str,
        site: str,
        mac: str | list[str],
        confirm: bool = False,
    ) -> Any:
        """Forget one or more devices through the Classic site manager.

        Consequence: an adopted device loses its controller configuration and must be adopted again. A pending device leaves the pending list but may reappear while it keeps broadcasting for adoption. Both are addressed by MAC.

        Sends one POST to network/api/s/{site}/cmd/sitemgr per distinct (normalized) MAC with {"cmd": "delete-device", "mac": ...}. Returns the upstream Classic {meta, data} body verbatim; errors are raised (an unknown MAC returns HTTP 400 api.err.UnknownDevice). A list returns {byMac, forgotten, errors} (byMac values are upstream bodies, errors are {mac, error}) and raises only if every MAC fails.

        UNIFI_WRITE_POLICY=deny blocks this write. Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}, _consequence}; a MAC list returns {status: "dry_run", byMac, errors} with each MAC's preview and no forgotten key. Never automatically retried.

        Example: docs/TOOL-USAGE.md#forget_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            mac: MAC address in any separator style, or a list of MACs. Get adopted MACs
                from list_site_devices and pending MACs from list_pending_devices.
                Shape: string|string[]
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await device_mgmt._forget_device(client, registry, host, site, mac)


def register_2(mcp, deps_fn) -> None:
    """Register Classic commands; a read command is an exact (route, command) pair of
    ``read_post_routes.READ_COMMANDS`` and its tool is a read tool; every other command
    tool is a write tool."""

    @mcp.tool(annotations=WRITE)
    async def provision_device(host: str, site: str, device_id: str) -> Any:
        """Force provision an adopted device. Consequence: configuration is reapplied
            and clients may disconnect.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#provision_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC from list_site_devices; not a Protect id.
        """
        client, registry = deps_fn()
        return await device_commands._provision_device(client, registry, host, site, device_id)

    @mcp.tool(annotations=WRITE)
    async def cancel_rolling_upgrade(host: str, site: str) -> Any:
        """Cancel the current rolling firmware upgrade. Consequence: devices already upgrading
            may continue and reboot.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#cancel_rolling_upgrade.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await device_commands._cancel_rolling_upgrade(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_device_firmware(host: str, site: str, cached: bool = False) -> Any:
        """List available or cached device firmware through a controller command.

        A read: it only reports firmware and upgrades nothing. Sends Classic POST
        api/s/{site}/cmd/firmware with exactly {"cmd": "list-available"}, or
        {"cmd": "list-cached"} when cached is true. UNIFI_WRITE_POLICY=deny and dry-run policy both
        send it and return its result.

        Returns the upstream body verbatim. Sent once, never automatically retried.

        Example: docs/TOOL-USAGE.md#list_device_firmware.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            cached: False lists available firmware; true lists cached firmware.
        """
        client, registry = deps_fn()
        return await device_commands._list_device_firmware(client, registry, host, site, cached)

    @mcp.tool(annotations=WRITE)
    async def migrate_device(host: str, site: str, device_id: str, inform_url: str) -> Any:
        """Migrate a device to another controller. Consequence: the device leaves
            controller management and may lose connectivity.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#migrate_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC from list_site_devices; not a Protect id.
            inform_url: Destination controller inform URL; for example
                http://controller.example:8080/inform.
        """
        client, registry = deps_fn()
        return await device_commands._migrate_device(
            client, registry, host, site, device_id, inform_url
        )

    @mcp.tool(annotations=WRITE)
    async def advanced_adopt_device(
        host: str,
        site: str,
        mac: str,
        ip: str,
        username: str,
        password: str,
        inform_url: str,
        port: int = 22,
        ssh_key_verify: bool = True,
    ) -> Any:
        """Adopt a device through SSH. Consequence: controller management and device
            connectivity may change.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#advanced_adopt_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            mac: Unadopted device MAC; for example aa:bb:cc:dd:ee:ff.
            ip: Device SSH IP address; for example 192.0.2.10.
            username: Existing device SSH username.
            password: Existing device SSH password; transmitted to the controller for adoption.
            inform_url: Controller inform URL; for example http://controller.example:8080/inform.
            port: Device SSH port, default 22.
            ssh_key_verify: Whether the controller verifies the device SSH key; default true.
        """
        client, registry = deps_fn()
        return await device_commands._advanced_adopt_device(
            client,
            registry,
            host,
            site,
            mac,
            ip,
            username,
            password,
            inform_url,
            port,
            ssh_key_verify,
        )

    @mcp.tool(annotations=WRITE)
    async def run_speedtest(host: str, site: str) -> Any:
        """Run a gateway speed test. Consequence: test traffic consumes WAN bandwidth
            and may affect clients.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#run_speedtest.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await device_commands._run_speedtest(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_speedtest_status(host: str, site: str) -> Any:
        """Get gateway speed-test status through a controller command.

        A read: it only reports status and starts no test (run_speedtest starts one).
        Sends Classic POST api/s/{site}/cmd/devmgr with exactly {"cmd": "speedtest-status"}.
        UNIFI_WRITE_POLICY=deny and dry-run policy both send it and return its result.

        Returns the upstream body verbatim. Sent once, never automatically retried.

        Example: docs/TOOL-USAGE.md#get_speedtest_status.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await device_commands._get_speedtest_status(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def upgrade_all_devices(host: str, site: str, device_type: str = "uap") -> Any:
        """Upgrade every device of a family. Consequence: devices reboot and clients or
            downstream equipment lose connectivity. On an MC-LAG pair, check that the peer switch is online first: the Network 11.1.47
        web app blocks an upgrade while the peer is offline, and this server adds no such check.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#upgrade_all_devices.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_type: Controller device family, documented values uap, usw, ugw; for example usw.
        """
        client, registry = deps_fn()
        return await device_commands._upgrade_all_devices(client, registry, host, site, device_type)

    @mcp.tool(annotations=WRITE)
    async def start_rolling_upgrade(
        host: str, site: str, device_types: list[str] | None = None
    ) -> Any:
        """Start a rolling firmware upgrade. Consequence: devices reboot in sequence
            and clients may disconnect. On an MC-LAG pair, check that the peer switch is online first: the Network 11.1.47
        web app blocks an upgrade while the peer is offline, and this server adds no such check.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#start_rolling_upgrade.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_types: Complete family array, for example ["uap", "usw"]. When omitted sends
                ["uap", "usw", "ugw", "uxg"]. The whole supplied array is sent verbatim.
                Shape: string[]
        """
        client, registry = deps_fn()
        return await device_commands._start_rolling_upgrade(
            client, registry, host, site, device_types
        )

    @mcp.tool(annotations=WRITE)
    async def move_device_to_site(
        host: str, site: str, device_id: str, destination_site_id: str
    ) -> Any:
        """Move a device into another controller site. Consequence: destination
            configuration is provisioned and connectivity may be interrupted.

        Returns the upstream body verbatim. Never automatically retried. Under dry-run policy
        nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#move_device_to_site.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC from list_site_devices; not a Protect id.
            destination_site_id: Destination Classic site _id from the controller self/sites
                endpoint, typically 24 hexadecimal characters. This is not an Integration UUID
                or site slug. Read it with fabric_connector_get, path
                "network/api/self/sites" (data[]._id).
        """
        client, registry = deps_fn()
        return await device_commands._move_device_to_site(
            client, registry, host, site, device_id, destination_site_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_backups(host: str, site: str) -> Any:
        """List backup metadata; never download or read backup file contents.

        A read: it only reads backup metadata. Sends Classic POST api/s/{site}/cmd/backup
        with exactly {"cmd": "list-backups"}. UNIFI_WRITE_POLICY=deny and dry-run policy both send
        it
        and return its result.

        Returns the upstream body verbatim. Sent once, never automatically retried.

        Example: docs/TOOL-USAGE.md#list_backups.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await device_commands._list_backups(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_backup(host: str, site: str, days: int = -1) -> Any:
        """Generate a one-off controller backup file and return its console download path; no stored backup is added. Backups may contain secrets; this command never downloads one.

        Consequence: writes one transient backup file on the console, replacing the previous one; no stored backup is added and nothing is downloaded.

        Returns the upstream body verbatim: on Network 11.0.97 {"meta": {"rc": "ok"}, "data": [{"url": "/dl/backup/{version}.unf"}]}. The file is transient (the next backup overwrites it), so list_backups, cancel_controller_backup and delete_controller_backup never see it and the answer carries no filename or backup_id. Never automatically retried. Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#create_backup.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            days: Number of days for which the backup is generated; -1 is the source client
                default, forwarded unchanged.
        """
        client, registry = deps_fn()
        return await device_commands._create_backup(client, registry, host, site, days)

    @mcp.tool(annotations=WRITE)
    async def export_site(host: str, site: str) -> Any:
        """Create a site export and return controller metadata. Exports may contain secrets;
            this command never downloads export contents.

        Consequence: the controller prepares a site export file (Classic cmd/backup
        export-site); site configuration is unchanged and the contents are not downloaded.

        Returns the upstream body verbatim. Never automatically retried. A console that cannot build
        the export answers HTTP 400 api.err.BackupFailed, whatever the body; the error names the
        next steps (free console storage first, then the Network application log).
        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true,
        sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#export_site.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await device_commands._export_site(client, registry, host, site)


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    @mcp.tool(annotations=WRITE)
    async def create_scheduled_task(host: str, site: str, task: dict[str, Any]) -> Any:
        """Create a scheduled task using the native Classic body.

        Consequence: the controller executes the action at its scheduled time; upgrades can
        interrupt devices and clients.

        Returns the upstream body verbatim. Under dry-run policy nothing is sent; returns {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#create_scheduled_task.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            task: Free-form native object. Source fields include name, action,
                cron_expr, execute_only_once and upgrade_targets, a list of objects with mac.
                Example: {"name": "Monthly upgrades", "action": "upgrade",
                "cron_expr": "0 0 1 * *", "execute_only_once": false,
                "upgrade_targets": [{"mac": "02:00:00:00:00:01"}]}.
                The controller validates actions and scheduling syntax; unknown fields
                are forwarded unchanged.
        """
        client, registry = deps_fn()
        return await scheduled_tasks._create_scheduled_task(client, registry, host, site, task)

    @mcp.tool(annotations=WRITE)
    async def update_scheduled_task(
        host: str, site: str, task_id: str, task: dict[str, Any]
    ) -> Any:
        """Update a scheduled task with a whole-record read-merge-write.

        Preserves unmentioned fields, upgrade_targets and the resolved _id. A supplied array
        replaces that array, including [] to clear it.

        Consequence: schedule or target changes affect future device actions; upgrades can interrupt
        devices and clients.

        Returns the upstream body verbatim. Under dry-run policy nothing is sent; returns {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#update_scheduled_task.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            task_id: Classic _id from list_scheduled_tasks data[], for example
                "000000000000000000000001".
            task: Free-form native changed fields, for example {"name": "Monthly upgrades"}.
                Source fields include name, action, cron_expr, execute_only_once and
                upgrade_targets, a list of objects with mac. Unknown fields are retained and
                forwarded; the controller validates values.
        """
        client, registry = deps_fn()
        return await scheduled_tasks._update_scheduled_task(
            client, registry, host, site, task_id, task
        )

    @mcp.tool(annotations=WRITE)
    async def delete_scheduled_task(host: str, site: str, task_id: str) -> Any:
        """Delete a scheduled task after resolving its Classic id in the site.

        Consequence: permanently removes the scheduled action.

        Returns {deleted, message, response}: deleted is true, message summarizes the delete, response is the upstream body verbatim. Under dry-run policy nothing is sent; returns {status: "dry_run", deleted: false,
        message, response}, where response is the dry-run preview {status, dryRun, sent: false,
        message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#delete_scheduled_task.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            task_id: Classic _id from list_scheduled_tasks data[], for example
                "000000000000000000000001".
        """
        client, registry = deps_fn()
        return await scheduled_tasks._delete_scheduled_task(client, registry, host, site, task_id)


def register_4(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the typed read and full-table write tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_device_radios(host: str, site: str, device: str) -> dict[str, Any]:
        """Read an AP's radio configuration, capabilities and operating state per band.

        Returns the complete upstream envelope and every device record unchanged.
        _device selects the requested AP; _radio_table and _radio_table_stats project its
        configuration and operating state. _radios is keyed by ng (2.4 GHz), na (5 GHz),
        6e (6 GHz). Classic stat/device is used; rest/device has no GET.
        Provide host (console name or id from list_hosts) and site (network site name or UUID
        from list_local_sites).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: AP MAC, e.g. "02:00:5e:00:00:a1", or Classic _id from list_device_stats.
                Unknown or ambiguous devices fail listing choices; Integration ids differ.
        """
        client, registry = deps_fn()
        return await device_radios._get_device_radios(client, registry, host, site, device)

    @mcp.tool(annotations=WRITE)
    async def update_device_radio(
        host: str,
        site: str,
        device: str,
        radios: dict[Literal["ng", "na", "6e"], RadioChanges],
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Update selected AP radio fields while preserving the full radio_table and its order.

        Reads stat/device by MAC, validates against the device's own radio capabilities, and PUTs the entire table to rest/device using its Classic _id. Other radios and fields stay unchanged. DFS channels may sit in DFS_WAIT for about 60 s; clients may roam; a device-settings write can restart or reprovision the AP and briefly drop its clients. Never co-channel a mesh AP's only wireless uplink. Never auto-retried; a timeout reports outcome unknown. Read back before retrying. Returns readBefore/readAfter, changed per band/field, noOp and radio_table_stats, with the upstream write response verbatim under response. _diff is the requested diff; _noOp is an alias of noOp. dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message, preview (method, path, params, body), and diff; changed/noOp are null, never write results; no-op skips PUT. Honours UNIFI_WRITE_POLICY=deny and family:connector=deny. _lookupResponse and _readBeforeResponse preserve the lookup and before envelopes; _readAfterResponse preserves the after envelope. readAfterError means verification failed on the fresh read-after; changed/noOp/_verified are null. _verified compares the complete desired table to the successful read-after; false means a mismatch. Even a skipped no-op PUT requires a new successful read; read back before retrying.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: AP MAC, e.g. "02:00:5e:00:00:a1", or Classic _id from list_device_stats.
                Unknown or ambiguous devices fail listing choices; Integration ids differ.
            radios: Changes keyed by band ng, na or 6e, e.g. {"na": {"channel": 44, "ht": 40},
                "ng": {"tx_power_mode": "medium"}}. Set only fields to change: channel (auto
                or a primary channel number), ht (MHz, device capabilities), tx_power_mode,
                tx_power (dBm, reported min/max), min_rssi_enabled or min_rssi (dBm).
                Shape: {ng?:RADIO,na?:RADIO,'6e'?:RADIO}; RADIO keys the server reads:
                {channel?:integer|'auto',ht?:integer,
                tx_power_mode?:'auto'|'low'|'medium'|'high'|'custom',tx_power?:integer,
                min_rssi_enabled?:boolean,min_rssi?:integer}
            dry_run: Preview the exact full-table PUT body and diff without writing, e.g. true.
                dry-run policy also previews; read-only and write opt-outs still apply.
        """
        client, registry = deps_fn()
        return await device_radios._update_device_radio(
            client,
            registry,
            host,
            site,
            device,
            {str(band): change for band, change in radios.items()},
            dry_run=dry_run,
        )


def register_5(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the switch port override read and merge-aware write tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_switch_port_overrides(host: str, site: str, device: str) -> dict[str, Any]:
        """Read a switch's per-port overrides (port_overrides) and port table, by port_idx.

        Returns the complete upstream stat/device envelope and every device record
        unchanged. _device selects the requested switch; _port_overrides is its native
        port_overrides array as read (profile portconf_id, op_mode switch/aggregate/the
        port-monitoring (SPAN) value, the monitored-port key, aggregate_num_ports, name,
        poe_mode and other native fields);
        _ports is keyed by port_idx with that port's override (null when none) and its
        port_table row, plus _phantom: true on an override whose port is not in the port table
        (remove it with remove_ports). _spanMode gives the native op_mode value and the
        monitored-port key for port monitoring (SPAN), whether or not any port monitors now.
        _portOverridesPresent is false when the device reported no
        port_overrides field (no overrides; a device without ports returns empty _ports).
        Use update_switch_port_overrides to change it.
        Provide host (console name or id from list_hosts) and site (network site name or UUID
        from list_local_sites).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: Switch MAC, e.g. "02:00:5e:00:00:a1", or Classic _id from
                list_device_stats. Unknown or ambiguous devices fail listing choices.
        """
        client, registry = deps_fn()
        return await switch_port_overrides._get_switch_port_overrides(
            client, registry, host, site, device
        )

    @mcp.tool(annotations=WRITE)
    async def update_switch_port_overrides(
        host: str,
        site: str,
        device: str,
        ports: list[PortOverrideChange] | None = None,
        remove_ports: list[StrictInt] | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Change selected switch ports' port_overrides by port_idx; keep all else as read.

        Reads stat/device, merges each requested field into its port's entry, drops
        remove_ports entries (they revert to defaults), PUTs the whole array once to
        rest/device and reads it back. Fields are native: portconf_id (from
        list_port_profiles), op_mode (the SPAN monitoring value and monitored-port key come from
        _spanMode in get_switch_port_overrides, a port cannot monitor itself; "aggregate" with
        aggregate_num_ports, which must stay within the last physical port).

        Consequence: port changes can drop links and PoE; never re-profile your own uplink.
        A write by the UI or another client between the read and the PUT can be overwritten.

        Returns _outcome (verified, mismatch with _mismatches, or unknown with
        readAfterError), _verified, readBefore/readAfter, changed, _diff, noOp, _noOp, _plan,
        _warnings, response (the upstream body, verbatim) and the raw _lookupResponse,
        _readBeforeResponse and _readAfterResponse. Never auto-retried: after a timeout or
        502/503/504 the outcome is unknown; check get_switch_port_overrides.
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message,
        preview (method, path, params, body), diff, _plan and _outcome "preview"; nothing is
        written. Honours UNIFI_WRITE_POLICY=deny and family:connector=deny.
        Provide host (console name or id from list_hosts) and site (network site name or UUID
        from list_local_sites).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: Switch MAC, e.g. "02:00:5e:00:00:a1", or Classic _id from
                list_device_stats. Unknown or ambiguous devices fail listing choices.
            ports: Ports to change, one entry per port, e.g. [{"port_idx": 5,
                "portconf_id": "000000000000000000000001"}, {"port_idx": 1, "op_mode": "aggregate",
                "aggregate_num_ports": 2}]. Each needs port_idx (integer, 1-based) and at
                least one native port_overrides field to set; null values are refused (omit a
                field to keep it). Free-form native fields; no published schema.
            remove_ports: Port numbers whose override to delete so they revert to
                defaults, e.g. [3, 4]. A port must currently have an override and cannot
                also appear in ports; otherwise the call fails before any write.
                Shape: integer[]
            dry_run: Preview the merged array, PUT body and diff without writing, e.g. true.
                dry-run policy also previews; read-only and write opt-outs still apply.
        """
        client, registry = deps_fn()
        return await switch_port_overrides._update_switch_port_overrides(
            client, registry, host, site, device, ports, remove_ports, dry_run=dry_run
        )


def register_6(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the read-only Wi-Fi diagnosis tool."""

    @mcp.tool(annotations=READ_ONLY)
    async def diagnose_wifi(
        host: str,
        site: str,
        thresholds: dict[str, Any] | None = None,
        window_hours: int = 24,
    ) -> dict[str, Any]:
        """Diagnose a site's Wi-Fi from live AP, client and statistics reads; read-only.

        Reads Classic stat/device and stat/sta plus Wi-Fi statistics, connectivity, neighbour,
        WLAN, channel-plan and spectrum reads that other read tools make (about eleven GETs,
        one after another) and reports findings under 20 rule ids: ap_offline, sticky_client,
        high_power_co_channel, non_standard_2ghz_channel, channel_width_policy, channel_flap,
        high_tx_retries, radio_window_health, neighbor_co_channel, spectrum_scan_quality,
        connection_failures, weak_snr_clients, band_fit, airtime_hog, roam_churn,
        client_retries, client_experience, ap_uplink_bottleneck, band_load and
        wlan_config_audit. Each finding has rule, severity, subject (id, name, mac), evidence
        and recommendation (advice only; nothing is applied).

        This is a composed tool: it returns only the fields its rules use, never an upstream
        body or any device key, passphrase or token. Returns host and site, readOnly (always
        true), windowHours, warnings (ignored threshold names), summary, findings, skipped,
        notAssessed, accessPoints, sources (each route and whether it was read) and
        thresholds. summary.byRule lists every rule that was assessed, with 0 when it found
        nothing; notAssessed lists each rule whose input could not be read, with the reason
        under skipped. byRule and notAssessed together name all 20 rules, each in exactly one.
        A 0 means assessed and clean; a rule with nothing to examine (for example every AP is
        offline) is in notAssessed. summary.clean is true with no findings; an offline AP
        counts under accessPointsNotAssessed, not as checked. Only stat/device and stat/sta
        are required.

        Provide host (console name or id from list_hosts) and site (network site name or UUID
        from list_local_sites).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            thresholds: Optional free-form object of threshold names to numbers that replaces
                the defaults, e.g. {"high_utilization_pct": 60, "weak_snr_db": 18}. Names (default
                and unit): sticky_rssi_dbm (unset: the SSID's roaming-assistant setting,
                else -75), sticky_min_associated_seconds (300), sticky_max_snr_db (25),
                high_tx_power_dbm (20), high_tx_retries_pct (15, 5 and 6 GHz),
                high_tx_retries_pct_2ghz (25), min_tx_packets (1000), min_connect_failures
                (3), min_connect_success_pct (90), high_utilization_pct (50),
                high_interference_pct (25), neighbor_min_signal_dbm (-75),
                neighbor_max_age_minutes (10), max_strong_neighbors (5), roam_churn_count
                (10), weak_snr_db (15), hog_traffic_share_pct (15), hog_max_phy_mbps (100),
                high_client_retries_pct (25), low_satisfaction (50),
                max_2ghz_client_share_pct (25), ap_load_ratio (2.0),
                max_spectrum_scan_age_hours (24), flap_window_days (7), flap_min_changes (3),
                min_legacy_rate_kbps (12000). A value that is not a number or is outside its
                range is rejected before any request; an unknown name is ignored and listed
                under warnings.
            window_hours: Hours of statistics and connection history to read, 1 to 168,
                e.g. 24.
        """
        client, registry = deps_fn()
        return await wifi_diagnosis._diagnose_wifi(
            client, registry, host, site, thresholds=thresholds, window_hours=window_hours
        )
