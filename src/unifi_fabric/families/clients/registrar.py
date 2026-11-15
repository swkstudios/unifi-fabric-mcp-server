"""The clients family registrar: its tool wrappers, in registration order (the family-owned layout).

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

from ...tool_annotations import READ_ONLY, WRITE
from . import client_records, clients


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all client management MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_clients(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        client_type: str | None = None,
        filter: str | None = None,
    ) -> Any:
        """List connected clients for a site via the published Network Integration API (for the private v2 active-client route use list_active_clients).

        Returns {data, totalCount}: by default every page is drained; data holds the client records verbatim and totalCount is the upstream total (null when none was reported). The first page's other envelope fields are kept, and incomplete/incompleteReason are added when a capped drain stopped short. A limit without offset requests a total gathered in batches; an explicit offset returns one upstream page with its envelope and page-size accounting and totalCount so you can advance.

        The client_type shorthand: WIRED, WIRELESS, VPN, TELEPORT or ALL (default all), translated into the upstream `type.eq(...)` filter (the raw type query parameter is ignored by the UniFi API).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            offset: Optional zero-based offset for fetching one page manually. Omit both offset and
                limit to drain every page and get the complete list.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            client_type: Optional shorthand WIRED, WIRELESS, VPN, TELEPORT (every type the spec
                lists) or ALL (default: all types), translated into the upstream `type.eq(...)`
                filter. Mutually exclusive with filter. An empty or whitespace value applies no
                type filter (like ALL).
            filter: optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `type.eq('WIRED')`, `macAddress.eq('aa:bb:cc:dd:ee:ff')`); omitted entirely when
                unset. client_type and an explicit filter are mutually exclusive (the upstream
                grammar has no conjunction operator to compose them); passing both raises an error
                rather than silently returning wrong results. A capped drain returns the clients
                gathered so far with incomplete=true rather than truncating silently.
                Example: `type.eq('WIRED')`.
        """
        client, registry = deps_fn()
        return await clients._list_clients(
            client,
            registry,
            host,
            site,
            offset=offset,
            limit=limit,
            client_type=client_type,
            filter=filter,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_active_clients(
        host: str,
        site: str,
        include_matter_thread_clients: bool | None = None,
        include_traffic_usage: bool | None = None,
        include_unifi_devices: bool | None = None,
    ) -> Any:
        """Retrieve the private v2 active-client roster and optional Matter/Thread rows.

        Returns the upstream body verbatim from GET
        network/v2/api/site/{site}/clients/active. FastMCP wraps a top-level array in
        result for MCP clients. This is the private-route counterpart
        to the official Integration API list_clients tool. Use it when the v2-specific
        flags or Matter/Thread client rows are required.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or slug; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            include_matter_thread_clients: Optional v2 flag (query includeMatterThreadClients):
                true also lists Matter/Thread clients. Example: `true`.
            include_traffic_usage: Optional v2 flag (query includeTrafficUsage): true asks the
                controller to include traffic usage. Example: `true`.
            include_unifi_devices: Optional v2 flag (query includeUnifiDevices): true asks the
                controller to include UniFi devices. Example: `false`.
        """
        client, registry = deps_fn()
        return await clients._list_active_clients(
            client,
            registry,
            host,
            site,
            {
                "include_matter_thread_clients": include_matter_thread_clients,
                "include_traffic_usage": include_traffic_usage,
                "include_unifi_devices": include_unifi_devices,
            },
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Get details for a single client.

        Returns the upstream client object verbatim, exactly as the API answers it.

        Example call (get_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Connected client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF);
                a MAC is resolved to the client id with list_clients (macAddress filter), so the
                client must be connected; an unknown MAC fails listing the connected clients.
                Get it from list_clients (data[].id or data[].macAddress). Network-app id — not
                a Protect id.
        """
        client, registry = deps_fn()
        return await clients._get_client(client, registry, host, site, client_id)

    @mcp.tool(annotations=WRITE)
    async def execute_client_action(
        host: str,
        site: str,
        client_id: str,
        action: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Execute a guest-access client action: AUTHORIZE_GUEST_ACCESS or UNAUTHORIZE_GUEST_ACCESS (the only accepted actions; others fail before any request, listing the valid ones). To block, unblock or reconnect use block_client, unblock_client or reconnect_client.

        Consequence: AUTHORIZE_GUEST_ACCESS lets the guest onto the network now; UNAUTHORIZE_GUEST_ACCESS revokes access and disconnects the guest.

        `action` is the body (Network 11.0.97, POST /v1/sites/{siteId}/clients/{clientId}/actions): {"action": ...}; AUTHORIZE_GUEST_ACCESS also takes optional integers timeLimitMinutes (1-1000000; omitted, the site default applies), dataUsageLimitMBytes (1-1048576), rxRateLimitKbps and txRateLimitKbps (2-100000). Returns the action-result object verbatim (under dry-run policy, the dry-run preview).

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (execute_client_action):
            {"host": "my-console", "site": "Default",
             "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "action": {"action": "AUTHORIZE_GUEST_ACCESS", "timeLimitMinutes": 60}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Connected client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF);
                a MAC is resolved to the client id with list_clients (macAddress filter), so the
                client must be connected; an unknown MAC fails listing the connected clients.
                Get it from list_clients (data[].id or data[].macAddress). Network-app id — not
                a Protect id.
            action: Action body; spec Client action request. Required: action. 'action' selects
                variant: AUTHORIZE_GUEST_ACCESS|UNAUTHORIZE_GUEST_ACCESS. AUTHORIZE_GUEST_ACCESS
                optionally takes timeLimitMinutes, dataUsageLimitMBytes, rxRateLimitKbps and
                txRateLimitKbps.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately
                when made unless the operator opted in to dry-run policy (then nothing
                is sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await clients._execute_client_action(client, registry, host, site, client_id, action)

    @mcp.tool(annotations=WRITE)
    async def block_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Block a client on a site: any client the controller knows, connected or not (an
        offline client can be pre-blocked by its MAC).

        Consequence: the client is disconnected and cannot rejoin the site until unblocked with
        unblock_client.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body: none is passed by the caller. Tool sends
        {"cmd": "block-sta", "mac": CLIENT_MAC} (CLIENT_MAC is the client MAC address) to
        classic cmd/stamgr (no published spec).

        Example call (block_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF). A MAC
                may be that of any client the controller knows, connected or not: it is sent
                to the controller as is (lowercase colon form) with no list lookup. A UUID is
                resolved to the MAC with the client GET, which finds connected clients only;
                an unknown UUID fails asking for the MAC. For a connected client,
                get it from list_clients (data[].macAddress or data[].id); for any known client,
                the mac from list_known_clients (includes offline and blocked clients).
                Network-app id — not a Protect id.
        """
        client, registry = deps_fn()
        return await clients._block_client(client, registry, host, site, client_id)

    @mcp.tool(annotations=WRITE)
    async def unblock_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Unblock a previously blocked client on a site: any client the controller knows,
        connected or not. A blocked client is offline and absent from list_clients: pass its
        MAC (list_known_clients mac).

        Consequence: the client may connect to the site again.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body: none is passed by the caller. Tool sends
        {"cmd": "unblock-sta", "mac": CLIENT_MAC} (CLIENT_MAC is the client MAC address) to
        classic cmd/stamgr (no published spec).

        Example call (unblock_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "aa:bb:cc:dd:ee:ff"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF). A MAC
                may be that of any client the controller knows, connected or not: it is sent
                to the controller as is (lowercase colon form) with no list lookup. A UUID is
                resolved to the MAC with the client GET, which finds connected clients only;
                an unknown UUID fails asking for the MAC. For a connected client,
                get it from list_clients (data[].macAddress or data[].id); for any known client,
                the mac from list_known_clients (includes offline and blocked clients).
                Network-app id — not a Protect id.
        """
        client, registry = deps_fn()
        return await clients._unblock_client(client, registry, host, site, client_id)

    @mcp.tool(annotations=WRITE)
    async def reconnect_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Force a client to reconnect on a site (addressed by MAC; a MAC given is sent as
        is, with no client list read).

        Consequence: the client is disconnected and has to reconnect, briefly interrupting its
        traffic.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body: none is passed by the caller. Tool sends
        {"cmd": "kick-sta", "mac": CLIENT_MAC} (CLIENT_MAC is the client MAC address) to
        classic cmd/stamgr (no published spec).

        Example call (reconnect_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF). A MAC
                may be that of any client the controller knows, connected or not: it is sent
                to the controller as is (lowercase colon form) with no list lookup. A UUID is
                resolved to the MAC with the client GET, which finds connected clients only;
                an unknown UUID fails asking for the MAC. For a connected client,
                get it from list_clients (data[].macAddress or data[].id); for any known client,
                the mac from list_known_clients (includes offline and blocked clients).
                Network-app id — not a Protect id.
        """
        client, registry = deps_fn()
        return await clients._reconnect_client(client, registry, host, site, client_id)

    @mcp.tool(annotations=WRITE)
    async def wake_client(
        host: str,
        site: str,
        client_id: str,
    ) -> Any:
        """Wake a wired client with a Wake-on-LAN packet (Network 11.1.47 and later).

        Consequence: the controller broadcasts a magic packet on the machine's network; a
        machine that has Wake-on-LAN enabled powers on. Waking an unwanted machine has no undo.
        The packet only reaches machines on the same layer-2 segment as the gateway or switch
        that relays it, and the machine firmware must have the feature switched on; the
        controller answers success whether or not the machine woke.

        Returns the upstream body verbatim (under dry-run policy, the dry-run preview {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query
        parameters), body}} instead). An older Network application answers 404.

        Request body: none is passed by the caller. Tool sends an empty JSON object {} with
        POST /proxy/network/v2/api/site/{site}/wake-on-lan/{CLIENT_MAC} (CLIENT_MAC is the
        client's lowercase colon MAC), the route the Network 11.1.47 web application calls
        (no published spec). Never auto-retried.

        Example call (wake_client):
            {
              "host": "my-console",
              "site": "Default",
              "client_id": "aa:bb:cc:dd:ee:ff"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            client_id: Client UUID or MAC (AA:BB:CC:DD:EE:FF, aa-bb-..., AABBCCDDEEFF). A MAC
                is sent to the controller as is (lowercase colon form) with no list lookup, so
                an offline machine can be woken. A UUID is resolved to the MAC with the client
                GET, which answers only while the machine is online; an unknown UUID fails
                asking for the MAC. Network-app id, not a Protect id.
        """
        client, registry = deps_fn()
        return await clients._wake_client(client, registry, host, site, client_id)


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the client-record MCP tools."""

    @mcp.tool(annotations=WRITE)
    async def forget_client(
        host: str,
        site: str,
        mac: str | list[str],
    ) -> Any:
        """Forget clients: delete the controller's record of each client (the UI's "Forget").

        Consequence: the client's whole list_users record is deleted with everything on it (name, note, fixed-IP reservation, user group, blocked flag). There is no undo.

        No published spec covers this; it uses the Classic station manager: POST network/api/s/{site}/cmd/stamgr with {"cmd": "forget-sta", "macs": [MAC, ...]} (lowercase colon form, duplicates collapsed), ONE request for every MAC. Verified on Network 11.0.81: the record is gone on the next read. A MAC the controller does not know is accepted (rc ok) and changes nothing.

        Returns the Classic body verbatim {meta: {rc}, data: [...]}, one envelope for one MAC or a list (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query parameters), body}} instead). Not auto-retried on HTTP 429: a retry could repeat the action.

        Example call (forget_client):
            {"host": "my-console", "site": "Default",
             "mac": ["aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:01"]}

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
        return await client_records._forget_client(client, registry, host, site, mac)

    @mcp.tool(annotations=WRITE)
    async def list_guests(
        host: str,
        site: str,
        within_hours: int | None = None,
        source: str | None = None,
    ) -> Any:
        """List guest authorizations (hotspot / guest-portal guests) of a site.

        Each record is one authorization: {_id, mac, start, end (epoch seconds), expired, authorized_by, bytes, rx_bytes, tx_bytes, qos_overwrite, ...} as the controller reports it. The _id is what extend_guest takes.

        Classic REST network/api/s/{site}/stat/guest: a GET when within_hours is unset (the controller's own window), else a POST {"within": within_hours}. Returns the upstream body verbatim: {meta: {rc}, data: [guest, ...]}; a scalar POST response is returned verbatim after the write, while a malformed Classic GET envelope raises with the shape received. With source "v2", GET network/v2/api/site/{site}/hotspot/clients (the web UI's hotspot client list) is returned verbatim instead.

        The POST form is a write pending a separately approved read-POST allowlist PR. Consequence: none intended; both forms only read guest records. UNIFI_WRITE_POLICY=deny hides the whole tool, including both GET forms. With dry-run policy, the POST returns {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} without sending it; the GET form returns the usual response.

        Example call (list_guests):
            {"host": "my-console", "site": "Default", "within_hours": 24}

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides the whole tool and discovery mode runs it through call_write_tool.

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
        return await client_records._list_guests(client, registry, host, site, within_hours, source)

    @mcp.tool(annotations=WRITE)
    async def extend_guest(
        host: str,
        site: str,
        guest: str,
    ) -> Any:
        """Extend a guest authorization (the UI's "Extend").

        Consequence: the guest keeps network access longer; the controller adds its own increment (24 hours on Network 11.0.81). Network 11.0.89 also stored qos_usage_quota: -1 on a guest record that had none; the tool sends only the extend command and returns the controller's answer.

        The guest is resolved in list_guests first by _id, or by MAC (its one active authorization, else its only one). An unknown value, or a MAC with several matching authorizations, fails listing the guests and nothing is sent. Then POST network/api/s/{site}/cmd/hotspot with {"cmd": "extend", "_id": GUEST_ID} (Classic REST, no published spec).

        Returns the Classic body verbatim {meta: {rc}, data: [...]} (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query parameters), body}} instead). Read list_guests afterwards for the new end. Not auto-retried on HTTP 429: a retry could extend twice.

        Example call (extend_guest):
            {"host": "my-console", "site": "Default", "guest": "aa:bb:cc:dd:ee:ff"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            guest: The guest authorization _id from list_guests (data[]._id, e.g.
                "000000000000000000000102") or the guest's MAC (any separator style).
        """
        client, registry = deps_fn()
        return await client_records._extend_guest(client, registry, host, site, guest)

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
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
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
        return await client_records._put_user(client_, registry, host, site, client, {"name": name})

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
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
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
        return await client_records._put_user(client_, registry, host, site, client, {"note": note})

    @mcp.tool(annotations=WRITE)
    async def set_client_fixed_ip(
        host: str,
        site: str,
        client: str,
        fixed_ip: str,
        network: str | None = None,
    ) -> Any:
        """Reserve a fixed IP (DHCP reservation) for a known client.

        Consequence: the gateway's DHCP server reserves this address for the client; it gets it when it next renews its lease.

        The known-client record (list_users) is resolved by MAC or _id first (a MAC with no record fails pointing at create_client_reservation); network, when given, is resolved to its networkconf _id by _id, Integration id or name (an unknown one fails listing the networks). Then Classic REST PUT network/api/s/{site}/rest/user/{_id} with {"use_fixedip": true, "fixed_ip": fixed_ip} plus network_id when given (verified on Network 11.0.81). The controller validates the address; an upstream error gets a hint.

        Returns the Classic body verbatim: {meta: {rc}, data: [the updated record]} (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query parameters), body}} instead).

        Example call (set_client_fixed_ip):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff",
             "fixed_ip": "192.168.1.50", "network": "Default"}

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
        return await client_records._set_client_fixed_ip(
            client_, registry, host, site, client, fixed_ip, network
        )

    @mcp.tool(annotations=WRITE)
    async def remove_client_fixed_ip(
        host: str,
        site: str,
        client: str,
    ) -> Any:
        """Remove a known client's fixed-IP (DHCP) reservation. Consequence: the reservation no longer applies; the client gets a pool address when it next renews its lease.

        The known-client record (list_users) is resolved by MAC or _id first (a MAC with no record fails pointing at create_client_reservation). Then Classic PUT network/api/s/{site}/rest/user/{_id} with {"use_fixedip": false} (the controller keeps the last fixed_ip, unused); the body is {meta: {rc}, data: [the updated record]}. deleted is true only when the returned record shows use_fixedip: false; otherwise it is false and message says why. The PUT is sent once, never retried: read with get_user before retrying. Under dry-run policy nothing is sent: {status: "dry_run", deleted: false, message, response (the dry-run preview)}.

        Dry-run preview: {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}.

        Example call (remove_client_fixed_ip):
            {"host": "my-console", "site": "Default", "client": "aa:bb:cc:dd:ee:ff"}

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
        return await client_records._remove_client_fixed_ip(client_, registry, host, site, client)

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
        """Create a known-client record for a MAC the controller has not seen yet, to pre-assign name, note or fixed IP before first connect.

        Classic REST POST network/api/s/{site}/rest/user with {"mac": MAC} plus name/note when given, {"use_fixedip": true, "fixed_ip": fixed_ip} when fixed_ip is given, and network_id when network is given (resolved by _id, Integration id or name; an unknown one fails listing the networks). Verified on Network 11.0.81: the record appears in list_users. For a client that already has a record use set_client_name, set_client_note or set_client_fixed_ip. The controller judges a duplicate MAC; an upstream error gets a hint.

        Returns the Classic body verbatim: {meta: {rc}, data: [the created record]} (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query parameters), body}} instead).

        Example call (create_client_reservation):
            {"host": "my-console", "site": "Default", "mac": "aa:bb:cc:dd:ee:ff", "name": "Printer",
             "fixed_ip": "192.168.1.60", "network": "Default"}

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
        return await client_records._create_client_reservation(
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
