"""UniFi Fabric MCP Server — FastMCP server exposing UniFi Site Manager API tools."""

from __future__ import annotations

import logging
import os
import ssl
import sys

# Suppress pydantic version URLs in validation error messages (information disclosure).
os.environ.setdefault("PYDANTIC_ERRORS_INCLUDE_URL", "0")

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from .client import UniFiClient
from .config import MCPTransportSettings, Settings
from .registry import Registry
from .tools import (
    aggregation,
    carrier_fabric,
    clients,
    connector,
    device_mgmt,
    firewall_proxy,
    hotspot,
    innerspace,
    mobility,
    network,
    network_services_proxy,
    protect,
    recognition,
    site_manager,
    statistics,
    vpn,
)

_settings: Settings | None = None
_client: UniFiClient | None = None
_registry: Registry | None = None


def get_settings() -> Settings:
    """Lazily construct and cache the top-level :class:`Settings`.

    Importing this module must not read the environment or be able to crash.
    ``Settings()`` parses the ``UNIFI_*`` environment (including JSON-decoding
    ``UNIFI_API_KEYS`` into ``list[APIKeyConfig]``) and raises ``SettingsError``
    on malformed input. Constructing it at module scope turned a bad env var
    into an *import-time* crash — surfacing as a pytest collection error for
    every module that imports this one. Construction is deferred to first use
    (``lifespan`` at server startup, or explicit callers) so the failure mode
    is a proper startup error, not an import-time one.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


@asynccontextmanager
async def lifespan(app: FastMCP) -> AsyncIterator[None]:
    global _client, _registry
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        force=True,
    )
    if not settings.get_key_configs():
        raise RuntimeError(
            "No API key configured. Set UNIFI_API_KEY or UNIFI_API_KEYS before starting the server."
        )
    _client = UniFiClient(settings)
    _registry = Registry(
        _client,
        ttl_seconds=settings.cache_ttl_seconds,
        cache_max_hosts=settings.cache_max_hosts,
        cache_max_sites=settings.cache_max_sites,
    )
    try:
        yield
    finally:
        await _client.close()
        _client = None
        _registry = None


INSTRUCTIONS = """
UniFi Fabric MCP Server — manages UniFi network infrastructure via the Ubiquiti
Site Manager (Fabric) API.

## Key Concepts
- **Host**: A UniFi console/gateway (UDM Pro, UDR, UCG, etc.). Each host runs one or
  more applications (Network, Protect, Access).
- **Site**: A logical network partition within a host. Most single-console setups have
  one site called "Default".
- Both `host` and `site` parameters accept human-readable names OR IDs. Prefer names.
- **Device** (in UniFi terminology): network infrastructure hardware — APs, switches,
  gateways, cameras, sensors. Managed via `list_site_devices`, `get_device`, etc.
- **Client**: an end-user device connected to the network (laptop, phone, IoT device).
  Managed via `list_clients`, `get_client`, `block_client`, etc. Do not confuse devices
  (infrastructure) with clients (end-users).

## Getting Started
1. Call `list_hosts` to discover available consoles. Note the host name (e.g., "MyConsole").
2. Call `list_sites` to discover sites. Note the site name (e.g., "Default").
3. Pass these names to any per-host tool: `list_networks(host="MyConsole", site="Default")`.

## Firewall Rule Hierarchy
UniFi has three distinct firewall systems — use the right one for your use case:
1. **Zone-based Firewall Policies** (`list/create/update_firewall_policy`): the modern,
   recommended approach. Rules are scoped between firewall zones (LAN, WAN, Guest, etc.).
   Use `list_firewall_zones_proxy` to discover zones and their IDs first.
2. **ACL Rules** (`list/create/update_acl_rule`): network-layer access control lists,
   typically used for intra-VLAN traffic filtering between networks.
3. **Classic Firewall Rules** (`list_firewall_rules`, `get_firewall_rule`): legacy
   iptables-style rules. Read-only in this server; prefer zone-based policies for new rules.

When asked to "add a firewall rule", default to zone-based firewall policies unless the
user specifically asks for ACL rules or classic rules.

## Tool Organization
- **Network**: application info, local sites, networks/VLANs, WiFi broadcasts, WAN interfaces
- **Switching**: LAGs, MC-LAG domains, switch stacks
- **Port Forwarding**: `list_port_forwards`, `create_port_forward`,
  `update_port_forward`, `delete_port_forward`
- **Firewall**: policies, zones, ACL rules, ordering
- **DNS & Traffic**: DNS policies, traffic rules, traffic matching lists, traffic routes
- **Traffic Routes**: `list_traffic_routes`, `create_traffic_route`,
  `update_traffic_route`, `delete_traffic_route`
- **Traffic Rules**: `list_traffic_rules`, `create_traffic_rule`,
  `update_traffic_rule`, `delete_traffic_rule`
- **Traffic Matching Lists**: `list_traffic_matching_lists`,
  `create_traffic_matching_list`, `update_traffic_matching_list`,
  `delete_traffic_matching_list`
- **Dynamic DNS**: `list_dynamic_dns`, `get_dynamic_dns`, `update_dynamic_dns`
- **Settings**: `list_settings`, `get_setting`, `update_setting`
- **WLAN**: `list_wlan_configs`, `get_wlan_config`, `update_wlan_config`,
  `list_wlan_groups`, `get_wlan_group`
- **Clients & Devices**: list/search connected clients, device stats,
  adoption, block/unblock clients
- **Device Stats**: `list_device_stats`, `list_active_clients_stats`, `get_device_statistics`,
  `get_site_statistics`, `get_system_info`,
  `get_client_link_diagnostics` (per-client link/policy diagnostics),
  `get_device_port_state` (switch port/PoE/optics/LLDP telemetry),
  `get_device_stp_state` (per-device + per-port STP/RSTP state)
- **History**: `list_client_sessions` (~90d session history), `get_historical_stats`
  (bucketed 5minutes/hourly/daily reports), `list_known_clients` (per-site roster incl. offline)
- **Device Management**: adopt, unadopt, restart, upgrade, locate, execute actions
- **Protect**: cameras, chimes, lights, sensors, viewers, liveviews, NVR, snapshots, PTZ control,
  `list_protect_events` (historical motion/smart-detect/sensor events, ~90d),
  face/vehicle recognition — `list_recognition_groups`, `get_recognition_group_counts`,
  `get_recognition_group_image`, `list_recognition_detections`, `get_thumbnail`
- **Protect alarm/arm & accessories** (Integration API v7.1.87, host only): arm
  profiles — `list_arm_profiles`, `get_arm_profile`, `create_arm_profile`,
  `update_arm_profile`, `delete_arm_profile`, `update_arm_profile_settings`,
  `enable_arm`, `disable_arm`; sirens — `list_sirens`, `get_siren`, `update_siren`,
  `siren_play`, `siren_stop`, `siren_test_sound`; fobs — `list_fobs`, `get_fob`,
  `update_fob`; relays — `list_relays`, `get_relay`, `update_relay`,
  `relay_activate_output`; speakers — `list_speakers`, `get_speaker`,
  `update_speaker`, `speaker_test_sound`; bridges — `list_bridges`, `get_bridge`,
  `update_bridge`; link stations — `list_link_stations`, `get_link_station`,
  `update_link_station`; alarm hubs — `list_alarm_hubs`, `get_alarm_hub`,
  `update_alarm_hub`, `alarm_hub_trigger_output`; Protect users —
  `list_protect_users`, `get_protect_user`; ULP (UniFi account) users —
  `list_ulp_users`, `get_ulp_user`; application metadata —
  `get_protect_application_info`; POS overlay ingestion — `pos_ingest_transaction`.
  Write/action tools honor UNIFI_PROTECT_MUTATIONS_ENABLED (default on);
  physical/irreversible actions additionally require confirm=true. The Protect
  WebSocket subscriptions (/v1/subscribe/devices, /v1/subscribe/events) are
  intentionally NOT exposed (no unary MCP wrapper for a streaming endpoint).
- **InnerSpace**: floor-plan project geometry — walls, placed devices (with 3D
  mounting heights), per-floor plans, product/material dictionaries
- **VPN**: VPN servers (full CRUD), site-to-site tunnels (full CRUD),
  RADIUS profiles (list/get/create via dedicated tools; no update/delete —
  the Site Manager API exposes no RADIUS profile mutation endpoint)
- **Hotspot**: voucher management, operators
- **ISP Metrics**: WAN health metrics (use interval='5m' or '1h')
- **Fleet**: cross-host device search, fleet summary, site comparison
- **Carrier / ISP Fabric** (org-scoped, no host/site): `list_carrier_subscribers`,
  `get_carrier_subscriber`, `list_carrier_service_plans`, `get_carrier_service_plan`,
  `create_carrier_subscriber`, `update_carrier_subscriber`,
  `attach_carrier_subscriber_host`, `detach_carrier_subscriber_host`,
  `assign_carrier_subscriber_plan`, `suspend_carrier_subscriber`,
  `resume_carrier_subscriber`. Identity: org-scoped via API key (no host/site). Writes
  require `confirm=true` + `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` (default off).
  **Not testable against the maintainer's live hardware** (hermetic/spec-conformance tests only).
- **Fabric connector relay** (host-scoped, no site): `fabric_connector_get` (always
  available), `fabric_connector_post/put/patch/delete` (mutations require `confirm=true`
  + `UNIFI_ENABLE_CONNECTOR_WRITE`, default off). Relays requests to a console's
  `/proxy/<path>` surface via the official Network Cloud Connector. Identity: `host`
  resolves to the owning API key + host id; `site` name/UUID substituted from Registry
  into `{site}`/`{site_id}` path placeholders.
- **Mobility** (workspace-scoped, no host/site): `list_mobility_workspaces`,
  `list_mobility_admins`, `list_mobility_devices`, `get_mobility_device`,
  `list_mobility_clients`, `update_mobility_device_name`,
  `update_mobility_device_network`, `update_mobility_device_wireless`. Identity:
  `workspace_id` (not host/site). Writes require `confirm=true` +
  `UNIFI_ENABLE_MOBILITY_WRITE` (default off).

## Parameter Scope Quick Reference
- **host + site required**: network, firewall, DNS, traffic routes, traffic rules,
  traffic matching lists, port forwarding, WLAN, dynamic DNS, settings, device,
  client, VPN server, RADIUS profile, hotspot operator tools,
  `list_lags`, `get_lag`, `list_mc_lag_domains`, `get_mc_lag_domain`,
  `list_switch_stacks`, `get_switch_stack`,
  `list_device_stats`, `list_active_clients_stats`, `get_device_statistics`,
  `get_site_statistics`, `get_system_info`, `create_radius_profile`,
  `list_client_sessions`, `get_historical_stats`, `list_known_clients`,
  `get_client_link_diagnostics`, `get_device_port_state`, `get_device_stp_state`,
  `query_isp_metrics`,
  `fabric_connector_get`, `fabric_connector_post`, `fabric_connector_put`,
  `fabric_connector_patch`, `fabric_connector_delete`
- **host only** (no site): `get_network_application_info`, `list_local_sites`,
  `list_pending_devices`, `list_devices`,
  `list_cameras`, `get_camera`, `get_camera_snapshot`, `update_camera`, `ptz_goto_preset`,
  `ptz_patrol_start`, `ptz_patrol_stop`, `list_sensors`, `get_sensor`, `update_sensor`,
  `list_lights`, `get_light`, `update_light`, `list_chimes`, `get_chime`, `update_chime`,
  `list_viewers`, `get_viewer`, `update_viewer`, `list_liveviews`, `get_liveview`,
  `create_liveview`, `update_liveview`, `get_nvr`, `list_protect_files`, `upload_protect_file`,
  `trigger_alarm_webhook`, `start_talkback_session`, `disable_camera_mic_permanently`,
  `list_protect_events`,
  `list_recognition_groups`, `get_recognition_group_counts`, `get_recognition_group_image`,
  `list_recognition_detections`, `get_thumbnail`,
  `get_innerspace_summary`, `get_innerspace_project`, `list_innerspace_devices`,
  `list_innerspace_floor_plans`, `list_innerspace_access_points`, `list_innerspace_switches`,
  `list_innerspace_inventory`, `get_innerspace_asset`,
  `list_arm_profiles`, `get_arm_profile`, `create_arm_profile`, `update_arm_profile`,
  `delete_arm_profile`, `update_arm_profile_settings`, `enable_arm`, `disable_arm`,
  `list_sirens`, `get_siren`, `update_siren`, `siren_play`, `siren_stop`,
  `siren_test_sound`, `list_fobs`, `get_fob`, `update_fob`, `list_relays`,
  `get_relay`, `update_relay`, `relay_activate_output`, `list_speakers`,
  `get_speaker`, `update_speaker`, `speaker_test_sound`, `list_bridges`,
  `get_bridge`, `update_bridge`, `list_link_stations`, `get_link_station`,
  `update_link_station`, `list_alarm_hubs`, `get_alarm_hub`, `update_alarm_hub`,
  `alarm_hub_trigger_output`, `list_protect_users`, `get_protect_user`,
  `list_ulp_users`, `get_ulp_user`, `get_protect_application_info`,
  `pos_ingest_transaction`, `list_countries`
- **workspace-scoped** (Mobility -- no host/site, takes `workspace_id`/`device_id`):
  `list_mobility_workspaces`, `list_mobility_admins`, `list_mobility_devices`,
  `get_mobility_device`, `list_mobility_clients`,
  `update_mobility_device_name`, `update_mobility_device_network`,
  `update_mobility_device_wireless`
- **org-scoped** (Carrier Fabric -- no host/site, key_label only):
  `list_carrier_subscribers`, `get_carrier_subscriber`,
  `list_carrier_service_plans`, `get_carrier_service_plan`,
  `create_carrier_subscriber`, `update_carrier_subscriber`,
  `attach_carrier_subscriber_host`, `detach_carrier_subscriber_host`,
  `assign_carrier_subscriber_plan`, `suspend_carrier_subscriber`,
  `resume_carrier_subscriber`
- **no host/site** (global Site Manager /v1/ API): fleet/aggregation tools
  (`list_hosts`, `list_sites`, `list_all_sites_aggregated`, `get_fleet_summary`,
  `list_all_clients`, `list_all_devices`, `compare_site_performance`,
  `search_across_sites`, `search_device_fleet`, `get_isp_metrics`)

## Common Workflows

**Create a new VLAN with firewall isolation:**
1. `list_firewall_zones_proxy` → get zone IDs
2. `create_network` → create VLAN with desired zoneId
3. `create_firewall_policy` → allow/deny traffic between zones

**Set up guest WiFi:**
1. `create_network` → create guest VLAN (set isolationEnabled=true)
2. `create_wifi_broadcast` → create SSID with security settings, reference the VLAN

**Block a client:**
1. `list_clients` → find the client MAC
2. `block_client` → block by client ID

**Check WAN health:**
1. `get_isp_metrics(interval='5m')` for recent metrics
2. `list_wan_interfaces` for current WAN config

**Look up face / vehicle recognition (Protect):**
1. `list_recognition_groups` → enrolled subjects. NOTE: the parameter is `type`
   (singular) and takes one value — `'face'` or `'vehicle'`, not a list. Each group has
   an `id` (e.g. `face_90`).
2. `list_recognition_detections` → individual sightings for a group. This step REQUIRES
   `group_id` — use the `id` from step 1; there is no "all groups" mode. Each detection
   carries a `thumbnailId`.
3. `get_thumbnail` → fetch that detection's crop (base64-encoded JPEG).

## Important Notes
- **Read-only tools** are safe to call freely. Write tools (create/update/delete) modify
  live infrastructure.
- **Irreversible operations** — confirm with the user before calling these:
  - `delete_network`: removes the VLAN and disconnects all clients on it
  - `unadopt_device`: factory-resets the device's association; requires re-adoption
  - `disable_camera_mic_permanently`: hardware-level mic disable, cannot be re-enabled
  - `trigger_alarm_webhook`: triggers physical alarm hardware; real-world consequences
  - `delete_*` tools in general: no undo, no recycle bin
- Many list tools support `page_token` for cursor pagination on large result sets.
- **Time parameters are NOT uniform across tools — check each tool before passing one:**
  - Epoch SECONDS as integers (e.g. 1690000000): `list_protect_events` (start/end),
    `list_client_sessions` (start/end), `get_historical_stats` (start/end),
    `list_recognition_detections` (start/end).
  - ISO 8601 UTC strings (e.g. "2026-07-23T00:00:00Z"): `query_isp_metrics`
    (start_time/end_time). Passing an epoch here — as a number OR as a bare-digit string —
    is rejected; convert to an ISO 8601 string first.
  - The seconds-based tools reject millisecond-magnitude values, and the string-based tool
    rejects numeric input, so a value copied from one tool to another will error rather
    than silently misbehave. Do not assume a format carries across tools.
- ISP metrics `interval` accepts '5m' (5-minute buckets) or '1h' (1-hour buckets) only.
- The server resolves host/site names internally — you do not need to look up IDs manually.
- **Site IDs**: `list_sites` returns a Site Manager `siteId` in Fabric **ObjectId** format
  (from the `/v1/sites` list — the same value the former `/ea/sites` returned). This differs
  from the UUID used in proxy API paths, which is served by the per-console connector
  `/sites` endpoint. Always pass site **names** — the server resolves the correct ID for
  each API subsystem automatically.
- **Security defaults for `create_network`**: new networks default to
  `internetAccessEnabled=true`, `isolationEnabled=false`. Set `isolationEnabled=true` for
  guest/IoT VLANs to prevent lateral movement between clients.
"""


def build_auth(s: MCPTransportSettings) -> AuthProvider | None:
    """Build the FastMCP auth provider for the resolved auth_mode.

    - ``"none"``   -> ``None`` (no transport auth)
    - ``"bearer"`` -> ``StaticTokenVerifier`` over the shared MCP_BEARER_TOKEN secret
    - ``"oauth"``  -> ``RemoteAuthProvider`` wrapping a ``JWTVerifier`` (this server
      is an OAuth 2.0 **resource server**: it verifies bearer JWTs minted by an
      external authorization server and advertises itself via the
      ``/.well-known/oauth-protected-resource`` metadata route — no IdP, login,
      consent or dynamic client registration lives here)

    The Phase-0 config validator already guarantees the oauth descriptor is complete
    (issuer + jwks_uri + audience + base_url, fail-closed), so this builder can rely
    on those fields being populated.
    """
    mode = s.auth_mode
    if mode in (None, "none"):
        return None
    if mode == "bearer":
        from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

        return StaticTokenVerifier(tokens={s.bearer_token: {"client_id": "mcp", "scopes": []}})
    if mode == "oauth":
        from fastmcp.server.auth import RemoteAuthProvider
        from fastmcp.server.auth.providers.jwt import JWTVerifier
        from pydantic import AnyHttpUrl

        # Token verifier: validate the JWT signature against the IdP's JWKS and
        # enforce issuer / audience / required-scope claims. ssrf_safe defaults to
        # False, which is appropriate for a JWKS URI supplied by the operator.
        verifier = JWTVerifier(
            jwks_uri=s.oauth_jwks_uri,
            issuer=s.oauth_issuer,
            audience=s.oauth_audience,
            required_scopes=s.oauth_required_scopes,
            algorithm=s.oauth_algorithm,
        )
        # Resource-server wrapper: serves the protected-resource discovery document
        # naming the upstream authorization server(s). No client-redirect handling
        # belongs here — that is the authorization server's responsibility.
        return RemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[AnyHttpUrl(u) for u in s.oauth_authorization_servers],
            base_url=s.oauth_base_url,
        )
    # Unreachable: config validation restricts auth_mode to the values above.
    raise ValueError(f"Unsupported auth_mode: {mode!r}")


# Maps the MCP_TLS_CERT_REQS selector to the stdlib ssl client-verification
# constant uvicorn expects. mTLS-only knob (https has no client cert).
_CERT_REQS_MAP: dict[str, int] = {
    "none": ssl.CERT_NONE,
    "optional": ssl.CERT_OPTIONAL,
    "required": ssl.CERT_REQUIRED,
}


def build_uvicorn_config(s: MCPTransportSettings) -> dict[str, Any] | None:
    """Build uvicorn ssl kwargs for the resolved tls_mode.

    Returns ``None`` for ``tls_mode="none"`` so the caller can omit the kwarg
    entirely (fail-closed: stdio's ``run_stdio_async`` rejects ``uvicorn_config``).

    Client-certificate verification (``ssl_cert_reqs``) is driven by the
    ``tls_cert_reqs`` selector rather than hard-coded:

    - ``https`` requests no client certificate, so ``ssl_cert_reqs`` is left
      unset — uvicorn's default is ``ssl.CERT_NONE``. The selector is an mTLS
      knob and does not apply here.
    - ``mtls`` maps the selector (``none``/``optional``/``required``) to the
      matching ``ssl.CERT_*`` constant, defaulting to ``ssl.CERT_REQUIRED`` when
      unset. ``none`` is rejected up-front by the fail-closed config validator,
      so it can never reach this builder under mTLS.
    """
    if s.tls_mode == "none":
        return None
    config: dict[str, Any] = {
        "ssl_certfile": s.tls_certfile,
        "ssl_keyfile": s.tls_keyfile,
        "ssl_keyfile_password": s.tls_key_password or None,
    }
    if s.tls_mode == "mtls":
        config["ssl_ca_certs"] = s.tls_ca_certs
        config["ssl_cert_reqs"] = _CERT_REQS_MAP[s.tls_cert_reqs or "required"]
    return config


_mcp_transport = MCPTransportSettings()

mcp = FastMCP(
    "UniFi Fabric",
    instructions=INSTRUCTIONS,
    lifespan=lifespan,
    auth=build_auth(_mcp_transport),
)


def _require() -> tuple[UniFiClient, Registry]:
    if _client is None or _registry is None:
        raise RuntimeError("Server not initialized")
    return _client, _registry


# --- Site Manager Tools ---


@mcp.tool()
async def list_hosts(
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all UniFi consoles (hosts) with firmware, WAN IP, and status.

    Host records are returned verbatim, including reportedState GPS coordinates.
    By default every page is drained and the complete host list is returned. Pass
    page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). A capped drain returns the hosts gathered so
    far with incomplete=true rather than truncating silently.
    """
    client, registry = _require()
    return await site_manager.list_hosts(client, registry, page_token=page_token)


@mcp.tool()
async def get_host(
    host: str,
) -> dict[str, Any]:
    """Get details for a single UniFi console by name or ID.

    host: console name, ID, or composite ID (MAC:numericId format for cloud consoles).
    Host record is returned verbatim, including reportedState GPS coordinates.
    """
    client, registry = _require()
    return await site_manager.get_host(client, registry, host)


@mcp.tool()
async def list_sites(
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all sites with device/client counts and ISP info.

    The `siteId` in the response is the Site Manager Fabric ObjectId
    (from the /v1/sites list) — it is NOT the same as the proxy-path UUID used by per-site tools.
    You do not need either ID:
    pass site **names** (e.g., "Default") to all tools and the server resolves the correct
    ID internally.

    By default every page is drained and the complete site list is returned. Pass
    page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). A capped drain returns the sites gathered so
    far with incomplete=true rather than truncating silently.
    """
    client, registry = _require()
    return await site_manager.list_sites(client, registry, page_token=page_token)


@mcp.tool()
async def list_devices(
    host: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    """List all devices across the fleet with status, firmware, and model.

    host: optional filter by console name, ID, or composite ID (MAC:numericId format).
    By default every page is drained and the complete device list is returned.
    Pass page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). A capped drain returns the devices gathered so
    far with incomplete=true rather than truncating silently.
    """
    client, registry = _require()
    return await site_manager.list_devices(client, registry, host=host, page_token=page_token)


@mcp.tool()
async def get_isp_metrics(
    interval: str,
) -> dict[str, Any]:
    """Get WAN health metrics (speed, latency, packet loss, uptime).

    This is the simple, unfiltered variant (interval only). To scope by console/site or a
    time window, use `query_isp_metrics` instead.

    interval: time bucket for metrics aggregation — '5m' or '1h'.
    Returns a dict with a 'periods' list containing WAN speed, latency, packet loss, and uptime.
    """
    client, _ = _require()
    return await site_manager.get_isp_metrics(client, interval)


@mcp.tool()
async def query_isp_metrics(
    interval: str,
    host: str | None = None,
    site: str | None = None,
    sites: list[dict] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict[str, Any]:
    """Query filtered ISP metrics with optional site/time range filters.

    This is the filtered variant of `get_isp_metrics`: pass host/site to scope the query and
    start_time/end_time to bound the window. For a quick unscoped read, use `get_isp_metrics`.

    interval: time bucket for metrics aggregation — '5m' or '1h'.
    host: console name, ID, or composite ID (MAC:numericId format) — resolves to hostId.
    site: site name or ID — resolves to siteId automatically.
    sites: advanced use — list of raw {hostId, siteId} dicts; use host/site params instead for
      human-readable names.
    start_time/end_time: ISO 8601 UTC timestamp STRINGS, e.g. "2026-07-23T00:00:00Z".
      These are strings, NOT epoch numbers — passing an epoch integer (seconds or
      milliseconds) is rejected by schema validation with
      'Input should be a valid string [type=string_type]'. (Note the deliberate
      inconsistency with the epoch-based history tools: list_protect_events,
      list_client_sessions and get_historical_stats take epoch SECONDS as integers,
      whereas this Site Manager tool takes ISO 8601 strings.) An epoch supplied AS a
      string (e.g. "1690000000000") is also rejected, with the expected format, rather
      than being forwarded to the API as a meaningless window.
    """
    client, registry = _require()
    resolved_sites = list(sites) if sites else []
    if host and site:
        host_id = await registry.resolve_host_id(host)
        site_id = await registry.resolve_site_id(site, host_id)
        resolved_sites.append({"hostId": host_id, "siteId": site_id})
    return await site_manager.query_isp_metrics(
        client,
        interval,
        sites=resolved_sites or None,
        start_time=start_time,
        end_time=end_time,
    )


@mcp.tool()
async def list_sdwan_configs(
    page_token: str | None = None,
) -> dict[str, Any]:
    """List Site Magic (SD-WAN) VPN mesh configurations.

    By default every page is drained and the complete config list is returned.
    Pass page_token to fetch a single page manually (the response then carries a
    nextToken cursor to continue). A capped drain returns the configs gathered so
    far with incomplete=true rather than truncating silently.
    """
    client, _ = _require()
    return await site_manager.list_sdwan_configs(client, page_token=page_token)


@mcp.tool()
async def get_sdwan_config(
    config_id: str,
) -> dict[str, Any]:
    """Get a single SD-WAN configuration by ID.

    config_id: REQUIRED. Obtain it from `list_sdwan_configs` (its id field).
    """
    client, _ = _require()
    return await site_manager.get_sdwan_config(client, config_id)


@mcp.tool()
async def get_sdwan_config_status(
    config_id: str,
) -> dict[str, Any]:
    """Get the status of an SD-WAN configuration by ID.

    config_id: REQUIRED. Obtain it from `list_sdwan_configs` (its id field).
    """
    client, _ = _require()
    return await site_manager.get_sdwan_config_status(client, config_id)


@mcp.tool()
async def list_all_sites_aggregated() -> dict[str, Any]:
    """List all sites with aggregated health stats from the /v1/sites/ API.

    Returns sites merged with health summary: device counts, client counts,
    alerts, and connectivity status in a single call.
    """
    client, registry = _require()
    return await site_manager.list_all_sites_aggregated(client, registry)


@mcp.tool()
async def get_site_health_summary(
    site: str,
) -> dict[str, Any]:
    """Get health summary for a single site: uptime, alerts, and device counts.

    site: site name or ID.
    """
    client, registry = _require()
    return await site_manager.get_site_health_summary(client, registry, site)


@mcp.tool()
async def compare_site_performance(
    sites: list[str],
) -> dict[str, Any]:
    """Compare health and performance metrics across multiple sites side-by-side.

    sites: list of site names or IDs to compare.
    """
    client, registry = _require()
    return await site_manager.compare_site_performance(client, registry, sites)


@mcp.tool()
async def search_across_sites(
    query: str,
) -> dict[str, Any]:
    """Search for devices or clients matching a query across all sites.

    query: search term matched against name, MAC address, IP, or model.
    """
    client, registry = _require()
    return await site_manager.search_across_sites(client, registry, query)


@mcp.tool()
async def get_site_inventory(
    site: str,
) -> dict[str, Any]:
    """Get full inventory for a site: all devices and connected clients.

    site: site name or ID.
    """
    client, registry = _require()
    return await site_manager.get_site_inventory(client, registry, site)


# --- Network Tools ---


@mcp.tool()
async def get_network_application_info(
    host: str,
) -> dict[str, Any]:
    """Get the UniFi Network application version reported by a console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await network.get_network_application_info(client, registry, host)


@mcp.tool()
async def list_local_sites(
    host: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List sites managed by one UniFi Network application.

    host: console name, ID, or composite ID (MAC:numericId format).
    By default every page is drained and the complete list is returned. Pass
    offset/limit to fetch a single page manually (native envelope preserved).
    A capped drain returns the sites gathered so far with incomplete=true rather
    than truncating silently. filter: optional UniFi Integration API filter.
    """
    client, registry = _require()
    return await network.list_local_sites(
        client,
        registry,
        host,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool()
async def list_networks(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all networks/VLANs for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Networks are offset-paginated (native default page size 25); by default every page
    is drained and the complete list is returned as {data, totalCount}. Pass offset or
    limit for a single manual page. filter: optional Network Integration API filter
    expression, forwarded unchanged as the upstream `filter` query parameter for
    server-side filtering (e.g. `vlanId.eq(100)`, `name.like('*guest*')`,
    `metadata.origin.eq('USER_DEFINED')`); omitted entirely when unset. A capped drain is
    flagged incomplete.
    """
    client, registry = _require()
    return await network.list_networks(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool()
async def create_network(
    host: str,
    site: str,
    network_config: dict[str, Any],
) -> dict[str, Any]:
    """Create a new network/VLAN on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Validated locally before the request (a missing field raises ValueError naming it):
    ``management`` — the discriminator the controller validates first. The rest of the
    required schema is management-mode-specific and enforced by the controller.
    network_config: for management='GATEWAY' the controller also requires (verified live):
      - name (str, max 32 chars)
      - vlanId (int, 1-4094)
      - enabled (bool)
      - internetAccessEnabled (bool)
      - isolationEnabled (bool)
      - cellularBackupEnabled (bool)
      - ipV4Configuration: {'dhcpMode': 'SERVER'|'RELAY'|'NONE', 'subnet': str CIDR,
          'hostAddress': str, 'netmask': str, 'broadcastAddress': str,
          'dhcpRangeStart': str, 'dhcpRangeStop': str}
      Optional: zoneId (str, zone UUID from list_firewall_zones_proxy),
      mdnsForwardingEnabled (bool).
      Field names are camelCase; there is no 'purpose' field in the Network Integration API.

    D12 auto-exclusion: UniFi silently adds every new network to the
    ``excluded_networkconf_ids`` of ALL custom-tagged port profiles
    (``tagged_vlan_mgmt == 'custom'``), blackholing the VLAN at the host uplink.
    When that happens this response carries a ``warnings`` entry (code
    ``D12_AUTO_EXCLUSION``) naming each affected profile; run
    ``allow_network_on_port_profile`` on each to restore tagging.
    """
    client, registry = _require()
    created = await network.create_network(client, registry, host, site, network_config)
    return await network_services_proxy.annotate_auto_exclusions(
        client, registry, host, site, created
    )


@mcp.tool()
async def get_network(
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get a single network/VLAN by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    network_id: REQUIRED. Obtain it from `list_networks` (its id field).
    """
    client, registry = _require()
    return await network.get_network(client, registry, host, site, network_id)


@mcp.tool()
async def update_network(
    host: str,
    site: str,
    network_id: str,
    network_config: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing network/VLAN.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    network_config: full network configuration to replace with.
    network_id: REQUIRED. Obtain it from `list_networks` (its id field).
    """
    client, registry = _require()
    return await network.update_network(client, registry, host, site, network_id, network_config)


@mcp.tool()
async def delete_network(
    host: str,
    site: str,
    network_id: str,
) -> str:
    """Delete a network/VLAN.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    network_id: REQUIRED. Obtain it from `list_networks` (its id field).
    """
    client, registry = _require()
    await network.delete_network(client, registry, host, site, network_id)
    return f"Network {network_id} deleted."


@mcp.tool()
async def get_network_references(
    host: str,
    site: str,
    network_id: str,
) -> dict[str, Any]:
    """Get all resources referencing a network — useful before deleting to check dependencies.

    Returns WiFi broadcasts, firewall policies, and port profiles that use this network.
    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    network_id: network UUID from list_networks.
    """
    client, registry = _require()
    return await network.get_network_references(client, registry, host, site, network_id)


@mcp.tool()
async def list_lags(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Link Aggregation Groups (LAGs) on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    filter: optional UniFi Integration API filter expression.
    """
    client, registry = _require()
    return await network.list_lags(
        client,
        registry,
        host,
        site,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool()
async def get_lag(
    host: str,
    site: str,
    lag_id: str,
) -> dict[str, Any]:
    """Get one Link Aggregation Group.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    lag_id: LAG UUID from list_lags.
    """
    client, registry = _require()
    return await network.get_lag(client, registry, host, site, lag_id)


@mcp.tool()
async def list_mc_lag_domains(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Multi-Chassis Link Aggregation (MC-LAG) domains on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    filter: optional UniFi Integration API filter expression.
    """
    client, registry = _require()
    return await network.list_mc_lag_domains(
        client,
        registry,
        host,
        site,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool()
async def get_mc_lag_domain(
    host: str,
    site: str,
    mc_lag_domain_id: str,
) -> dict[str, Any]:
    """Get one Multi-Chassis Link Aggregation domain.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    mc_lag_domain_id: domain UUID from list_mc_lag_domains.
    """
    client, registry = _require()
    return await network.get_mc_lag_domain(client, registry, host, site, mc_lag_domain_id)


@mcp.tool()
async def list_switch_stacks(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List switch stacks on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    filter: optional UniFi Integration API filter expression.
    """
    client, registry = _require()
    return await network.list_switch_stacks(
        client,
        registry,
        host,
        site,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool()
async def get_switch_stack(
    host: str,
    site: str,
    switch_stack_id: str,
) -> dict[str, Any]:
    """Get one switch stack.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    switch_stack_id: switch-stack UUID from list_switch_stacks.
    """
    client, registry = _require()
    return await network.get_switch_stack(client, registry, host, site, switch_stack_id)


@mcp.tool()
async def list_wifi_broadcasts(
    host: str,
    site: str,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all WiFi broadcast SSIDs for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    filter: optional Network Integration API filter expression, forwarded unchanged as
    the upstream `filter` query parameter for server-side filtering (e.g.
    `enabled.eq(true)`, `name.like('*Guest*')`); omitted entirely when unset.
    """
    client, registry = _require()
    return await network.list_wifi_broadcasts(client, registry, host, site, filter=filter)


@mcp.tool()
async def create_wifi_broadcast(
    host: str,
    site: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Create a new WiFi broadcast SSID on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Validated locally before the request (a missing field raises ValueError naming it):
    ``type`` — the discriminator the controller validates first (observed value:
    'STANDARD'). The remaining fields are type-specific and enforced by the controller.
    broadcast: for a STANDARD SSID also include: {'name': str (SSID name), 'enabled': bool,
      'securityConfiguration': {...}, 'network': str, 'broadcastingFrequenciesGHz': [...]}.
      Field names must be camelCase to match the UniFi Integration API.
    """
    client, registry = _require()
    return await network.create_wifi_broadcast(client, registry, host, site, broadcast)


@mcp.tool()
async def get_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
) -> dict[str, Any]:
    """Get a single WiFi broadcast SSID by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    broadcast_id: REQUIRED. Obtain it from `list_wifi_broadcasts` (its id field).
    """
    client, registry = _require()
    return await network.get_wifi_broadcast(client, registry, host, site, broadcast_id)


@mcp.tool()
async def update_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
    broadcast: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing WiFi broadcast SSID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    broadcast: full WiFi broadcast configuration to replace with.
    broadcast_id: REQUIRED. Obtain it from `list_wifi_broadcasts` (its id field).
    """
    client, registry = _require()
    return await network.update_wifi_broadcast(
        client, registry, host, site, broadcast_id, broadcast
    )


@mcp.tool()
async def delete_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
) -> str:
    """Delete a WiFi broadcast SSID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    broadcast_id: REQUIRED. Obtain it from `list_wifi_broadcasts` (its id field).
    """
    client, registry = _require()
    await network.delete_wifi_broadcast(client, registry, host, site, broadcast_id)
    return f"WiFi broadcast {broadcast_id} deleted."


@mcp.tool()
async def list_wan_interfaces(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List WAN interfaces for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network.list_wan_interfaces(client, registry, host, site)


@mcp.tool()
async def update_wan_interface(
    host: str,
    site: str,
    wan_id: str,
    wan: dict[str, Any],
) -> dict[str, Any]:
    """Update a WAN interface configuration.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    wan_id: WAN interface ID to update.
    wan: fields to update (name, ip, gateway, dns, etc.).
    """
    client, registry = _require()
    return await network.update_wan_interface(client, registry, host, site, wan_id, wan)


device_mgmt.register(mcp, _require)
clients.register(mcp, _require)


# --- Firewall Policy Tools ---


@mcp.tool()
async def list_firewall_policies(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List firewall policies for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    By default every page is drained and the complete policy list is returned as
    {data, totalCount}. Pass offset/limit to fetch a single page manually (the
    API's totalCount is surfaced so you can advance). filter: optional Network
    Integration API filter expression, forwarded unchanged as the upstream `filter`
    query parameter for server-side filtering (e.g. `name.like('*guest*')`,
    `metadata.origin.eq('USER_DEFINED')`); omitted entirely when unset. A capped drain
    returns the policies gathered so far with incomplete=true rather than truncating
    silently.
    """
    client, registry = _require()
    return await firewall_proxy.list_firewall_policies(
        client, registry, host, site, offset, limit, filter=filter
    )


@mcp.tool()
async def create_firewall_policy(
    host: str,
    site: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Create a new firewall policy on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy: required fields (all validated locally — a missing field raises ValueError
    naming it — and all verified against the live controller):
      - name (str)
      - enabled (bool)
      - action: {'type': 'ALLOW'|'DENY'|'REJECT', 'allowReturnTraffic': bool}
      - source: {'zoneId': str}
      - destination: {'zoneId': str}
      - ipProtocolScope: {'ipVersion': 'IPV4'|'IPV6'|'BOTH'}
      - loggingEnabled (bool)
      Note: there is NO 'index' field; use set_firewall_policy_ordering to manage rule order.
      Get zone IDs from list_firewall_zones_proxy.
      trafficFilter (optional; may appear on source and/or destination) narrows the match
      beyond the zone pair. Set trafficFilter.type plus the ONE matching nested object:
        - IP_ADDRESS  -> ipAddressFilter.items[]        (IP addresses / CIDRs)
        - NETWORK     -> networkFilter.networkIds[]      (network UUIDs)
        - PORT        -> portFilter.items[]              (ports / port ranges)
        - MAC_ADDRESS -> macAddressFilter.macAddresses[] (client MAC addresses)
        The controller may also support further types (e.g. region/identity-based);
        list_firewall_policies only reveals the types already in use on a site, so an
        unlisted type is not evidence it is unsupported.
      PORT-FILTER PLACEMENT FOOTGUN: a portFilter under source.trafficFilter filters
      SOURCE ports, which for outbound flows are ephemeral (random high ports) -> the rule
      silently matches nothing. A destination-port rule MUST use destination.trafficFilter
      with type PORT, never a source portFilter. (create/update_firewall_policy log a
      runtime warning when a source PORT filter is combined with an any-destination ALLOW.)
    """
    client, registry = _require()
    return await firewall_proxy.create_firewall_policy(client, registry, host, site, policy)


@mcp.tool()
async def get_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
) -> dict[str, Any]:
    """Get a single firewall policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy_id: REQUIRED. The policy's id; obtain it from `list_firewall_policies` (its id field).
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_policy(client, registry, host, site, policy_id)


@mcp.tool()
async def update_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Full-replace a firewall policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy: full firewall policy configuration to replace with.
    policy_id: REQUIRED. The policy's id; obtain it from `list_firewall_policies` (its id field).
    trafficFilter (optional; may appear on source and/or destination) narrows the match
    beyond the zone pair. Set trafficFilter.type plus the ONE matching nested object:
      - IP_ADDRESS  -> ipAddressFilter.items[]        (IP addresses / CIDRs)
      - NETWORK     -> networkFilter.networkIds[]      (network UUIDs)
      - PORT        -> portFilter.items[]              (ports / port ranges)
      - MAC_ADDRESS -> macAddressFilter.macAddresses[] (client MAC addresses)
      The controller may also support further types (e.g. region/identity-based);
      list_firewall_policies only reveals the types already in use on a site, so an
      unlisted type is not evidence it is unsupported.
    PORT-FILTER PLACEMENT FOOTGUN: a portFilter under source.trafficFilter filters
    SOURCE ports, which for outbound flows are ephemeral (random high ports) -> the rule
    silently matches nothing. A destination-port rule MUST use destination.trafficFilter
    with type PORT, never a source portFilter. (create/update_firewall_policy log a
    runtime warning when a source PORT filter is combined with an any-destination ALLOW.)
    """
    client, registry = _require()
    return await firewall_proxy.update_firewall_policy(
        client, registry, host, site, policy_id, policy
    )


@mcp.tool()
async def patch_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """Partially update a firewall policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    fields: fields to update on the policy.
    policy_id: REQUIRED. The policy's id; obtain it from `list_firewall_policies` (its id field).
    """
    client, registry = _require()
    return await firewall_proxy.patch_firewall_policy(
        client, registry, host, site, policy_id, fields
    )


@mcp.tool()
async def delete_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
) -> str:
    """Delete a firewall policy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy_id: REQUIRED. The policy's id; obtain it from `list_firewall_policies` (its id field).
    """
    client, registry = _require()
    await firewall_proxy.delete_firewall_policy(client, registry, host, site, policy_id)
    return f"Firewall policy {policy_id} deleted."


@mcp.tool()
async def get_firewall_policy_ordering(
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
) -> dict[str, Any]:
    """Get the ordering of firewall policies for a site filtered by source and destination zone.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    source_zone_id: UUID of the source firewall zone (required by the API).
    destination_zone_id: UUID of the destination firewall zone (required by the API).
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_policy_ordering(
        client, registry, host, site, source_zone_id, destination_zone_id
    )


@mcp.tool()
async def set_firewall_policy_ordering(
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    """Set the ordering of firewall policies within one source/destination zone pair.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    source_zone_id: UUID of the source firewall zone. REQUIRED by the API and sent as a
      query parameter (NOT read from the ordering body); omitting it returns HTTP 400.
    destination_zone_id: UUID of the destination firewall zone. Same requirement as
      source_zone_id. Use the same zone pair you read with get_firewall_policy_ordering.
    ordering: policy ordering configuration (the ordered policy list for that zone pair).
    """
    client, registry = _require()
    return await firewall_proxy.set_firewall_policy_ordering(
        client, registry, host, site, source_zone_id, destination_zone_id, ordering
    )


# --- Firewall Zone Tools ---


@mcp.tool()
async def list_firewall_zones_proxy(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List all firewall zones for a site via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Zones are offset-paginated (native default page size 25); by default every page is
    drained and the complete list is returned as {data, totalCount}. Pass offset or
    limit for a single manual page. A capped drain is flagged incomplete.
    """
    client, registry = _require()
    return await firewall_proxy.list_firewall_zones(
        client, registry, host, site, offset=offset, limit=limit
    )


@mcp.tool()
async def create_firewall_zone_proxy(
    host: str,
    site: str,
    zone: dict[str, Any],
) -> dict[str, Any]:
    """Create a new firewall zone on a site via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    zone: must include {'name': str, 'networkIds': [str]} — both required, validated
    locally (a missing field raises ValueError naming it) and verified against the live
    controller. Get network IDs from list_networks.
    """
    client, registry = _require()
    return await firewall_proxy.create_firewall_zone(client, registry, host, site, zone)


@mcp.tool()
async def get_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
) -> dict[str, Any]:
    """Get a single firewall zone by ID via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    zone_id: REQUIRED. Obtain it from `list_firewall_zones_proxy` (its id field).
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_zone(client, registry, host, site, zone_id)


@mcp.tool()
async def update_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
    zone: dict[str, Any],
) -> dict[str, Any]:
    """Update a firewall zone by ID via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    zone: full firewall zone configuration to replace with.
    zone_id: REQUIRED. Obtain it from `list_firewall_zones_proxy` (its id field).
    """
    client, registry = _require()
    return await firewall_proxy.update_firewall_zone(client, registry, host, site, zone_id, zone)


@mcp.tool()
async def delete_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
) -> str:
    """Delete a firewall zone via connector proxy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    zone_id: REQUIRED. Obtain it from `list_firewall_zones_proxy` (its id field).
    """
    client, registry = _require()
    await firewall_proxy.delete_firewall_zone(client, registry, host, site, zone_id)
    return f"Firewall zone {zone_id} deleted."


# --- ACL Rule Tools ---


@mcp.tool()
async def list_acl_rules(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all ACL rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.list_acl_rules(client, registry, host, site)


@mcp.tool()
async def create_acl_rule(
    host: str,
    site: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Create a new ACL rule on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Validated locally before the request (a missing field raises ValueError naming it):
    ``type`` — the discriminator the controller validates first (verified live: an empty
    body is rejected with ``Missing $.type value``; observed value: 'MAC'). The remaining
    fields are type-specific and enforced by the controller.
    rule: for a MAC-type rule the live object also carries: name (str), action, enabled
    (bool), sourceFilter, networkIdFilter. Read an existing rule with get_acl_rule to see
    the exact shape for the type you want.
    Note: ACL rules are for intra-VLAN/inter-network L3 filtering. For zone-based
    perimeter firewall rules, use create_firewall_policy instead.
    """
    client, registry = _require()
    return await firewall_proxy.create_acl_rule(client, registry, host, site, rule)


@mcp.tool()
async def get_acl_rule(
    host: str,
    site: str,
    rule_id: str,
) -> dict[str, Any]:
    """Get a single ACL rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule_id: REQUIRED. The rule's id; obtain it from `list_acl_rules` (its id field).
    """
    client, registry = _require()
    return await firewall_proxy.get_acl_rule(client, registry, host, site, rule_id)


@mcp.tool()
async def update_acl_rule(
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Update an existing ACL rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule: full ACL rule configuration to replace with.
    rule_id: REQUIRED. The rule's id; obtain it from `list_acl_rules` (its id field).
    """
    client, registry = _require()
    return await firewall_proxy.update_acl_rule(client, registry, host, site, rule_id, rule)


@mcp.tool()
async def delete_acl_rule(
    host: str,
    site: str,
    rule_id: str,
) -> str:
    """Delete an ACL rule.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule_id: REQUIRED. The rule's id; obtain it from `list_acl_rules` (its id field).
    """
    client, registry = _require()
    await firewall_proxy.delete_acl_rule(client, registry, host, site, rule_id)
    return f"ACL rule {rule_id} deleted."


@mcp.tool()
async def get_acl_rule_ordering(
    host: str,
    site: str,
) -> dict[str, Any]:
    """Get the ordering of ACL rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await firewall_proxy.get_acl_rule_ordering(client, registry, host, site)


@mcp.tool()
async def set_acl_rule_ordering(
    host: str,
    site: str,
    ordering: dict[str, Any],
) -> dict[str, Any]:
    """Set the ordering of ACL rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    ordering: ACL rule ordering configuration.
    """
    client, registry = _require()
    return await firewall_proxy.set_acl_rule_ordering(client, registry, host, site, ordering)


# --- DNS Policy Tools ---


@mcp.tool()
async def list_dns_policies(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List all DNS policies for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    DNS policies are offset-paginated (native default page size 25); by default every
    page is drained and the complete list is returned as {data, totalCount}. Pass
    offset or limit for a single manual page. A capped drain is flagged incomplete.
    """
    client, registry = _require()
    return await network_services_proxy.list_dns_policies(
        client, registry, host, site, offset=offset, limit=limit
    )


@mcp.tool()
async def create_dns_policy(
    host: str,
    site: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Create a new DNS policy on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Validated locally before the request (a missing field raises ValueError naming it):
    ``type`` — the discriminator the controller validates first (verified live: an empty
    body is rejected with ``Missing $.type value``). The remaining fields are type-specific
    and enforced by the controller.
    policy: for a typical policy also include a name and the network scope; read an
    existing policy with get_dns_policy to confirm the exact shape for the type you want.
    """
    client, registry = _require()
    return await network_services_proxy.create_dns_policy(client, registry, host, site, policy)


@mcp.tool()
async def get_dns_policy(
    host: str,
    site: str,
    policy_id: str,
) -> dict[str, Any]:
    """Get a single DNS policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy_id: REQUIRED. The policy's id; obtain it from `list_dns_policies` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.get_dns_policy(client, registry, host, site, policy_id)


@mcp.tool()
async def update_dns_policy(
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Update a DNS policy by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy: full DNS policy configuration to replace with.
    policy_id: REQUIRED. The policy's id; obtain it from `list_dns_policies` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.update_dns_policy(
        client, registry, host, site, policy_id, policy
    )


@mcp.tool()
async def delete_dns_policy(
    host: str,
    site: str,
    policy_id: str,
) -> str:
    """Delete a DNS policy.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    policy_id: REQUIRED. The policy's id; obtain it from `list_dns_policies` (its id field).
    """
    client, registry = _require()
    await network_services_proxy.delete_dns_policy(client, registry, host, site, policy_id)
    return f"DNS policy {policy_id} deleted."


# --- Traffic Matching List Tools ---


@mcp.tool()
async def list_traffic_matching_lists(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all traffic matching lists for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_matching_lists(client, registry, host, site)


@mcp.tool()
async def create_traffic_matching_list(
    host: str,
    site: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    """Create a new traffic matching list on a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Validated locally before the request (a missing field raises ValueError naming it):
    a top-level ``type`` — the discriminator the controller validates first (verified live:
    an empty body is rejected with ``Missing $.type value``; observed value: 'PORTS').
    traffic_list: for a PORTS list the live object also carries ``name`` (str) and
    ``items`` (list). Note: the list field is 'items', not 'entries'.
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_matching_list(
        client, registry, host, site, traffic_list
    )


@mcp.tool()
async def get_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
) -> dict[str, Any]:
    """Get a single traffic matching list by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    list_id: REQUIRED. Obtain it from `list_traffic_matching_lists` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.get_traffic_matching_list(
        client, registry, host, site, list_id
    )


@mcp.tool()
async def update_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    """Update a traffic matching list by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    traffic_list: full traffic matching list configuration to replace with.
    list_id: REQUIRED. Obtain it from `list_traffic_matching_lists` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_matching_list(
        client, registry, host, site, list_id, traffic_list
    )


@mcp.tool()
async def delete_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
) -> str:
    """Delete a traffic matching list.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    list_id: REQUIRED. Obtain it from `list_traffic_matching_lists` (its id field).
    """
    client, registry = _require()
    await network_services_proxy.delete_traffic_matching_list(client, registry, host, site, list_id)
    return f"Traffic matching list {list_id} deleted."


# --- VPN Server Tools ---


@mcp.tool()
async def list_vpn_servers(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List VPN servers for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    VPN servers are offset-paginated (native default page size 25); by default every
    page is drained and the complete list is returned as {data, totalCount}. Pass
    offset or limit for a single manual page. A capped drain is flagged incomplete.
    """
    client, registry = _require()
    return await network_services_proxy.list_vpn_servers(
        client, registry, host, site, offset=offset, limit=limit
    )


@mcp.tool()
async def list_site_to_site_tunnels(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List site-to-site VPN tunnels for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_site_to_site_tunnels(client, registry, host, site)


# --- RADIUS Profile Tools ---


@mcp.tool()
async def list_radius_profiles(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List RADIUS profiles for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    RADIUS profiles are offset-paginated (native default page size 25); by default
    every page is drained and the complete list is returned as {data, totalCount}.
    Pass offset or limit for a single manual page. A capped drain is flagged incomplete.
    """
    client, registry = _require()
    return await network_services_proxy.list_radius_profiles(
        client, registry, host, site, offset=offset, limit=limit
    )


# --- Hotspot Voucher Tools ---


@mcp.tool()
async def list_hotspot_vouchers(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List all hotspot/guest vouchers for a site (there is no `list_vouchers` — this is it).

    This is the voucher-listing tool; the family is `list_hotspot_vouchers`,
    `create_hotspot_vouchers`, `get_hotspot_voucher`, `delete_hotspot_voucher` — all
    prefixed `hotspot_`. There is no shorter `list_vouchers`/`get_voucher` alias.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Vouchers are offset-paginated (native default page size 100) and batches routinely
    exceed that; by default every page is drained and the complete list is returned as
    {data, totalCount}. Pass offset or limit for a single manual page. A capped drain
    is flagged incomplete.
    """
    client, registry = _require()
    return await network_services_proxy.list_hotspot_vouchers(
        client, registry, host, site, offset=offset, limit=limit
    )


@mcp.tool()
async def create_hotspot_vouchers(
    host: str,
    site: str,
    voucher_config: dict[str, Any],
) -> dict[str, Any]:
    """Generate hotspot vouchers for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    voucher_config: required fields (validated locally — a missing field raises ValueError
    naming it — and verified against the live controller): ``name`` and
    ``timeLimitMinutes`` (voucher validity window, minutes). Optional: count, quota,
    bandwidth limits, etc.
    """
    client, registry = _require()
    return await network_services_proxy.create_hotspot_vouchers(
        client, registry, host, site, voucher_config
    )


@mcp.tool()
async def get_hotspot_voucher(
    host: str,
    site: str,
    voucher_id: str,
) -> dict[str, Any]:
    """Get a single hotspot voucher by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    voucher_id: REQUIRED. Obtain it from `list_hotspot_vouchers` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.get_hotspot_voucher(
        client, registry, host, site, voucher_id
    )


@mcp.tool()
async def delete_hotspot_voucher(
    host: str,
    site: str,
    voucher_id: str,
) -> str:
    """Delete a single hotspot voucher.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    voucher_id: REQUIRED. Obtain it from `list_hotspot_vouchers` (its id field).
    """
    client, registry = _require()
    await network_services_proxy.delete_hotspot_voucher(client, registry, host, site, voucher_id)
    return f"Hotspot voucher {voucher_id} deleted."


@mcp.tool()
async def bulk_delete_hotspot_vouchers(
    host: str,
    site: str,
    filter_params: dict[str, Any],
) -> str:
    """Bulk delete hotspot vouchers matching filter criteria.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    filter_params: filter parameters to select vouchers for deletion.
    """
    client, registry = _require()
    await network_services_proxy.bulk_delete_hotspot_vouchers(
        client, registry, host, site, filter_params
    )
    return "Hotspot vouchers deleted."


# --- Supporting Resources Tools ---


@mcp.tool()
async def list_device_tags(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all device tags defined in a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_device_tags(client, registry, host, site)


@mcp.tool()
async def list_countries(
    host: str,
) -> dict[str, Any]:
    """List all countries with ISO codes available on a console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await network_services_proxy.list_countries(client, registry, host)


# --- Protect Camera Management Tools ---


@mcp.tool()
async def list_cameras(
    host: str,
) -> dict[str, Any]:
    """List all cameras on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_cameras(client, registry, host)


@mcp.tool()
async def get_camera(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect camera by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.get_camera(client, registry, host, camera_id)


@mcp.tool()
async def update_camera(
    host: str,
    camera_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect camera (name, recording mode, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of camera settings to update.
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.update_camera(client, registry, host, camera_id, **settings)


@mcp.tool()
async def get_camera_snapshot(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get a snapshot from a Protect camera. Returns base64-encoded JPEG image data.

    host: console name, ID, or composite ID (MAC:numericId format).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.get_camera_snapshot(client, registry, host, camera_id)


@mcp.tool()
async def get_rtsps_stream(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get existing RTSPS stream URLs for a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.get_rtsps_stream(client, registry, host, camera_id)


@mcp.tool()
async def create_rtsps_stream(
    host: str,
    camera_id: str,
    qualities: list[str],
) -> dict[str, Any]:
    """Create an RTSPS stream for a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    qualities: list of channel names to enable. The exhaustive set is 'high', 'medium',
      'low', and 'package' (verified live against get_rtsps_stream, which reports exactly
      these four channel keys). 'package' exists only on package-camera doorbells; on other
      cameras it is null. There is NO 'highest' channel. Case-insensitive — values are
      normalized to lowercase before sending. The list is forwarded to the API as-is with
      no local allow-list, so an unrecognised name is not validated here; the upstream
      Protect API governs the outcome (a name with no matching channel yields no stream for
      that entry rather than a local error).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.create_rtsps_stream(client, registry, host, camera_id, qualities)


@mcp.tool()
async def delete_rtsps_stream(
    host: str,
    camera_id: str,
    qualities: list[str],
) -> str:
    """Delete an RTSPS stream for a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    qualities: list of channel names to delete. The exhaustive set is 'high', 'medium',
      'low', and 'package' (verified live; 'package' only on package-camera doorbells).
      There is NO 'highest' channel. Case-insensitive — values are normalized to lowercase
      before sending. Forwarded to the API as-is with no local allow-list; an unrecognised
      name is not validated here and the upstream Protect API governs the outcome.
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    await protect.delete_rtsps_stream(client, registry, host, camera_id, qualities)
    return f"RTSPS stream for camera {camera_id} deleted."


@mcp.tool()
async def start_talkback_session(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Start a talkback audio session on a Protect camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.talkback_start(client, registry, host, camera_id)


@mcp.tool()
async def disable_camera_mic_permanently(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Permanently disable the microphone on a Protect camera. This cannot be undone.

    host: console name, ID, or composite ID (MAC:numericId format).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.disable_mic_permanently(client, registry, host, camera_id)


@mcp.tool()
async def ptz_goto_preset(
    host: str,
    camera_id: str,
    slot: int,
) -> dict[str, Any]:
    """Move a PTZ camera to a preset position slot.

    host: console name, ID, or composite ID (MAC:numericId format).
    slot: preset slot number to move to.
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.ptz_goto(client, registry, host, camera_id, slot)


@mcp.tool()
async def ptz_patrol_start(
    host: str,
    camera_id: str,
    slot: int,
) -> dict[str, Any]:
    """Start a PTZ patrol on a preset slot.

    host: console name, ID, or composite ID (MAC:numericId format).
    slot: patrol preset slot number.
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.ptz_patrol_start(client, registry, host, camera_id, slot)


@mcp.tool()
async def ptz_patrol_stop(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Stop the current PTZ patrol on a camera.

    host: console name, ID, or composite ID (MAC:numericId format).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    """
    client, registry = _require()
    return await protect.ptz_patrol_stop(client, registry, host, camera_id)


# --- Protect Sensor Tools ---


@mcp.tool()
async def list_sensors(
    host: str,
) -> dict[str, Any]:
    """List all sensors on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_sensors(client, registry, host)


@mcp.tool()
async def get_sensor(
    host: str,
    sensor_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect sensor by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    sensor_id: REQUIRED. Obtain it from `list_sensors` (its id field).
    """
    client, registry = _require()
    return await protect.get_sensor(client, registry, host, sensor_id)


@mcp.tool()
async def update_sensor(
    host: str,
    sensor_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect sensor.

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of sensor settings to update.
    sensor_id: REQUIRED. Obtain it from `list_sensors` (its id field).
    """
    client, registry = _require()
    return await protect.update_sensor(client, registry, host, sensor_id, **settings)


# --- Protect Historical Events ---


@mcp.tool()
async def list_protect_events(
    host: str,
    start: int,
    end: int,
    types: str | list[str] | None = None,
    cameras: str | list[str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    order_direction: str = "ASC",
    smart_detect_types: str | list[str] | None = None,
    categories: str | list[str] | None = None,
    without_descriptions: bool | None = None,
) -> dict[str, Any]:
    """Query historical Protect events (motion, smart-detect, sensor open/close, etc.).

    This uses the private /proxy/protect/api/events REST path — the ONLY source of
    historical events. The official Protect Integration API exposes events solely over
    WebSocket (/v1/subscribe/events) with no REST query endpoint, so do not expect the
    integration path to answer this.

    REQUIRED: host, start, and end. `start`/`end` are epoch SECONDS as INTEGERS (e.g.
    1690000000 for 2023-07-22T06:13:20Z), NOT milliseconds and NOT an ISO 8601 string:
    a millisecond-magnitude value is rejected up front, and a string fails schema
    validation. This differs on purpose from query_isp_metrics, whose start_time/end_time
    are ISO 8601 STRINGS — do not carry a format across the two tools.

    host: console name, ID, or composite ID (MAC:numericId format).
    start/end: REQUIRED. Epoch SECONDS (UTC) as integers, converted to milliseconds
      internally. Ranges are inclusive on both ends. History depth is bounded by the
      NVR's retention. (Contrast query_isp_metrics, which wants ISO 8601 strings.)
    types: filter by event TYPE; single value or a list. Verified-present values:
      motion, smartDetectZone, smartAudioDetect, sensorOpened, sensorClosed, access.
      NOTE: person/face/animal/alrmSpeak are NOT event types — they are smart-detect
      subtypes and belong in smart_detect_types, not here. An unrecognised value
      returns zero events.
    smart_detect_types: filter by the smart-detect SUBTYPE — person, vehicle, animal,
      package, face, licensePlate (on smartDetectZone events) and the audio alarms
      alrmSpeak, alrmSiren, alrmBark, alrmCarHorn (on smartAudioDetect events). This is
      a distinct upstream parameter from types. The API only honours it when types is
      also set to the relevant event type(s); passing smart_detect_types alone is a
      silent no-op upstream, so this tool rejects that with a clear error. Example:
      types="smartDetectZone", smart_detect_types="person" for just person detections;
      types="smartAudioDetect", smart_detect_types="alrmSpeak" to isolate the dominant
      audio-alarm noise.
    cameras: filter by camera NAME or ID; single value or list. Names resolve to IDs
      (case-insensitive) — an unknown name errors rather than silently matching nothing.
    categories: filter by event category; single value or list. Verified values:
      motion, smart, iot, admin. Unknown values are silently ignored by the upstream API.
    without_descriptions: when true, ask the API to omit each event's description block
      (~16% smaller payload). Opt-in only — full-fidelity records are the default and
      descriptions are never dropped automatically.
    limit/offset: offset-based pagination (not cursor-based). By default (neither
      given) every page is drained and the complete event set for the window is
      returned — a wide window can hold tens of thousands of events, so expect all of
      them, not just the first page. Pass offset or limit to fetch a single manual
      page instead; a capped drain is flagged incomplete rather than truncating.
    order_direction: "ASC" (default, oldest-first) or "DESC" (newest-first).

    Sensor events set the top-level ``sensor`` field to null; the sensor reference at
    metadata.sensorId.text is promoted to that field so you can filter/join on it.
    Events are passed through verbatim, including identifiers (MAC/IP/hostname/name) and
    the metadata.name object carrying camera / recognised-person / license-plate text; the
    recognised-person name on face events is at metadata.detectedThumbnails[].matchedName.
    """
    client, registry = _require()
    return await protect.list_protect_events(
        client,
        registry,
        host,
        start,
        end,
        types,
        cameras,
        limit,
        offset,
        order_direction,
        smart_detect_types=smart_detect_types,
        categories=categories,
        without_descriptions=without_descriptions,
    )


# --- Protect Face/Vehicle Recognition (private REST path) ---


@mcp.tool()
async def list_recognition_groups(
    host: str,
    type: str,
    has_name: bool | None = None,
    page_size: int | None = None,
    order_by: str | None = None,
    order_direction: str | None = None,
    page: int | None = None,
) -> dict[str, Any]:
    """List recognition groups (enrolled faces / vehicles) on a Protect console.

    Uses the private /proxy/protect/api/recognition/{type}/groups REST path (not the
    Protect Integration API, which has no recognition surface). Each group is a
    recognised subject with a stable, monotonic id (face_1, face_90, …), a name /
    matchedName label, a detectionsCount, and createdAt/firstDetectedAt/lastDetectedAt
    timestamps usable as sync and change-detection keys. This is a faithful pass-through:
    the name label is returned as-is and nothing is redacted.

    Response shape: {"groups": [...], "count": N} (plus "nextPage" / "incomplete" when
    paging manually). The array key is "groups", NOT "data" — unlike the offset-proxy
    tools that return {"data": [...], "totalCount": N}; read the list from result["groups"].

    host: console name, ID, or composite ID (MAC:numericId format).
    type: recognition type. Use 'face' or 'vehicle' (singular). Plural forms
      ('faces', 'vehicles') are NOT valid and return HTTP 400 from upstream — two
      separate agents have guessed plural and hit this error. The value is forwarded
      as-is, so any other type the console accepts also works, and any it rejects is
      answered by the API's own error.
    has_name: when true, return only named groups (unnamed groups are filtered out).
    page_size: API page size; also the drain page size. Defaults to 200.
    order_by / order_direction: server-side sort. order_direction is 'asc' or 'desc',
      case-insensitive ('ASC'/'DESC' behave identically); an unrecognised value is
      rejected upstream with HTTP 400. It only takes effect together with order_by
      (e.g. order_by='name') — with order_by set but order_direction omitted the API
      defaults to descending. order_by accepts name, createdAt, lastDetectedAt, or
      detectionsCount.
    page: fetch a single page (1-based) instead of draining. The response pages via a
      links.next envelope; by default every page is drained and the complete group set
      is returned. Pass page to fetch one page manually — nextPage is then surfaced.
    """
    client, registry = _require()
    return await recognition.list_recognition_groups(
        client, registry, host, type, has_name, page_size, order_by, order_direction, page
    )


@mcp.tool()
async def get_recognition_group_counts(
    host: str,
    type: str,
) -> dict[str, Any]:
    """Get aggregate recognition-group counts for a Protect console.

    Returns totals such as totalCount, nameNotNullCount (named groups), nameIsNullCount,
    notificationEnabledCount, and degradedCount.

    host: console name, ID, or composite ID (MAC:numericId format).
    type: recognition type. Use 'face' or 'vehicle' (singular — plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.
    """
    client, registry = _require()
    return await recognition.get_recognition_group_counts(client, registry, host, type)


@mcp.tool()
async def get_recognition_group_image(
    host: str,
    type: str,
    group_id: str,
) -> dict[str, Any]:
    """Get a recognition group's reference crop. Returns base64-encoded JPEG image data.

    host: console name, ID, or composite ID (MAC:numericId format).
    type: recognition type. Use 'face' or 'vehicle' (singular -- plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.
    group_id: the group's stable id, e.g. face_90.
    """
    client, registry = _require()
    return await recognition.get_recognition_group_image(client, registry, host, type, group_id)


@mcp.tool()
async def list_recognition_detections(
    host: str,
    type: str,
    group_id: str,
    page_size: int | None = None,
    start: int | None = None,
    end: int | None = None,
    page: int | None = None,
) -> dict[str, Any]:
    """List a recognition group's detections (individual sightings) on a Protect console.

    REQUIRED: both `type` and `group_id`. `group_id` identifies which enrolled subject to
    list sightings for — obtain a valid one from `list_recognition_groups` (its `id` field,
    e.g. face_90); there is no "all groups" mode. Calling without `group_id` fails schema
    validation, and passing an id that does not exist on the console returns HTTP 404.

    Each detection carries id, eventId (joinable against list_protect_events), thumbnailId
    (fetch the crop with get_thumbnail), detectedAt (epoch ms), cameraId, and
    matchedGroupConfidence (0-100).

    Response shape: {"detections": [...], "count": N} (plus "nextPage" / "incomplete" when
    paging manually). The array key is "detections", NOT "data" — unlike the offset-proxy
    tools that return {"data": [...], "totalCount": N}; read the list from
    result["detections"].

    host: console name, ID, or composite ID (MAC:numericId format).
    type: recognition type. Use 'face' or 'vehicle' (singular -- plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.
    group_id: REQUIRED. The group's stable id, e.g. face_90 — take it from a
      `list_recognition_groups` result (the `id` field). Not optional; not guessable.
    page_size: API page size; also the drain page size. Defaults to 200.
    start/end: optional time window in epoch SECONDS (UTC), converted to milliseconds
      internally. Verified live: the endpoint filters detections server-side by detectedAt
      against this window, so an arbitrary range (e.g. the last hour, 30 days, or 90 days)
      can be requested directly. Omit both for all detections.
    page: fetch a single page (1-based) instead of draining. The response pages via a
      links.next envelope; by default every page is drained so the complete detection set
      for the group (and window, if given) is returned. Pass page to fetch one page
      manually — nextPage is then surfaced.
    """
    client, registry = _require()
    return await recognition.list_recognition_detections(
        client, registry, host, type, group_id, page_size, start, end, page
    )


@mcp.tool()
async def get_thumbnail(
    host: str,
    thumbnail_id: str,
) -> dict[str, Any]:
    """Get a detection thumbnail crop. Returns base64-encoded JPEG image data.

    host: console name, ID, or composite ID (MAC:numericId format).
    thumbnail_id: the thumbnailId from a detection record.
    """
    client, registry = _require()
    return await recognition.get_thumbnail(client, registry, host, thumbnail_id)


# --- Protect Light Tools ---


@mcp.tool()
async def list_lights(
    host: str,
) -> dict[str, Any]:
    """List all lights on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_lights(client, registry, host)


@mcp.tool()
async def get_light(
    host: str,
    light_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect light by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    light_id: REQUIRED. Obtain it from `list_lights` (its id field).
    """
    client, registry = _require()
    return await protect.get_light(client, registry, host, light_id)


@mcp.tool()
async def update_light(
    host: str,
    light_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect light (brightness, sensitivity, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of light settings to update.
    light_id: REQUIRED. Obtain it from `list_lights` (its id field).
    """
    client, registry = _require()
    return await protect.update_light(client, registry, host, light_id, **settings)


# --- Protect Chime Tools ---


@mcp.tool()
async def list_chimes(
    host: str,
) -> dict[str, Any]:
    """List all chimes on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_chimes(client, registry, host)


@mcp.tool()
async def get_chime(
    host: str,
    chime_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect chime by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    chime_id: REQUIRED. Obtain it from `list_chimes` (its id field).
    """
    client, registry = _require()
    return await protect.get_chime(client, registry, host, chime_id)


@mcp.tool()
async def update_chime(
    host: str,
    chime_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect chime (volume, ringtone, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of chime settings to update.
    chime_id: REQUIRED. Obtain it from `list_chimes` (its id field).
    """
    client, registry = _require()
    return await protect.update_chime(client, registry, host, chime_id, **settings)


# --- Protect Viewer Tools ---


@mcp.tool()
async def list_viewers(
    host: str,
) -> dict[str, Any]:
    """List all viewers on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_viewers(client, registry, host)


@mcp.tool()
async def get_viewer(
    host: str,
    viewer_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect viewer by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    viewer_id: REQUIRED. Obtain it from `list_viewers` (its id field).
    """
    client, registry = _require()
    return await protect.get_viewer(client, registry, host, viewer_id)


@mcp.tool()
async def update_viewer(
    host: str,
    viewer_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect viewer (liveview assignment, etc.).

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of viewer settings to update.
    viewer_id: REQUIRED. Obtain it from `list_viewers` (its id field).
    """
    client, registry = _require()
    return await protect.update_viewer(client, registry, host, viewer_id, **settings)


# --- Protect Liveview Tools ---


@mcp.tool()
async def list_liveviews(
    host: str,
) -> dict[str, Any]:
    """List all liveviews on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_liveviews(client, registry, host)


@mcp.tool()
async def get_liveview(
    host: str,
    liveview_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect liveview by ID.

    host: console name, ID, or composite ID (MAC:numericId format).
    liveview_id: REQUIRED. Obtain it from `list_liveviews` (its id field).
    """
    client, registry = _require()
    return await protect.get_liveview(client, registry, host, liveview_id)


@mcp.tool()
async def create_liveview(
    host: str,
    name: str,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a liveview on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    name: liveview display name.
    settings: optional additional liveview fields (layout, slots, etc.).
    """
    client, registry = _require()
    extra = settings or {}
    return await protect.create_liveview(client, registry, host, name, **extra)


@mcp.tool()
async def update_liveview(
    host: str,
    liveview_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update a liveview on a Protect console.

    host: console name, ID, or composite ID (MAC:numericId format).
    settings: key-value pairs of liveview settings to update.
    liveview_id: REQUIRED. Obtain it from `list_liveviews` (its id field).
    """
    client, registry = _require()
    return await protect.update_liveview(client, registry, host, liveview_id, **settings)


# --- Protect NVR Tools ---


@mcp.tool()
async def get_nvr(
    host: str,
) -> dict[str, Any]:
    """Get NVR details from a Protect console.

    Returns NVR hardware info, storage status, firmware version, and system health.
    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_nvr(client, registry, host)


# --- Protect File Tools ---


@mcp.tool()
async def list_protect_files(
    host: str,
    file_type: str,
) -> dict[str, Any]:
    """List Protect device asset files of a given type.

    host: console name, ID, or composite ID (MAC:numericId format).
    file_type: Protect asset category. 'sounds' and 'images' are the known categories.
      The GET endpoint does NOT validate this value — an unrecognised category returns
      HTTP 200 with an empty list rather than an error, so a wrong value is
      indistinguishable from a genuinely empty category. Pass a known category exactly.
    """
    client, registry = _require()
    return await protect.list_protect_files(client, registry, host, file_type)


@mcp.tool()
async def upload_protect_file(
    host: str,
    file_type: str,
    filename: str,
    file_content_base64: str,
) -> dict[str, Any]:
    """Upload a Protect device asset file. WARNING: Uploads asset file to NVR storage.
    Overwriting system files may not be reversible.

    host: console name, ID, or composite ID (MAC:numericId format).
    file_type: Protect asset category. 'sounds' and 'images' are the known categories;
      the value selects the upload target path (/files/{file_type}). The category is not
      validated on read-back, so pass a known category exactly.
    filename: name of the file to upload (e.g. 'alert.mp3').
    file_content_base64: base64-encoded file content.
    """
    client, registry = _require()
    return await protect.upload_protect_file(
        client, registry, host, file_type, filename, file_content_base64
    )


# --- Protect Alarm Manager Tools ---


@mcp.tool()
async def trigger_alarm_webhook(
    host: str,
    webhook_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Trigger an alarm manager webhook by ID. WARNING: triggers physical alarm hardware.
    Verify webhook ID is correct before confirming.

    host: console name, ID, or composite ID (MAC:numericId format).
    webhook_id: alarm webhook ID to trigger.
    confirm: must be True to execute. Prevents accidental triggers on live infrastructure.
    """
    if not confirm:
        return {
            "status": "not_triggered",
            "reason": (
                "Set confirm=True to trigger physical alarm hardware. Verify webhook_id first."
            ),
        }
    client, registry = _require()
    return await protect.trigger_alarm_webhook(client, registry, host, webhook_id)


# --- Protect Arm Profile & Alarm Tools ---
#
# Extended Protect Integration API families (v7.1.87), all reached over the same
# Fabric connector base (…/proxy/protect/integration/v1) as the camera tools. The
# write/action tools are governed by the UNIFI_PROTECT_MUTATIONS_ENABLED env gate
# (default ON); physical/irreversible actions additionally require confirm=true.


@mcp.tool()
async def list_arm_profiles(
    host: str,
) -> dict[str, Any]:
    """List arm profiles on a Protect console (GET /v1/arm-profiles via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    Availability requires a Protect application exposing the v7.1.87 Integration API.
    """
    client, registry = _require()
    return await protect.list_arm_profiles(client, registry, host)


@mcp.tool()
async def get_arm_profile(
    host: str,
    arm_profile_id: str,
) -> dict[str, Any]:
    """Get one arm profile by id (filters GET /v1/arm-profiles; no GET-by-id exists upstream).

    host: console name, ID, or composite ID (MAC:numericId format).
    arm_profile_id: REQUIRED. Obtain it from `list_arm_profiles` (its id field).
    """
    client, registry = _require()
    return await protect.get_arm_profile(client, registry, host, arm_profile_id)


@mcp.tool()
async def create_arm_profile(
    host: str,
    name: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Create an arm profile (POST /v1/arm-profiles via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    name: REQUIRED display name for the profile.
    settings: the rest of the required body — automations, schedules, recordEverything,
      activationDelay (server-side validated). Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.create_arm_profile(client, registry, host, name, **settings)


@mcp.tool()
async def update_arm_profile(
    host: str,
    arm_profile_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update an arm profile (PATCH /v1/arm-profiles/{id}) with read-before/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    arm_profile_id: REQUIRED. Obtain it from `list_arm_profiles` (its id field).
    settings: fields to change. If all already match, no write is sent (status=noop).
      Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_arm_profile(client, registry, host, arm_profile_id, **settings)


@mcp.tool()
async def delete_arm_profile(
    host: str,
    arm_profile_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete an arm profile (DELETE /v1/arm-profiles/{id}). Irreversible — no undo.

    host: console name, ID, or composite ID (MAC:numericId format).
    arm_profile_id: REQUIRED. Obtain it from `list_arm_profiles` (its id field).
    confirm: must be true to execute. Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.delete_arm_profile(client, registry, host, arm_profile_id, confirm=confirm)


@mcp.tool()
async def update_arm_profile_settings(
    host: str,
    arm_profile_id: str,
) -> dict[str, Any]:
    """Select the active arm profile (PATCH /v1/arm-profiles/settings).

    host: console name, ID, or composite ID (MAC:numericId format).
    arm_profile_id: REQUIRED. Obtain it from `list_arm_profiles` (its id field); this
      becomes the console's selected arm profile. Reads the NVR armMode before/after
      (no-op if already selected). Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_arm_profile_settings(client, registry, host, arm_profile_id)


@mcp.tool()
async def enable_arm(
    host: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Enable the arm alarm using the selected profile (POST /v1/arm-profiles/enable).

    WARNING: arms the alarm system (physical side effects); requires a local Alarm Manager.
    host: console name, ID, or composite ID (MAC:numericId format).
    confirm: must be true to execute. Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.enable_arm(client, registry, host, confirm=confirm)


@mcp.tool()
async def disable_arm(
    host: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Disable the arm alarm (POST /v1/arm-profiles/disable). Disarms the system.

    WARNING: physical side effects; requires a local Alarm Manager.
    host: console name, ID, or composite ID (MAC:numericId format).
    confirm: must be true to execute. Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.disable_arm(client, registry, host, confirm=confirm)


# --- Protect Siren Tools ---


@mcp.tool()
async def list_sirens(
    host: str,
) -> dict[str, Any]:
    """List sirens on a Protect console (GET /v1/sirens via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_sirens(client, registry, host)


@mcp.tool()
async def get_siren(
    host: str,
    siren_id: str,
) -> dict[str, Any]:
    """Get one siren by id (GET /v1/sirens/{id}).

    host: console name, ID, or composite ID (MAC:numericId format).
    siren_id: REQUIRED. Obtain it from `list_sirens` (its id field).
    """
    client, registry = _require()
    return await protect.get_siren(client, registry, host, siren_id)


@mcp.tool()
async def update_siren(
    host: str,
    siren_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update siren settings (PATCH /v1/sirens/{id}) with read-before/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    siren_id: REQUIRED. Obtain it from `list_sirens` (its id field).
    settings: fields to change (name, volume 1-100, ledSettings). No write when all match.
      Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_siren(client, registry, host, siren_id, **settings)


@mcp.tool()
async def siren_play(
    host: str,
    siren_id: str,
    confirm: bool = False,
    duration: int | None = None,
) -> dict[str, Any]:
    """Sound a siren (POST /v1/sirens/{id}/play). WARNING: physical alarm sound.

    host: console name, ID, or composite ID (MAC:numericId format).
    siren_id: REQUIRED. Obtain it from `list_sirens` (its id field).
    confirm: must be true to execute. duration: seconds (5/10/20/30; defaults to 5
      upstream). Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.siren_play(
        client, registry, host, siren_id, confirm=confirm, duration=duration
    )


@mcp.tool()
async def siren_stop(
    host: str,
    siren_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Stop a sounding siren (POST /v1/sirens/{id}/stop). WARNING: physical action.

    host: console name, ID, or composite ID (MAC:numericId format).
    siren_id: REQUIRED. Obtain it from `list_sirens` (its id field).
    confirm: must be true to execute. Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.siren_stop(client, registry, host, siren_id, confirm=confirm)


@mcp.tool()
async def siren_test_sound(
    host: str,
    siren_id: str,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a siren's sound (POST /v1/sirens/{id}/test-sound). WARNING: physical sound.

    host: console name, ID, or composite ID (MAC:numericId format).
    siren_id: REQUIRED. Obtain it from `list_sirens` (its id field).
    confirm: must be true to execute. volume: 1-100 (defaults to device volume upstream).
      Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.siren_test_sound(
        client, registry, host, siren_id, confirm=confirm, volume=volume
    )


# --- Protect Fob Tools ---


@mcp.tool()
async def list_fobs(
    host: str,
) -> dict[str, Any]:
    """List fobs on a Protect console (GET /v1/fobs via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_fobs(client, registry, host)


@mcp.tool()
async def get_fob(
    host: str,
    fob_id: str,
) -> dict[str, Any]:
    """Get one fob by id (GET /v1/fobs/{id}).

    host: console name, ID, or composite ID (MAC:numericId format).
    fob_id: REQUIRED. Obtain it from `list_fobs` (its id field).
    """
    client, registry = _require()
    return await protect.get_fob(client, registry, host, fob_id)


@mcp.tool()
async def update_fob(
    host: str,
    fob_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update fob settings (PATCH /v1/fobs/{id}) with read-before/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    fob_id: REQUIRED. Obtain it from `list_fobs` (its id field).
    settings: fields to change. No write when all match. Governed by
      UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_fob(client, registry, host, fob_id, **settings)


# --- Protect Relay Tools ---


@mcp.tool()
async def list_relays(
    host: str,
) -> dict[str, Any]:
    """List relays on a Protect console (GET /v1/relays via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_relays(client, registry, host)


@mcp.tool()
async def get_relay(
    host: str,
    relay_id: str,
) -> dict[str, Any]:
    """Get one relay by id (GET /v1/relays/{id}).

    host: console name, ID, or composite ID (MAC:numericId format).
    relay_id: REQUIRED. Obtain it from `list_relays` (its id field).
    """
    client, registry = _require()
    return await protect.get_relay(client, registry, host, relay_id)


@mcp.tool()
async def update_relay(
    host: str,
    relay_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update relay settings (PATCH /v1/relays/{id}) with read-before/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    relay_id: REQUIRED. Obtain it from `list_relays` (its id field).
    settings: fields to change. No write when all match. Governed by
      UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_relay(client, registry, host, relay_id, **settings)


@mcp.tool()
async def relay_activate_output(
    host: str,
    relay_id: str,
    output_id: str,
    confirm: bool = False,
    state: str | None = None,
    pulse_duration: int | None = None,
) -> dict[str, Any]:
    """Switch a relay output (POST /v1/relays/{id}/outputs/{outputId}/activate).

    WARNING: physically switches hardware.
    host: console name, ID, or composite ID (MAC:numericId format).
    relay_id: REQUIRED. Obtain it from `list_relays` (its id field).
    output_id: REQUIRED output identifier on that relay.
    confirm: must be true to execute. state: 'on'|'off' (omit to toggle).
      pulse_duration: auto-off ms (only when state='on'). Governed by
      UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.relay_activate_output(
        client,
        registry,
        host,
        relay_id,
        output_id,
        confirm=confirm,
        state=state,
        pulse_duration=pulse_duration,
    )


# --- Protect Speaker Tools ---


@mcp.tool()
async def list_speakers(
    host: str,
) -> dict[str, Any]:
    """List speakers on a Protect console (GET /v1/speakers via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_speakers(client, registry, host)


@mcp.tool()
async def get_speaker(
    host: str,
    speaker_id: str,
) -> dict[str, Any]:
    """Get one speaker by id (GET /v1/speakers/{id}).

    host: console name, ID, or composite ID (MAC:numericId format).
    speaker_id: REQUIRED. Obtain it from `list_speakers` (its id field).
    """
    client, registry = _require()
    return await protect.get_speaker(client, registry, host, speaker_id)


@mcp.tool()
async def update_speaker(
    host: str,
    speaker_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update speaker settings (PATCH /v1/speakers/{id}) with read-before/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    speaker_id: REQUIRED. Obtain it from `list_speakers` (its id field).
    settings: fields to change. No write when all match. Governed by
      UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_speaker(client, registry, host, speaker_id, **settings)


@mcp.tool()
async def speaker_test_sound(
    host: str,
    speaker_id: str,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a speaker's sound (POST /v1/speakers/{id}/test-sound). WARNING: physical sound.

    host: console name, ID, or composite ID (MAC:numericId format).
    speaker_id: REQUIRED. Obtain it from `list_speakers` (its id field).
    confirm: must be true to execute. volume: 0-100 (defaults to device volume upstream).
      Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.speaker_test_sound(
        client, registry, host, speaker_id, confirm=confirm, volume=volume
    )


# --- Protect Bridge Tools ---


@mcp.tool()
async def list_bridges(
    host: str,
) -> dict[str, Any]:
    """List bridges on a Protect console (GET /v1/bridges via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_bridges(client, registry, host)


@mcp.tool()
async def get_bridge(
    host: str,
    bridge_id: str,
) -> dict[str, Any]:
    """Get one bridge by id (GET /v1/bridges/{id}).

    host: console name, ID, or composite ID (MAC:numericId format).
    bridge_id: REQUIRED. Obtain it from `list_bridges` (its id field).
    """
    client, registry = _require()
    return await protect.get_bridge(client, registry, host, bridge_id)


@mcp.tool()
async def update_bridge(
    host: str,
    bridge_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update bridge settings (PATCH /v1/bridges/{id}) with read-before/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    bridge_id: REQUIRED. Obtain it from `list_bridges` (its id field).
    settings: fields to change. No write when all match. Governed by
      UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_bridge(client, registry, host, bridge_id, **settings)


# --- Protect Link Station Tools ---


@mcp.tool()
async def list_link_stations(
    host: str,
) -> dict[str, Any]:
    """List link stations on a Protect console (GET /v1/link-stations via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_link_stations(client, registry, host)


@mcp.tool()
async def get_link_station(
    host: str,
    link_station_id: str,
) -> dict[str, Any]:
    """Get one link station by id (GET /v1/link-stations/{id}).

    host: console name, ID, or composite ID (MAC:numericId format).
    link_station_id: REQUIRED. Obtain it from `list_link_stations` (its id field).
    """
    client, registry = _require()
    return await protect.get_link_station(client, registry, host, link_station_id)


@mcp.tool()
async def update_link_station(
    host: str,
    link_station_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update link-station settings (PATCH /v1/link-stations/{id}) with read/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    link_station_id: REQUIRED. Obtain it from `list_link_stations` (its id field).
    settings: fields to change. No write when all match. Governed by
      UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_link_station(client, registry, host, link_station_id, **settings)


# --- Protect Alarm Hub Tools ---


@mcp.tool()
async def list_alarm_hubs(
    host: str,
) -> dict[str, Any]:
    """List alarm hubs on a Protect console (GET /v1/alarm-hubs via Fabric proxy).

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_alarm_hubs(client, registry, host)


@mcp.tool()
async def get_alarm_hub(
    host: str,
    alarm_hub_id: str,
) -> dict[str, Any]:
    """Get one alarm hub by id (GET /v1/alarm-hubs/{id}).

    host: console name, ID, or composite ID (MAC:numericId format).
    alarm_hub_id: REQUIRED. Obtain it from `list_alarm_hubs` (its id field).
    """
    client, registry = _require()
    return await protect.get_alarm_hub(client, registry, host, alarm_hub_id)


@mcp.tool()
async def update_alarm_hub(
    host: str,
    alarm_hub_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update alarm-hub settings (PATCH /v1/alarm-hubs/{id}) with read-before/no-op/read-after.

    host: console name, ID, or composite ID (MAC:numericId format).
    alarm_hub_id: REQUIRED. Obtain it from `list_alarm_hubs` (its id field).
    settings: fields to change. No write when all match. Governed by
      UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.update_alarm_hub(client, registry, host, alarm_hub_id, **settings)


@mcp.tool()
async def alarm_hub_trigger_output(
    host: str,
    alarm_hub_id: str,
    output_id: str,
    confirm: bool = False,
    enable: bool | None = None,
    delay: int | None = None,
    duration: int | None = None,
) -> dict[str, Any]:
    """Trigger an alarm-hub output (POST /v1/alarm-hubs/{id}/outputs/{outputId}/trigger).

    WARNING: physically triggers alarm-hub output hardware.
    host: console name, ID, or composite ID (MAC:numericId format).
    alarm_hub_id: REQUIRED. Obtain it from `list_alarm_hubs` (its id field).
    output_id: REQUIRED output identifier on that hub.
    confirm: must be true to execute. enable: true on / false off (omit to toggle).
      delay: ms before activating. duration: ms to stay active (0 = indefinite).
      Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.alarm_hub_trigger_output(
        client,
        registry,
        host,
        alarm_hub_id,
        output_id,
        confirm=confirm,
        enable=enable,
        delay=delay,
        duration=duration,
    )


# --- Protect User Tools (read-only) ---


@mcp.tool()
async def list_protect_users(
    host: str,
) -> dict[str, Any]:
    """List Protect users (GET /v1/users via Fabric proxy). Read-only in the Integration API.

    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_protect_users(client, registry, host)


@mcp.tool()
async def get_protect_user(
    host: str,
    user_id: str,
) -> dict[str, Any]:
    """Get one Protect user by id (GET /v1/users/{id}). Read-only.

    host: console name, ID, or composite ID (MAC:numericId format).
    user_id: REQUIRED. Obtain it from `list_protect_users` (its id field).
    """
    client, registry = _require()
    return await protect.get_protect_user(client, registry, host, user_id)


# --- Protect Application Metadata ---


@mcp.tool()
async def get_protect_application_info(
    host: str,
) -> dict[str, Any]:
    """Get Protect application metadata (GET /v1/meta/info via Fabric proxy). Read-only.

    Reports the Protect application version and Integration-API capabilities — the
    authoritative check for which extended Protect families this console supports.
    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.get_protect_application_info(client, registry, host)


# --- Protect ULP User Tools (read-only) ---


@mcp.tool()
async def list_ulp_users(
    host: str,
) -> dict[str, Any]:
    """List ULP (UniFi account) users (GET /v1/ulp-users). Read-only.

    Distinct from `list_protect_users` (/v1/users): these are UI-account identities.
    host: console name, ID, or composite ID (MAC:numericId format).
    """
    client, registry = _require()
    return await protect.list_ulp_users(client, registry, host)


@mcp.tool()
async def get_ulp_user(
    host: str,
    ulp_user_id: str,
) -> dict[str, Any]:
    """Get one ULP (UniFi account) user by id (GET /v1/ulp-users/{id}). Read-only.

    host: console name, ID, or composite ID (MAC:numericId format).
    ulp_user_id: REQUIRED. Obtain it from `list_ulp_users` (its id field).
    """
    client, registry = _require()
    return await protect.get_ulp_user(client, registry, host, ulp_user_id)


# --- Protect POS Transaction Ingestion ---


@mcp.tool()
async def pos_ingest_transaction(
    host: str,
    camera_id: str,
    transaction: dict[str, Any],
    confirm: bool = False,
) -> dict[str, Any]:
    """Ingest a POS transaction overlay onto camera footage.

    Route: POST /v1/pos/cameras/{id}/transactions (Fabric proxy).

    WARNING: creates a footage overlay event with no documented rollback. This has its own
    confirmation boundary and an idempotency guard; the POS write is never auto-retried.
    host: console name, ID, or composite ID (MAC:numericId format).
    camera_id: REQUIRED. Obtain it from `list_cameras` (its id field).
    transaction: REQUIRED posTransactionRequest object. Must include `type`
      ('sale'|'refund'), `externalId` (per-camera unique idempotency/dedup key), and
      `amount`; optional currency/lineItems/location/paymentTypes/timestamp pass through.
    confirm: must be true to execute. Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.
    """
    client, registry = _require()
    return await protect.pos_ingest_transaction(
        client, registry, host, camera_id, transaction, confirm=confirm
    )


# --- Port Forwarding Tools ---


@mcp.tool()
async def list_port_forwards(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List all port forwarding rules for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_port_forwards(client, registry, host, site)


@mcp.tool()
async def create_port_forward(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Create a port forwarding rule via the Classic REST API.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: port forward config. Required fields (validated locally — a missing field
    raises ValueError naming it): name, dst_port, fwd, fwd_port. ``proto`` is optional
    (the controller defaults it, typically 'tcp_udp'). This Classic REST endpoint enforces
    no required fields server-side (verified live: it accepts an empty body and silently
    creates a broken rule), so the local check is the only guard.
    Example: {"enabled": true, "name": "SSH", "pfwd_interface": "wan", "src": "any",
    "dst_port": "2222", "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "log": false}
    """
    client, registry = _require()
    return await network_services_proxy.create_port_forward(client, registry, host, site, payload)


@mcp.tool()
async def update_port_forward(
    host: str,
    site: str,
    forward_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a port forwarding rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    forward_id: port forward rule ID.
    payload: fields to update.
    """
    client, registry = _require()
    return await network_services_proxy.update_port_forward(
        client, registry, host, site, forward_id, payload
    )


@mcp.tool()
async def delete_port_forward(
    host: str,
    site: str,
    forward_id: str,
) -> str:
    """Delete a port forwarding rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    forward_id: REQUIRED. Obtain it from `list_port_forwards` (its id field).
    """
    client, registry = _require()
    await network_services_proxy.delete_port_forward(client, registry, host, site, forward_id)
    return f"Port forward {forward_id} deleted."


# --- Traffic Rule Tools ---


@mcp.tool()
async def list_traffic_rules(
    host: str,
    site: str,
) -> dict[str, Any]:
    """List traffic matching rules (QoS, application, IP group matching).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_rules(client, registry, host, site)


@mcp.tool()
async def create_traffic_rule(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Create a traffic matching rule (QoS, block, or route by application/IP group).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: required fields (validated locally — a missing field raises ValueError naming
    it — and verified against the live controller):
      - action: 'BLOCK'|'THROTTLE_RATE'|'QUEUE'
      - matching_target: 'INTERNET'|'LOCAL'|'ALL' or a traffic matching list ID
      - target_devices: the devices/networks the rule applies to (required by the API;
        previously undocumented)
      Optional (NOT required by the API): description (str), enabled (bool, controller
      defaults it), matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'|'APPLICATION_GROUP'),
      bandwidth_limit (dict with up_limit_kbps/down_limit_kbps for THROTTLE_RATE).
    Note: uses the Classic REST v2 API (/v2/api/site/{siteId}/trafficrules). May not exist
    on firmware 10.2.105 and below.
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_rule(client, registry, host, site, payload)


@mcp.tool()
async def update_traffic_rule(
    host: str,
    site: str,
    rule_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a traffic rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule_id: traffic rule ID.
    payload: fields to update.
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_rule(
        client, registry, host, site, rule_id, payload
    )


@mcp.tool()
async def delete_traffic_rule(
    host: str,
    site: str,
    rule_id: str,
) -> str:
    """Delete a traffic rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule_id: REQUIRED. The rule's id; obtain it from `list_traffic_rules` (its id field).
    """
    client, registry = _require()
    await network_services_proxy.delete_traffic_rule(client, registry, host, site, rule_id)
    return f"Traffic rule {rule_id} deleted."


vpn.register(mcp, _require)
hotspot.register(mcp, _require)
aggregation.register(mcp, _require)
statistics.register(mcp, _require)


# --- User / DHCP Reservation Tools ---


@mcp.tool()
async def list_users(
    host: str,
    site: str,
) -> Any:
    """List DHCP fixed-IP reservations and client aliases for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returns entries with fields: name, note, fixed_ip, use_fixedip, network_id.
    """
    client, registry = _require()
    return await network_services_proxy.list_users(client, registry, host, site)


@mcp.tool()
async def get_user(
    host: str,
    site: str,
    user_id: str,
) -> Any:
    """Get a single DHCP/client-alias entry by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    user_id: REQUIRED. Obtain it from `list_users` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.get_user(client, registry, host, site, user_id)


@mcp.tool()
async def update_user(
    host: str,
    site: str,
    user_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a DHCP/client-alias entry by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: fields to update (name, note, fixed_ip, use_fixedip, network_id).
    user_id: REQUIRED. Obtain it from `list_users` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.update_user(client, registry, host, site, user_id, payload)


# --- Traffic Route Tools ---


@mcp.tool()
async def list_traffic_routes(
    host: str,
    site: str,
) -> Any:
    """List static/policy traffic routes for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_routes(client, registry, host, site)


@mcp.tool()
async def create_traffic_route(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> Any:
    """Create a traffic route on a site (policy-based routing / WAN load-balancing).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: required fields (validated locally — a missing field raises ValueError naming
    it — and verified against the live controller). This v2 endpoint uses snake_case wire
    field names (verified: 'network_id' is accepted, 'networkId' is not):
      - network_id (str): source network UUID (from list_networks), or 'ANY'
      - matching_target: 'INTERNET'|'ALL' or a traffic matching list ID
      - target_devices: the devices/networks the route applies to
      Optional: matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'), description (str).
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_route(client, registry, host, site, payload)


@mcp.tool()
async def get_traffic_route(
    host: str,
    site: str,
    route_id: str,
) -> Any:
    """Get a single traffic route by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    route_id: REQUIRED. Obtain it from `list_traffic_routes` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.get_traffic_route(client, registry, host, site, route_id)


@mcp.tool()
async def update_traffic_route(
    host: str,
    site: str,
    route_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a traffic route by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: full traffic route configuration to replace with.
    route_id: REQUIRED. Obtain it from `list_traffic_routes` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_route(
        client, registry, host, site, route_id, payload
    )


@mcp.tool()
async def delete_traffic_route(
    host: str,
    site: str,
    route_id: str,
) -> str:
    """Delete a traffic route by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    route_id: REQUIRED. Obtain it from `list_traffic_routes` (its id field).
    """
    client, registry = _require()
    await network_services_proxy.delete_traffic_route(client, registry, host, site, route_id)
    return f"Traffic route {route_id} deleted."


# --- Controller Settings Tools ---


@mcp.tool()
async def list_settings(
    host: str,
    site: str,
) -> Any:
    """List all controller setting groups for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returns a list of setting objects grouped by key (mgmt, super_smtp, guest_access, etc.).
    """
    client, registry = _require()
    return await network_services_proxy.list_settings(client, registry, host, site)


@mcp.tool()
async def get_setting(
    host: str,
    site: str,
    setting_key: str,
) -> Any:
    """Get a controller setting group by key.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    setting_key: setting group identifier (e.g. 'mgmt', 'super_smtp', 'guest_access').

    There is no schema endpoint, so reading a group is how you discover what it accepts:
    the returned object lists every settable field and its current (valid) value. Inspect
    it before calling update_setting — the controller silently drops any field or enum
    value it does not recognise, so match an existing field's shape exactly. Common keys
    and notable enum fields (grounded in live responses): mdns (mode, enabled_for),
    ntp (setting_preference), doh (state), ips (ips_mode), global_nat (mode),
    ssl_inspection (state), dashboard (layout_preference), locale (timezone),
    country (code), guest_access (auth), super_mgmt (data_retention_setting_preference).
    Fields prefixed 'x_' hold credentials/secrets and are returned verbatim.
    """
    client, registry = _require()
    return await network_services_proxy.get_setting(client, registry, host, site, setting_key)


@mcp.tool()
async def update_setting(
    host: str,
    site: str,
    setting_key: str,
    payload: dict[str, Any],
) -> Any:
    """Update a controller setting group by key.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    setting_key: setting group identifier (e.g. 'mgmt', 'super_smtp', 'guest_access').
    payload: setting fields to update.

    Discover the schema first by calling get_setting(setting_key): it returns every
    settable field and its current (valid) value. The controller silently drops any
    unrecognised field or enum value (HTTP 200, value unchanged), so a guessed value
    fails invisibly; this tool detects that no-op and raises an error naming the rejected
    field and pointing you back at get_setting.
    """
    client, registry = _require()
    return await network_services_proxy.update_setting(
        client, registry, host, site, setting_key, payload
    )


# --- Dynamic DNS Tools ---


@mcp.tool()
async def list_dynamic_dns(
    host: str,
    site: str,
) -> Any:
    """List Dynamic DNS provider configurations for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returned verbatim, including plaintext x_password credential fields.
    """
    client, registry = _require()
    return await network_services_proxy.list_dynamic_dns(client, registry, host, site)


@mcp.tool()
async def get_dynamic_dns(
    host: str,
    site: str,
    ddns_id: str,
) -> Any:
    """Get a single Dynamic DNS configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returned verbatim, including plaintext x_password credential fields.
    ddns_id: REQUIRED. Obtain it from `list_dynamic_dns` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.get_dynamic_dns(client, registry, host, site, ddns_id)


@mcp.tool()
async def update_dynamic_dns(
    host: str,
    site: str,
    ddns_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a Dynamic DNS configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    payload: DDNS configuration fields to update.
    ddns_id: REQUIRED. Obtain it from `list_dynamic_dns` (its id field).
    """
    client, registry = _require()
    return await network_services_proxy.update_dynamic_dns(
        client, registry, host, site, ddns_id, payload
    )


# --- Port Profile Tools ---


@mcp.tool()
async def list_port_profiles(
    host: str,
    site: str,
) -> Any:
    """List switch port profiles (speed, VLAN, PoE config) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_port_profiles(client, registry, host, site)


@mcp.tool()
async def get_port_profile(
    host: str,
    site: str,
    profile_id: str,
) -> Any:
    """Get a single switch port profile by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    profile_id: port profile ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_port_profile(client, registry, host, site, profile_id)


@mcp.tool()
async def update_port_profile(
    host: str,
    site: str,
    profile_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a switch port profile by ID.

    WARNING -- SHARED PROFILE, WIDE BLAST RADIUS: this edits a shared Ethernet Port
    Profile (Classic REST /rest/portconf), NOT one switch or one port. A single write
    changes STP/PoE/storm-control/VLAN/etc. for EVERY port on EVERY switch that has this
    profile assigned. It is NOT a per-device or per-port writer and must never be
    presented or used as a per-port/per-device STP-priority or PoE-mode writer -- for
    that, no confirmed per-port config route exists via this API. Read the profile's
    assignments and confirm the intended blast radius before writing.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    profile_id: port profile ID.
    payload: fields to update (e.g. speed, native_networkconf_id, op_mode, poe_mode).
      Applies to every port using this profile, not a single port.
    """
    client, registry = _require()
    return await network_services_proxy.update_port_profile(
        client, registry, host, site, profile_id, payload
    )


@mcp.tool()
async def allow_network_on_port_profile(
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Atomically allow (un-exclude) a VLAN network on a switch port profile.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    profile_id: REQUIRED. The port profile id; from `list_port_profiles` (its `_id`).
    network_id: REQUIRED. The networkconf id to allow; from `list_networks` (its id) or
      the resolved id fields in `list_port_profiles` output.
    confirm: must be True to execute. This is a live PUT to a SHARED port profile
      (its exclusion list affects every switch port using it); it refuses with an
      error dict when confirm is False, before any controller call.

    This is the D12 auto-exclusion remediation: it fresh-reads the profile, removes
    `network_id` from `excluded_networkconf_ids`, PUTs, and returns
    {profile, tagged_networks} with the resulting tagged VLAN set rendered with names.
    Use it on every profile named in a `create_network` `D12_AUTO_EXCLUSION` warning.
    """
    if not confirm:
        return {
            "error": "confirm=True required",
            "reason": (
                "allow_network_on_port_profile issues a live PUT to a shared port "
                "profile; re-call with confirm=True to proceed."
            ),
            "profile_id": profile_id,
            "network_id": network_id,
        }
    client, registry = _require()
    return await network_services_proxy.allow_network_on_port_profile(
        client, registry, host, site, profile_id, network_id, confirm=confirm
    )


@mcp.tool()
async def exclude_network_on_port_profile(
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Atomically exclude (untag) a VLAN network from a switch port profile.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    profile_id: REQUIRED. The port profile id; from `list_port_profiles` (its `_id`).
    network_id: REQUIRED. The networkconf id to exclude; from `list_networks` (its id).
    confirm: must be True to execute. This is a live PUT to a SHARED port profile
      (its exclusion list affects every switch port using it); it refuses with an
      error dict when confirm is False, before any controller call.

    Inverse of `allow_network_on_port_profile`: fresh-reads the profile, adds
    `network_id` to `excluded_networkconf_ids`, PUTs, and returns
    {profile, tagged_networks} with names resolved.
    """
    if not confirm:
        return {
            "error": "confirm=True required",
            "reason": (
                "exclude_network_on_port_profile issues a live PUT to a shared port "
                "profile; re-call with confirm=True to proceed."
            ),
            "profile_id": profile_id,
            "network_id": network_id,
        }
    client, registry = _require()
    return await network_services_proxy.exclude_network_on_port_profile(
        client, registry, host, site, profile_id, network_id, confirm=confirm
    )


# --- Routing Table Tools ---


@mcp.tool()
async def list_routing_entries(
    host: str,
    site: str,
) -> Any:
    """List static routing table entries for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_routing_entries(client, registry, host, site)


# --- WLAN Config Tools ---


@mcp.tool()
async def list_wlan_configs(
    host: str,
    site: str,
) -> Any:
    """List per-SSID WLAN configurations (security, band steering, rate limits) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returned verbatim, including plaintext x_passphrase credential fields.
    """
    client, registry = _require()
    return await network_services_proxy.list_wlan_configs(client, registry, host, site)


@mcp.tool()
async def get_wlan_config(
    host: str,
    site: str,
    wlan_id: str,
) -> Any:
    """Get a single WLAN (SSID) configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    wlan_id: WLAN config ID.
    Returned verbatim, including plaintext x_passphrase credential fields.
    """
    client, registry = _require()
    return await network_services_proxy.get_wlan_config(client, registry, host, site, wlan_id)


@mcp.tool()
async def update_wlan_config(
    host: str,
    site: str,
    wlan_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a WLAN (SSID) configuration by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    wlan_id: WLAN config ID.
    payload: fields to update (e.g. x_passphrase, security, band, enabled).
    """
    client, registry = _require()
    return await network_services_proxy.update_wlan_config(
        client, registry, host, site, wlan_id, payload
    )


# --- WLAN Group Tools ---


@mcp.tool()
async def list_wlan_groups(
    host: str,
    site: str,
) -> Any:
    """List WLAN groups for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_wlan_groups(client, registry, host, site)


@mcp.tool()
async def get_wlan_group(
    host: str,
    site: str,
    group_id: str,
) -> Any:
    """Get a single WLAN group by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    group_id: WLAN group ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_wlan_group(client, registry, host, site, group_id)


# --- Channel Plan Tools ---


@mcp.tool()
async def get_channel_plan(
    host: str,
    site: str,
) -> Any:
    """Get RF channel assignments and DFS status for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_channel_plan(client, registry, host, site)


# --- Rogue AP Tools ---


@mcp.tool()
async def list_rogue_aps(
    host: str,
    site: str,
    rogue_only: bool = False,
) -> Any:
    """List neighboring APs detected by the site's radios.

    Returns ALL neighboring APs (most will have is_rogue=false and are benign neighbors).
    Only a small subset with is_rogue=true are confirmed rogue APs. Set rogue_only=true to
    filter to confirmed rogues only.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returns entries with BSSID, SSID, channel, signal strength, is_rogue flag, and detection time.
    """
    client, registry = _require()
    return await network_services_proxy.list_rogue_aps(
        client, registry, host, site, rogue_only=rogue_only
    )


# --- Classic Firewall Rule Tools ---


@mcp.tool()
async def list_firewall_rules(
    host: str,
    site: str,
) -> Any:
    """List classic L3/L4 firewall rules for a site (distinct from Integration API policies).

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_firewall_rules(client, registry, host, site)


@mcp.tool()
async def get_firewall_rule(
    host: str,
    site: str,
    rule_id: str,
) -> Any:
    """Get a single classic firewall rule by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    rule_id: firewall rule ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_firewall_rule(client, registry, host, site, rule_id)


# --- Firewall Group Tools ---


@mcp.tool()
async def list_firewall_groups(
    host: str,
    site: str,
) -> Any:
    """List firewall groups (IP/port sets referenced by firewall rules) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_firewall_groups(client, registry, host, site)


@mcp.tool()
async def get_firewall_group(
    host: str,
    site: str,
    group_id: str,
) -> Any:
    """Get a single firewall group by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    group_id: firewall group ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_firewall_group(client, registry, host, site, group_id)


# --- RADIUS Account Tools ---


@mcp.tool()
async def list_accounts(
    host: str,
    site: str,
) -> Any:
    """List local RADIUS user accounts for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    Returned verbatim, including plaintext x_password credential fields.
    """
    client, registry = _require()
    return await network_services_proxy.list_accounts(client, registry, host, site)


@mcp.tool()
async def get_account(
    host: str,
    site: str,
    account_id: str,
) -> Any:
    """Get a single RADIUS account by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    account_id: RADIUS account ID.
    Returned verbatim, including plaintext x_password credential fields.
    """
    client, registry = _require()
    return await network_services_proxy.get_account(client, registry, host, site, account_id)


# --- Hotspot Package Tools ---


@mcp.tool()
async def list_hotspot_packages(
    host: str,
    site: str,
) -> Any:
    """List guest portal billing packages for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_hotspot_packages(client, registry, host, site)


@mcp.tool()
async def get_hotspot_package(
    host: str,
    site: str,
    package_id: str,
) -> Any:
    """Get a single hotspot billing package by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    package_id: hotspot package ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_hotspot_package(
        client, registry, host, site, package_id
    )


# --- Scheduled Task Tools ---


@mcp.tool()
async def list_scheduled_tasks(
    host: str,
    site: str,
) -> Any:
    """List scheduled tasks (firmware upgrade schedules, speed tests) for a site.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    """
    client, registry = _require()
    return await network_services_proxy.list_scheduled_tasks(client, registry, host, site)


@mcp.tool()
async def get_scheduled_task(
    host: str,
    site: str,
    task_id: str,
) -> Any:
    """Get a single scheduled task by ID.

    host: console name, ID, or composite ID (MAC:numericId format). site: site name or ID.
    task_id: scheduled task ID.
    """
    client, registry = _require()
    return await network_services_proxy.get_scheduled_task(client, registry, host, site, task_id)


# --- DPI Tools ---


@mcp.tool()
async def list_dpi_categories(
    host: str,
    site: str = "",
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List DPI (Deep Packet Inspection) app categories available for traffic rules.

    Categories include Social Media, Streaming Video, Gaming, etc.
    host: console name, ID, or composite ID (MAC:numericId format).
    site: ignored — DPI data is host-level, not site-scoped.
    By default every page is drained and the complete catalogue is returned as
    {data, totalCount}. Pass offset/limit to fetch a single page manually. A
    capped drain returns the categories gathered so far with incomplete=true
    rather than truncating silently.
    """
    client, registry = _require()
    return await network_services_proxy.list_dpi_categories(client, registry, host, offset, limit)


@mcp.tool()
async def list_dpi_applications(
    host: str,
    site: str = "",
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List DPI applications available for traffic rules.

    Companion to list_dpi_categories; use application IDs in traffic rule configurations.
    host: console name, ID, or composite ID (MAC:numericId format).
    site: ignored — DPI data is host-level, not site-scoped.
    By default every page is drained and the complete catalogue is returned as
    {data, totalCount}. Pass offset/limit to fetch a single page manually. A
    capped drain returns the applications gathered so far with incomplete=true
    rather than truncating silently.
    """
    client, registry = _require()
    return await network_services_proxy.list_dpi_applications(client, registry, host, offset, limit)


# --- InnerSpace Floor-Plan Tools ---


@mcp.tool()
async def get_innerspace_summary(
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """Inventory a console's InnerSpace floor-plan project without the full payload.

    Returns counts and structure: shape breakdown by type (wall / device / map /
    scale), per-floor plans with each plan's own scale, product and wall-material /
    attenuation-type dictionary sizes, and project metadata. Call this before
    get_innerspace_project when you only need to know what's present. Surfaces the
    multi-floor caveat: floors do not share a coordinate origin.

    host: console name, ID, or composite ID (MAC:numericId format).
    mode: '3D' (default; device shapes carry real metric mounting heights) or '2D'.
    """
    client, registry = _require()
    return await innerspace.get_innerspace_summary(client, registry, host, mode)


@mcp.tool()
async def get_innerspace_project(
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """Return the full InnerSpace floor-plan project geometry for a console.

    The complete (~66 KB) project document: shapes, plans, products, wall types,
    and attenuation-object types. Returned verbatim, including device meta.mac /
    meta.ip and floor-plan image/asset URLs. Prefer get_innerspace_summary first
    if you only need an inventory — this payload is large.

    host: console name, ID, or composite ID (MAC:numericId format).
    mode: '3D' (default; device shapes carry real metric mounting heights) or '2D'
    (device shapes flattened to z=0). 3D is the only mode with real heights.
    """
    client, registry = _require()
    return await innerspace.get_innerspace_project(client, registry, host, mode)


@mcp.tool()
async def list_innerspace_devices(
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """List placed device shapes from a console's InnerSpace floor-plan.

    Each mounted device's placement: mount, productId, title, position, and
    rotation (pov = heading/yaw, base = mount tilt). Returned verbatim, including
    device meta.mac / meta.ip. Use mode='3D' (default) for real metric mounting
    heights; mode='2D' flattens positions to z=0.

    host: console name, ID, or composite ID (MAC:numericId format).
    mode: '3D' (default) or '2D'.
    """
    client, registry = _require()
    return await innerspace.list_innerspace_devices(client, registry, host, mode)


@mcp.tool()
async def list_innerspace_floor_plans(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List a console's InnerSpace floor plans (documented Integration API).

    Each floor plan carries id, name, floor_number, image_url (an asset path — fetch
    with get_innerspace_asset), ppm (pixels per metre, the scale for interpreting
    coordinates/heights), width/height (image pixels), origin_x/origin_y, and site_id
    when filtered. Returned verbatim.

    host: console name, ID, or composite ID (MAC:numericId format).
    site_id: optional UniFi site filter — only floor plans whose product siteId matches.
    """
    client, registry = _require()
    return await innerspace.list_innerspace_floor_plans(client, registry, host, site_id)


@mcp.tool()
async def list_innerspace_access_points(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List placed access points from a console's InnerSpace floor plans (Integration API).

    Each AP carries id, name, model (SKU), mac, serial, floor_plan_id, x/y (pixels on
    the floor-plan image), height (mounting height in metres), azimuth (antenna
    orientation, 0-360 degrees), mount, and status. Returned verbatim, including
    mac/serial.

    host: console name, ID, or composite ID (MAC:numericId format).
    site_id: optional UniFi site filter — only APs whose product siteId matches.
    """
    client, registry = _require()
    return await innerspace.list_innerspace_access_points(client, registry, host, site_id)


@mcp.tool()
async def list_innerspace_switches(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List placed switches from a console's InnerSpace floor plans (Integration API).

    Each switch carries id, name, model, type (switch), mac, serial, floor_plan_id,
    x/y (pixels on the floor-plan image), and status. Returned verbatim, including
    mac/serial.

    host: console name, ID, or composite ID (MAC:numericId format).
    site_id: optional UniFi site filter — only switches whose product siteId matches.
    """
    client, registry = _require()
    return await innerspace.list_innerspace_switches(client, registry, host, site_id)


@mcp.tool()
async def list_innerspace_inventory(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List UNPLACED device inventory for a console's InnerSpace project (Integration API).

    Devices known to the project but not yet positioned on a floor plan. Each carries
    id, name, model, mac, and serial. Returned verbatim, including mac/serial. The
    response array key is 'devices'.

    host: console name, ID, or composite ID (MAC:numericId format).
    site_id: optional UniFi site filter — only inventory whose product siteId matches.
    """
    client, registry = _require()
    return await innerspace.list_innerspace_inventory(client, registry, host, site_id)


@mcp.tool()
async def get_innerspace_asset(
    host: str,
    plan_id: str,
    filename: str,
) -> dict[str, Any]:
    """Download a floor-plan asset (image) from a console's InnerSpace project.

    Fetches the binary asset from the documented …/integration/v1/assets/{planId}/
    {filename} endpoint (a floor plan's image_url resolves here). Bytes are returned
    base64-encoded inline under image_base64 when at or below the 10 MiB inline cap;
    a larger asset returns metadata only (image_base64=null) plus a note and the
    connector path to fetch it out-of-band. content_type is the upstream media type
    (typically image/jpeg or image/png).

    host: console name, ID, or composite ID (MAC:numericId format).
    plan_id: the id in the {planId} segment of the floor plan's image_url -- i.e. the
      value between '/assets/' and the trailing '/{filename}'. This is the asset-group
      UUID and is NOT the floor plan's own 'id' field (they differ); passing the plan
      'id' returns HTTP 404. Parse both plan_id and filename from image_url (from
      list_innerspace_floor_plans) rather than constructing them from the plan id.
    filename: the asset filename as published in the floor plan's image_url.
    """
    client, registry = _require()
    return await innerspace.get_innerspace_asset(client, registry, host, plan_id, filename)


# --- Carrier / ISP Fabric Tools (org-scoped identity; no host/site resolution) ---
#
# Not testable against the maintainer's live hardware; hermetic/spec-conformance tested
# only: the UniFi Carrier / ISP Fabric (published Subscriber API v1.0.0,
# developer.ui.com/carrier-fabric/v1.0.0) is not deployed on the maintainer's hardware — we
# operate no ISP organization and hold no ISP-type API key, so no live call is ever
# possible. These tools are verified only against the OpenAPI request/response shapes
# (hermetic respx), never live-verified against a production deployment. The seven
# writes ship behind
# confirm=true + read-before/no-op/read-after and the UNIFI_ENABLE_CARRIER_FABRIC_WRITE
# kill-switch (OFF by default).


@mcp.tool()
async def list_carrier_subscribers(
    plan_id: str | None = None,
    suspended: bool | None = None,
    sort: str | None = None,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List Carrier / ISP Fabric subscribers visible to the authenticated ISP key.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only — the Carrier
    Fabric is not deployed here. Cursor-paginated by the API; every page is drained
    and the complete list is returned under subscribers.

    plan_id: optional service-plan UUID filter. suspended: optional boolean filter.
    sort: optional createdAt/-createdAt/name/-name/subscriberNumber/-subscriberNumber.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.list_carrier_subscribers(
        client, plan_id=plan_id, suspended=suspended, sort=sort, key_label=key_label
    )


@mcp.tool()
async def get_carrier_subscriber(
    subscriber_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric subscriber by ID.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. Returns the full
    Subscriber object verbatim under subscriber; an unknown id surfaces the upstream
    subscriber_not_found (404) verbatim.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.get_carrier_subscriber(client, subscriber_id, key_label=key_label)


@mcp.tool()
async def list_carrier_service_plans(
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the Carrier / ISP Fabric service plans for the authenticated organization.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. Not query-
    paginated by the API; the full set is returned under service_plans.

    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.list_carrier_service_plans(client, key_label=key_label)


@mcp.tool()
async def get_carrier_service_plan(
    plan_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric service plan by ID.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. An unknown id
    surfaces the upstream service_plan_not_found (404) verbatim.

    plan_id: the service-plan UUID from list_carrier_service_plans.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.get_carrier_service_plan(client, plan_id, key_label=key_label)


@mcp.tool()
async def create_carrier_subscriber(
    subscriber_number: str,
    name: str | None = None,
    email: str | None = None,
    notes: str | None = None,
    service_address: str | None = None,
    plan_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Create a Carrier / ISP Fabric subscriber (POST /v1/carrier/subscribers). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only; a live create is
    impossible here. subscriber_number is required (1-32 chars). Optional name (<=128),
    email (<=255), notes (<=4096), service_address (<=1024), plan_id (UUID), metadata
    (object). Requires confirm=true and the UNIFI_ENABLE_CARRIER_FABRIC_WRITE gate.

    subscriber_number: unique subscriber number (1-32 characters).
    name/email/notes/service_address/plan_id/metadata: optional profile fields.
    confirm: must be true to apply the create.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.create_carrier_subscriber(
        client,
        subscriber_number,
        name=name,
        email=email,
        notes=notes,
        service_address=service_address,
        plan_id=plan_id,
        metadata=metadata,
        confirm=confirm,
        key_label=key_label,
    )


@mcp.tool()
async def update_carrier_subscriber(
    subscriber_id: str,
    subscriber_number: str | None = None,
    name: str | None = None,
    email: str | None = None,
    notes: str | None = None,
    service_address: str | None = None,
    plan_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a Carrier / ISP Fabric subscriber (PATCH .../subscribers/{id}). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. Documented partial
    update: only the fields you pass are sent; omitted fields are left unchanged; pass
    at least one. subscriber_number is 1-32 chars when provided. Guarded: read-before,
    no-op when all provided fields already match, confirm=true, write kill-switch,
    read-after. NOTE: unlike the module function, omitting a field here (None) leaves it
    unchanged — MCP cannot express an explicit-null "clear" through this wrapper.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    subscriber_number/name/email/notes/service_address/plan_id/metadata: optional new values.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    kwargs: dict[str, Any] = {"confirm": confirm, "key_label": key_label}
    # Only forward fields the caller actually set, so unset args do not become an
    # explicit-null clear on the nullable subscriber fields.
    if subscriber_number is not None:
        kwargs["subscriber_number"] = subscriber_number
    if name is not None:
        kwargs["name"] = name
    if email is not None:
        kwargs["email"] = email
    if notes is not None:
        kwargs["notes"] = notes
    if service_address is not None:
        kwargs["service_address"] = service_address
    if plan_id is not None:
        kwargs["plan_id"] = plan_id
    if metadata is not None:
        kwargs["metadata"] = metadata
    return await carrier_fabric.update_carrier_subscriber(client, subscriber_id, **kwargs)


@mcp.tool()
async def attach_carrier_subscriber_host(
    subscriber_id: str,
    host_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Attach or re-link a subscriber's gateway host (PUT .../subscribers/{id}/host). Guarded.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. host_id must be a
    host in the same ISP organization. Guarded: read-before, no-op when already linked,
    confirm=true, write kill-switch, read-after (reports prev_host_id).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    host_id: the gateway host id to link.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.attach_carrier_subscriber_host(
        client, subscriber_id, host_id, confirm=confirm, key_label=key_label
    )


@mcp.tool()
async def detach_carrier_subscriber_host(
    subscriber_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Detach a subscriber's gateway host (DELETE .../subscribers/{id}/host). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. Guarded:
    read-before, no-op when no host is attached, confirm=true, write kill-switch,
    read-after (reports the just-detached prev_host_id).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.detach_carrier_subscriber_host(
        client, subscriber_id, confirm=confirm, key_label=key_label
    )


@mcp.tool()
async def assign_carrier_subscriber_plan(
    subscriber_id: str,
    plan_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Assign a service plan to a subscriber (PUT .../subscribers/{id}/plan). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. An archived or
    unknown plan is rejected upstream. Guarded: read-before, no-op when already on this
    plan, confirm=true, write kill-switch, read-after.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    plan_id: the service-plan UUID to assign (from list_carrier_service_plans).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.assign_carrier_subscriber_plan(
        client, subscriber_id, plan_id, confirm=confirm, key_label=key_label
    )


@mcp.tool()
async def suspend_carrier_subscriber(
    subscriber_id: str,
    reason: str | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Suspend a subscriber's service (POST .../subscribers/{id}/suspend). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. Guarded:
    read-before, no-op when already suspended, confirm=true, write kill-switch,
    read-after. An optional reason is recorded on the subscriber.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    reason: optional free-text suspension reason.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.suspend_carrier_subscriber(
        client, subscriber_id, reason=reason, confirm=confirm, key_label=key_label
    )


@mcp.tool()
async def resume_carrier_subscriber(
    subscriber_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Resume a suspended subscriber's service (POST .../subscribers/{id}/resume). Guarded.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. Guarded:
    read-before, no-op when not currently suspended, confirm=true, write kill-switch,
    read-after.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await carrier_fabric.resume_carrier_subscriber(
        client, subscriber_id, confirm=confirm, key_label=key_label
    )


# --- Guarded generic Fabric connector relay (issue #189) ---
#
# GET is always available. POST/PUT/PATCH/DELETE are mutations: each requires
# confirm=true AND the server-side UNIFI_ENABLE_CONNECTOR_WRITE flag (code default
# OFF, fail-closed). See tools/connector.py for the full guard model (Registry-only
# identity, namespace allowlist, positive-charset path validation, read-before/
# write/read-after, scope guard, credential redaction, structured audit).


@mcp.tool()
async def fabric_connector_get(
    host: str,
    path: str,
    site: str | None = None,
    params: dict[str, Any] | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    """Relay a GET through the official Fabric connector to a console's /proxy/<path>.

    The escape hatch for a controller-supported route that has no typed tool yet. Always
    available — GET needs no confirm. A 4xx/5xx is returned as ``status`` (not raised), so
    a probe of an unknown route surfaces its own reachability status.

    host: console name or ID (resolved to the owning API key + host id via the Registry).
    path: the relay-relative application path AFTER ``/proxy/`` — e.g.
      ``network/integration/v1/sites`` or ``network/api/s/{site}/stat/device``. Use the
      ``{site}`` (slug) or ``{site_id}`` (UUID) placeholder for the site segment; the
      server resolves and substitutes it (raw host/site ids and API keys never appear on
      the tool surface). Only approved UniFi application namespaces are allowed (Network
      integration/classic/v2, Protect integration/private, InnerSpace integration/legacy,
      Access); ``..``, ``%``-encoding, and control characters are rejected.
    site: site name or UUID — REQUIRED only when path contains a site placeholder.
    params: optional query-string parameters.
    scope: optional 'device' / 'site' / 'global' — cross-checked against the path so a
      device route cannot be confused with a site-global setting route.
    Returns {method, routeClass, path, resolvedPath, status, body} (body credential-redacted).
    """
    client, registry = _require()
    return await connector.connector_get(
        client, registry, host, path, site=site, params=params, scope=scope
    )


@mcp.tool()
async def fabric_connector_post(
    host: str,
    path: str,
    site: str | None = None,
    body: dict[str, Any] | None = None,
    confirm: bool = False,
    scope: str | None = None,
) -> dict[str, Any]:
    """Relay a POST (create/command) through the Fabric connector. MUTATION — GATED.

    Refused unless BOTH confirm=true AND the server's UNIFI_ENABLE_CONNECTOR_WRITE flag are
    set (fail-closed; gating is checked before any network call). POST targets a collection
    or command route (e.g. ``network/api/s/{site}/cmd/...``); it has no GET twin, so no
    read-before/after is performed. The upstream status/body (redacted) and routeClass are
    returned; a 4xx/5xx is reported, not raised.

    See fabric_connector_get for host/path/site/scope semantics. body: the JSON request body.
    Every attempt is written to the structured audit log (never the API key value).
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "POST",
        path,
        site=site,
        body=body,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


@mcp.tool()
async def fabric_connector_put(
    host: str,
    path: str,
    site: str | None = None,
    body: dict[str, Any] | None = None,
    confirm: bool = False,
    scope: str | None = None,
) -> dict[str, Any]:
    """Relay a PUT (full replace) through the Fabric connector. MUTATION — GATED.

    Refused unless BOTH confirm=true AND UNIFI_ENABLE_CONNECTOR_WRITE are set. PUT has a GET
    twin at the same resource path, so the resource is read BEFORE and AFTER the write and
    the result carries readBefore / readAfter / noOp (diff-based: a same-value write is
    flagged noOp=true). Use this for reversible per-device config probes (e.g. Classic REST
    ``network/api/s/{site}/rest/device/{id}``); scope='device' guards against selecting a
    site-global setting route. EXPERIMENTAL for undocumented legacy routes until persistence
    and rollback are proven live.

    See fabric_connector_get for host/path/site/scope semantics. body: the JSON request body.
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "PUT",
        path,
        site=site,
        body=body,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


@mcp.tool()
async def fabric_connector_patch(
    host: str,
    path: str,
    site: str | None = None,
    body: dict[str, Any] | None = None,
    confirm: bool = False,
    scope: str | None = None,
) -> dict[str, Any]:
    """Relay a PATCH (partial update) through the Fabric connector. MUTATION — GATED.

    Refused unless BOTH confirm=true AND UNIFI_ENABLE_CONNECTOR_WRITE are set. PATCH has a
    GET twin, so read-before/write/read-after with noOp detection applies (see
    fabric_connector_put). The candidate legacy InnerSpace save route
    (``innerspace/api/shapes/{id}``) is a PATCH; probe it with a nonexistent shape ID and an
    empty/invalid body first — a 4xx is reachability evidence, and a 200/204 on such a probe
    is a stop condition, not a success. EXPERIMENTAL until persistence/rollback are proven.

    See fabric_connector_get for host/path/site/scope semantics. body: the JSON request body.
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "PATCH",
        path,
        site=site,
        body=body,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


@mcp.tool()
async def fabric_connector_delete(
    host: str,
    path: str,
    site: str | None = None,
    body: dict[str, Any] | None = None,
    confirm: bool = False,
    scope: str | None = None,
) -> dict[str, Any]:
    """Relay a DELETE through the Fabric connector. MUTATION — GATED, IRREVERSIBLE.

    Refused unless BOTH confirm=true AND UNIFI_ENABLE_CONNECTOR_WRITE are set. DELETE has a
    GET twin, so the resource is read before and after; a successful delete makes the
    read-after return a 4xx, which the result records. There is no undo — confirm the exact
    resource path before enabling.

    See fabric_connector_get for host/path/site/scope semantics. body: optional JSON body.
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "DELETE",
        path,
        site=site,
        body=body,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


# --- Mobility Tools (workspace-scoped identity; no host/site resolution) ---


@mcp.tool()
async def list_mobility_workspaces(
    key_label: str | None = None,
) -> dict[str, Any]:
    """List UniFi Mobility workspaces visible to the authenticated API key.

    A workspace is a mobility "cloud site" (workspace_id, workspace_name, is_owner,
    status). Returned verbatim. Not query-paginated by the API. Mobility identity is
    workspace-based and independent of the console host/site model.

    key_label: optional configured API-key label to route the request on a specific
    key (multi-key deployments). Omit to use the default key.
    """
    client, _ = _require()
    return await mobility.list_mobility_workspaces(client, key_label=key_label)


@mcp.tool()
async def list_mobility_admins(
    workspace_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the admins of a Mobility workspace (mobility permissions only).

    Each admin carries name, email, status, is_owner and a permissions object
    exposing the umr (Mobile Routing) level (ALL/VIEW_ONLY/NONE); permissions is
    null for a pending invite. Returned verbatim.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await mobility.list_mobility_admins(client, workspace_id, key_label=key_label)


@mcp.tool()
async def list_mobility_devices(
    workspace_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the UMR devices in a Mobility workspace.

    Each device is the lightweight summary (id, name, model, state,
    firmware_version, mac_address). Offset-paginated by the API (limit/offset, 200
    max); every page is drained.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await mobility.list_mobility_devices(client, workspace_id, key_label=key_label)


@mcp.tool()
async def get_mobility_device(
    workspace_id: str,
    device_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get full detail for one UMR device in a Mobility workspace.

    Returns the complete DeviceDetail (WAN/cellular/WiFi/VPN/subscription/GPS,
    counts, and the summary fields) verbatim under device.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await mobility.get_mobility_device(client, workspace_id, device_id, key_label=key_label)


@mcp.tool()
async def list_mobility_clients(
    workspace_id: str,
    device_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the clients associated with a UMR device.

    Each client carries mac, name, type (WIRED/WIRELESS), connection_status,
    ip_address, is_blocked and (wireless only) a wifi_experience score.
    Offset-paginated by the API (limit/offset, 200 max); every page is drained.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await mobility.list_mobility_clients(
        client, workspace_id, device_id, key_label=key_label
    )


@mcp.tool()
async def update_mobility_device_name(
    workspace_id: str,
    device_id: str,
    name: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Rename a UMR device (guarded write). WARNING: mutates live device config.

    Sends the full documented body {"name": name} (1-32 chars). Read-before, no-op
    detection (returns status="no_op" when already named this), confirm=true guard
    (returns a current-vs-proposed preview otherwise), an environment kill-switch
    (UNIFI_ENABLE_MOBILITY_WRITE, gated OFF by default pending issue #186 semantics
    verification), and a read-after verification.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    name: the new device name (1-32 characters).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await mobility.update_mobility_device_name(
        client, workspace_id, device_id, name, confirm=confirm, key_label=key_label
    )


@mcp.tool()
async def update_mobility_device_network(
    workspace_id: str,
    device_id: str,
    host_address: str | None = None,
    dhcp_mode: str | None = None,
    dhcp_range_start: str | None = None,
    dhcp_range_stop: str | None = None,
    dhcp_lease_time: int | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's LAN / DHCP settings (guarded write). Mutates live config.

    DOCUMENTED partial update: only provided fields are applied (WAN/IPv6/
    InternetSource are not configurable here). At least one field is required.
    WARNING: docs conflict on full-replacement vs partial-merge PUT semantics, so
    writes are gated OFF by default pending live verification (issue #186).
    dhcp_mode is 'dhcp' (enabled) or 'none' (disabled); IPs must be IPv4;
    dhcp_lease_time is seconds (0 = infinite). Read-before, no-op detection on the
    observable host_address, confirm=true guard, kill-switch, read-after.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    host_address: optional new LAN gateway IPv4.
    dhcp_mode: optional 'dhcp' or 'none'.
    dhcp_range_start: optional DHCP pool start IPv4.
    dhcp_range_stop: optional DHCP pool end IPv4.
    dhcp_lease_time: optional DHCP lease seconds (>=0; 0 = infinite).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
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


@mcp.tool()
async def update_mobility_device_wireless(
    workspace_id: str,
    device_id: str,
    ssid: str,
    password: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's WiFi SSID + password (guarded write). Mutates live config.

    Both fields are required by the API (channel/TX power/security protocol are not
    configurable here). ssid is 1-32 chars; password is a WPA2-PSK secret of 8-63
    chars. Read-before, confirm=true guard, kill-switch, read-after. There is no
    no-op short-circuit (the password is not observable, so an unchanged config
    cannot be proven). The supplied password is not echoed back in the result.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    ssid: the new WiFi SSID (1-32 characters).
    password: the new WPA2-PSK password (8-63 characters).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    client, _ = _require()
    return await mobility.update_mobility_device_wireless(
        client, workspace_id, device_id, ssid, password, confirm=confirm, key_label=key_label
    )


def main() -> None:
    """Entry point for the MCP server."""
    # Conditional uvicorn_config: only pass it when TLS is configured. stdio's
    # run_stdio_async() takes no **kwargs, so an unconditional uvicorn_config
    # would raise TypeError whenever the transport is stdio.
    uvicorn_config = build_uvicorn_config(_mcp_transport)
    if uvicorn_config:
        mcp.run(uvicorn_config=uvicorn_config)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
