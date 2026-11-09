# Tool usage details

The advertised instructions and each tool description stay within 2,048 characters, the Claude
Code limit before v2.1.296 (current releases
[cut at 4,096 characters, and at 16,384 for tools loaded through tool search](https://code.claude.com/docs/en/mcp)).
Parameter schemas carry the request shapes. This reference preserves the detailed workflows and examples.

## Tool annotations

Every tool advertises four MCP annotation hints, derived from its upstream routes and whether
it reads local state.

- Read tools: `readOnlyHint: true` and `destructiveHint: false`. They change nothing, so a
  client that confirms destructive tools does not prompt before a read.
- Write, action, delete and connector-relay tools: `readOnlyHint: false` and
  `destructiveHint: true`. No write is advertised as non-destructive: a create or update can
  replace live configuration, and an action can have physical effects. Delete and
  physical-action tools also state their effect in a `Consequence:` line of their description.
- `fabric_connector_get` is the one exception among reads: it can relay a state-changing GET, so it
  is annotated `readOnlyHint: false`, `destructiveHint: true` and `idempotentHint: false`.
- `idempotentHint` is true for reads and for writes whose only upstream verb is PUT or
  DELETE; `openWorldHint` is false for local-state tools (`list_configured_api_keys`,
  `search_tools`, `describe_tool`, `list_tool_families`) and true for tools that reach UniFi.

`UNIFI_WRITE_POLICY=deny` is opt-in (the default policy is `allow`). At startup it hides every tool that
is not annotated `readOnlyHint: true` (except `fabric_connector_get`) from `tools/list`, discovery search, descriptions
and family counts, after the family allowlist and the exclusions (`UNIFI_EXCLUDE`). The
read discovery meta-tools stay available; `call_write_tool` is hidden. A hidden write
called by name is still refused and audited before any upstream call. The mixed
`fabric_connector_get` relay (annotated as a write because it can relay a state-changing GET)
stays listed, but a call to a known state-changing GET
route (Protect camera `enable-control` / `disable-control`) is refused at call time.

Writes are enabled by default; each area has its own write opt-out:

<!-- BEGIN GENERATED: write-switches -->
- `family:network=deny`: the write tools of `network`, `firewall`, `clients`, `devices`, `vpn`, `hotspot`, `statistics` and every write request to its console routes, the connector relay included
- `family:protect=deny`: the write tools of `protect` and every write request to its console routes, the connector relay included
- `family:mobility=deny`: the write tools of `mobility` and every write request to its console routes, the connector relay included
- `family:carrier=deny`: the write tools of `carrier` and every write request to its console routes, the connector relay included
- `family:innerspace=deny`: the write tools of `innerspace` and every write request to its console routes, the connector relay included
- `family:connector=deny`: the connector relay's write tools and the typed tools it also governs
Each is one entry of `UNIFI_WRITE_EXCEPTIONS` (unset by default: every write allowed); `dry-run` in place of `deny` previews the same writes instead of refusing them.
<!-- END GENERATED -->

A `deny` entry hides its
area's write tools the same way, so `tools/list` and discovery offer only tools that
can run; a hidden write called by name is refused with the entry as its reason and
audited. With `UNIFI_WRITE_EXCEPTIONS=family:connector=deny` the server also hides the typed write tools
that relay through the connector (for example `update_device_radio`, `start_spectrum_scan`,
`reboot_nvr`), not only the four relay writes.

<!-- BEGIN GENERATED: tool-mode-defaults -->
Defaults: `UNIFI_TOOL_MODE=discovery` (modes `full`, `discovery`, `codemode`), `UNIFI_FAMILY_ALLOW` unset (every family), `UNIFI_EXCLUDE` unset, `UNIFI_WRITE_POLICY` unset (`allow`). Discovery mode advertises 5 meta-tools (`call_read_tool`, `call_write_tool`, `describe_tool`, `list_tool_families`, `search_tools`), or 4 with `UNIFI_WRITE_POLICY=deny`.
<!-- END GENERATED -->

<!-- BEGIN GENERATED: tool-mode-choices -->
Empty or whitespace-only `UNIFI_TOOL_MODE` uses the default; any value other than `full`, `discovery`, `codemode` fails startup with an error naming `UNIFI_TOOL_MODE` and the valid choices.
<!-- END GENERATED -->

## Server workflows

UniFi Fabric MCP Server — manages UniFi network infrastructure via the Ubiquiti
Site Manager (Fabric) API.

By default (`UNIFI_TOOL_MODE=discovery`) the server advertises the discovery meta-tools listed
in the defaults above. Find a tool with `search_tools`, inspect it with `describe_tool`, and run it
with `call_read_tool` or `call_write_tool` (`name` plus the `arguments` shown in the examples
here). Set `UNIFI_TOOL_MODE=full` to advertise every tool for direct calls.

## Key Concepts
- **Host**: A UniFi console/gateway (UDM Pro, UDR, UCG, etc.). Each host runs one or
  more applications (Network, Protect, Access).
- **Site**: A logical network partition within a host. Most single-console setups have
  one site called "Default".
- Both `host` and `site` parameters accept human-readable names OR IDs. Prefer names.
- **Device** (in UniFi terminology): network infrastructure hardware — APs, switches,
  gateways. Managed via `list_site_devices`, `get_device`, etc. Protect cameras and sensors have
  their own tools (`list_cameras`, `list_sensors`).
- **Client**: an end-user device connected to the network (laptop, phone, IoT device).
  Managed via `list_clients`, `get_client`, `block_client`, etc. Do not confuse devices
  (infrastructure) with clients (end-users).

## Getting Started
1. Call `list_hosts` to discover available consoles. Note the short console name
   (`data[].reportedState.hostname`, e.g. "MyConsole"); the long `data[].id` also works.
2. Call `list_local_sites(host="MyConsole")` to discover that console's sites. Note the site name
   (e.g., "Default"). `list_sites` is the cross-console Site Manager overview.
3. Pass these names to any per-host tool: `list_networks(host="MyConsole", site="Default")`.

## Firewall Rule Hierarchy
UniFi has three distinct firewall systems — use the right one for your use case:
1. **Zone-based Firewall Policies** (`list_firewall_policies`, `create_firewall_policy`, `update_firewall_policy`, ...): the modern,
   recommended approach. Rules are scoped between firewall zones. Use
   `list_firewall_zones_proxy` to discover zones and their IDs first: system zones carry the
   names the controller returns (e.g. Internal, External, Gateway, Vpn, Hotspot, Dmz), so match
   names case-insensitively; every tool takes the zone id, never the name.
2. **ACL Rules** (`list_acl_rules`, `create_acl_rule`, `update_acl_rule`, ...): network-layer access control lists,
   typically used for intra-VLAN traffic filtering between networks.
3. **Classic Firewall Rules** (`list_firewall_rules`, `get_firewall_rule`): legacy
   iptables-style rules. Read-only in this server; prefer zone-based policies for new rules.

When asked to "add a firewall rule", default to zone-based firewall policies unless the
user specifically asks for ACL rules or classic rules.

## Tool Organization
<!-- BEGIN GENERATED: family-names -->
The 13 families are `carrier`, `clients`, `connector`, `devices`, `firewall`, `hotspot`, `innerspace`, `mobility`, `network`, `protect`, `site_manager`, `statistics`, `vpn`.
<!-- END GENERATED -->

- A deployment may set `UNIFI_FAMILY_ALLOW` (an allowlist) or `family:<id>` entries of
  `UNIFI_EXCLUDE` to select among the families above; unset (default) advertises every
  family. `firewall` is assigned by route.
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
- **Dynamic DNS**: `list_dynamic_dns`, `get_dynamic_dns`, `create_dynamic_dns`,
  `update_dynamic_dns`, `delete_dynamic_dns`
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
  (bucketed minute/5minutes/hourly/daily/monthly/archive reports), `list_known_clients`
  (per-site roster incl. offline)
- **Device Management**: adopt, unadopt, restart, upgrade, locate, execute actions,
  `forget_device` (remove adopted or pending devices from the controller by MAC)
- **Protect**: cameras, chimes, lights, sensors, viewers, liveviews, NVR, snapshots, PTZ control,
  `list_protect_events` (historical motion/smart-detect/sensor events, limited by the NVR's retention),
  face/vehicle recognition — `list_recognition_groups`, `get_recognition_group_counts`,
  `get_recognition_group_image`, `list_recognition_detections`, `get_thumbnail`
- **Protect alarm/arm & accessories** (published Protect Integration API, host only): arm
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
  Write/action tools honor the UNIFI_WRITE_EXCEPTIONS entry family:protect=deny (writes on by default); the confirm
  argument is accepted and ignored. Live-stream
  collectors — `collect_protect_events`, `collect_protect_device_changes` —
  bounded-window REST polls that return new events / device add-remove-modify
  changes in one call. A persistent Protect WebSocket subscription
  (/v1/subscribe/devices, /v1/subscribe/events) is NOT available over the Fabric
  cloud connector (a unary request/response relay — verified: an upgrade GET
  returns 404, never 101); use the collectors for live-ish data, or local console
  access for a true persistent stream.
- **InnerSpace**: floor-plan project geometry — walls, placed devices (with 3D
  mounting heights), per-floor plans, product/material dictionaries
- **VPN**: VPN servers (full CRUD), site-to-site tunnels (full CRUD),
  RADIUS profiles (list/get/create/update/delete) and RADIUS accounts
  (create/update/delete). The Network Integration API publishes only
  the list operations, so reads use it while writes use the routes the controller
  UI uses: VPN servers and site-to-site tunnels are Classic networkconf records
  (purpose remote-user-vpn / site-vpn; ids from the list tools or the Classic _id
  both work), and create_radius_profile posts Classic rest/radiusprofile. WAN
  updates (update_wan_interface) likewise write the Classic networkconf record of
  purpose wan, and device-tag reads and writes use the v2 device-tags route.
- **Hotspot**: voucher management, operators
- **ISP Metrics**: WAN health metrics (use interval='5m' or '1h')
- **Fleet**: cross-host device search, fleet summary, site comparison
- **Carrier / ISP Fabric** (org-scoped, no host/site): `list_carrier_subscribers`,
  `get_carrier_subscriber`, `list_carrier_service_plans`, `get_carrier_service_plan`,
  `create_carrier_subscriber`, `update_carrier_subscriber`,
  `attach_carrier_subscriber_host`, `detach_carrier_subscriber_host`,
  `assign_carrier_subscriber_plan`, `suspend_carrier_subscriber`,
  `resume_carrier_subscriber`. Identity: org-scoped via API key (no host/site). Writes
  are enabled by default; add `family:carrier=deny` to `UNIFI_WRITE_EXCEPTIONS` for a
  read-only Carrier Fabric deployment. A `confirm` argument is ignored.
  Spec-conformance tested only (not against a live Carrier Fabric).
- **InnerSpace writes** (`clean_innerspace_storage`, `create_innerspace_plan`, ...): enabled by
  default; add `family:innerspace=deny` to `UNIFI_WRITE_EXCEPTIONS` to refuse every InnerSpace write,
  the connector relay included. Reads are unaffected.
- **Fabric connector relay** (host-scoped, site optional): `fabric_connector_get`
  (ordinary GET reads always available; a known state-changing GET route, the Protect
  camera `enable-control` / `disable-control`, is a write and follows the write policy and
  exceptions below), `fabric_connector_post/put/patch/delete` (read and write enabled by
  default; add `family:connector=deny` to `UNIFI_WRITE_EXCEPTIONS` for a
  read-only deployment; the `confirm` argument is accepted and ignored). Relays requests to a console's
  `/proxy/{path}` surface via the official Network Cloud Connector. Identity: `host`
  resolves to the owning API key + host id; `site` name/UUID substituted from Registry
  into `{site}`/`{site_id}` path placeholders.
- **Mobility** (workspace-scoped, no host/site): `list_mobility_workspaces`,
  `list_mobility_admins`, `list_mobility_devices`, `get_mobility_device`,
  `list_mobility_clients`, `update_mobility_device_name`,
  `update_mobility_device_network`, `update_mobility_device_wireless`. Identity:
  `workspace_id` (not host/site). Writes are enabled by default; add
  `family:mobility=deny` to `UNIFI_WRITE_EXCEPTIONS` for a read-only Mobility deployment. The
  `confirm` argument is accepted and ignored.

## Parameter Scope Quick Reference
Examples by scope; the `required` list in each tool schema is authoritative.

- **host + site required**: network, firewall, DNS, traffic routes, traffic rules,
  traffic matching lists, port forwarding, WLAN, dynamic DNS, settings, device,
  client, VPN server, RADIUS profile, hotspot operator tools,
  `list_lags`, `get_lag`, `list_mc_lag_domains`, `get_mc_lag_domain`,
  `list_switch_stacks`, `get_switch_stack`,
  `list_device_stats`, `list_active_clients_stats`, `get_device_statistics`,
  `get_site_statistics`, `get_system_info`, `create_radius_profile`,
  `list_client_sessions`, `get_historical_stats`, `list_known_clients`,
  `get_client_link_diagnostics`, `get_device_port_state`, `get_device_stp_state`
- **host required, site optional**: `fabric_connector_get`, `fabric_connector_post`,
  `fabric_connector_put`, `fabric_connector_patch`, `fabric_connector_delete` (site only
  when the path has a `{site}` / `{site_id}` placeholder), `list_dpi_categories`,
  `list_dpi_applications` (a given site must exist on the console), `get_network_config_defaults`
  (site only for per-site kinds)
- **host + site optional**: `query_isp_metrics` (scope by `host` and `site`, or by the
  `sites` list)
- **site only** (no host): `get_site_health_summary`, `get_site_inventory`
- **host optional** (no site): `list_devices` (omit host for every console)
- **host only** (no site): `get_network_application_info`, `list_local_sites`,
  `list_pending_devices`,
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
- **no host/site** (global Site Manager /v1/ API): fleet and cross-site tools
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

**Block or unblock a client:**
1. `list_clients` (connected) or `list_known_clients` (incl. offline and blocked) → its MAC
2. `block_client` → block by client id or MAC (a MAC is sent as is: offline clients work too)
3. `unblock_client` → unblock by MAC (a blocked client is offline, absent from list_clients)

**Check WAN health:**
1. `get_isp_metrics(interval='5m')` for recent metrics
2. `list_wan_interfaces` for current WAN config

**Look up face / vehicle recognition (Protect):**
1. `list_recognition_groups` → enrolled subjects. NOTE: the parameter is `type`
   (singular) and takes one value — `'face'` or `'vehicle'`, not a list. Each group has
   an `id` (e.g. `face_90`).
2. `list_recognition_detections` → individual sightings for a group. This step REQUIRES `type`
   (the same value as in step 1) and `group_id` — use the `id` from step 1; there is no "all groups" mode. Each detection
   carries a `thumbnailId`.
3. `get_thumbnail` → fetch that detection's crop (base64 image with its upstream content_type).

## Important Notes
- **Read-only tools** change nothing, but by default they return credential fields verbatim:
  `get_protect_device_password`, `get_openvpn_client_config` and the WLAN, RADIUS, Dynamic
  DNS and VPN configuration reads can bring passwords, passphrases and keys into the model
  context. Set
  `UNIFI_REDACT_SECRETS` to mask the documented credential fields (see
  [Credential redaction](CONFIGURATION.md#credential-redaction)). Write tools
  (create/update/delete) modify live infrastructure.
- **Read-only mode**: if the deployment sets `UNIFI_WRITE_POLICY=deny` (opt-in, default `allow`), every
  write/action tool is refused with an actionable error and only read tools work — a
  deployment switch, not a per-call option.
- **Destructive / physical-effect operations** — irreversible real-world effects; use
  deliberately:
  - `delete_network`: removes the VLAN and disconnects all clients on it
  - `unadopt_device`: removes the device's association with the site; it must be re-adopted
  - `forget_device`: removes the device from the controller (an adopted device loses its
    controller configuration and must be re-adopted)
  - `disable_camera_mic_permanently`: hardware-level mic disable, cannot be re-enabled
  - `trigger_alarm_webhook`: triggers physical alarm hardware; real-world consequences
  - `delete_*` tools in general: no undo, no recycle bin
- **List paging**: every list tool that pages upstream drains every page by default and returns the complete set
  (a list answered from local state, such as `list_configured_api_keys`, returns its full set in one call)
  (a drain stopped by `UNIFI_PAGINATE_MAX_PAGES`, unset by default, or by a stalled cursor returns
  incomplete=true with incompleteReason). To page manually, use the tool's own paging
  arguments. A count argument (`page_size`, `limit`) requests a total gathered across native
  pages, whatever their size, and `_pageSize` reports the requested count, the sizes sent, the
  effective size and the returned count. A token, cursor or offset can request a page, subject to the family-specific rules below:
  - Site Manager (`list_hosts`, `list_sites`, `list_devices`): `page_size` is the requested
    total; `page_token` takes the unchanged nextToken for one verbatim page, or the returned
    `_continuation` string to resume under a different `page_size` (`list_sdwan_configs`:
    `page_token` only).
  - Network (including `list_protect_events`): `limit` alone is the requested total,
    counted from the start; `offset`, with or without `limit`, fetches ONE page (a `limit` is then
    sent on that page as given). Network lists return totalCount.
  - Mobility: `limit` requests a total gathered across pages starting at `offset` (or zero);
    `offset` alone fetches one page. Lists report `total` only when upstream sent it, plus `_count`.
  - Carrier `list_carrier_subscribers`: `limit` is the requested total; `cursor` takes the raw
    meta.nextCursor for one page, or `_continuation` to resume under a different `limit`.
  - Window tools (`list_recognition_groups`, `list_recognition_detections`,
    `get_protect_case_activity`, `get_sites_overview`, `get_system_log`): Recognition's
    `page_size` requests a total gathered across pages, and so does that of the others, counted
    from the start; `page` with `page_size` returns exactly that window of
    records with `_nextPage` to resume under the same `page_size`; `page` alone is one native
    console page verbatim. `page` is 1-based for recognition and case activity and 0-based for
    `get_sites_overview` and `get_system_log`.
  With several API keys a manual page of an org-scoped or Site Manager list needs `key_label`
  (a cursor or token belongs to one key).
- A blank string or an empty list for one of the parameters named here is not refused before
  the request: a filter or search the server applies itself (`query`, `status_filter`,
  `client_type`, `client_ids`) is then not applied, and a value forwarded upstream (`types`,
  `categories`, `smart_detect_types`, `attrs`, `host_ids`, `sites`) is sent as given for
  the upstream to judge. An argument limited to a fixed set of values is still checked first,
  so a blank one is refused (for example `session_type` of `list_client_sessions`).
- **Time parameters are NOT uniform across tools — check each tool before passing one:**
  - Epoch SECONDS as integers (e.g. 1690000000): `list_protect_events` (start/end),
    `collect_protect_events` (since), `list_client_sessions` (start/end),
    `get_historical_stats` (start/end), `list_recognition_detections` (start/end).
  - ISO 8601 UTC strings (e.g. "2026-07-23T00:00:00Z"): `query_isp_metrics`
    (start_time/end_time). Passing an epoch here — as a number OR as a bare-digit string —
    is rejected; convert to an ISO 8601 string first.
  - RFC3339 strings: `get_isp_metrics` (`begin_timestamp` / `end_timestamp`, or `duration` of
    `24h` for 5m metrics and `7d` or `30d` for 1h metrics, which cannot be combined with the
    timestamps) and `list_devices` (`time`).
  - The seconds-based tools send a negative or millisecond-magnitude value (>= 1e11) as
    given and add a `_warnings` entry saying so; the string-based tools reject numeric
    input. Do not assume a format carries across tools.
- ISP metrics `interval` accepts '5m' (5-minute buckets) or '1h' (1-hour buckets) only.
- The server resolves host/site names internally — you do not need to look up IDs manually.
- **Site IDs**: `list_sites` returns a Site Manager `siteId` in Fabric **ObjectId** format
  (from the `/v1/sites` list — the same value the former `/ea/sites` returned). This differs
  from the UUID used in proxy API paths, which is served by the per-console connector
  `/sites` endpoint. Always pass site **names** — the server resolves the correct ID for
  each API subsystem automatically.

## Port profiles and VLAN auto-exclusion

Switch port profiles reference networks by their internal `networkconf` id.
`list_port_profiles`, `get_port_profile`, `update_port_profile`,
`allow_network_on_port_profile` and `exclude_network_on_port_profile` return the
`excluded_networkconf_ids`, `native_networkconf_id` and `voice_networkconf_id` fields
as the bare ids the controller sends (so a read result writes back unchanged), and
report the `{id, name, vlan}` resolution of each (joined against `/rest/networkconf`)
under the additive `_resolved_networks` key, by field name, so a bare 24-hex id never
hides which network it is. `_resolved_networks` appears only on a profile that references
networks; an id with no match renders as `{id, name: null, vlan: null}`. Write tools drop
`_resolved_networks` and `_resolvedNetworksError` before sending. A failed network-name lookup
is reported under `_resolvedNetworksError` on each returned profile instead of failing the
call; on writes it also appears as `readAfterError` and the write result stands. Under
`UNIFI_WRITE_POLICY=dry-run` a port-profile write returns the bare preview with none of these keys.
`update_port_profile` maps each native, voice and excluded network value to its Classic `_id`
(an Integration id from `list_networks` or a unique network name converts); an unknown value
fails listing every network and sends no PUT.

**The auto-exclusion behavior:** when you create a new network, UniFi silently
adds it to the `excluded_networkconf_ids` of every custom-tagged port profile
(`tagged_vlan_mgmt: custom`). The new VLAN is then untagged on those uplinks and
blackholed at the host — a guest ARP to the gateway fails — even though nothing
looks wrong in the raw tool output. The UI "Tagged VLANs" list is *derived* (all
VLAN networks minus native minus excluded); there is no separate tagged-list
object to inspect.

**How this server surfaces and fixes it:**

- `create_network` appends an additive `_warnings` entry (code `D12_AUTO_EXCLUSION`) listing
  every custom-tagged profile that auto-excluded the new network. No `_warnings` entry means no
  custom-tagged profile excluded it. If the follow-up check cannot run (a non-object create
  response, no networkconf document linked to the new id, or a failed read), the response
  carries a `D12_CHECK_FAILED` warning (and `readAfterError`) instead and the network was still
  created: run `list_port_profiles` and look for the new network in each profile's
  `_resolved_networks.excluded_networkconf_ids`.
- `allow_network_on_port_profile(host, site, profile_id, network_id)` atomically
  fresh-reads the profile, removes the network from `excluded_networkconf_ids`,
  PUTs, and returns the resulting derived tagged set with names — run it on each
  profile named in the warning. `network_id` accepts the Network Integration id (`list_networks`
  `data[].id`, the id `create_network` returns) or the Classic networkconf `_id`; an unknown id
  fails before any write, listing every network. The result also carries `_network`
  (`{_id, id, name, vlan}`) and, when the controller returns no profile, `_profileNote`. The
  optional `confirm` argument is accepted and ignored.
- `exclude_network_on_port_profile(...)` is the inverse (untag a network from a
  profile).

Remediation in short: create the network, read the `D12_AUTO_EXCLUSION` warning (or run the
`D12_CHECK_FAILED` check above),
call `allow_network_on_port_profile` for each named profile, then verify
guest-to-gateway reachability.

The tool sections that follow are mostly write tools. They are hidden and refused when
`UNIFI_WRITE_POLICY=deny` or the `UNIFI_WRITE_EXCEPTIONS` entry `family:network=deny` (a `deny` wins over `UNIFI_WRITE_POLICY=dry-run`).
In the default discovery mode call them through `call_write_tool` with the arguments shown in
each example; set `UNIFI_TOOL_MODE=full` for direct calls.

## create_network

Create a new network/VLAN on a site.

Returns the upstream response body verbatim: the created network object the API answers with
(under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
preview: {method, path, params (query parameters), body}} instead).

Validated locally before the request (a missing field raises ValueError naming it):
``management`` — the discriminator the controller validates first. The rest of the
required schema is management-mode-specific and enforced by the controller. Spec value limits
are also checked locally before any request (for example vlanId 1-4009); a violation fails with
no request.
`network_config` is sent verbatim. Field names are camelCase exactly as in the spec —
the IPv4 block is ``ipv4Configuration`` (lower-case v), not ``ipV4Configuration``; there
is no 'purpose' field in the Network Integration API. For management='GATEWAY' the
controller also requires name, vlanId (1 only for the default network,
otherwise 2-4009), enabled, internetAccessEnabled, isolationEnabled,
cellularBackupEnabled, and ipv4Configuration (e.g. hostIpAddress + prefixLength, with
required autoScaleEnabled and optional DHCP settings). Optional: zoneId (zone UUID from
list_firewall_zones_proxy). Read an existing network with get_network to copy a working
ipv4Configuration shape.

Network auto-exclusion: UniFi silently adds every new network to the
``excluded_networkconf_ids`` of ALL custom-tagged port profiles
(``tagged_vlan_mgmt == 'custom'``), blackholing the VLAN at the host uplink.
When that happens this response carries an additive ``_warnings`` entry (code
``D12_AUTO_EXCLUSION``) naming each affected profile and the network's Classic
networkconf ``_id`` (profiles store that ``_id``, not this response's ``id``); run
``allow_network_on_port_profile`` on each to restore tagging (it accepts either id).

Request body (Network 11.0.97, POST /v1/sites/{siteId}/networks (createNetwork); schema "Create
or update Network") is passed in `network_config`. Required keys — enabled, management, name,
vlanId.
- dhcpGuarding: object (Network DHCP Guarding)
- enabled: boolean
- management: string
- name: string
- vlanId: integer(int32)
- ipv4Configuration, ipv6Configuration: objects; mdnsForwardingEnabled: boolean; zoneId: uuid
- Variant fields: cellularBackupEnabled, deviceId, internetAccessEnabled, isolationEnabled
Variants by `management` — GATEWAY requires cellularBackupEnabled, enabled,
internetAccessEnabled, ipv4Configuration, isolationEnabled, name, vlanId, management; SWITCH
requires cellularBackupEnabled, deviceId, enabled, ipv4Configuration, isolationEnabled, name,
vlanId, management; UNMANAGED requires enabled, name, vlanId, management.

Example call (create_network):
    {
      "host": "my-console",
      "site": "Default",
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

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
        id). Names like "Default" work.
    network_config: Full object to create; spec Create or update Network. Required: enabled,
        management, name, vlanId. 'management' selects variant: GATEWAY|SWITCH|UNMANAGED.

## create_wifi_broadcast

Create a new WiFi broadcast SSID on a site.

Returns the upstream response body verbatim: the created WiFi broadcast object the API answers
with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
preview: {method, path, params (query parameters), body}} instead).

Validated locally before the request (a missing field raises ValueError naming it):
``type`` — the discriminator the controller validates first (observed value:
'STANDARD'). The remaining fields are type-specific and enforced by the controller. Spec enum
values (for example the basic data rates) are also checked locally before any request.
`broadcast`: the fields each ``type`` requires are listed per variant under "Variants by
  `type`" below (STANDARD and IOT_OPTIMIZED differ). The spec permits omitting ``network``,
  but the live controller requires an explicit network reference for an OPEN broadcast:
  send securityConfiguration {"type": "OPEN"} together with ``network``.
  Field names must be camelCase to match the UniFi Integration API.

Request body (Network 11.0.97, POST /v1/sites/{siteId}/wifi/broadcasts (createWifiBroadcast);
schema "Wifi broadcast create or update") is passed in `broadcast`. Required keys —
channel2gLockedTo6, clientIsolationEnabled, dtimPeriod2gLockedTo3, enabled, hideName,
multicastToUnicastConversionEnabled, name, securityConfiguration, type, uapsdEnabled.
- basicDataRateKbpsByFrequencyGHz: object (IntegrationWifiBasicDataRateConfigurationDto)
- blackoutScheduleConfiguration: object (Integration blackout schedule configuration)
- broadcastingDeviceFilter: oneOf by type[DEVICES|DEVICE_TAGS] (Broadcasting device filter)
- channel2gLockedTo6: boolean
- clientFilteringPolicy: object (IntegrationWifiClientFilteringPolicyDto)
- clientIsolationEnabled: boolean
- dtimPeriod2gLockedTo3: boolean
- enabled: boolean
- hideName: boolean
- mdnsProxyConfiguration: oneOf by mode[AUTO|CUSTOM] (mDNS filtering configuration)
- multicastFilteringPolicy: oneOf by action[ALLOW|BLOCK] (Multicast filtering policy)
- multicastToUnicastConversionEnabled: boolean
- name: string
- network: oneOf by type[NATIVE|SPECIFIC] (Wifi network reference)
- securityConfiguration: oneOf by
  type[OPEN|WPA2_ENTERPRISE|WPA2_PERSONAL|WPA2_WPA3_ENTERPRISE|WPA2_WPA3_PERSONAL|WPA3_ENTERPRISE|WPA3_PERSONAL]
  (Wifi security configuration detailObject)
- type: string
- uapsdEnabled: boolean
- STANDARD only: advertiseDeviceName, arpProxyEnabled, bandSteeringEnabled,
  broadcastingFrequenciesGHz, bssTransitionEnabled, dnsAssistanceConfiguration,
  dtimPeriodByFrequencyGHzOverride, handoffSuggestionsConfiguration, hotspotConfiguration,
  mloEnabled (see the parameter schema for each shape)
Variants by `type` — IOT_OPTIMIZED requires channel2gLockedTo6, clientIsolationEnabled,
dtimPeriod2gLockedTo3, enabled, hideName, multicastToUnicastConversionEnabled, name,
securityConfiguration, uapsdEnabled, type; STANDARD requires advertiseDeviceName,
arpProxyEnabled, broadcastingFrequenciesGHz, bssTransitionEnabled, channel2gLockedTo6,
clientIsolationEnabled, dtimPeriod2gLockedTo3, enabled, hideName,
multicastToUnicastConversionEnabled, name, securityConfiguration, uapsdEnabled, type.

Example call (create_wifi_broadcast):
    {
      "host": "my-console",
      "site": "Default",
      "broadcast": {
        "type": "IOT_OPTIMIZED",
        "channel2gLockedTo6": true,
        "clientIsolationEnabled": true,
        "dtimPeriod2gLockedTo3": true,
        "enabled": true,
        "hideName": true,
        "multicastToUnicastConversionEnabled": true,
        "name": "IoT",
        "network": {"type": "NATIVE"},
        "securityConfiguration": {"type": "OPEN"},
        "uapsdEnabled": true
      }
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
        id). Names like "Default" work.
    broadcast: Full object to create; spec Wifi broadcast create or update. 'type' selects
        variant: IOT_OPTIMIZED|STANDARD.

## update_wifi_broadcast

Update an existing WiFi broadcast SSID.

Returns the upstream response body verbatim: the updated WiFi broadcast object the API answers
with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
preview: {method, path, params (query parameters), body}} instead).

For an OPEN broadcast retain the explicit ``network`` reference in the replacement object: the
live controller requires it.

Request body (Network 11.0.97, PUT /v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}
(updateWifiBroadcast); schema "Wifi broadcast create or update") is passed in `broadcast`.
Required keys — channel2gLockedTo6, clientIsolationEnabled, dtimPeriod2gLockedTo3, enabled,
hideName, multicastToUnicastConversionEnabled, name, securityConfiguration, type, uapsdEnabled.
- basicDataRateKbpsByFrequencyGHz: object (IntegrationWifiBasicDataRateConfigurationDto)
- blackoutScheduleConfiguration: object (Integration blackout schedule configuration)
- broadcastingDeviceFilter: oneOf by type[DEVICES|DEVICE_TAGS] (Broadcasting device filter)
- channel2gLockedTo6: boolean
- clientFilteringPolicy: object (IntegrationWifiClientFilteringPolicyDto)
- clientIsolationEnabled: boolean
- dtimPeriod2gLockedTo3: boolean
- enabled: boolean
- hideName: boolean
- mdnsProxyConfiguration: oneOf by mode[AUTO|CUSTOM] (mDNS filtering configuration)
- multicastFilteringPolicy: oneOf by action[ALLOW|BLOCK] (Multicast filtering policy)
- multicastToUnicastConversionEnabled: boolean
- name: string
- network: oneOf by type[NATIVE|SPECIFIC] (Wifi network reference)
- securityConfiguration: oneOf by
  type[OPEN|WPA2_ENTERPRISE|WPA2_PERSONAL|WPA2_WPA3_ENTERPRISE|WPA2_WPA3_PERSONAL|WPA3_ENTERPRISE|WPA3_PERSONAL]
  (Wifi security configuration detailObject)
- type: string
- uapsdEnabled: boolean
- STANDARD only: advertiseDeviceName, arpProxyEnabled, bandSteeringEnabled,
  broadcastingFrequenciesGHz, bssTransitionEnabled, dnsAssistanceConfiguration,
  dtimPeriodByFrequencyGHzOverride, handoffSuggestionsConfiguration, hotspotConfiguration,
  mloEnabled (see the parameter schema for each shape)
Variants by `type` — IOT_OPTIMIZED requires channel2gLockedTo6, clientIsolationEnabled,
dtimPeriod2gLockedTo3, enabled, hideName, multicastToUnicastConversionEnabled, name,
securityConfiguration, uapsdEnabled, type; STANDARD requires advertiseDeviceName,
arpProxyEnabled, broadcastingFrequenciesGHz, bssTransitionEnabled, channel2gLockedTo6,
clientIsolationEnabled, dtimPeriod2gLockedTo3, enabled, hideName,
multicastToUnicastConversionEnabled, name, securityConfiguration, uapsdEnabled, type.

Example call (update_wifi_broadcast):
    {
      "host": "my-console",
      "site": "Default",
      "broadcast_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "broadcast": {
        "type": "IOT_OPTIMIZED",
        "channel2gLockedTo6": true,
        "clientIsolationEnabled": true,
        "dtimPeriod2gLockedTo3": true,
        "enabled": true,
        "hideName": true,
        "multicastToUnicastConversionEnabled": true,
        "name": "IoT",
        "network": {"type": "NATIVE"},
        "securityConfiguration": {"type": "OPEN"},
        "uapsdEnabled": true
      }
    }

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

## create_firewall_policy

Create a new firewall policy on a site.

Returns the upstream response body verbatim: the created firewall policy object the API answers
with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
preview: {method, path, params (query parameters), body}} instead).

The seven required keys of `policy` (name, enabled, loggingEnabled, action, source,
destination, ipProtocolScope) are validated locally — a missing key raises ValueError
naming it. Spec limits are also checked locally (name minLength 1, enum values such as
connectionStateFilter and ipsecFilter); a violation fails with no request. action.type is ALLOW, BLOCK, or REJECT (ALLOW also requires
allowReturnTraffic); ipProtocolScope.ipVersion is IPV4, IPV6, or IPV4_AND_IPV6. There is
NO 'index' field; use set_firewall_policy_ordering to manage rule order. Get zone IDs
from list_firewall_zones_proxy (data[].id; match zone names case-insensitively).
An optional trafficFilter (on source and/or destination) narrows the match
beyond the zone pair. Set trafficFilter.type plus its matching nested object (the
port and IP-address filters carry their own required type and matchOpposite). A portFilter
may sit beside any type: for port-only destination matching use type PORT, and for combined
address and port matching use type IP_ADDRESS with ipAddressFilter and portFilter:
  - IP_ADDRESS  -> ipAddressFilter {"type": "IP_ADDRESSES", "matchOpposite": false,
                   "items": [{"type": "IP_ADDRESS"|"SUBNET", "value": ...}]}
  - NETWORK     -> networkFilter {"networkIds": [uuid from list_networks],
                   "matchOpposite": false}
  - PORT        -> portFilter {"type": "PORTS", "matchOpposite": false,
                   "items": [{"type": "PORT_NUMBER", "value": 443}]}
  - MAC_ADDRESS -> macAddressFilter {"macAddresses": [...]} (source only)
  Either filter type may instead be TRAFFIC_MATCHING_LIST with a trafficMatchingListId
  from list_traffic_matching_lists. The spec also defines further trafficFilter types
  (listed under the request body below); list_firewall_policies only reveals the types
  already in use on a site, so an unlisted type is not evidence it is unsupported.
PORT-FILTER PLACEMENT FOOTGUN: a portFilter under source.trafficFilter filters
SOURCE ports, which for outbound flows are ephemeral (random high ports) -> the rule
silently matches nothing. A destination-port rule MUST use destination.trafficFilter
with type PORT, never a source portFilter. (create/update_firewall_policy log a
runtime warning when a source PORT filter is combined with an any-destination ALLOW.)

Request body (Network 11.0.97, POST /v1/sites/{siteId}/firewall/policies
(createFirewallPolicy); schema "Create or update firewall policy") is passed in `policy`.
Required keys — action, destination, enabled, ipProtocolScope, loggingEnabled, name, source.
- name: string (minLength 1)
- description: string
- enabled: boolean
- loggingEnabled: boolean
- action: oneOf by type: ALLOW (IntegrationFirewallPolicyActionAllowDto, requires
  allowReturnTraffic: boolean) | BLOCK | REJECT
- source: Firewall policy source {zoneId: uuid REQUIRED, trafficFilter?: oneOf by type
  IP_ADDRESS|MAC_ADDRESS|NETWORK|PORT|REGION|IPV6_IID|SITE_TO_SITE_VPN_TUNNEL|VPN_SERVER}
- destination: Firewall policy destination {zoneId: uuid REQUIRED, trafficFilter?: oneOf by type
  APPLICATION|APPLICATION_CATEGORY|DOMAIN|IPV6_IID|IP_ADDRESS|NETWORK|PORT|REGION|SITE_TO_SITE_VPN_TUNNEL|VPN_SERVER}
- ipProtocolScope: oneOf by ipVersion: IPV4 | IPV6 | IPV4_AND_IPV6 (optional protocolFilter)
- connectionStateFilter: array of enum NEW|INVALID|ESTABLISHED|RELATED
- ipsecFilter: enum MATCH_ENCRYPTED|MATCH_NOT_ENCRYPTED
- schedule: object
Nested under source/destination trafficFilter:
  - portFilter: {type: PORTS|TRAFFIC_MATCHING_LIST, matchOpposite: bool} + items[] {type:
    PORT_NUMBER, value} | {type: PORT_NUMBER_RANGE, start, stop} for PORTS, or
    trafficMatchingListId for TRAFFIC_MATCHING_LIST
  - ipAddressFilter: {type: IP_ADDRESSES|TRAFFIC_MATCHING_LIST, matchOpposite: bool} + items[]
    {type: IP_ADDRESS|SUBNET, value} | {type: IP_ADDRESS_RANGE, start, stop}, or
    trafficMatchingListId
  - networkFilter: {networkIds: [uuid from list_networks], matchOpposite: bool}
  - macAddressFilter (source MAC_ADDRESS): {macAddresses: [string]}
  - trafficMatchingListId: uuid from list_traffic_matching_lists

Typical sequence (one tool call per step):
1. list_firewall_zones_proxy(host="my-console", site="Default") — source/destination zone ids.
2. create_firewall_policy(host="my-console", site="Default", policy={…}).
3. get_firewall_policy_ordering(host="my-console", site="Default",
   source_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
   destination_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02") — see where the new policy
   landed; reorder with set_firewall_policy_ordering.

Example call (create_firewall_policy):
    {
      "host": "my-console",
      "site": "Default",
      "policy": {
        "name": "Block IoT to LAN",
        "enabled": true,
        "loggingEnabled": false,
        "action": {"type": "BLOCK"},
        "source": {"zoneId": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01"},
        "destination": {
          "zoneId": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02",
          "trafficFilter": {
            "type": "PORT",
            "portFilter": {
              "type": "PORTS",
              "matchOpposite": false,
              "items": [
                {
                  "type":
                    "PORT_NUMBER",
                  "value": 443
                }
              ]
            }
          }
        },
        "ipProtocolScope": {"ipVersion": "IPV4"}
      }
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
        id). Names like "Default" work.
    policy: Full policy, schema "Create or update firewall policy". Required: name, enabled,
        loggingEnabled, action{type:ALLOW|BLOCK|REJECT}, source{zoneId}, destination{zoneId},
        ipProtocolScope{ipVersion}.

## update_firewall_policy

Full-replace a firewall policy by ID.

Returns the upstream response body verbatim: the replaced firewall policy object the API answers
with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
preview: {method, path, params (query parameters), body}} instead).

An optional trafficFilter (on source and/or destination) narrows the match
beyond the zone pair. Set trafficFilter.type plus its matching nested object (the
port and IP-address filters carry their own required type and matchOpposite). A portFilter
may sit beside any type: for port-only destination matching use type PORT, and for combined
address and port matching use type IP_ADDRESS with ipAddressFilter and portFilter:
  - IP_ADDRESS  -> ipAddressFilter {"type": "IP_ADDRESSES", "matchOpposite": false,
                   "items": [{"type": "IP_ADDRESS"|"SUBNET", "value": ...}]}
  - NETWORK     -> networkFilter {"networkIds": [uuid from list_networks],
                   "matchOpposite": false}
  - PORT        -> portFilter {"type": "PORTS", "matchOpposite": false,
                   "items": [{"type": "PORT_NUMBER", "value": 443}]}
  - MAC_ADDRESS -> macAddressFilter {"macAddresses": [...]} (source only)
  Either filter type may instead be TRAFFIC_MATCHING_LIST with a trafficMatchingListId
  from list_traffic_matching_lists. The spec also defines further trafficFilter types
  (listed under the request body below); list_firewall_policies only reveals the types
  already in use on a site, so an unlisted type is not evidence it is unsupported.
PORT-FILTER PLACEMENT FOOTGUN: a portFilter under source.trafficFilter filters
SOURCE ports, which for outbound flows are ephemeral (random high ports) -> the rule
silently matches nothing. A destination-port rule MUST use destination.trafficFilter
with type PORT, never a source portFilter. (create/update_firewall_policy log a
runtime warning when a source PORT filter is combined with an any-destination ALLOW.)

Request body (Network 11.0.97, PUT /v1/sites/{siteId}/firewall/policies/{firewallPolicyId}
(updateFirewallPolicy); schema "Create or update firewall policy") is passed in `policy`.
Required keys — action, destination, enabled, ipProtocolScope, loggingEnabled, name, source.
- name: string (minLength 1)
- description: string
- enabled: boolean
- loggingEnabled: boolean
- action: oneOf by type: ALLOW (IntegrationFirewallPolicyActionAllowDto, requires
  allowReturnTraffic: boolean) | BLOCK | REJECT
- source: Firewall policy source {zoneId: uuid REQUIRED, trafficFilter?: oneOf by type
  IP_ADDRESS|MAC_ADDRESS|NETWORK|PORT|REGION|IPV6_IID|SITE_TO_SITE_VPN_TUNNEL|VPN_SERVER}
- destination: Firewall policy destination {zoneId: uuid REQUIRED, trafficFilter?: oneOf by type
  APPLICATION|APPLICATION_CATEGORY|DOMAIN|IPV6_IID|IP_ADDRESS|NETWORK|PORT|REGION|SITE_TO_SITE_VPN_TUNNEL|VPN_SERVER}
- ipProtocolScope: oneOf by ipVersion: IPV4 | IPV6 | IPV4_AND_IPV6 (optional protocolFilter)
- connectionStateFilter: array of enum NEW|INVALID|ESTABLISHED|RELATED
- ipsecFilter: enum MATCH_ENCRYPTED|MATCH_NOT_ENCRYPTED
- schedule: object
Nested under source/destination trafficFilter:
  - portFilter: {type: PORTS|TRAFFIC_MATCHING_LIST, matchOpposite: bool} + items[] {type:
    PORT_NUMBER, value} | {type: PORT_NUMBER_RANGE, start, stop} for PORTS, or
    trafficMatchingListId for TRAFFIC_MATCHING_LIST
  - ipAddressFilter: {type: IP_ADDRESSES|TRAFFIC_MATCHING_LIST, matchOpposite: bool} + items[]
    {type: IP_ADDRESS|SUBNET, value} | {type: IP_ADDRESS_RANGE, start, stop}, or
    trafficMatchingListId
  - networkFilter: {networkIds: [uuid from list_networks], matchOpposite: bool}
  - macAddressFilter (source MAC_ADDRESS): {macAddresses: [string]}
  - trafficMatchingListId: uuid from list_traffic_matching_lists
Full replace. Read-modify-write via get_firewall_policy; send every required key (the controller
checks them; only create checks them locally). Server-managed top-level fields (id, metadata,
default, index) are stripped before sending, so a get_firewall_policy result can be sent back as
is. A body with no settable field is refused ("No fields provided"). For a partial change use
patch_firewall_policy(host, site, policy_id, fields) instead of a full replace.

Typical sequence (one tool call per step):
1. list_firewall_policies(host="my-console", site="Default") — policy id.
2. get_firewall_policy(host="my-console", site="Default",
   policy_id="7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f01") — current full object.
3. update_firewall_policy(host="my-console", site="Default",
   policy_id="7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f01", policy={…}).

Example call (update_firewall_policy):
    {
      "host": "my-console",
      "site": "Default",
      "policy_id": "7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f01",
      "policy": {
        "name": "Block IoT to LAN",
        "enabled": true,
        "loggingEnabled": false,
        "action": {"type": "BLOCK"},
        "source": {"zoneId": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01"},
        "destination": {
          "zoneId": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02",
          "trafficFilter": {
            "type": "PORT",
            "portFilter": {
              "type": "PORTS",
              "matchOpposite": false,
              "items": [
                {
                  "type":
                    "PORT_NUMBER",
                  "value": 443
                }
              ]
            }
          }
        },
        "ipProtocolScope": {"ipVersion": "IPV4"}
      }
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
        id). Names like "Default" work.
    policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
        UUID — not a Protect id.
    policy: FULL replacement (PUT), same schema/required keys as create_firewall_policy. Fetch
        with get_firewall_policy, edit, send whole object; omitted optional fields are cleared.

## set_firewall_policy_ordering

Set the ordering of firewall policies within one source/destination zone pair.

Returns: the controller's response, verbatim — the resulting order in the same
{"orderedFirewallPolicyIds": {"beforeSystemDefined": […], "afterSystemDefined": […]}} shape
(published response schema IntegrationFirewallPolicyOrderingDto).
Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
"dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query parameters),
body}} in place of the upstream body.

Request body (Network 11.0.97, PUT /v1/sites/{siteId}/firewall/policies/ordering
(updateFirewallPolicyOrdering) — "Reorder User-Defined Firewall Policies"; schema
"IntegrationFirewallPolicyOrderingDto") is passed in `ordering` (sent verbatim as the body).
Required keys — orderedFirewallPolicyIds.
- orderedFirewallPolicyIds: required keys beforeSystemDefined, afterSystemDefined;
  beforeSystemDefined: array of string (uuid) — user-defined policy ids evaluated BEFORE
  system-defined policies, in order; afterSystemDefined: array of string (uuid) — user-defined
  policy ids evaluated AFTER system-defined policies, in order
Query parameters: sourceFirewallZoneId = uuid (tool param source_zone_id);
destinationFirewallZoneId = uuid (tool param destination_zone_id).
Full replace of the user-defined order for ONE source/destination zone pair. Read first with
get_firewall_policy_ordering for the same pair, reorder, PUT back. Use [] for an empty side.
Ordering is per source/destination zone pair: find the pairs that have policies by
calling list_firewall_policies and grouping data[] by source.zoneId /
destination.zoneId (its `filter` narrows it, e.g. metadata.origin.eq('USER_DEFINED')).
Both zone ids are required tool arguments (query parameters, never read from the body): omitting
one fails argument validation and sends nothing, and a value that is not a UUID is refused locally.

Typical sequence (one tool call per step):
1. list_firewall_zones_proxy(host="my-console", site="Default") — pick the source and
   destination zone ids (data[].id).
2. get_firewall_policy_ordering(host="my-console", site="Default",
   source_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
   destination_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02").
3. set_firewall_policy_ordering(host="my-console", site="Default",
   source_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
   destination_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02", ordering={…}).
4. get_firewall_policy_ordering(host="my-console", site="Default",
   source_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
   destination_zone_id="0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02") — read back and compare.
No-op variant — pass the get result unchanged as ordering; before/after reads must be equal.

Example call (set_firewall_policy_ordering):
    {
      "host": "my-console",
      "site": "Default",
      "source_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
      "destination_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02",
      "ordering": {
        "orderedFirewallPolicyIds": {
          "beforeSystemDefined": [
            "7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f02",
            "7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f01"
          ],
          "afterSystemDefined": [
            "7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f03"
          ]
        }
      }
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
        id). Names like "Default" work.
    source_zone_id: REQUIRED source firewall zone UUID, sent as query param
        sourceFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the zone
        by name case-insensitively (e.g. Internal, External). Network UUID.
    destination_zone_id: REQUIRED destination firewall zone UUID, sent as query param
        destinationFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the
        zone by name case-insensitively (e.g. Internal, External). Network UUID.
    ordering: Full replacement
        {"orderedFirewallPolicyIds":{"beforeSystemDefined":[uuid…],"afterSystemDefined":[uuid…]}};
        both arrays required. Start from get_firewall_policy_ordering output.

## update_camera

Update settings for a Protect camera (name, OSD, LED, LCD message, mic volume, video mode,
HDR, smart detection).

Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason,
resource} when every sent leaf already matches (no PATCH is sent). Read-before, no-op,
PATCH, read-after: before/after are the object read before and after the write, verified
is true when the read-after carries every sent leaf value (nested objects such as
osdSettings are compared leaf by leaf, so a partial nested update verifies by the leaves
it sends; sibling keys it does not send are ignored), and response is the PATCH body
verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty).
verified is false when a sent leaf is missing or differs, and null, with readAfterError, when the
read-after fails or returns no object. Protect writes are enabled by default;
family:protect=deny or UNIFI_WRITE_POLICY=deny refuses the call before any request.
Under dry-run policy nothing is sent: {status: "dry_run", before (the body read first), response
(the preview)}; there is no read-after.

Request body (Protect 7.3.74, PATCH /v1/cameras/{id}; schema "inline requestBody schema") is
passed in `settings`. No key is required; send only the keys to change.
- name: string
- osdSettings: object {isNameEnabled: boolean, isDateEnabled: boolean, isLogoEnabled:
  boolean, isDebugEnabled: boolean, overlayLocation:
  enum[topLeft|topMiddle|topRight|bottomLeft|bottomMiddle|bottomRight]}
- ledSettings: object {isEnabled: boolean, welcomeLed: boolean, floodLed: boolean}
- lcdMessage: oneOf[{type: "DO_NOT_DISTURB", resetAt?} | {type:
  "LEAVE_PACKAGE_AT_DOOR", resetAt?} | {type: "CUSTOM_MESSAGE", text, resetAt?} |
  {type: "IMAGE", text, resetAt?}] (type required; text: string, required for
  CUSTOM_MESSAGE / IMAGE; resetAt: number or null)
- micVolume: number (1-100)
- videoMode: enum[default|highFps|sport|slowShutter|lprReflex|lprNoneReflex]
- hdrType: enum[auto|on|off]
- smartDetectSettings: object {objectTypes: array of
  enum[person|vehicle|package|licensePlate|face|animal], audioTypes: array of
  enum[alrmSmoke|alrmCmonx|alrmSiren|alrmBabyCry|alrmSpeak|alrmBark|alrmBurglar|
  alrmCarHorn|alrmGlassBreak]}

Example call (update_camera):
    {
      "host": "my-console",
      "camera_id": "66d025b301ebc903e80003ea",
      "settings": {"name": "Front door"}
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
        Network device UUID.
    settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.74 PATCH
        /v1/cameras/{id} body. Keys: name, osdSettings, ledSettings, lcdMessage, micVolume
        (number 1-100), videoMode, hdrType, smartDetectSettings (nested keys above).

## list_protect_events

Query historical Protect events (motion, smart-detect, sensor open/close, etc.).

A drain of object pages preserves data and the first page's envelope fields, adding _count
and _warnings. A drain of bare arrays returns {result, _count} with _warnings when
applicable. Capped drains also carry incomplete / incompleteReason.

One explicit page (offset given, with or without limit) follows the upstream page's shape:
- a bare-list page is returned as that list: each event verbatim, except that a sensor
  event in it gains _resolved_sensor; no _warnings are attached (a list has no place
  for them), so the epoch-unit and smart-detect warnings are not reported;
- an object page preserves every upstream top-level field verbatim, including data and
  totalCount. Sensor events gain only _resolved_sensor; the page gains _count and the
  epoch-unit and smart-detect _warnings, as a drained result does.

This uses the private /proxy/protect/api/events REST path — the ONLY source of
historical events. The official Protect Integration API exposes events solely over
WebSocket (/v1/subscribe/events) with no REST query endpoint, so do not expect the
integration path to answer this.

REQUIRED: host, start, and end. `start`/`end` are epoch SECONDS as INTEGERS (e.g.
1690000000 for 2023-07-22T04:26:40Z), NOT milliseconds and NOT an ISO 8601 string:
a negative or millisecond-magnitude value (>= 1e11) is not refused: it is converted to
milliseconds like any time, with a `_warnings` entry, and a string fails schema
validation. This differs on purpose from query_isp_metrics, whose start_time/end_time
are ISO 8601 STRINGS — do not carry a format across the two tools.

Sensor events set the top-level ``sensor`` field to null; it is left exactly as sent,
and the sensor id from metadata.sensorId.text is added as ``_resolved_sensor`` (an
additive key, not a controller field) so you can filter/join on it.
Events are passed through verbatim, including identifiers (MAC/IP/hostname/name) and
the metadata.name object carrying camera / recognised-person / license-plate text; the
recognised-person name on face events is at metadata.detectedThumbnails[].matchedName.

The types, smart_detect_types and categories filters are sent as given (an empty list sends no
parameter, so no filter applies; a blank string is sent as is for the upstream to
judge); an empty cameras list applies no camera filter.

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    start: REQUIRED. Epoch SECONDS (UTC) as integers, converted to milliseconds internally.
        Bounds are exact millisecond instants; end excludes the remainder of its second.
        History depth is bounded by the NVR's retention.
        (Contrast query_isp_metrics, which wants ISO 8601 strings.)
    end: REQUIRED. Epoch SECONDS (UTC) as integers, converted to milliseconds internally. Ranges
        are exact millisecond instants; end excludes the remainder of its second.
        History depth is bounded by the NVR's retention. (Contrast
        query_isp_metrics, which wants ISO 8601 strings.)
    types: Filter by event TYPE; single value or a list. Verified-present values: motion,
        smartDetectZone, smartAudioDetect, sensorOpened, sensorClosed, access. Smart-detect
        subtypes (person, face, animal, alrmSpeak and so on) are not event types; pass them in
        smart_detect_types instead. An unrecognised value returns zero events.
    cameras: filter by camera NAME or ID; single value or list. Names resolve to IDs: an exact
        match first, then Unicode-normalized (NFC) and case-insensitive, then ignoring
        surrounding whitespace (case kept before case-insensitive); an unknown name errors
        (listing the camera names as the console has them) rather than silently matching
        nothing.
    limit: Requested event count, gathered across effective pages from the beginning (with
        offset, the limit is sent as given on that one page), returning fewer only when the window
        ends. _pageSize reports the requested
        count, the sizes sent, the observed effective size and the returned count. Omit limit
        and offset to drain every event for the window (a wide window can hold tens of thousands
        of events). There is no page cap by default; only the opt-in UNIFI_PAGINATE_MAX_PAGES
        can stop a drain early, and then the result is flagged incomplete rather than truncated.
        Example: `25`.
    offset: Zero-based starting record. Fetches one native page; with limit, that limit is sent on
        the page. Omit both to drain every event for the window.
        Example: `25`.
    order_direction: Optional sort order sent as orderDirection: "ASC" (oldest-first) or "DESC"
        (newest-first). Omitted (default): no orderDirection is sent and the upstream's own
        order applies.
    smart_detect_types: filter by the smart-detect SUBTYPE — person, vehicle, animal, package,
        face, licensePlate (on smartDetectZone events) and the audio alarms alrmSpeak,
        alrmSiren, alrmBark, alrmCarHorn (on smartAudioDetect events). This is a distinct
        upstream parameter from types. The API only honours it when types is also set to the
        relevant event type(s); passing smart_detect_types alone is a silent no-op upstream:
        it is still sent, and the result carries a _warnings entry
        (SMART_DETECT_TYPES_WITHOUT_TYPES). Example: types="smartDetectZone",
        smart_detect_types="person" for just person detections; types="smartAudioDetect",
        smart_detect_types="alrmSpeak" to isolate the dominant audio-alarm noise.
    categories: filter by event category; single value or list. Verified values: motion, smart,
        iot, admin. Unknown values are silently ignored by the upstream API.
    without_descriptions: when true, ask the API to omit each event's description block (~16%
        smaller payload). Opt-in only — full-fidelity records are the default and descriptions
        are never dropped automatically.

## collect_protect_device_changes

Collect Protect device add/remove/modify changes for an explicit number of polls.

Protect's `/v1/subscribe/devices` WebSocket feed is NOT reachable over the Fabric
cloud connector (verified: an upgrade GET returns 404, never 101). This tool is
the REST equivalent: it polls every Protect device family (cameras, sensors, lights,
chimes, viewers, sirens, fobs, relays, speakers, bridges, link-stations, alarm-hubs)
for `poll_count` complete snapshots and reports what changed between consecutive snapshots.
Read-only and stateless.

Returns {_poll_count, _polls, _truncated, changes} (the same _-prefixed run keys as
collect_protect_events). A device object without an id cannot
be diffed: it is listed verbatim under unidentified ([{family, device}], every distinct
one seen in any poll of the run, even one a later poll no longer returns; the same
object with only lastSeen/uptime/upSince changed is one entry, its latest form) and the
result adds incomplete: true with incompleteReason. Each change is
{"change": "added"|"removed"|"modified", "device": {...}} (the verbatim upstream object) —
added/modified carry the current object, removed the last-seen object; the
change label is derived here, the device object is never altered. A device counts
as "modified" only when its upstream object differs after excluding the volatile
heartbeat fields lastSeen/uptime/upSince, so routine beacons do not show as
changes. A family this console's Protect version does not serve (its list answers
404/501) is named under unavailableFamilies ({family: upstream error}) with
incomplete: true, and the other families still count; a family unavailable in either
of two consecutive polls is left out of their diff, so a family that stops or starts
answering never reports its devices removed or added. When every family answers
404/501 (Protect absent) that upstream error is passed straight through. When a poll
fails after an earlier poll succeeded (any error: an HTTP error, a 429 that outlasted
the retries, a transport or shape error), polling stops and the changes gathered so
far are returned with incomplete: true and an incompleteReason carrying that poll's
complete error; a failing first poll raises it.

Required arguments: host (see each parameter's description).

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    poll_count: positive integer number of complete snapshots (default 6). At least two
        polls detect changes; elapsed time never interrupts an active snapshot.
    max_changes: Optional early stop: once this many change records accumulate, stop and flag
        `_truncated=true`. Default None (omit it): no limit, all requested polls complete.
    poll_interval_seconds: delay between polls (default 2). Very small values may hit the shared
        429 backoff, which the client already handles.

## list_recognition_detections

List a recognition group's detections (individual sightings) on a Protect console.

Returns {detections, _count} plus the first page's other envelope fields; _nextPage when
fetching one page, _pageSize ({requested, sent, effective, returned}) when page_size is given,
incomplete / incompleteReason on a capped drain.

One explicit page (page given without page_size) follows the upstream page's shape:
- a bare-list page is returned verbatim, without _warnings (so the epoch-unit warning
  is not reported);
- an object page is returned as {detections, _count} plus its other top-level fields
  (e.g. links) and _nextPage when it has a links.next; it carries the epoch-unit
  _warnings, as a drained result does.

REQUIRED: both `type` and `group_id`. `group_id` identifies which enrolled subject to
list sightings for — obtain a valid one from `list_recognition_groups` (its `id` field,
e.g. face_90); there is no "all groups" mode. Calling without `group_id` fails schema
validation, and passing an id that does not exist on the console returns HTTP 404.

Each detection carries id, eventId (joinable against list_protect_events), thumbnailId
(fetch the crop with get_thumbnail), detectedAt (epoch ms), cameraId, and
matchedGroupConfidence (0-100).

Response shape: {"detections": [...], "_count": N} (plus "_nextPage" when paging manually,
or "incomplete" / "incompleteReason" when a drain was capped). The array key is "detections"
(the upstream key), NOT "data" — unlike the offset-proxy tools that return {"data": [...],
"totalCount": N}; read the list from result["detections"].

`type`: recognition type. Use 'face' or 'vehicle' (singular -- plural forms
  return HTTP 400 from upstream). Forwarded to the API as-is.
`group_id`: REQUIRED. The group's stable id, e.g. face_90 — take it from a
  `list_recognition_groups` result (the `id` field). Not optional; not guessable.
`start/end`: optional time window in epoch SECONDS (UTC), converted to milliseconds
  internally. Verified live: the endpoint filters detections server-side by detectedAt
  against this window, so an arbitrary range (e.g. the last hour, 30 days, or 90 days)
  can be requested directly. Omit both for all detections.
`page`, `page_size`: by default every links.next page is drained so the complete detection
  set for the group (and window, if given) is returned. `page_size=N` returns records
  [(page-1)*N, page*N): exactly N when that many exist, fewer only at the end; `page` is the
  1-based window number in units of page_size (default 1). Resume from _nextPage with the same
  page_size; _pageSize reports the requested, sent, effective and returned sizes. `page` alone
  fetches one native console page.

Example call (list_recognition_detections):
    {"host": "my-console", "type": "face", "group_id": "face_90"}

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    type: 'face' or 'vehicle' (singular; plural returns HTTP 400).
    group_id: Recognition group id, e.g. 'face_90'. Get it from list_recognition_groups (id).
        Protect recognition id.
    page_size: Window size N: returns records [(page-1)*N, page*N) gathered across console
        pages; resume from _nextPage with the same page_size. Omit to drain all.
        Example: `100`.
    start: Optional window start, epoch SECONDS UTC. A negative or millisecond-magnitude
        value (>= 1e11) is sent as given with a _warnings entry.
    end: Optional window end, epoch SECONDS UTC. A negative or millisecond-magnitude value
        (>= 1e11) is sent as given with a _warnings entry.
    page: 1-based window number counted in units of page_size (default 1); without page_size,
        one native console page. Example: `2`.

## get_unifi_placement_snapshot

Return a bounded, read-only UniFi topology and placement snapshot.

A projection built by this server onto the closed unifi.placement-snapshot/v1
schema, unlike every other tool, which returns upstream bodies whole: fields are
selected, renamed (snake_case) and derived (a MAC-only device gets a SHA-256 derived
source_id, device_type is a closed enum). Every projected string is the upstream value
verbatim. Use the get_innerspace_*, list_cameras / list_sensors and list_devices tools
for the controller's complete payloads.

This is the canonical placement-consumer projection, not a general-purpose UniFi
payload. It fetches only InnerSpace 3D placement, Protect cameras/sensors, and
Site Manager device inventory through GET-backed helpers; it never invokes a
connector write route. The schema includes provenance and a 120-second freshness
contract. Address and asset fields are included by default: topology[].mac (cameras,
sensors, devices) and topology[].ip (Site Manager devices), placed_devices[].ip / mac
(the InnerSpace device meta), and floors[].image_url / model_url / additional_zip_url /
additional_bin_url (the plan's floor-plan map asset).

Withholding is opt-in: only with UNIFI_REDACT_SECRETS on are those address and asset
fields left out, together with any string value that is a URL, an IP or MAC address,
or carries a credential marker (password, api_key, access token, bearer, cookie,
private key, session/browser id, serial number). Each value left out is counted under
the additive _withheld object (keyed "section.field", e.g. "topology.mac", then by
reason: url, hardware_address, network_address, credential_marker), and
_withheld_how_to_obtain says for each key how to get the value: unset
UNIFI_REDACT_SECRETS, or read it verbatim with the named source tool. With
UNIFI_REDACT_SECRETS off (the default) _withheld is never present. Separately, and in
either mode, records schema v1 cannot represent (not_an_object, no_position,
no_geometry, no_source_id, not_numeric) are counted under the additive _unprojected
object (same shape), and _unprojected_how_to_obtain names for each key the verbatim
read tool (get_innerspace_project, list_innerspace_devices, list_cameras,
list_sensors or list_devices), so nothing is dropped silently.
It runs with any connector-write setting (it never writes).

Returns {schema_version, generated_at, freshness, provenance, floors, walls,
placed_devices, topology, placement_links}, plus incomplete/incompleteReason when a
source list stopped short, _unprojected / _unprojected_how_to_obtain when a record
could not be represented, and (redaction only) _withheld / _withheld_how_to_obtain
when a value was left out.

Required arguments: host (see each parameter's description).

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.

## Generic Fabric Connector Relay (guarded)

Ubiquiti's official Network Cloud Connector (and the Site Manager v1.0.0 OpenAPI) document a generic method relay family — `GET | POST | PUT | PATCH | DELETE /v1/connector/consoles/{id}/*path` — that forwards a request through Fabric to a console's `/proxy/<path>` surface. The typed console tools (Network, Protect, InnerSpace) ride that connector. The Site Manager reads of hosts, sites, devices, ISP metrics and SD-WAN configs, and the Mobility and Carrier Fabric tools, call their `api.ui.com` cloud routes directly (`/v1/hosts`, `/v1/sites`, `/v1/devices`, `/v1/isp-metrics/...`, `/v1/sd-wan-configs`, `/v1/mobility/...`, `/v1/carrier/...`) without the connector. The `fabric_connector_*` family exposes the relay **directly**, as a guarded escape hatch for a controller-supported route that has no typed wrapper yet (a per-device Classic REST config route, a legacy InnerSpace save route, etc.). Verb references: [Connector PUT](https://developer.ui.com/network/v11.0.97/connectorput), [Connector PATCH](https://developer.ui.com/network/v11.0.97/connectorpatch) (documented against Network app **v11.0.97**), and the Site Manager **v1.0.0** OpenAPI.

| Tool | Availability |
|------|--------------|
| `fabric_connector_get` | Read; available by default and under every write opt-out. A known state-changing GET route (Protect camera `enable-control` / `disable-control`) is a write: it follows the same opt-outs, read-only mode and dry-run as the mutation tools (no `confirm`) |
| `fabric_connector_post` | Mutation — writes **enabled by default**; opt out with `UNIFI_WRITE_EXCEPTIONS=family:connector=deny`. `confirm` is accepted and ignored |
| `fabric_connector_put` | Mutation — writes **enabled by default**; opt out with `UNIFI_WRITE_EXCEPTIONS=family:connector=deny`. `confirm` is accepted and ignored |
| `fabric_connector_patch` | Mutation — writes **enabled by default**; opt out with `UNIFI_WRITE_EXCEPTIONS=family:connector=deny`. `confirm` is accepted and ignored |
| `fabric_connector_delete` | Mutation — writes **enabled by default**; opt out with `UNIFI_WRITE_EXCEPTIONS=family:connector=deny`. `confirm` is accepted and ignored |

**`path`** is the relay-relative application path *after* `/proxy/` — e.g. `network/integration/v1/sites`, `network/api/s/{site}/rest/device/{id}`, or `innerspace/api/shapes/{id}`. Use the `{site}` (slug) or `{site_id}` (UUID) placeholder for the site segment; the server resolves the site through the Registry and substitutes its slug or UUID, and the result reports the path as sent, substituted site included, under `resolvedPath`. Like `path`, `resolvedPath` is relative to the console's `/proxy/`: the console id (resolved from `host`) and the API key are never part of either.

Guards (all enforced, none optional):

- **Registry-only identity** — `host` (name/id) resolves to the owning API key + host id; `{site}`/`{site_id}` are substituted from the Registry.
- **Route classes** (a route-to-area map, not a capability cap): Network `integration/v1`, Network Classic `api/s/{site}/rest|cmd|stat` (and every other Classic route), Network `v2/api`, Protect `integration/v1` and `api`, InnerSpace `integration/v1` and `api`, Access `integration/v1` and `api` each map to a `routeClass`, so a per-area write opt-out binds the relay as it binds that area's typed tools. Any other valid path (for example `talk/...`, `connect/...`, `drive/...`) relays with `routeClass: "unclassified"`: a GET always, and a mutation unless a per-area deny entry of `UNIFI_WRITE_EXCEPTIONS` (`family:network=deny`, `family:protect=deny`, `family:mobility=deny`, `family:carrier=deny` or `family:innerspace=deny`) is set. Its area cannot be proven, so while one is set the mutation is refused, naming the active entries.
- **Positive-charset path validation** — `..`, `%`-encoding, backslash, whitespace, control characters, `//` empty segments, and a URL scheme (`://`) are rejected before any network call.
- **Mutation gating (read + write on by default)** — an ordinary GET read is always available. A known state-changing GET route (Protect camera `enable-control` / `disable-control`) is a write: `family:connector=deny`, `family:protect=deny` and `UNIFI_WRITE_POLICY` (`deny` or `dry-run`) apply to it as to a mutation, and it is sent once. Connector writes are **enabled by default**; a deployment opts out by setting `UNIFI_WRITE_EXCEPTIONS=family:connector=deny` (see [Enabling / disabling connector writes](CONFIGURATION.md#enabling--disabling-connector-writes)). When opted out, a mutation is refused before the console is touched. The `confirm` argument is accepted for compatibility but is ignored.
- **Area opt-outs apply to the relay** — a relayed mutation on a `network/` route is refused before the console is touched when `family:network=deny` opts Network out, one on a `protect/` route when `family:protect=deny` opts Protect out, and one on an `innerspace/` route when `family:innerspace=deny` opts InnerSpace out, exactly as the typed write tools of those areas are; the Mobility and Carrier Fabric opt-outs are honoured the same way for any relay route of their area (both live on Site Manager cloud routes the console relay does not reach). The refusal names the entry.
- **No 429 auto-retry on a write** — a relayed POST/PUT/PATCH/DELETE is sent once and an HTTP 429 is raised with the upstream body (the server-wide retry rule: only a read via GET is retried; a relayed GET of a state-changing route, the Protect camera enable-control or disable-control, is sent once too), because the relay cannot tell a physical action (a siren, a relay output, a Classic `cmd`) from a settings write and a retry can repeat it. The read-before / read-after GETs keep the GET retry.
- **Read-before / write / read-after** — for PUT/PATCH/DELETE the resource is read before and after the write (`readBefore` / `readAfter`), and the no-op verdict compares only what the write requests (`_no_op_verdict` in `src/unifi_fabric/tools/connector.py`). A PUT/PATCH with a JSON object body is `noOp: true` when the write and both reads answered 2xx and every leaf the body names holds the same value (type-strict) before and after; unrequested siblings never count, so an unchanged requested `enabled` beside a changed `updatedAt` is still `noOp: true`. A requested leaf that differs, appears or disappears is `noOp: false`; a requested leaf absent from both reads, or a read that is not one JSON object, is `noOp: null` with `noOpReason`. A body-less write, a non-object body, or an empty object (`{}`) falls back to comparing the two whole reads, so a change only to `updatedAt` makes an empty-object PATCH `noOp: false`. A Classic `rest/device/<_id>` write reads the site's `stat/device` list narrowed to that device and compares only the fields the body writes (`noOpBasis`). A DELETE is `noOp: false`, `changed: true` only when the read-after answers 404; one still readable afterwards is `noOp: null` ("deletion not confirmed"). `noOp` is null when it cannot be told (a rejected write, a failed or non-2xx read: `readAfterError`), and `changed` is present only beside a non-null `noOp`.
- **Classic `meta.rc` errors** — a Classic route (`network/api/...`) reports its outcome in the body: HTTP 200 with `meta.rc` other than `"ok"` (e.g. `{"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []}`) is a rejected request. The relay reports it the way it reports any upstream error status, without raising: `status` and `body` stay verbatim and the result gains `_classicRcError` (the reason, `meta.msg` included); the write then has no `noOp` / `changed` verdict. A `readBefore` / `readAfter` answered that way carries the same marker and never counts as a successful read.
- **Scope guard** — an optional `scope` (`device` / `site` / `global`) is cross-checked against the path so a site-global setting route (e.g. `global_switch.stp_version`) cannot be driven by a device-scoped request.
- **Verbatim bodies + audit** — the relayed upstream body is returned unchanged, except that the server's own configured secrets (its API keys, `MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`) are always replaced by `***` if the body echoes them (credential fields are masked only when the operator opts in with [`UNIFI_REDACT_SECRETS`](CONFIGURATION.md#credential-redaction), which covers this relay like every tool); every relayed body carries the upstream `contentType`. JSON is returned decoded and any other text exactly as received (decoded in its declared charset, such as latin-1), under `body`. A **binary** body (a non-text Content-Type such as `image/jpeg` or `application/octet-stream`, or bytes that do not decode in the declared charset, UTF-8 when none) is returned the way the typed binary tools return bytes: complete, with no size cap, base64-encoded under `bodyBase64` with `sizeBytes`, and `body` null. The same applies to the write responses and to `readBefore` / `readAfter`. A 3xx is never followed: its response headers (`Location` included; credentials and cookies excluded) come back under `headers`, on the write and on `readBefore` / `readAfter`. Bodies are never logged. Audit is best-effort and off by default: with [`UNIFI_AUDIT_LOG`](CONFIGURATION.md#audit-log) unset (the default) a relayed mutation writes no audit record, and with it set every relayed mutation attempt is recorded in that file (fields under that heading). Separately, each attempt emits a best-effort INFO log line, `connector-relay-audit` (host, site, method, path, confirm, outcome, status). Neither contains the API key.
- **Dry-run** — under `UNIFI_WRITE_POLICY=dry-run` (or a matching `dry-run` exception) a relayed mutation is not sent: the result's `status` is `"dry_run"` (never an HTTP status) and `body` is the preview, and the audit line says `outcome=dry_run` with no status.

A 4xx/5xx from the relay is returned as `status` (not raised), so an invalid-ID probe surfaces its own reachability status. Undocumented legacy routes remain **experimental** until persistence and rollback are proven against a live console.

**Live decision-closing probe procedures** (documented; each is deferred to a maintenance window and is covered only by hermetic tests in this repo, never run live here):

1. *InnerSpace save route.* `PATCH innerspace/api/shapes/00000000-0000-0000-0000-000000000000` with an empty/invalid body. Expect a 4xx (`400/404/405/422` = route/method reachability evidence). **A 200/204 is an immediate stop condition** — do not use a real shape ID and do not issue a collection create/delete. Only after the route + schema are confirmed: one low-stakes reversible shape update, read back, restore the exact original shape, verify persistence on a fresh read. A 401/403 on the legacy namespace is auth/namespace gating, not a write path.
2. *Per-device STP/PoE config.* Read the target switch via `network/api/s/{site}/rest/device/{id}` (scope `device`), probe with the exact current value first (a same-value write → `noOp: true`), then change only that switch's STP priority (or a harmless empty-port field), read back via `/stat/device` (the controller has no GET on `/rest/device`; the relay's own read-before/read-after use `stat/device` for this route), then restore the original value and verify. Global `global_switch.stp_version` is site-wide — the scope guard refuses it for a `device`-scoped request; keep it to a separately named site-wide path.

## fabric_connector_post

HTTP 401/403 retains the complete upstream body and status and adds _hint naming
the API key variable or multi-key label, with setup or permission guidance.

Relay a POST (create/command) through the Fabric connector. Writes to the controller.

Connector writes are enabled by default; the connector flag refuses this only when
UNIFI_WRITE_EXCEPTIONS contains family:connector=deny for a read-only
deployment (checked before any network call). The confirm argument is accepted and
ignored. POST targets a collection
or command route (e.g. ``network/api/s/{site}/cmd/...``); it has no GET twin, so no
read-before/after is performed. The upstream status/body (verbatim) and routeClass are
returned; a 4xx/5xx other than 429 is reported, not raised (a 429 is raised, see below).

See fabric_connector_get for host/path/site/scope semantics. body: the JSON request body.
Every attempt is logged as a `connector-relay-audit` INFO line on stderr and, only when the
opt-in audit stream is configured (`UNIFI_AUDIT_LOG` or `UNIFI_AUDIT_SINK`), recorded in it
(never the API key value).

Request body: free-form. Generic relay: the body is forwarded verbatim; its shape is whatever
the target route's own spec defines (Network 11.0.97 / Protect 7.3.74 for integration routes;
classic network/api and network/v2 routes have no published spec). POST has no GET twin; no
read-before/after. Note: a PUT to an Integration ordering route needs its query params:
pass them in params (the typed tool is set_firewall_policy_ordering).
Returns — {method, routeClass, scope, path, resolvedPath, status, contentType, body,
writeEnabled}; body is the upstream body verbatim (decoded JSON, the exact text
of a non-JSON body, or null when empty). A binary body comes back complete as bodyBase64
(base64) plus sizeBytes, with body null (text in its declared charset, such as
latin-1, is decoded with it); contentType is the upstream Content-Type.
A 3xx (never followed) also returns its response headers (Location included; credentials
and cookies excluded) under headers. Under dry-run policy nothing is sent: status is
"dry_run" (never an HTTP status) and body is the preview.
Refused when — family:connector=deny is set, UNIFI_WRITE_POLICY=deny is set, the
path is a protect/ route while family:protect=deny is set (every area
write opt-out applies to the relay too), or the route is unclassified while any area write
opt-out is active. A Classic route (network/api/...) answered 2xx without meta.rc "ok" is an
upstream error: status and body stay verbatim and _classicRcError gives the reason. The write
is sent once: an HTTP 429 is raised with the upstream body, never auto-retried (a retry can
repeat a physical action).

Note — Typed equivalent: create_firewall_zone_proxy (Network 11.0.97 "Create or update firewall
zone").

Example call (fabric_connector_post):
    {
      "host": "my-console",
      "site": "Default",
      "path": "network/integration/v1/sites/{site_id}/firewall/zones",
      "body": {"name": "IoT", "networkIds": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"]}
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
        routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
        An ordinary GET relays even while an area write opt-out is active. A GET of a
        state-changing route (protect/api/cameras/{id}/enable-control or
        protect/api/cameras/{id}/disable-control) is a write: it follows the area write
        opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
        once. Mutations on
        unclassified routes are refused only while an area write opt-out is active, with
        the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
        placeholder for the site segment; '..', %-encoding and control characters are
        rejected.
    site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
        (UUID); the server substitutes it.
    body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
        Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
        Free-form JSON value: object, array, string, number, boolean or null. The caller-chosen
        route determines its shape.
    confirm: Ignored; accepted for backward compatibility. The call executes immediately when
        made unless the operator opted in to dry-run policy (then nothing is sent upstream and
        a preview of the request is returned).
    scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
        global-setting routes; 'site'/'global' reject /rest|/stat/device.
    params: Optional query-string parameters sent with the write (and with the
        read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
        sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
        Free-form JSON object; the caller-chosen route determines its shape.

## fabric_connector_put

HTTP 401/403 retains the complete upstream body and status and adds _hint naming
the API key variable or multi-key label, with setup or permission guidance. Read-before
and read-after GET failures carry the same additive hint.

Relay a PUT (full replace) through the Fabric connector. Writes to the controller.

Connector writes are enabled by default; the connector flag refuses this only when
UNIFI_WRITE_EXCEPTIONS contains family:connector=deny. The confirm
argument is accepted and ignored. PUT has a GET
twin at the same resource path, so the resource is read BEFORE and AFTER the write and
the result carries readBefore / readAfter / noOp (diff-based: a same-value write is
flagged noOp=true). Use this for reversible per-device config probes (e.g. Classic REST
``network/api/s/{site}/rest/device/{id}``); scope='device' guards against selecting a
site-global setting route. The controller has no GET on ``rest/device`` (it answers 404),
so for that route the reads are the site's ``stat/device`` list narrowed to the device
(``readBefore.twin`` names the route read), and noOp / changed compare only the fields
the body writes, since stat/device also carries live statistics that change between any
two reads. ``noOpBasis`` gives the route read and the compared fields; noOp is null when
the device or one of those fields is missing from a read. EXPERIMENTAL for undocumented legacy routes until persistence
and rollback are proven live.

See fabric_connector_get for host/path/site/scope semantics. body: the JSON request body.

Request body: free-form. Generic relay: the body is forwarded verbatim; its shape is whatever
the target route's own spec defines (Network 11.0.97 / Protect 7.3.74 for integration routes;
classic network/api and network/v2 routes have no published spec). PUT/PATCH/DELETE read the
same path before and after (Classic rest/device/{id}: stat/device, see fabric_connector_put)
and return readBefore/readAfter/noOp. Note: a PUT to an Integration
ordering route needs its query params: pass them in params (the typed tool is
set_firewall_policy_ordering).
Returns — {method, routeClass, scope, path, resolvedPath, status, contentType, body,
writeEnabled, readBefore, readAfter, noOp[, changed]}; body and
readBefore/readAfter.body are verbatim (decoded JSON, the exact text of a non-JSON body, or
null when empty). A binary body (the write's or a read's) comes back complete as bodyBase64
(base64) plus sizeBytes, with body null (text in its declared charset, such as
latin-1, is decoded with it); each carries the upstream contentType. A read that
fails is {status: null, error}; when the read-after fails or answers non-2xx,
readAfterError gives the reason — the write itself was still sent and its status/body are
reported. A 3xx (never followed) also returns its response headers (Location included;
credentials and cookies excluded) under headers.
noOp is true only when the write and both reads answered 2xx and every leaf the body
sends is identical in both reads (unrequested siblings are ignored; a body-less write
compares whole bodies). A DELETE is confirmed only by a 404 read-after: noOp: false,
changed: true; a read-after that still returns the resource is noOp: null with noOpReason
"deletion not confirmed". noOp is null when it cannot be told (noOpReason or
readAfterError says why).
changed (= not noOp) is present only when noOp is non-null; when noOp is null the key is
absent. Under dry-run policy nothing is sent: status is "dry_run" (never an HTTP status),
body is the preview, readAfter / noOp are null and changed is absent.
The dry-run body is the {method, path, params, body} preview. If post-write processing fails,
the write status and raw body are still returned with postWriteError. For rest/device,
readBefore/readAfter.body holds the full stat/device list, comparisonRecords holds the matched
record, `twin` names the GET twin and twinError says why a device could not be compared.
Refused when — family:connector=deny is set, UNIFI_WRITE_POLICY=deny is set, the
path is a protect/ route while family:protect=deny is set (every area
write opt-out applies to the relay too), or the route is unclassified while any area write
opt-out is active. A Classic route (network/api/...) answered 2xx without meta.rc "ok" is an
upstream error: status and body stay verbatim and _classicRcError gives the reason. The write
is sent once: an HTTP 429 is raised with the upstream body, never auto-retried (a retry can
repeat a physical action).

Note — Classic REST device route (no published spec); read-before/after reports noOp.

Example call (fabric_connector_put):
    {
      "host": "my-console",
      "site": "Default",
      "path": "network/api/s/{site}/rest/device/65f1c0ffee0123456789abcd",
      "body": {"name": "Core switch"},
      "scope": "device"
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
        routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
        An ordinary GET relays even while an area write opt-out is active. A GET of a
        state-changing route (protect/api/cameras/{id}/enable-control or
        protect/api/cameras/{id}/disable-control) is a write: it follows the area write
        opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
        once. Mutations on
        unclassified routes are refused only while an area write opt-out is active, with
        the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
        placeholder for the site segment; '..', %-encoding and control characters are
        rejected.
    site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
        (UUID); the server substitutes it.
    body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
        Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
        Free-form JSON value: object, array, string, number, boolean or null. The caller-chosen
        route determines its shape.
    confirm: Ignored; accepted for backward compatibility. The call executes immediately when
        made unless the operator opted in to dry-run policy (then nothing is sent upstream and
        a preview of the request is returned).
    scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
        global-setting routes; 'site'/'global' reject /rest|/stat/device.
    params: Optional query-string parameters sent with the write (and with the
        read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
        sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
        Free-form JSON object; the caller-chosen route determines its shape.

## fabric_connector_patch

HTTP 401/403 retains the complete upstream body and status and adds _hint naming
the API key variable or multi-key label, with setup or permission guidance. Read-before
and read-after GET failures carry the same additive hint.

Relay a PATCH (partial update) through the Fabric connector. Writes to the controller.

Connector writes are enabled by default; the connector flag refuses this only when
UNIFI_WRITE_EXCEPTIONS contains family:connector=deny. The confirm
argument is accepted and ignored. PATCH has a
GET twin, so read-before/write/read-after with noOp detection applies (see
fabric_connector_put). The candidate legacy InnerSpace save route
(``innerspace/api/shapes/{id}``) is a PATCH; probe it with a nonexistent shape ID and an
empty/invalid body first — a 4xx is reachability evidence, and a 200/204 on such a probe
is a stop condition, not a success. EXPERIMENTAL until persistence/rollback are proven.

See fabric_connector_get for host/path/site/scope semantics. body: the JSON request body.

Request body: free-form. Generic relay: the body is forwarded verbatim; its shape is whatever
the target route's own spec defines (Network 11.0.97 / Protect 7.3.74 for integration routes;
classic network/api and network/v2 routes have no published spec). PUT/PATCH/DELETE read the
same path before and after (Classic rest/device/{id}: stat/device, see fabric_connector_put)
and return readBefore/readAfter/noOp. Note: a PUT to an Integration
ordering route needs its query params: pass them in params (the typed tool is
set_firewall_policy_ordering).
Returns — {method, routeClass, scope, path, resolvedPath, status, contentType, body,
writeEnabled, readBefore, readAfter, noOp[, changed]}; body and
readBefore/readAfter.body are verbatim (decoded JSON, the exact text of a non-JSON body, or
null when empty). A binary body (the write's or a read's) comes back complete as bodyBase64
(base64) plus sizeBytes, with body null (text in its declared charset, such as
latin-1, is decoded with it); each carries the upstream contentType. A read that
fails is {status: null, error}; when the read-after fails or answers non-2xx,
readAfterError gives the reason — the write itself was still sent and its status/body are
reported. A 3xx (never followed) also returns its response headers (Location included;
credentials and cookies excluded) under headers.
noOp is true only when the write and both reads answered 2xx and every leaf the body
sends is identical in both reads (unrequested siblings are ignored; a body-less write
compares whole bodies). A DELETE is confirmed only by a 404 read-after: noOp: false,
changed: true; a read-after that still returns the resource is noOp: null with noOpReason
"deletion not confirmed". noOp is null when it cannot be told (noOpReason or
readAfterError says why).
changed (= not noOp) is present only when noOp is non-null; when noOp is null the key is
absent. Under dry-run policy nothing is sent: status is "dry_run" (never an HTTP status),
body is the preview, readAfter / noOp are null and changed is absent.
The dry-run body is the {method, path, params, body} preview. If post-write processing fails,
the write status and raw body are still returned with postWriteError. For rest/device,
readBefore/readAfter.body holds the full stat/device list, comparisonRecords holds the matched
record, `twin` names the GET twin and twinError says why a device could not be compared.
Refused when — family:connector=deny is set, UNIFI_WRITE_POLICY=deny is set, the
path is a protect/ route while family:protect=deny is set (every area
write opt-out applies to the relay too), or the route is unclassified while any area write
opt-out is active. A Classic route (network/api/...) answered 2xx without meta.rc "ok" is an
upstream error: status and body stay verbatim and _classicRcError gives the reason. The write
is sent once: an HTTP 429 is raised with the upstream body, never auto-retried (a retry can
repeat a physical action).

Note — Typed equivalent: patch_firewall_policy. Network 11.0.97 "Patch firewall policy" only
defines loggingEnabled and reportFlowEnabled.

Example call (fabric_connector_patch):
    {
      "host": "my-console",
      "site": "Default",
      "path":
        "network/integration/v1/sites/{site_id}/firewall/policies/3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "body": {"loggingEnabled": true},
      "scope": "site"
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
        routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
        An ordinary GET relays even while an area write opt-out is active. A GET of a
        state-changing route (protect/api/cameras/{id}/enable-control or
        protect/api/cameras/{id}/disable-control) is a write: it follows the area write
        opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
        once. Mutations on
        unclassified routes are refused only while an area write opt-out is active, with
        the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
        placeholder for the site segment; '..', %-encoding and control characters are
        rejected.
    site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
        (UUID); the server substitutes it.
    body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
        Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
        Free-form JSON value: object, array, string, number, boolean or null. The caller-chosen
        route determines its shape.
    confirm: Ignored; accepted for backward compatibility. The call executes immediately when
        made unless the operator opted in to dry-run policy (then nothing is sent upstream and
        a preview of the request is returned).
    scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
        global-setting routes; 'site'/'global' reject /rest|/stat/device.
    params: Optional query-string parameters sent with the write (and with the
        read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
        sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
        Free-form JSON object; the caller-chosen route determines its shape.

## fabric_connector_delete

HTTP 401/403 retains the complete upstream body and status and adds _hint naming
the API key variable or multi-key label, with setup or permission guidance. Read-before
and read-after GET failures carry the same additive hint.

Relay a DELETE through the Fabric connector. Irreversible write to the controller.

Connector writes are enabled by default; the connector flag refuses this only when
UNIFI_WRITE_EXCEPTIONS contains family:connector=deny. The confirm
argument is accepted and ignored. DELETE has a
GET twin, so the resource is read before and after; a delete is confirmed only by a 404
read-after following a 2xx read-before (noOp false, changed true). There is no undo: confirm the
exact resource path before calling.

See fabric_connector_get for host/path/site/scope semantics. body: optional JSON body.

Request body: free-form. Generic relay: the body is forwarded verbatim; its shape is whatever
the target route's own spec defines (Network 11.0.97 / Protect 7.3.74 for integration routes;
classic network/api and network/v2 routes have no published spec). PUT/PATCH/DELETE read the
same path before and after (a DELETE always reads its own path)
and return readBefore/readAfter/noOp. Note: a PUT to an Integration
ordering route needs its query params: pass them in params (the typed tool is
set_firewall_policy_ordering).
Returns — {method, routeClass, scope, path, resolvedPath, status, contentType, body,
writeEnabled, readBefore, readAfter, noOp[, changed]}; body and
readBefore/readAfter.body are verbatim (decoded JSON, the exact text of a non-JSON body, or
null when empty). A binary body (the write's or a read's) comes back complete as bodyBase64
(base64) plus sizeBytes, with body null (text in its declared charset, such as
latin-1, is decoded with it); each carries the upstream contentType. A read that
fails is {status: null, error}; when the read-after fails or answers non-2xx,
readAfterError gives the reason — the write itself was still sent and its status/body are
reported. A 3xx (never followed) also returns its response headers (Location included;
credentials and cookies excluded) under headers.
noOp is true only when the write and both reads answered 2xx and every leaf the body
sends is identical in both reads (unrequested siblings are ignored; a body-less write
compares whole bodies). A DELETE is confirmed only by a 404 read-after: noOp: false,
changed: true; a read-after that still returns the resource is noOp: null with noOpReason
"deletion not confirmed". noOp is null when it cannot be told (noOpReason or
readAfterError says why).
changed (= not noOp) is present only when noOp is non-null; when noOp is null the key is
absent. Under dry-run policy nothing is sent: status is "dry_run" (never an HTTP status),
body is the preview, readAfter / noOp are null and changed is absent.
The dry-run body is the {method, path, params, body} preview. If post-write processing fails,
the write status and raw body are still returned with postWriteError. For rest/device,
readBefore/readAfter.body holds the full stat/device list, comparisonRecords holds the matched
record, `twin` names the GET twin and twinError says why a device could not be compared.
Refused when — family:connector=deny is set, UNIFI_WRITE_POLICY=deny is set, the
path is a protect/ route while family:protect=deny is set (every area
write opt-out applies to the relay too), or the route is unclassified while any area write
opt-out is active. A Classic route (network/api/...) answered 2xx without meta.rc "ok" is an
upstream error: status and body stay verbatim and _classicRcError gives the reason. The write
is sent once: an HTTP 429 is raised with the upstream body, never auto-retried (a retry can
repeat a physical action).

Note — Irreversible. Typed equivalent: delete_firewall_policy.

Example call (fabric_connector_delete):
    {
      "host": "my-console",
      "site": "Default",
      "path":
        "network/integration/v1/sites/{site_id}/firewall/policies/3fa85f64-5717-4562-b3fc-2c963f66afa6"
    }

Args:
    host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
        reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
        (MAC:numericId composite). One console serves both Network and Protect.
    path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
        routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
        An ordinary GET relays even while an area write opt-out is active. A GET of a
        state-changing route (protect/api/cameras/{id}/enable-control or
        protect/api/cameras/{id}/disable-control) is a write: it follows the area write
        opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
        once. Mutations on
        unclassified routes are refused only while an area write opt-out is active, with
        the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
        placeholder for the site segment; '..', %-encoding and control characters are
        rejected.
    site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
        (UUID); the server substitutes it.
    body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
        Network 11.0.97 for network/integration/v1). Optional for DELETE. Omit to send no body; an explicit null is sent as the JSON body null.
        Free-form JSON object; the caller-chosen route determines its shape.
    confirm: Ignored; accepted for backward compatibility. The call executes immediately when
        made unless the operator opted in to dry-run policy (then nothing is sent upstream and
        a preview of the request is returned).
    scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
        global-setting routes; 'site'/'global' reject /rest|/stat/device.
    params: Optional query-string parameters sent with the write (and with the
        read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
        sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
        Free-form JSON object; the caller-chosen route determines its shape.

## update_mobility_device_network

Update a UMR device's LAN / DHCP settings (guarded write). Mutates live config.

Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null}
for every requested field (null for fields absent from the pinned device-detail schema;
the whole map is null on read-after failure, with readAfterError), device
(the read-after device-detail GET body verbatim, {data, httpStatusCode,
traceId}), response (the PUT body verbatim; null for the documented 204)}, or {status:
"no_op", reason, device (the GET body read first)}.
Under dry-run policy nothing is sent: {status: "dry_run", device (the body read first), response
(the preview)}; verified is absent (there is no read-after).

DOCUMENTED partial update: only provided fields are applied (WAN/IPv6/InternetSource are
not configurable here). At least one field is required. The Mobility docs differ on PUT
semantics (full replacement vs this endpoint's documented partial merge); if the console
applies full replacement, unsent LAN/DHCP fields can be reset. Add
family:mobility=deny to UNIFI_WRITE_EXCEPTIONS for a read-only deployment. dhcp_mode is 'dhcp' (enabled) or
'none' (disabled); IPs must be dotted-quad IPv4 (spec format: ipv4; a leading-zero octet
such as 192.168.01.1 is refused before any request); dhcp_lease_time is seconds
(0 = infinite). Guarded, in order: the Mobility write opt-out
(family:mobility=deny refuses first), read-before, no-op detection on the
observable host_address, write, read-after.

Request body (Mobility 1.0.0, PUT
/v1/mobility/workspaces/{workspaceID}/devices/{deviceID}/network (updateDeviceNetwork); schema
"UpdateNetworkReq") is built from scalar parameters. No key is required; send only the keys to
change. Each field is nullable: explicit null is forwarded; omitted fields stay omitted.
- host_address: string(ipv4)
- dhcp_mode: enum[dhcp|none]
- dhcp_range_start: string(ipv4)
- dhcp_range_stop: string(ipv4)
- dhcp_lease_time: integer

Example call (update_mobility_device_network):
    {
      "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "dhcp_mode": "dhcp"
    }

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


## fabric_connector_get

Relay a GET through the Fabric connector to a console's `/proxy/{path}`, for routes without a
typed tool. `host` is the console name or id (as for every host tool). `path` is the application
path AFTER `/proxy/`, for example `network/integration/v1/sites` or
`network/api/s/{site}/stat/device`; use the `{site}` (slug) or `{site_id}` (UUID) placeholder for
the site segment and pass `site` (name or UUID) only then, and `resolvedPath` in the result shows
the path as sent. `params` are optional query-string parameters. `scope` (`device`, `site` or
`global`) is an optional guard cross-checked against the path. Mapped routes carry their
`routeClass`; unmapped ones relay as `unclassified`. `..`, %-encoding and control characters in
`path` are rejected. Returns {method, routeClass, scope, path, resolvedPath, status, contentType,
body}; a 4xx/5xx other than 429 is returned, not raised, so a probe of an unknown route shows
reachability (a 429 that persists through the read retries is raised as `RateLimitError`).
`body` is the upstream body verbatim (decoded JSON, the exact text of a non-JSON body, or null
when empty; masked only under UNIFI_REDACT_SECRETS). A binary body comes back complete as
bodyBase64 plus sizeBytes with body null, and a 3xx (never followed) adds its response headers.
HTTP 401/403 retains the complete upstream body and status and adds _hint naming the API key
variable or multi-key label. A Classic route (network/api/...) answered 2xx without meta.rc
"ok" is an upstream error: status and body stay verbatim and _classicRcError gives the reason.

Ordinary GETs relay even while an area write opt-out is active. The GET of a state-changing
route (Protect camera `enable-control` / `disable-control`) is a write: it follows
family:connector=deny, the area opt-outs and `UNIFI_WRITE_POLICY` (`deny`, or `dry-run`: an
action GET sends nothing and returns status "dry_run"), is sent once, and in discovery mode
goes through `call_write_tool`.

Example call (fabric_connector_get):
    {
      "host": "my-console",
      "site": "Default",
      "path": "network/integration/v1/sites/{site_id}/networks"
    }

## API-source selection

The `source:<selector>` entries of `UNIFI_EXCLUDE` select tools by API source. Unset
enables every source; a blank `UNIFI_EXCLUDE` fails startup. Select an app (`network`), a source (`network/private.classic`,
`protect/private`), a private group (`network/private`), or an access level
(`network/private/write`, `protect/write`, `*/write`). `*/private` disables all private
surfaces; `*/generic` selects generic relays and `*/local` selects tools with no upstream
request. Selectors are case-sensitive; unknown or repeated selectors fail at startup naming
the setting.

The `fabric_connector_*` tools are `relay/generic` and can reach any route, including
private APIs. `*/private` does not disable them. Use `source:relay` or `source:*/generic` to disable
those tools explicitly; `*/read` and `relay/read` also remove `fabric_connector_get` (class `relay/generic/read`, the only GET relay), and `*/write` keeps it. A write selector (`*/write`, `protect/write`) therefore leaves the Protect camera `enable-control` and `disable-control` GET routes reachable through `fabric_connector_get`; to block them, use `UNIFI_WRITE_POLICY=deny`, `UNIFI_WRITE_EXCEPTIONS=family:connector=deny` or `source:relay`. This selector does not
filter the routes an enabled relay may reach. `UNIFI_WRITE_POLICY` is an independent setting.

## Discovery mode

In the default UNIFI_TOOL_MODE=discovery, begin with search_tools using a clear intent such as camera recordings; use describe_tool on a returned name before calling it through call_read_tool or call_write_tool. Empty search browses enabled tools. A stopword-only or unmatched query is rejected with an error that tells you to broaden the intent or use an empty query to browse the catalog. Set UNIFI_TOOL_MODE=full when a client needs direct domain-tool calls.

<!-- BEGIN GENERATED: search-tools-limit -->
`search_tools` returns 10 matches by default; `limit` takes any positive integer, or null for every match.
<!-- END GENERATED -->

`family` narrows to one slug from `list_tool_families`, and `writes` selects mutations (true) or reads (false). `describe_tool` returns the same schema the tool has in full mode. `call_read_tool` refuses a write, including the state-changing GET relay routes, and names `call_write_tool` instead (with `UNIFI_WRITE_POLICY=deny`, it returns the read-only refusal, since `call_write_tool` is not listed); the target's own validation, the write policy and its exceptions, dry-run and audit apply to both. With `UNIFI_WRITE_POLICY=deny`, `call_write_tool` is not offered.

## provision_device

Example call (provision_device):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

## cancel_rolling_upgrade

Example call (cancel_rolling_upgrade):
    {
          "host": "my-console",
          "site": "Default"
        }

## list_device_firmware

Example call (list_device_firmware):
    {
          "host": "my-console",
          "site": "Default"
        }

## migrate_device

Example call (migrate_device):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "inform_url": "http://controller.example:8080/inform"
        }

## advanced_adopt_device

Example call (advanced_adopt_device):
    {
          "host": "my-console",
          "site": "Default",
          "mac": "aa:bb:cc:dd:ee:ff",
          "ip": "192.0.2.10",
          "username": "admin",
          "password": "change-me-123",
          "inform_url": "http://controller.example:8080/inform"
        }

## run_speedtest

Example call (run_speedtest):
    {
          "host": "my-console",
          "site": "Default"
        }

## get_speedtest_status

Example call (get_speedtest_status):
    {
          "host": "my-console",
          "site": "Default"
        }

## upgrade_all_devices

Example call (upgrade_all_devices):
    {
          "host": "my-console",
          "site": "Default"
        }

## start_rolling_upgrade

Example call (start_rolling_upgrade):
    {
          "host": "my-console",
          "site": "Default"
        }

## move_device_to_site

Example call (move_device_to_site):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "destination_site_id": "5f0c4d2e8b1a2c3d4e5f6a7b"
        }

## list_backups

Example call (list_backups):
    {
          "host": "my-console",
          "site": "Default"
        }

## create_backup

Example call (create_backup):
    {
          "host": "my-console",
          "site": "Default"
        }

## export_site

Example call (export_site):
    {
          "host": "my-console",
          "site": "Default"
        }

## adopt_device

Example call (adopt_device):
    {
          "host": "my-console",
          "site": "Default",
          "device": {"ignoreDeviceLimit": true, "macAddress": "aa:bb:cc:dd:ee:ff"}
        }

## unadopt_device

Example call (unadopt_device):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

## execute_device_action

Example call (execute_device_action):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "action": {"action": "RESTART"}
        }

## execute_port_action

Example call (execute_port_action):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "port_idx": 1,
          "action": {"action": "POWER_CYCLE"}
        }

## restart_device

Example call (restart_device):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

## locate_device

Example call (locate_device):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

## upgrade_device

Example call (upgrade_device):
    {
          "host": "my-console",
          "site": "Default",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

## forget_device

Example call (forget_device):
    {
          "host": "my-console",
          "site": "Default",
          "mac": "aa:bb:cc:dd:ee:ff"
        }

## create_scheduled_task

Example call (create_scheduled_task):
    {
          "host": "my-console",
          "site": "Default",
          "task": {
            "name": "Monthly upgrades",
            "action": "upgrade",
            "cron_expr": "0 0 1 * *"
          }
        }

## update_scheduled_task

Example call (update_scheduled_task):
    {
          "host": "my-console",
          "site": "Default",
          "task_id": "5f0c4d2e8b1a2c3d4e5f6a7c",
          "task": {
            "name": "Monthly upgrades",
            "action": "upgrade",
            "cron_expr": "0 0 1 * *"
          }
        }

## delete_scheduled_task

Example call (delete_scheduled_task):
    {
          "host": "my-console",
          "site": "Default",
          "task_id": "5f0c4d2e8b1a2c3d4e5f6a7c"
        }

## Placement snapshot fields

`get_unifi_placement_snapshot`: a bounded, read-only 3D placement and topology
projection (versioned `unifi.placement-snapshot/v1`, with provenance and a 120-second
freshness contract) for floor-plan, map and dashboard consumers, built from InnerSpace,
Protect and Site Manager reads. It is a projection onto a closed field selection (not
whole upstream bodies), and every projected string is the upstream value verbatim. The
address and asset fields are included by default: `topology[].mac` / `ip`,
`placed_devices[].mac` / `ip` (InnerSpace device `meta`) and the floor-plan asset URLs
`floors[].image_url` / `model_url` / `additional_zip_url` / `additional_bin_url` (the
plan's `map` shape). Withholding is opt-in: with `UNIFI_REDACT_SECRETS` on, those fields
and any text value that is a URL, carries a hardware or network address or a whole-word
credential or browser marker are left out and counted under `_withheld`, and
`_withheld_how_to_obtain` says for each key how to get the value (unset
`UNIFI_REDACT_SECRETS`, or the named verbatim source tool); with it off, `_withheld`
is never present. A record schema v1 cannot represent (a non-object entry, a device
without a position, a wall without geometry, a Site Manager device without a stable id, a
non-numeric rotation) is counted in either mode under the separate `_unprojected` key,
and `_unprojected_how_to_obtain` names the verbatim `get_innerspace_*` / `list_*`
tool for each key. Site Manager
device wrappers are flattened so each switch, AP and gateway is its own node; a
record with a MAC but no id gets a `source_id` of `smdev-` plus the first 24 hex characters of
SHA-256 over its kind and MAC (stable across snapshots; the hash is unkeyed and would reveal
the MAC, so with `UNIFI_REDACT_SECRETS` on such a record is left out and counted under
`_withheld` as `topology.record` / `hardware_address`); a device Protect
and Site Manager both list appears once; a source list that stopped short (an opt-in page cap, or
a repeated or cycling cursor) sets `incomplete: true` and `incompleteReason`.
Placed devices carry InnerSpace `rotation` as `pov` / `base` objects with numeric
`x`, `y`, `z`, `w`; NaN / Infinity in projected numbers are shape errors.
Failed snapshot reads cancel any remaining upstream requests before returning the error.
When a documented InnerSpace path and its legacy fallback both fail, both
upstream errors are preserved.
Each node carries a closed-enum `device_type` and, for models in a curated table, an
`icon` (`{"kind": "unifi_fingerprint", "id": <int>}`). A floor's `scale` is read
exactly as `get_innerspace_summary` reads it: the plan's own `scale` / `planScale` /
`planScales` (a number or an object with `scale`), else the value on the plan's `scale` shape
(`scale`, then `computedScale`).

Fields, by top-level key (a key with no value is omitted):

- `schema_version`, `generated_at`, `freshness` (`{observed_at, max_age_seconds, cache: "none"}`),
  `provenance` (`{source, approved_read_sources, read_only, innerspace_project_updated_at}`).
- `floors[]`: `source_id`, `display_name`, `ordering`, `scale`, and the asset URLs `image_url`,
  `model_url`, `additional_zip_url`, `additional_bin_url`.
- `walls[]`: `start` and `end` (`{x, y, z}` points), `material`, `floor_source_id`.
- `placed_devices[]`: `source_id`, `display_name`, `product_id`, `mount`, `floor_source_id`,
  `position` (`{x, y, z}`), `rotation` (`pov` / `base` quaternions), `ip`, `mac`.
- `topology[]`: `kind` (`protect_camera`, `protect_sensor` or `network_device`), `source_id`,
  `display_name`, `model`, `device_type`, `mac`, `ip`, `icon`. `device_type` is one of `camera`,
  `doorbell`, `access_point`, `switch`, `gateway`, `motion_sensor`, `presence_sensor`, `chime`,
  `sensor`, `client` or `unknown`.
- `placement_links[]`: `inventory_source_id`, `placement_source_id` and `match_method`
  (`unique_exact_display_name`; links are made only on a unique exact display-name match).

Before relying on the snapshot, `unifi-fabric-mcp placement-snapshot-preflight --host <console>`
checks that the four read sources answer.

For official-only deployments, use `list_all_clients` and select records by `_siteId` for per-site client inventory; `list_clients` also supports a private v2 route.
