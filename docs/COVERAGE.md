# Compatibility, testing and coverage

What the server was verified against, what has and has not been run on live hardware, and the known limits. The live-sweep figures in the Compatibility and Tested against sections are refreshed after each release's live sweep and say which sweep they come from.

## Live evidence (historical: build `8a86a795f635`, 2026-11-10)

<!-- live-evidence: passed=402 writes=170 total=798 build=8a86a795f635 date=2026-11-10 -->
The live figures below are historical: recorded on build `8a86a795f635` on 2026-11-10 and not re-measured at the current head.

Every registered tool runs in CI against a simulated upstream. The 2026-11-10 live acceptance run on build `8a86a795f635` recorded 402 passing tools against the console, of the registry, which is this release's 798 tools. The passes included 170 write tools. The write checks ran on the preceding build, `77b814a7c02d`, and their results are carried to `8a86a795f635`, the build the read checks ran on. The run recorded a result for 685 of the 798 tools. Beyond the passes, 60 read tools answered with an empty list (hardware or a feature the test console does not have; counted separately, not as passed), 35 ended partial, 29 were skipped for lack of an input or target, 16 are unsupported on this console, two met an upstream error, one met a rate limit, one confirmed a documented rejection, two are not proven, 62 are covered by hermetic tests and source-route checks only, and 75 were not probed. No tool is left in a failing state in the final record; the run's harness failures were reviewed and recorded as the unsupported, upstream-error, expected-rejection and not-proven results listed under [Limits of the 2026-11-10 run](#limits-of-the-2026-11-10-run). The run used a single UniFi Dream Machine Pro Max console (UniFi OS 6.0.17) with a single site, Network 11.1.47, which is an early-access build, and Protect 7.3.74. It was not a multi-site or multi-organization estate.

Changes made after build `8a86a795f635` are covered by CI only: the figures above do not imply that every tool passed at the current head. CI uses shape-faithful fake upstreams; published API routes are checked against pinned specifications in [LAST_AUDITED.md](../LAST_AUDITED.md). Private routes have no published specification.

### Limits of the 2026-11-10 run

- **33 write tools are not proven live; their request bodies are unproven.** The test harness needs a dry-run preview server to approve a request body before it sends the first write, none answered in this run, and so no request was sent for: `apply_test_config`, `batch_delete_acl_rules`, `batch_delete_firewall_policies`, `batch_delete_firewall_zones`, `create_bgp_config`, `create_content_filter`, `create_energy_saving_policy`, `create_nat_rule`, `create_ospf_router`, `create_policy_engine_rule`, `create_qos_rule`, `create_ssl_inspection_profile`, `create_test_config`, `delete_bgp_config`, `delete_content_filter`, `delete_energy_saving_policy`, `delete_nat_rule`, `delete_ospf_router`, `delete_policy_engine_rule`, `delete_qos_rule`, `delete_ssl_inspection_profile`, `delete_test_config`, `preview_policy_engine_rule`, `reorder_qos_rules`, `set_client_fingerprint_override`, `update_bgp_config`, `update_content_filter`, `update_energy_saving_policy`, `update_nat_rule`, `update_ospf_router`, `update_policy_engine_rule`, `update_qos_rule`, `update_ssl_inspection_profile`.
- **Unverified:** `acknowledge_critical_alert`, whose route no console has been shown to serve, and `execute_device_action`, `execute_port_action` and `mark_critical_logs_read`, which were excluded from the run. None of the four has a live result.
- **`get_multicast_insights` is unsupported on Network 11.1.47.** The console does not serve the route: it answers with its HTML 404 page for `insights/multicast/clients`.
- **`export_traffic_flows`:** the console timed out (HTTP 408) on a one-hour export, at the cloud connector's 25-second limit. This is an upstream limit, not a tool failure.
- **`recover_switch_port`:** the documented rejection is confirmed. A port that is merely down answers HTTP 400 `api.err.InvalidTargetPort` and nothing changes, as the tool description says. The positive path is unproven, because the test console has no port blocked by loop detection or BPDU guard.
- **`set_camera_video_codec`:** the write that re-sent the camera's current codec got an HTTP 408 from the connector, which gives up after 25 seconds while Protect holds the request open during the camera's codec switch. The console applied the switch a few seconds after the timeout and the camera's final state matched its original. The run record keeps the tool as not proven (the switch did not settle inside the check window), so it is not in the passed count. The tool does not retry a write after a 408.
- **`update_digital_twin_layout` passed with a console behavior to know:** the write was accepted, and the console dropped a layout element that referenced a device no longer on the site. The dropped element could not be restored through the API.
- **`create_recognition_object_group` is not proven live.** The objects group list answered HTTP 400, so there was no group to borrow or create against; no objects write was sent.

209 write and action tools accept an optional `confirm` argument for compatibility. It is accepted and ignored; it does not authorize a write. Set approval permissions in the MCP client.

## Compatibility

The 2026-11-10 live run used Network 11.1.47 (an early-access build) and Protect 7.3.74 on a UniFi Dream Machine Pro Max running UniFi OS 6.0.17, as a single console with a single site. The server does not enforce a minimum application version. Compatibility depends on the controller, application version, enabled features and hardware; see [developer.ui.com](https://developer.ui.com) and [LAST_AUDITED.md](../LAST_AUDITED.md).

## Tested against

The live acceptance report distinguishes passing, failed, infrastructure, configuration and untested results. Untested paths include unavailable equipment or applications, missing inputs and deliberately excluded disruptive or irreversible actions. A passing result applies to the tested build and environment.

## Coverage and limitations

**Tool coverage:** The 2026-11-10 acceptance run recorded 402 passes on build `8a86a795f635`, 170 of them on write tools. Other paths were not established as passing by that run. Tool code paths are also exercised by hermetic tests in CI. Writes are on by default; `UNIFI_WRITE_POLICY=deny` or a `deny` entry of `UNIFI_WRITE_EXCEPTIONS` refuses them (see [CONFIGURATION.md](CONFIGURATION.md)). Verify a specific write against a non-production console before deploying it.

**Read-only tools with no data:** Several read-only tools were called and returned empty results because the corresponding hardware or feature was not present in the test environment. This reflects a gap in the test environment, not a code defect. Readers with the following equipment should expect these tools to work:

- **Switching:** LAGs, switch stacks, and MC-LAG domains
- **Network services:** DNS policies, traffic routes, traffic rules, and traffic matching lists
- **Identity and access:** dynamic DNS, RADIUS profiles
- **Hotspot:** vouchers and billing packages
- **VPN:** site-to-site tunnels
- **Protect extras:** UniFi lights, chimes, viewers, and configured liveviews
- **Protect alarm/arm & accessories (published Protect Integration API):** arm profiles (with active-profile selection and arm/disarm enable/disable), sirens, fobs, relays, speakers, bridges, link stations, alarm hubs, and Protect users — all reached through UniFi Fabric only (`…/proxy/protect/integration/v1/*`). Availability is firmware/application-version dependent (an unsupported family answers with an upstream 404/501, passed through). Write and physical-action tools honor the `UNIFI_WRITE_EXCEPTIONS` entry `family:protect=deny` (writes on by default); siren play/stop/test, speaker test, relay and alarm-hub output actions, arm enable/disable, and `delete_arm_profile` accept a `confirm` argument and ignore it, POS ingestion carries an `externalId` idempotency key and is never auto-retried, and settings writes read-before, skip on no-op, and read-after to verify. Also added: Protect application metadata (`get_protect_application_info` → `/v1/meta/info`) and the ULP (UniFi account) user directory (`list_ulp_users`/`get_ulp_user` → `/v1/ulp-users`), distinct from Protect users. For live-ish event and device-change data, the bounded-window REST-poll collectors `collect_protect_events` and `collect_protect_device_changes` stand in for the Protect WebSocket subscriptions (`/v1/subscribe/devices`, `/v1/subscribe/events`), which are not reachable over the Fabric cloud connector (verified: an upgrade GET returns 404, never 101) — see "Future and unsupported tools" below. `get_protect_alarm_manager_mode` reports whether a console's Alarm Manager runs in local or global mode; in global mode the Integration arm-profile routes are documented as local-only and the console answered the reads with HTTP 400 (see [Protect global Alarm Manager](#protect-global-alarm-manager) below).
- **InnerSpace:** the application is installed and running on this console with an active floor-plan project. All eight Integration-API InnerSpace read tools were live-verified 2026-08-09 against the documented Integration API (`…/proxy/innerspace/integration/v1/*`) and returned real project geometry — placed devices, shaped floor plans, and plan assets all round-trip correctly. (An earlier probe during the same session returned HTTP 403 for the `innerspace` connector namespace; in that session the documented `/proxy/innerspace/integration/v1/*` path answered instead. The internal `/proxy/innerspace/api/*` routes still serve the five internal-route reads and every InnerSpace write; see the InnerSpace section of the [README](../README.md).)
- **Access:** Access is not available through the UniFi Fabric/cloud connector API and has no published spec, so this release has no Access tools; tracked as a future tool.

**Door locks:** `list_door_locks` and `set_door_lock_state` ship with hermetic coverage only. They use the Protect 7.x door-lock routes, `GET /locks` and `POST /locks/{id}/unlock`, which are proven against the Protect 7.x route table but not run against a console: the estate has no door lock. Consoles older than Protect 7.x do not serve these routes.

**Protect database restore:** `restore_protect_database` ships with hermetic coverage only. Its Protect 7.x route, `POST protect/api/nvr/restore-database-backup` with no body, is proven against the Protect 7.x route table and in hermetic tests (route, method, no body, the HTTP 400 passed through unchanged) but not run against a console: it replaces the live Protect database and restarts Protect, so live acceptance excludes it.

**Door lock reads:** `get_door_lock` and `list_door_lock_unlock_events` ship with hermetic coverage only (simulated-only). They use the Protect 7.x door-lock routes, `GET /locks/{id}` and `GET /locks/{id}/unlock/events`, which are proven against the Protect 7.3.74 route table (the unlock-events route takes only `limit` 1 to 100 and `offset` 0 to 10000) but not run against a console: the estate has no door lock. Consoles older than Protect 7.x do not serve these routes.

**Added tools with no recorded live fixture:** `get_site_dpi_usage`, `get_client_dpi_usage`, `get_client_wifi_experience`, `suggest_service_port`, `get_switch_port_overrides`, `update_switch_port_overrides`, `collect_network_incident_evidence`, `collect_protect_incident_evidence`, `get_server_diagnostic_bundle` and `acknowledge_critical_alert` ship with hermetic coverage only (simulated-only): their requests and answers are checked against simulated upstream replies and the published route and schema sources, and no recorded console answer is stored for them. `acknowledge_critical_alert` also sends a route that has not been run against a console.

**Write tools tested only against a simulated upstream, by what the console offers:** these tools are registered and exercised in CI against a simulated upstream. A live run on Network 11.0.97 cannot prove them end to end, and none is removed for that.

- **`cancel_controller_backup`, `delete_controller_backup`:** they act on a stored backup. No tool in this server creates one that returns a `backup_id` (the Network web UI's stored backup uses a different command), so a live run has no backup of its own to cancel or delete. Simulated only.
- **`export_site`:** its request matches the Network web UI's request (checked against the 11.0.81 web app, not against 11.0.97). The tested console answered HTTP 400 `api.err.BackupFailed` in both earlier releases' live runs; the cause was not established, so a site export is unproven on it. Simulated only.
- **`create_wifi_broadcast`, `update_wifi_broadcast`, `delete_wifi_broadcast`:** the tested access point refused a create with HTTP 400 `too-many-wifi-broadcasts` at its SSID limit for the tested band, even for a disabled SSID. A create with a free slot has not been attempted. Simulated only.

**`create_backup` is not in that list.** It writes one transient `/dl/backup/*.unf` export and answers its download path, as observed live on Network 11.0.97. It adds no stored backup, so `list_backups` never shows it. The live check is the returned path; the file's contents are never downloaded.

**Deployment matrix:** stdio, streamable-http, and SSE transports were verified end-to-end. Bearer-token auth on both plain HTTP and HTTPS was verified. mTLS was verified as the live production transport for the canonical deployment.

**OAuth:** End-to-end OAuth flow requires a running external identity provider and could not be exercised in this environment. The fail-closed startup behavior — the server refuses to start when required OAuth parameters are missing — is covered by unit tests in CI. See [docs/AUTH-OAUTH.md](AUTH-OAUTH.md) for deployment guidance.

**Multi-key MSP:** The single-key path (`UNIFI_API_KEY`) was fully exercised live. Per-host tools (any tool that accepts a `host` parameter) resolve the API key that owns the target console and route the request on that key, so a console owned by any configured key — not only the first — is reachable; this ownership routing is covered by unit tests. The multi-key tools (`list_hosts`, `list_sites`, `list_all_devices`, `list_all_clients`, `get_fleet_summary`, `search_device_fleet`, `list_devices` without `host`, `list_mobility_workspaces`, `list_carrier_subscribers`, `list_carrier_service_plans` and `list_sdwan_configs`) iterate all keys unless a `key_label` argument names one, and `list_all_sites_aggregated` and `search_across_sites`, which take no `key_label`, always iterate all keys; this fan-out, the per-key `errors` and the shared-console de-duplication are covered by unit tests. See [Multi-key MSP setup](CONFIGURATION.md#multi-key-msp-setup).

## Future and unsupported tools

This section documents API surfaces that are deliberately absent from the current tool set, and why.

### Network single-site gateways and unavailable Classic routes

`create_site` and `delete_site` ship with hermetic/spec-conformance coverage only:
the maintainer's console is a single-site UniFi OS gateway. It rejects `add-site`
with `api.err.NotImplemented`, and its sole site cannot be deleted. Successful
live acceptance requires a console that supports multiple Network sites, such as
UniFi OS Server or a Cloud Key. `rename_site` passed a live no-op rename.

Alarms listing/archiving and controller-admin listing are unavailable through the
tested Network 11.0.81 cloud connector routes, so no typed tools are offered for
those operations. Alarm collection routes return 400/404; the archive command
returns 404; admin discovery returns empty data, 400/404, or a users-proxy 403.
Network alerts and events are available through `get_system_log`,
`list_network_events` and `list_ips_events`.

### Network traffic rules (legacy)

`list_traffic_rules` is legacy. It reads traffic rules carried over from earlier Network
versions on the v2 `trafficrules` route; the Network 11.0.99 web app no longer shows them.
It answered HTTP 200 on a Network 11.0.97 console. On 2026-11-08 that console answered
HTTP 501 `api.err.NotImplemented` to every traffic-rule write: a POST, and a PUT and a DELETE
on a nonexistent rule id (nothing was changed). The write tools `create_traffic_rule`,
`update_traffic_rule` and `delete_traffic_rule` are therefore removed; build new rules with
`create_firewall_policy`, `create_qos_rule` or `create_traffic_route`.
Upgrading from 0.7.1: see the [migration guide](MIGRATING-0.7.2.md#network-traffic-rule-changes).

### Access

No Access tools are included in this release. UniFi Access is not part of the UniFi Fabric (cloud connector) API this server uses: every `/proxy/access/*` path through the connector returns 403, and the Fabric API documentation lists no Access section. Ubiquiti does publish a separate local Access API, served by the console on the local network and authenticated with its own Access API token. That API sits outside this server's cloud-only design, which has no local network access, so it is not offered. This changes if Ubiquiti exposes Access through the Fabric API.

### Protect global Alarm Manager

When a console runs the UniFi OS global Alarm Manager (adopting UniFi sensors, fobs,
relays or an alarm hub can turn it on), the Protect Integration
API documents the arm-profile routes (`list_arm_profiles`, `enable_arm`, `disable_arm` and
the rest) as available only with the local Alarm Manager. The console was observed
answering the arm-profile reads with HTTP 400 "This operation is not available when global
alarm manager is enabled". The write and arm/disarm routes were not exercised in global mode,
so what they answer is not known, and a `sent` result from `enable_arm` or `disable_arm` is
not proof of the arm state: read `body.armMode` from `get_protect_alarm_manager_mode`. The
global Alarm Manager's own API (`/api/v2/alarms`: alarm rules, alarm profiles and
profile arm/disarm actions) is served at the console root, outside the
`/proxy/<application>/` paths the Fabric connector relays. The connector answers it
with HTTP 403 `forbidden` ("insufficient permissions for this endpoint"), the same
answer it gives any unknown console-root path, while unknown paths under
`/proxy/protect/` reach the console and get its own 404. So this server offers no
global alarm rule, profile or arm/disarm tools. `get_protect_alarm_manager_mode`
returns the NVR object unchanged plus an additive `_alarmManager` summary: the mode
(from the console's `featureFlags.useExternalAlarmManager`; null with a reason when the read
fails) and which alarm operations are available; the arm-profile tools append the same guidance to the
console's 400. Manage global alarms in the UniFi Protect app. Evidence recorded
2026-11-08 with read-only requests on a global-mode console running Protect 7.3.70.

Local-mode detection is simulated. `get_protect_alarm_manager_mode` reporting `local`, and
the arm-profile tools working on such a console, are exercised only against simulated
upstream responses, because no console running the local Alarm Manager has been available
for a live check. This needs live testing on a Protect console in local mode; the global-mode
behaviour above was read live.

### Live event streams (Network and Protect)

Network and Protect publish live events only over WebSocket, and this server reaches consoles only through the Fabric cloud connector, which forwards requests with plain HTTP methods and does not carry the WebSocket upgrade. Compatibility is recorded per product, and neither stream is offered:

| Product | Stream | Checked through the connector (read-only, 2026-11-08; UniFi OS 6.0.130, Network Integration API v11.0.97, Protect 7.3.74) | Status |
| --- | --- | --- | --- |
| Network | Network application event socket `wss/s/{site}/events` | WebSocket handshake answered HTTP 404 (the Network application's not-found page); the console system socket `api/ws/system` answered 403. The published Network Integration API defines no event stream. | Not supported |
| Protect | Integration API `GET /v1/subscribe/events` and `GET /v1/subscribe/devices` | Both answered HTTP 404 `Entity 'endpoint' not found`; the private update socket `ws/updates` answered a 302 redirect to the login page. | Not supported |

A WebSocket handshake to a plain REST route (`protect/integration/v1/meta/info`) answered 200 with the REST body, so the connector drops the upgrade rather than refusing these paths. No direct local-network transport is assumed.

`get_event_stream_status` reports this compatibility, the evidence and the state of every listener, and `read_recent_events` reads one console's (and Network site's) recent-event buffer. Both read the server's own state; `read_recent_events` first resolves its console (and Network site), so an unknown one fails with the valid choices. For an unsupported product they open no stream, report state `unsupported` with no `events` list and name the history and polling tools. For Network, those are `list_network_events`, `get_system_log` and `list_ips_events`; for Protect, `list_protect_events`, `collect_protect_events` and `collect_protect_device_changes`. On a product whose stream is supported, the buffer holds 1,000 events per console and site, evicts the oldest first, keeps nothing by age, and reports evicted events (`missed`) and disconnected periods (`gaps`). Reading a buffer never subscribes the MCP client to notifications; the server sends no MCP push notifications for events.

### Protect persistent WebSocket subscription

The Protect Integration API documents two WebSocket subscription endpoints: `GET /v1/subscribe/devices` and `GET /v1/subscribe/events`. A *persistent* subscription to either is not available through this server because it is not reachable over the Fabric cloud connector — the connector is a unary request/response relay. Verified live (read-only canary): a GET carrying the WebSocket upgrade headers through `…/proxy/protect/integration/v1/subscribe/events` returns an upstream HTTP 404 (`Entity 'endpoint' not found`), never a `101 Switching Protocols`. A true persistent stream needs local console (`wss://`) access, which this cloud-only server does not have. For live-ish data without a persistent socket, use the bounded-window REST-poll collectors `collect_protect_events` and `collect_protect_device_changes` (see the Protect tools above), which return the same event and device-change data assembled over a polling window.
