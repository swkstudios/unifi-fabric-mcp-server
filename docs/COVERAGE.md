# Compatibility, testing and coverage

What the server was verified against, what has and has not been run on live hardware, and the known limits. The live-sweep figures in the Compatibility and Tested against sections are refreshed after each release's live sweep and say which sweep they come from.

## Live evidence (historical: build `b5c901fd0277`, 2026-11-14)

<!-- live-evidence: passed=442 writes=205 total=815 build=b5c901fd0277 date=2026-11-14 -->
The live figures below are historical: recorded on build `b5c901fd0277` on 2026-11-14 and not re-measured at the current head.

Every registered tool runs in CI against a simulated upstream. The completed 2026-11-14 live acceptance record on build `b5c901fd0277` records 442 unique passing tools against the console out of 815 registered tools, including 205 passing write tools and 237 passing read tools. Each tool is counted once. These are the accepted final PASS dispositions, after review; empty, partial, skipped, unsupported, expected-refusal, hermetic-only and not-probed results are not counted as passes. Cleanup completed with no outstanding ledger entries and a complete synthetic scan and estate comparison.

Following removal of the stored-backup tool, this release's 814 tools differ from the tested build. The live record belongs to the tested 815-tool build; it is not a claim that every tool passed at the current head. The test console was a single UniFi Dream Machine Pro Max with Network 11.1.47 (early access) and Protect 7.3.74, with one site. It was not a multi-site or multi-organization estate.

The run retained partial or skipped results for unavailable inputs and unsupported console features, including external arm-profile routes requiring Protect 7.4.96. The stored-backup rows were excluded. Passing the acceptance gate does not turn those dispositions into live coverage. Private routes have no published specification; published routes are checked against pinned specifications in [LAST_AUDITED.md](../LAST_AUDITED.md).

### Known limits of the latest live run

- **Network references:** Network 11.0.81–11.1.47 returns HTTP 500 when reading network references for some networks, including Default. Other networks answer normally.
- **Multicast insights:** Network 11.1.47 returns HTTP 404 for the clients view of multicast insights.
- **External alarm-manager arm profiles:** these routes require Protect 7.4.96 or later. Protect 7.3.74 returns HTTP 404.
- **Stored backups:** stored-backup creation is withheld from this release until the console's stored-backup listing can be verified.

The following limitations describe the earlier 2026-11-10 run and are retained as history; they do not override the 2026-11-14 pass figures above.

### Limits of the 2026-11-10 run

- **33 write tools are not proven live; their request bodies are unproven.** The test harness needs a dry-run preview server to approve a request body before it sends the first write, none answered in this run, and so no request was sent for: `apply_test_config`, `batch_delete_acl_rules`, `batch_delete_firewall_policies`, `batch_delete_firewall_zones`, `create_bgp_config`, `create_content_filter`, `create_energy_saving_policy`, `create_nat_rule`, `create_ospf_router`, `create_policy_engine_rule`, `create_qos_rule`, `create_ssl_inspection_profile`, `create_test_config`, `delete_bgp_config`, `delete_content_filter`, `delete_energy_saving_policy`, `delete_nat_rule`, `delete_ospf_router`, `delete_policy_engine_rule`, `delete_qos_rule`, `delete_ssl_inspection_profile`, `delete_test_config`, `preview_policy_engine_rule`, `reorder_qos_rules`, `set_client_fingerprint_override`, `update_bgp_config`, `update_content_filter`, `update_energy_saving_policy`, `update_nat_rule`, `update_ospf_router`, `update_policy_engine_rule`, `update_qos_rule`, `update_ssl_inspection_profile`.
- **Unverified:** `acknowledge_critical_alert`, whose route is bound to PUT in Ubiquiti's Network 11.0.99 server code but which no console has been shown to answer, and `execute_device_action`, `execute_port_action` and `mark_critical_logs_read`, which were excluded from the run. None of the four has a live result.
- **`get_multicast_insights` is unsupported on Network 11.1.47.** The console does not serve the route: it answers with its HTML 404 page for `insights/multicast/clients`.
- **`export_traffic_flows`:** the console timed out (HTTP 408) on a one-hour export, at the cloud connector's 25-second limit. This is an upstream limit, not a tool failure.
- **`recover_switch_port`:** the documented rejection is confirmed. A port that is merely down answers HTTP 400 `api.err.InvalidTargetPort` and nothing changes, as the tool description says. The positive path is unproven, because the test console has no port blocked by loop detection or BPDU guard.
- **`set_camera_video_codec`:** the write that re-sent the camera's current codec got an HTTP 408 from the connector, which gives up after 25 seconds while Protect holds the request open during the camera's codec switch. The console applied the switch a few seconds after the timeout and the camera's final state matched its original. The run record keeps the tool as not proven (the switch did not settle inside the check window), so it is not in the passed count. The tool does not retry a write after a 408.
- **`update_digital_twin_layout` passed with a console behavior to know:** the write was accepted, and the console dropped a layout element that referenced a device no longer on the site. The dropped element could not be restored through the API.
- **`create_recognition_object_group` is not proven live.** The objects group list answered HTTP 400, so there was no group to borrow or create against; no objects write was sent.

209 write and action tools accept an optional `confirm` argument for compatibility. It is accepted and ignored; it does not authorize a write. Set approval permissions in the MCP client.

## Compatibility

The 2026-11-10 live run used Network 11.1.47 (an early-access build) and Protect 7.3.74 on a UniFi Dream Machine Pro Max running UniFi OS 6.0.17, as a single console with a single site. UniFi OS 6.0.17, a release candidate, bundles Network 10.6.109; the pinned Network spec is 11.0.97, so fields and routes newer than 10.6.109 can answer 404 on a console that has not updated its Network application. Network 11.1.47 fixes an upstream stall of up to 40 seconds in Integration API requests; a rare stall seen on an older build is that upstream bug, not a hang in this server. The server does not enforce a minimum application version. Compatibility depends on the controller, application version, enabled features and hardware; see [developer.ui.com](https://developer.ui.com) and [LAST_AUDITED.md](../LAST_AUDITED.md).

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
- **Wi-Fi diagnosis:** `diagnose_wifi` is read-only. CI runs it against fixtures built from Wi-Fi reads recorded on the dev console (identifiers replaced); its own run against live hardware follows its deployment to the dev instance, so treat its findings as advice until that run is recorded.
- **Access:** Access is not available through the UniFi Fabric/cloud connector API and has no published spec, so this release has no Access tools; tracked as a future tool.

**Door locks:** `list_door_locks` and `set_door_lock_state` ship with hermetic coverage only. They use the Protect 7.x door-lock routes, `GET /locks` and `POST /locks/{id}/unlock`, which are proven against the Protect 7.x route table but not run against a console: the estate has no door lock. Consoles older than Protect 7.x do not serve these routes.

**Protect database restore:** `restore_protect_database` ships with hermetic coverage only. Its Protect 7.x route, `POST protect/api/nvr/restore-database-backup` with no body, is proven against the Protect 7.x route table and in hermetic tests (route, method, no body, the HTTP 400 passed through unchanged) but not run against a console: it replaces the live Protect database and restarts Protect, so live acceptance excludes it.

**Door lock reads:** `get_door_lock` and `list_door_lock_unlock_events` ship with hermetic coverage only (simulated-only). They use the Protect 7.x door-lock routes, `GET /locks/{id}` and `GET /locks/{id}/unlock/events`, which are proven against the Protect 7.3.74 route table (the unlock-events route takes only `limit` 1 to 100 and `offset` 0 to 10000) but not run against a console: the estate has no door lock. Consoles older than Protect 7.x do not serve these routes.

**Added tools with no recorded live fixture:** `get_hotspot_guest_webhook_delivery`, `list_port_automations` (read live on 11.1.47 as an empty list), `get_port_automation`, `create_port_automation`, `update_port_automation`, `delete_port_automation`, `wake_client` (all simulated only: none of the writes was run live), `get_site_dpi_usage`, `get_client_dpi_usage`, `get_client_wifi_experience`, `get_switch_port_overrides`, `update_switch_port_overrides`, `collect_network_incident_evidence`, `collect_protect_incident_evidence`, `get_server_diagnostic_bundle` and `acknowledge_critical_alert` ship with hermetic coverage only (simulated-only): their requests and answers are checked against simulated upstream replies and the published route and schema sources, and no recorded console answer is stored for them. `acknowledge_critical_alert` also sends a route that has not been run against a console.

**Write tools tested only against a simulated upstream, by what the console offers:** these tools are registered and exercised in CI against a simulated upstream. A live run on Network 11.0.97 cannot prove them end to end, and none is removed for that.

- **`cancel_controller_backup`, `delete_controller_backup`:** no producer; SKIPPED-NO-INPUT. They require a stored backup or backup_id; create_backup produces only a transient file. Simulated only.
- **`list_backups`:** on the development console running UniFi OS 6.0.130 and Network 11.1.47 (beta channel), with autobackups enabled (weekly, maximum 5), returned `[]` when checked on 2026-11-13.
- **`export_site`:** its request matches the Network web UI's request (checked against the 11.0.81 web app, not against 11.0.97). The tested console answered HTTP 400 `api.err.BackupFailed` in both earlier releases' live runs; the cause was not established, so a site export is unproven on it. Simulated only.
- **`create_wifi_broadcast`, `update_wifi_broadcast`, `delete_wifi_broadcast`:** the tested access point refused a create with HTTP 400 `too-many-wifi-broadcasts` at its SSID limit for the tested band, even for a disabled SSID. The refusal is Ubiquiti's own capacity check: the Network 11.0.99 server counts the WLANs of the access point's groups on the target band, the new one included, and refuses above 3 (an AP with limited WiFi resources), 4 (a wireless uplink), 7 (element adoption) or otherwise 8, so a valid body is refused when its APs are full on that band. A create with a free slot has not been attempted. Simulated only.
- **`list_external_arm_profiles`, `get_external_arm_profile`, `create_external_arm_profile`, `update_external_arm_profile`, `delete_external_arm_profile`, `arm_external_arm_profile`, `disarm_external_arm_profile`, `stop_speaker_siren`:** Protect 7.4.96 tools. The development console runs Protect 7.3.74 and answered HTTP 404 for these routes on 2026-11-11, and the external arm-profile tools also need a console in global Alarm Manager mode. Simulated only.

**`list_external_arm_profiles` live result:** on the development console at 2026-11-13T19:01Z, Protect 7.3.74 returned HTTP 404 `{"error":"Entity 'endpoint' not found","name":"NOT_FOUND"}` from `GET /proxy/protect/integration/v1/external/arm-profiles`, even with `featureFlags.useExternalAlarmManager` and `featureFlags.externalAlarmManagerReady` both true. These routes first appear in the Protect 7.4.96 spec and require that version or later as well as the external alarm manager.

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

### UniFi OS backups (not reachable)

Status of the names below: **unverified**. Ubiquiti's UniFi OS 6.0.17 release notes (RC,
2026-11-05) say the release adds configurable backup schedules, multiple backup destinations and
local backup management, which is the only published source. The route and field names in the
next paragraph were reported during follow-up research on the backup feature; the capture or firmware file they
came from was not recorded, nothing in this repository holds it, and no request to any of them
can be made through this server to confirm them.

UniFi OS 6.0.17 is reported to serve its own backups from `unifi-core` at
`/api/backup/local/list`, `/api/backup/now`, `/api/backup/local/{id}`,
`/api/cloud/backup/settings/list` and related routes, with the schedule and destination settings
(`autoBackupEnabled`, `backupSchedule` with `frequency`, `dayOfWeek`, `dayOfMonth`, `hour`,
`localRetention`) in the console system object. The Fabric connector forwards only to
`http://127.0.0.1/proxy/[path]` (Site Manager API), so a console-root `/api` route is out of
reach: on 2026-11-11 a read of the existing backup route, of `api/system` and of a route that
does not exist all answered the same HTTP 403 `insufficient permissions for this endpoint`. That
result holds whether or not the names above are right. The Network application's web app has
no OS backup route either. No tool is possible for these routes through this server (blocked by
the connector), and the Network application's own backup tools are unaffected.

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

### UniFi OS console reboot

`reboot_unifi_os_console` does not reboot a console through this server. UniFi OS reboots a
console at the console root, `POST /api/system/reboot` (UniFi OS 6.0.17), which the Fabric
connector does not relay: it relays `/proxy/<application>/` paths only and answers console-root
paths with HTTP 403. The tool posts to `/proxy/network/api/system/reboot`, which reaches the
Network application, and Network 11.0.99 has no console reboot route, so the application refuses
the call and no console is rebooted. The tool has never been run against a console, because it
is a write; the finding rests on Ubiquiti's own code, and a read-only request to the neighbouring
`/proxy/network/api/system` path answered the Network application's HTTP 401
`api.err.NoSiteContext`. Reboot a console from its UniFi OS interface.

### Protect global Alarm Manager

When a console runs the UniFi OS global Alarm Manager (adopting UniFi sensors, fobs,
relays or an alarm hub can turn it on), the Protect Integration
API documents the arm-profile routes (`list_arm_profiles`, `enable_arm`, `disable_arm` and
the rest) as available only with the local Alarm Manager. The console was observed
answering the arm-profile reads with HTTP 400 "This operation is not available when global
alarm manager is enabled". The write and arm/disarm routes were not exercised in global mode,
so what they answer is not known. A `sent` result from `enable_arm` or `disable_arm` is not
proof of the arm state on its own (the route answers an empty 204), so both read the NVR's
`armMode` back and report `verified`: true when `armMode.status` is `arming`, `armed` or
`breach` after an enable, or `disabled` after a disable; false for any other status (read the
NVR again, since the console may not have applied it yet); null with `readAfterError` when the
read-back itself failed. `get_protect_alarm_manager_mode` returns the same `body.armMode`. The
global Alarm Manager's own API (`/api/v2/alarms`: alarm rules, alarm profiles and
profile arm/disarm actions) is served at the console root, outside the
`/proxy/<application>/` paths the Fabric connector relays. The connector answers it
with HTTP 403 `forbidden` ("insufficient permissions for this endpoint"), the same
answer it gives any unknown console-root path, while unknown paths under
`/proxy/protect/` reach the console and get its own 404. So this server offers no
global alarm rule tools. The arm profiles of the external Alarm Manager are a
separate API that Protect 7.4.96 publishes under `/proxy/protect/integration/v1/external/arm-profiles`
(its `nvrArmMode` description: when `featureFlags.useExternalAlarmManager` is true, read the
external profile state there); `list_external_arm_profiles`, `get_external_arm_profile`,
`create_external_arm_profile`, `update_external_arm_profile`, `delete_external_arm_profile`,
`arm_external_arm_profile` and `disarm_external_arm_profile` cover them on a console running
Protect 7.4.96 or later. `get_protect_alarm_manager_mode`
returns the NVR object unchanged plus an additive `_alarmManager` summary: the mode
(from the console's `featureFlags.useExternalAlarmManager`; null with a reason when the read
fails), which alarm operations are available and the external arm-profile tools; the
arm-profile tools append the same guidance to the console's 400. Manage global alarm rules in
the UniFi Protect app. Evidence recorded
2026-11-08 with read-only requests on a global-mode console running Protect 7.3.70.

This compatibility gate is kept, not lifted: no `/api/v2/alarms` tool is
offered, and nothing here claims support. It would re-open only if the gateway began to relay
console-root paths, so a read-only canary watches it: `tf alarm-gateway` sends three GETs
through the connector and fails if `/api/v2/alarms/profiles` stops answering the gateway's own
403, if an invented console-root path stops answering the same 403, or if
`/proxy/protect/api/v2/alarms/profiles` stops answering the console's own 404. A server that
talked to the console directly (on the local network, with a local SuperAdmin session) could
reach the v2 API, but that is a different transport and credential model from this cloud-only
server; that stays a pending transport and credential decision, as it does for the local Access API
above, and is not offered.

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

### UniFi OS per-application memory

No tool reports per-application memory (UniFi OS memory by application, such as Network or
Protect), and none can be built on this server. UniFi OS serves the figures on its own console
`/api` router, as the `SYSTEM_STATS` object (per slice and per service `memoryMB`,
`memoryLimitMB`, `memoryUtilization`, `rssMB` and `oomKillCount`): over the WebSocket
`api/ws/systemStats` and, in UniFi OS 6.0.17, also over HTTP at `GET /api/system/stats`, next to
`GET /api/system`. UniFi OS 5.1.35, the earlier evidence, showed only the WebSocket. This
server is cloud-only: every request goes to `/v1/connector/consoles/{id}/…`, and the Fabric
connector relays plain HTTP to `/proxy/<application>/` paths only, so the console root is out
of reach. The Site Manager v1.0.0 OpenAPI says the same for each method of
`/v1/connector/consoles/{id}/*path`: "The request is proxied through `api.ui.com` cloud
endpoint to the remote console at `http://127.0.0.1/proxy/[path]`." Read-only requests on
2026-11-11 to a console running UniFi OS 6.0.x answered HTTP 403 `forbidden`
("insufficient permissions for this endpoint") for `/api/system/stats` and for
`/proxy/<name>/api/system/stats` with `<name>` one of `users`, `core`, `unifi-core`, `ucore`,
`system` and `ucs`. The path `/proxy/network/api/system/…` is not UniFi OS: it is the Network
application's namespace, which answered `/proxy/network/api/system/stats` and
`/proxy/network/api/system` with HTTP 401 `api.err.NoSiteContext` (Protect answered 404). No
published API carries the figures. Evidence: UniFi OS 6.0.17 `usr/share/unifi-core/app/service.js`
registers `GET /system/stats` on the router mounted at `/api`, with a handler that returns the
object the WebSocket sends. This changes if the connector relays console-root `/api` routes,
Ubiquiti publishes the figures in an official API, or this server gains a local-console
transport.

### Protect persistent WebSocket subscription

The Protect Integration API documents three WebSocket subscription endpoints: `GET /v1/subscribe/devices`, `GET /v1/subscribe/events` and, from Protect 7.4.96, `GET /v1/subscribe/updates` (changes to models chosen by `modelKeys`, including the new `externalArmProfile`). A *persistent* subscription to any of them is not available through this server because it is not reachable over the Fabric cloud connector — the connector is a unary request/response relay. Verified live (read-only canary): a GET carrying the WebSocket upgrade headers through `…/proxy/protect/integration/v1/subscribe/events` returns an upstream HTTP 404 (`Entity 'endpoint' not found`), never a `101 Switching Protocols`. The development console runs Protect 7.3.74 and answered HTTP 404 to a plain GET of `subscribe/updates` on 2026-11-11, as it does for the 7.4.96 `external/arm-profiles` routes, so the 7.4.96 tools listed in the changelog need a live check once a console runs Protect 7.4.96 or later. A true persistent stream needs local console (`wss://`) access, which this cloud-only server does not have. For live-ish data without a persistent socket, use the bounded-window REST-poll collectors `collect_protect_events` and `collect_protect_device_changes` (see the Protect tools above), which return the same event and device-change data assembled over a polling window.
