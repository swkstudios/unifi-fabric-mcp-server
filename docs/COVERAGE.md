# Compatibility, testing and coverage

What the server was verified against, what has and has not been run on live hardware, and the known limits. The live-sweep figures in the Compatibility and Tested against sections are refreshed after each release's live sweep and say which sweep they come from.

## What is verified at this release's head

<!-- live-evidence: passed=380 writes=114 total=786 build=cde04b5c1520 date=2026-10-28 -->
Every registered tool runs in CI against a simulated upstream. The 2026-10-28 live acceptance run on build `cde04b5c1520` recorded 380 passing tools against the console, plus one passing server-local tool, of this release's 786 tools. The console passes included 114 write tools. It also recorded 22 failures, one infrastructure result, five configuration findings and 377 untested tools. The single-console run used a UniFi Dream Machine Pro with Network 11.0.89 and Protect 7.3.70. It was not a multi-site or multi-organization estate.

Later focused tests exercised corrections on different builds, including selected Network and Protect writes. They do not represent a new complete live sweep, and the original aggregate does not imply that every tool passed on the current head. CI uses shape-faithful fake upstreams; published API routes are checked against pinned specifications in [LAST_AUDITED.md](../LAST_AUDITED.md). Private routes have no published specification.

210 write and action tools accept an optional `confirm` argument for compatibility. It is accepted and ignored; it does not authorize a write. Set approval permissions in the MCP client.

## Compatibility

The 2026-10-28 live run used Network 11.0.89 and Protect 7.3.70 on a UniFi Dream Machine Pro. The server does not enforce a minimum application version. Compatibility depends on the controller, application version, enabled features and hardware; see [developer.ui.com](https://developer.ui.com) and [LAST_AUDITED.md](../LAST_AUDITED.md).

## Tested against

The live acceptance report distinguishes passing, failed, infrastructure, configuration and untested results. Untested paths include unavailable equipment or applications, missing inputs and deliberately excluded disruptive or irreversible actions. A passing result applies to the tested build and environment.

## Coverage and limitations

**Tool coverage:** The 2026-10-28 acceptance run passed 267 read and 114 write tools on build `cde04b5c1520`. Other paths were not established as passing by that run. Tool code paths are also exercised by hermetic tests in CI. Writes are on by default; `UNIFI_READ_ONLY=1` or a per-area write opt-out refuses them (see [CONFIGURATION.md](CONFIGURATION.md)). Verify a specific write against a non-production console before deploying it.

**Read-only tools with no data:** Several read-only tools were called and returned empty results because the corresponding hardware or feature was not present in the test environment. This reflects a gap in the test environment, not a code defect. Readers with the following equipment should expect these tools to work:

- **Switching:** LAGs, switch stacks, and MC-LAG domains
- **Network services:** DNS policies, traffic routes, traffic rules, and traffic matching lists
- **Identity and access:** dynamic DNS, RADIUS profiles
- **Hotspot:** vouchers and billing packages
- **VPN:** site-to-site tunnels
- **Protect extras:** UniFi lights, chimes, viewers, and configured liveviews
- **Protect alarm/arm & accessories (published Protect Integration API):** arm profiles (with active-profile selection and arm/disarm enable/disable), sirens, fobs, relays, speakers, bridges, link stations, alarm hubs, and Protect users — all reached through UniFi Fabric only (`…/proxy/protect/integration/v1/*`). Availability is firmware/application-version dependent (an unsupported family answers with an upstream 404/501, passed through). Write and physical-action tools honor the `UNIFI_PROTECT_MUTATIONS_ENABLED` env gate (default on); siren play/stop/test, speaker test, relay and alarm-hub output actions, arm enable/disable, and `delete_arm_profile` accept a `confirm` argument and ignore it, POS ingestion carries an `externalId` idempotency key and is never auto-retried, and settings writes read-before, skip on no-op, and read-after to verify. Also added: Protect application metadata (`get_protect_application_info` → `/v1/meta/info`) and the ULP (UniFi account) user directory (`list_ulp_users`/`get_ulp_user` → `/v1/ulp-users`), distinct from Protect users. For live-ish event and device-change data, the bounded-window REST-poll collectors `collect_protect_events` and `collect_protect_device_changes` stand in for the Protect WebSocket subscriptions (`/v1/subscribe/devices`, `/v1/subscribe/events`), which are not reachable over the Fabric cloud connector (verified: an upgrade GET returns 404, never 101) — see "Future and unsupported tools" below.
- **InnerSpace:** the application is installed and running on this console with an active floor-plan project. All eight InnerSpace read tools were live-verified 2026-08-09 against the documented Integration API (`…/proxy/innerspace/integration/v1/*`) and returned real project geometry — placed devices, shaped floor plans, and plan assets all round-trip correctly. (An earlier probe during the same session returned HTTP 403 for the `innerspace` connector namespace; the root cause was that UniFi deprecated the legacy `/proxy/innerspace/api/*` relay when it formalized the documented `/proxy/innerspace/integration/v1/*` path — switching to the documented path resolved the 403.)
- **Access:** Access is not available through the UniFi Fabric/cloud connector API and has no published spec, so this release has no Access tools; tracked as a future tool.

**Deployment matrix:** stdio, streamable-http, and SSE transports were verified end-to-end. Bearer-token auth on both plain HTTP and HTTPS was verified. mTLS was verified as the live production transport for the canonical deployment.

**OAuth:** End-to-end OAuth flow requires a running external identity provider and could not be exercised in this environment. The fail-closed startup behavior — the server refuses to start when required OAuth parameters are missing — is covered by unit tests in CI. See [docs/AUTH-OAUTH.md](AUTH-OAUTH.md) for deployment guidance.

**Multi-key MSP:** The single-key path (`UNIFI_API_KEY`) was fully exercised live. Per-host tools (any tool that accepts a `host` parameter) resolve the API key that owns the target console and route the request on that key, so a console owned by any configured key — not only the first — is reachable; this ownership routing is covered by unit tests. The multi-key tools (`list_hosts`, `list_sites`, `list_all_sites_aggregated`, `list_all_devices`, `list_all_clients`, `get_fleet_summary`, `search_device_fleet`, `search_across_sites`, `list_devices` without `host`, `list_mobility_workspaces`, `list_carrier_subscribers`, `list_carrier_service_plans` and `list_sdwan_configs`) iterate all keys unless a `key_label` argument names one; this fan-out, the per-key `errors` and the shared-console de-duplication are covered by unit tests. See [Multi-key MSP setup](CONFIGURATION.md#multi-key-msp-setup).

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

### Access

No Access tools are included in this release. UniFi Access is not part of the UniFi Fabric (cloud connector) API this server uses: every `/proxy/access/*` path through the connector returns 403, and the Fabric API documentation lists no Access section. Ubiquiti does publish a separate local Access API, served by the console on the local network and authenticated with its own Access API token. That API sits outside this server's cloud-only design, which has no local network access, so it is not offered. This changes if Ubiquiti exposes Access through the Fabric API.

### Protect persistent WebSocket subscription

The Protect Integration API documents two WebSocket subscription endpoints: `GET /v1/subscribe/devices` and `GET /v1/subscribe/events`. A *persistent* subscription to either is not available through this server because it is not reachable over the Fabric cloud connector — the connector is a unary request/response relay. Verified live (read-only canary): a GET carrying the WebSocket upgrade headers through `…/proxy/protect/integration/v1/subscribe/events` returns an upstream HTTP 404 (`Entity 'endpoint' not found`), never a `101 Switching Protocols`. A true persistent stream needs local console (`wss://`) access, which this cloud-only server does not have. For live-ish data without a persistent socket, use the bounded-window REST-poll collectors `collect_protect_events` and `collect_protect_device_changes` (see the Protect tools above), which return the same event and device-change data assembled over a polling window.
