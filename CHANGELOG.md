# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.2] - 2026-11-10

Highlights: 798 tools (15 added, 9 removed); the full list is in the [tool catalog](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOLS.md).

- Opt-in tamper evidence and a remote sink for the audit log.
- Read UniFi API keys from a file or a helper command instead of the environment.
- A sanitized server diagnostic bundle for bug reports.
- Opt-in OTLP trace export of per-request MCP spans.
- Protect MCP resources for consoles, events and camera snapshots.
- Tools whose routes no current UniFi application serves are removed.

**Breaking:** 9 tools are removed; a client that calls one gets an unknown-tool error. 1 Changed entry marked Breaking alters existing behavior. **Upgrade:** the [migration guide](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md) says what to use instead, where one exists.

### Added

#### Credentials and audit

- **Audit:** opt-in remote sink to a TLS collector with `UNIFI_AUDIT_SINK=remote`; TLS 1.3 is the default and fails closed. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/CONFIGURATION.md#remote-audit-sink-unifi_audit_sinkremote)

- **Audit:** opt-in `UNIFI_AUDIT_HMAC_IDENTIFIERS` replaces client MAC addresses and user identifiers in audit records with stable HMAC tokens. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/CONFIGURATION.md#pseudonymised-identifiers-unifi_audit_hmac_identifiers)

- **Audit:** opt-in tamper evidence for the JSON audit file with `UNIFI_AUDIT_CHAIN`, checked offline by the `unifi-fabric-audit-verify` command. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/CONFIGURATION.md#tamper-evidence-unifi_audit_chain)

- **Credentials:** read API keys from a file or helper command with `UNIFI_API_KEY_FILE` or `UNIFI_API_KEY_COMMAND` (list forms too). [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/CONFIGURATION.md#key-files-and-helper-commands)

#### Diagnostics and observability

- **Diagnostics:** `get_server_diagnostic_bundle` returns a sanitized, reviewable bundle describing this server, with no UniFi request by default. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#server-diagnostics)

- **Traces:** opt-in OTLP trace export of per-request MCP spans to a collector you run; with no endpoint set, nothing is loaded. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/CONFIGURATION.md#trace-export-otlp)

#### Discovery

- **Search:** `search_tools` results now say when the limit cut the list (`more_available`, `total_matched`). [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#discovery-mode)

- **Schemas:** twelve server-assembled tools, including `search_tools` and `get_fleet_summary`, now advertise a fully described `outputSchema`; results are unchanged. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#output-schemas-of-server-assembled-tools)

#### Incident evidence

- **Incident evidence:** `collect_network_incident_evidence` and `collect_protect_incident_evidence` return one versioned document of evidence ids, provenance and coverage for a time window. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#incident-evidence)

#### Network

- **Network diagnostics:** `get_site_dpi_usage`, `get_client_dpi_usage` and `get_client_wifi_experience` read per-application traffic and per-client Wi-Fi experience. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOLS.md#get_site_dpi_usage)

- **Network:** `suggest_service_port` lists free ports for a VPN service; `acknowledge_critical_alert` marks one critical alert as read. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOLS.md#suggest_service_port)

- **Switch ports:** `get_switch_port_overrides` and `update_switch_port_overrides` change only the named ports and fields, preview with `dry_run` and verify on read-back. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#update_switch_port_overrides)

#### Statistics

- **Statistics:** `get_controller_stats` gains `view: "series"` for history in hourly, eight-hourly or monthly buckets. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOLS.md#get_controller_stats)

#### Protect

- **Alarm Manager:** `get_protect_alarm_manager_mode` reports whether a console runs local or global Alarm Manager, and whether the arm-profile tools apply. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/COVERAGE.md#protect-global-alarm-manager)

- **Protect door locks:** `get_door_lock` and `list_door_lock_unlock_events` read one Protect 7.x lock and its remote unlock requests. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOLS.md#get_door_lock)

- **Resources:** MCP resources for consoles, recent events, an event summary and camera snapshots. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#protect-mcp-resources)

#### Event streams

- **Event streams:** `get_event_stream_status` and `read_recent_events` report stream compatibility and read bounded recent-event buffers; both report `unsupported` today. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/COVERAGE.md#live-event-streams-network-and-protect)

### Changed

#### Documentation

- **Docs:** Docker examples now pass the API key without putting it on the `docker run` command line.

- **Docs:** the README's Claude Desktop install badge links straight to the current `.mcpb` bundle.

#### Install

- **Install:** the minimum `pydantic-settings` is now 2.7.

- **Upgrade kit:** the 0.7.1 settings migrator and its guide leave the source tree; use the v0.7.1 tag to migrate from 0.7.0. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#the-071-settings-migration-kit-is-removed)

- **Install:** `server.json` now carries a display `title` (`UniFi Fabric MCP Server`) and `websiteUrl` (`https://github.com/swkstudios/unifi-fabric-mcp-server`), so MCP registries show the server's name and project page.

#### Network

- **Descriptions:** `preview_policy_engine_rule` says it needs Network 11.1.11 or later; 11.0.89 answered HTTP 405 and 11.0.99 does not list the route.

- **Traffic rules:** `list_traffic_rules` is labelled legacy; Network 11 no longer shows or manages them. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#network-traffic-rule-changes)

- **Hints:** the placement snapshot's missing-key hint now names the key file and helper settings.

#### Protect

- **Protect 7.x:** `restore_protect_database` now sends the 7.x restore route; with no dump staged, Protect's HTTP 400 passes through unchanged. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Breaking:** `set_door_lock_state` takes `unlock` and now refuses `lock` and `close`, and gains `hold_extra_sec`; affected: `set_door_lock_state`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Door locks:** `list_door_locks` reads the Protect 7.x `/locks` route. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Arm profiles:** the arm-profile tools keep the console's HTTP 400 and add a pointer to `get_protect_alarm_manager_mode`.

#### Fabric connector

- **Fabric connector:** `fabric_connector_get` and the other relays state the connector's documented limits, and a matching error gets an actionable hint. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/RETRY.md#fabric-connector-limits-http-408-429-502)

- **Fabric connector:** `fabric_connector_put`, `fabric_connector_patch` and `update_device_radio` now say a device-settings write can restart the device. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#fabric_connector_put)

### Removed

- **Breaking (tool removed): `create_traffic_rule`.** The console answers HTTP 501. Use `create_firewall_policy`; affected: `create_traffic_rule`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#network-traffic-rule-changes)

- **Breaking (tool removed): `update_traffic_rule`.** The console answers HTTP 501. No replacement; affected: `update_traffic_rule`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#network-traffic-rule-changes)

- **Breaking (tool removed): `delete_traffic_rule`.** The console answers HTTP 501. No replacement; affected: `delete_traffic_rule`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#network-traffic-rule-changes)

- **Breaking (tool removed): `get_camera_adoption_qr`.** Protect 7.3 has no QR route. No replacement; affected: `get_camera_adoption_qr`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Breaking (tool removed): `calibrate_door_lock`.** Protect 7.x door locks have no calibrate route. No replacement; affected: `calibrate_door_lock`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Breaking (tool removed): `set_door_lock_auto_close`.** Protect 7.x door locks have no auto-close route. No replacement; affected: `set_door_lock_auto_close`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Breaking (tool removed): `get_protect_case_asset_snapshot`.** Protect 7.3 has no snapshot route. Use `list_protect_case_assets` then `get_thumbnail`; affected: `get_protect_case_asset_snapshot`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Breaking (tool removed): `reboot_nvr`.** No Protect version serves it. Use `reboot_unifi_os_console`; affected: `reboot_nvr`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

- **Breaking (tool removed): `update_protect_user_notifications`.** Protect 7.3 keeps notifications per automation. No direct replacement; `set_protect_notifications_muted` still mutes; affected: `update_protect_user_notifications`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/MIGRATING-0.7.2.md#protect-7x-route-changes)

### Fixed

#### Network

- **Fixed IPs:** `remove_client_fixed_ip` reports `deleted: true` only when the client's fixed IP is actually gone. [#47](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/47)

- **Clients:** `set_client_name` and three related writes read the client's own record when the client list omits it, instead of reporting not found ([#48](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/48)).

- **Descriptions:** `get_firewall_policy_ordering` and `set_firewall_policy_ordering` now say zone ids must be UUIDs, and the latter says the ordering body is sent as given.

- **Descriptions:** the firewall zone tools, such as `list_firewall_zones_proxy`, now say they call the Network Integration API through the connector proxy.

- **Errors:** `get_multicast_insights` now explains that an HTML 404 means this console's Network application does not serve multicast insights, and keeps the upstream body.

- **Purpose-only updates:** `update_vpn_server` and three sibling tools refuse a body holding only `purpose`, with a clearer reason.

- **Network:** an HTML 404 from `/v2/api/stats/*` now carries a hint that the console's Network application does not serve that statistics route. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#generic-fabric-connector-relay-guarded)

- **Network:** a write the console refuses inside an HTTP 200 reply is now reported as an error, and the audit log records it as `upstream_error_body`. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/RETRY.md#http-200-carrying-an-error-network-v2)

- **Error hints:** `get_innerspace_ucore_manifest` and `search_detections` name the working tool on a refusal, `get_5g_topology` explains its 404, and a 403 with `errors.ucore.access` drops the API-key hint.

#### Pagination

- **Pagination:** all-pages lists no longer stop early when rows share a MAC address; records are told apart by `id`, `_id` or `uuid`. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/PAGINATION.md#partial-results-when-a-page-cap-is-set)

#### Tool descriptions

- **Descriptions:** write tool descriptions now say what the dry-run preview returns and what the write changes; the `UNIFI_WRITE_POLICY=dry-run` setting is explained in its own sentence. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/CONFIGURATION.md#dry-run-behavior)

#### Credentials and audit

- **Redaction:** with `UNIFI_REDACT_SECRETS`, WireGuard client configurations and preshared keys are masked in every tool. [#46](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/46)

#### Write policy

- **Write policy:** reads that send a POST outside the read allowlist are now classed as writes consistently, so `UNIFI_WRITE_POLICY=deny` hides them. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/TOOL-USAGE.md#reads-that-send-a-post)

#### Fabric connector

- **Fabric connector:** an HTTP 408 now carries a hint after the upstream body; a 408 on a write is reported as outcome unknown, never retried. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/RETRY.md#fabric-connector-limits-http-408-429-502)

#### Retries

- **Retries:** a read that gets HTTP 429 waits for `Retry-After` up to 64 seconds; a longer wait is raised with the header value. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/RETRY.md#rate-limit-handling-http-429-for-a-read-via-get)

### Security

#### Install

- **Bundle build:** the Claude Desktop bundle build no longer installs `zod` or `tmp` versions with published advisories (build-time only; [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5), [GHSA-ph9p-34f9-6g65](https://github.com/advisories/GHSA-ph9p-34f9-6g65), [GHSA-52f5-9888-hmc6](https://github.com/advisories/GHSA-52f5-9888-hmc6)).

#### Credentials and audit

- **Credentials:** API key fingerprints are now keyed hashes that change at each server start, so they cannot be guessed offline. [Details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.2/docs/CONFIGURATION.md#credential-redaction)

Fixes #46, Fixes #47, Fixes #48.

## [0.7.1] - 2026-11-08

Highlights: 792 tools (6 added, 0 removed); four settings replace the 0.7.0 write and exposure settings (`UNIFI_WRITE_POLICY`, `UNIFI_WRITE_EXCEPTIONS`, `UNIFI_FAMILY_ALLOW`, `UNIFI_EXCLUDE`); opt-in header mode (`UNIFI_KEY_MODE=header`) takes UniFi API keys per request; request headers can tighten, never loosen, the operator policy; opt-in read-only Code Mode (experimental, may change without a deprecation cycle); audit log sink and file-mode hardening; opt-in `/health` route. Breaking (configuration): the 0.7.0 settings are retired with no aliases and the server refuses to start while one is set (see the Breaking items below and the migration guide).

**Breaking:** a 0.7.1 server refuses to start while any 0.7.0 write or exposure setting is in its environment. **Upgrade note:** run the migrator on each configuration file, or follow [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/docs/MIGRATING-0.7.1.md), then change the package pin or image tag to 0.7.1. Stay on `==0.7.0` until you have migrated.

### Added

- The 0.7.1 migrator merges the values a Compose service `env_file` sets into the new `environment:` entries it writes, because an `environment:` entry replaces the env_file's value. It rewrites a service only when it can resolve every source of that service's environment (its own `environment:` and an `env_file` of `NAME=value` lines). A service in a file that uses YAML anchors, aliases, `<<:` merge keys, tags, `extends:`, `include:` or an override file, has more than one YAML document, an explicit `? key` or an escaped quoted key, or a service with `build:`, or is read with `COMPOSE_FILE` (shell or `.env`) or `COMPOSE_ENV_FILES` set, or whose `env_file` it cannot read in full, or an `environment:` map entry with no value (filled from the shell), is left unchanged and marked `# MANUAL:` (exit status 3); so is `docker run -e` next to `--env-file`.

- `list_integration_device_tags` discovers device tags used for WiFi broadcast assignments from the official Network Integration API (`GET /v1/sites/{siteId}/device-tags`).

- A generated route manifest inventories tool requests and their availability baseline; `scripts/route_audit.py` audits representative integration, console-internal, Site Manager and local-only routes with GET requests only.

- Header mode (`UNIFI_KEY_MODE=header`; the default `environment` is unchanged): the server stores no key, and each `tools/call` carries its keys in one `X-UniFi-Api-Key` header, a JSON object of label to key, which that call uses only for its own duration. A header that is repeated, not valid JSON, not an object, empty, or has an empty label or key is refused with `invalid_api_key_header`; a call without the header is refused with `missing_api_key_header`; `key_label` is refused with `key_label_not_allowed`; a full credential cache is refused with `credential_cache_saturated` (at most 256 key identities are held at once). Messages name labels and member positions, never a key. A repeated label is also `invalid_api_key_header`. A write refused at this ingress writes one `outcome=refused` audit record whose reason is the refusal code, never key material. Header mode needs an HTTP transport: with stdio it fails at startup with `startup:UNIFI_KEY_MODE`. In the default environment mode a call that sends `X-UniFi-Api-Key` is refused with `invalid_api_key_header`.

- Request headers `X-UniFi-Write-Policy`, `X-UniFi-Family-Allow` and `X-UniFi-Exclude` use the same grammars as the settings and can only tighten the operator policy: the stricter write policy applies, family sets intersect, exclusions unite and a request adds no write exception; valid loosening is ignored. A blank, malformed or repeated policy header is refused with `invalid_policy_header`; a call to a tool the policy does not expose is refused with `tool_not_exposed`, and a write the policy denies is refused with `write_denied`, both before any console call. Each of these refusals writes one `policy.refusal` record. Under an effective `dry-run` a write returns its dry-run preview and sends no change. `tools/list` and `search_tools` list only the tools the request may call.

- Opt-in `GET /health` route on the HTTP transports (`MCP_HEALTH_ROUTE=on`): answers `ok` or `degraded:<reason>` from local process state, with no console call and no metrics.

- Experimental: opt-in, read-only Code Mode (`UNIFI_TOOL_MODE=codemode`) lists `search_tools`, `describe_tool` and `execute`; `execute` runs a sandboxed Python script that reads through the same read-only checks as `call_read_tool` and never dispatches a write. Code Mode is an opt-in, read-only experimental feature. It may change without a deprecation cycle. There is no compatibility promise for execute()'s schema or output shape until graduation. Limits: script 32,768 UTF-8 bytes; 32 tool calls per script; 262,144 bytes per tool response and 2,097,152 in total; 64 MiB memory; recursion depth 64; 30 seconds of interpreter time (waits on the console are not counted); output 65,536 bytes, longer output ends with `...[truncated]`; one script at a time per server process.

- Listing and discovery: `list_active_clients` exposes the v2 active-client route.
- Network services: `create_firewall_rule`.
- Network controller administration: `reboot_unifi_os_console`.
- Statistics: `list_speedtest_results`, `list_controller_stat_schemas`.

### Changed

- The documentation now states that tools routed to the consoles' internal APIs depend on paths Ubiquiti can restrict without notice, and names the official-APIs-only profile (`UNIFI_EXCLUDE=unofficial,source:relay`) for deployments that need to avoid that dependency. No tool, route or default changed.

- FastMCP 4.1.6 (from 4.1.4; the `fastmcp` floor rises from 4.0 to 4.1.1, range `>=4.1.1,<5.0`), which compares `enum` and `const` values by JSON equality, not Python equality, so `1` no longer matches `true` or `0` `false` (an in-place change versus 0.7.0). No registered tool input schema has an `enum` or `const` value that disagrees with its declared type, so only a caller that sends a number for a boolean parameter is now refused.

- Dependencies: every hash-locked requirements file is refreshed in one step from a single manifest, so packages shared between the image, the Homebrew formula, development and the release tooling have one version and one hash set; refreshed pins include starlette 1.10.0, pydantic 2.14.2, websockets 17.4 and hatchling 1.33.0, and new releases wait three days before a refresh takes them. New required runtime dependency: `pydantic-monty` (`>=1.4,<2`, locked at 1.4.0 in the image and the Homebrew formula), the sandbox that runs Code Mode scripts; it is installed whether or not Code Mode is used.

- The published source tree is formatted with Ruff, and the release build fails when the formatted output drifts.

- **Breaking (configuration): the 0.7.0 write and exposure settings are retired and a server that finds one refuses to start.** Upgrading from 0.7.0: the write and exposure settings (`UNIFI_READ_ONLY`, `UNIFI_DRY_RUN`, the per-area `UNIFI_ENABLE_..._WRITE` settings, `UNIFI_PROTECT_MUTATIONS_ENABLED`, `UNIFI_TOOL_FAMILIES`, `UNIFI_DISABLED_TOOL_FAMILIES` and `UNIFI_DISABLE_API_SOURCES`) are retired with no aliases. The server will not start while any `UNIFI_*` variable it does not recognise is set: it names every such variable on stderr, links the migration guide, prints `startup:retired:<NAME>` as the last line and exits with status 2. Replace them with `UNIFI_WRITE_POLICY`, `UNIFI_WRITE_EXCEPTIONS`, `UNIFI_FAMILY_ALLOW` and `UNIFI_EXCLUDE`. Run the migrator on each configuration file (dry run by default; `--write` keeps a `.bak` copy): `uv run https://raw.githubusercontent.com/swkstudios/unifi-fabric-mcp-server/v0.7.1/tools/migrate-0.7.1-env.py <config file>`. Mapping and per-client examples: [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/docs/MIGRATING-0.7.1.md). Stay on `==0.7.0` until you have migrated.

- **Breaking (configuration): four settings now control writes and tool exposure.** `UNIFI_WRITE_POLICY` is `allow` (the default when unset), `dry-run` or `deny`. `UNIFI_WRITE_EXCEPTIONS` is one semicolon-separated list of `<target>=deny` or `<target>=dry-run` entries, where a target is `family:<family-id>` or `tool:<tool-name>`; the strictest of the policy and any matching exception applies. A family `dry-run` exception previews every write that the same family exception set to `deny` refuses, including the typed tools governed by `family:connector` and the Network write families governed by `family:network`. `UNIFI_FAMILY_ALLOW` is a comma-separated list of family IDs (unset means every family). `UNIFI_EXCLUDE` is a comma-separated list of `family:<family-id>`, `tool:<tool-name>`, `source:<selector>` and `unofficial`. Values are case-sensitive lower case; a blank, malformed or unknown value fails startup naming the setting. The settings listed below are retired without aliases: a server that finds one in its environment refuses to start, names the setting and links the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/docs/MIGRATING-0.7.1.md).
- Retired setting `UNIFI_READ_ONLY`: replace `UNIFI_READ_ONLY=1` with `UNIFI_WRITE_POLICY=deny`.
- Retired setting `UNIFI_DRY_RUN`: replace `UNIFI_DRY_RUN=1` with `UNIFI_WRITE_POLICY=dry-run`.
- Retired setting `UNIFI_ENABLE_CONNECTOR_WRITE`: replace `UNIFI_ENABLE_CONNECTOR_WRITE=0` with the `UNIFI_WRITE_EXCEPTIONS` entry `family:connector=deny`; remove `UNIFI_ENABLE_CONNECTOR_WRITE=1`, which is now the default.
- Retired setting `UNIFI_ENABLE_NETWORK_WRITE`: replace `UNIFI_ENABLE_NETWORK_WRITE=0` with the `UNIFI_WRITE_EXCEPTIONS` entry `family:network=deny`; remove `UNIFI_ENABLE_NETWORK_WRITE=1`, which is now the default.
- Retired setting `UNIFI_ENABLE_MOBILITY_WRITE`: replace `UNIFI_ENABLE_MOBILITY_WRITE=0` with the `UNIFI_WRITE_EXCEPTIONS` entry `family:mobility=deny`; remove `UNIFI_ENABLE_MOBILITY_WRITE=1`, which is now the default.
- Retired setting `UNIFI_ENABLE_CARRIER_FABRIC_WRITE`: replace `UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0` with the `UNIFI_WRITE_EXCEPTIONS` entry `family:carrier=deny`; remove `UNIFI_ENABLE_CARRIER_FABRIC_WRITE=1`, which is now the default.
- Retired setting `UNIFI_ENABLE_INNERSPACE_WRITE`: replace `UNIFI_ENABLE_INNERSPACE_WRITE=0` with the `UNIFI_WRITE_EXCEPTIONS` entry `family:innerspace=deny`; remove `UNIFI_ENABLE_INNERSPACE_WRITE=1`, which is now the default.
- Retired setting `UNIFI_PROTECT_MUTATIONS_ENABLED`: replace `UNIFI_PROTECT_MUTATIONS_ENABLED=0` with the `UNIFI_WRITE_EXCEPTIONS` entry `family:protect=deny`; remove `UNIFI_PROTECT_MUTATIONS_ENABLED=1`, which is now the default. Several entries share one list, for example `UNIFI_WRITE_EXCEPTIONS=family:network=deny;family:protect=deny`.
- Retired setting `UNIFI_TOOL_FAMILIES`: rename it to `UNIFI_FAMILY_ALLOW`. The new grammar is lower case with commas only: `"Network PROTECT"` becomes `network,protect`.
- Retired setting `UNIFI_DISABLED_TOOL_FAMILIES`: replace `UNIFI_DISABLED_TOOL_FAMILIES=a,b` with `UNIFI_EXCLUDE=family:a,family:b`. The new grammar is lower case with commas only (no whitespace separators).
- Retired setting `UNIFI_DISABLE_API_SOURCES`: replace each selector `sel` with the `UNIFI_EXCLUDE` entry `source:sel`, for example `UNIFI_EXCLUDE=source:network/private`. Selectors match case-sensitively.

- Vendored UniFi contracts advance to Network 11.0.97 and Protect 7.3.74; firewall-policy tool bodies now advertise the new optional `reportFlowEnabled` field, and device reads and adoption pass the new radio fields (0.9 GHz band, `txPowerMode`, 802.11ah) through unchanged.

- Audit log format: the default is now `json` (one JSON object per line with `schema_version`, `event` and `timestamp_utc`); 0.7.0 wrote `text`. Set `UNIFI_AUDIT_LOG_FORMAT=text` to keep the 0.7.0 key=value line for write records; other record types then start with `event=<name>`. The audit file is no longer reached through a symlink: a symlinked `UNIFI_AUDIT_LOG` path (other than one to the process's own standard error) is refused and the stream reports `audit_unavailable`.

- Internal/CI: CI tiers are static: dev runs the fast checks, main runs the full suites; the PR test selector is removed.
- Internal/CI: the public-artifact dry-run runs on pull requests into `main` and on demand, not on every pull request into `dev`.

- Clarify the testing procedure and acceptance discovery documentation for ordering verification.

- Documentation: carry the untested-tool family manifest forward for version 0.7.1.

- Align CRUD resource families: VPN server, site-to-site tunnel, and RADIUS profile lists now belong to `vpn`; device tag and scheduled task reads now belong to `devices`. Update family selection and write rules accordingly.

- Renamed the public release PR terminology in workflow display names and release documentation to "public release PR" and "public release workflow"; the workflow file and its dispatch inputs are unchanged.

- The release image workflow validates the release tag and workflow ref with one shared script in both build jobs instead of two copies.

- Clarified the release process, public pull request approval, and release tag and workflow responsibilities.

- Clarify that a successful empty response from `set_ups_pairing` does not prove an unpair occurred.

- Improve development CI selection with a conservative fast, targeted, or complete verification tier.

- Code Mode now requires an operator-provisioned per-installation `UNIFI_AUDIT_HMAC_KEY` and records domain-separated HMACs of canonical tool arguments instead of retaining raw argument values.

- Use the runner image’s bundled CodeQL tools for advisory scans.

- Rename the private-to-public release tooling to public-release terminology and build public artifacts from the approved public source.
- Remove the private-image precondition from the public release path; hosted public release builds retain native amd64 and arm64 validation, signing, and attestations.

- **Breaking (tool split): `list_clients` no longer accepts `source="v2"` or the `include_*` flags; use `list_active_clients` for the unchanged v2 active-client route and verbatim body.** affected: `list_clients`, `list_active_clients`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/docs/MIGRATING-0.7.1.md#active-clients-tool-split).

- The README is shorter and now points to the docs for detail: configuration reference material moves to `docs/CONFIGURATION.md`, tool-usage guidance to `docs/TOOL-USAGE.md` and the tool catalog overview to `docs/CATALOG.md`. `docs/CLIENT-SETUP.md` gains a Troubleshooting section, and the README More-info table links to it. No tool, route or default changes.
- Refusal and error text that cites documentation now names the page that holds the section (for example `docs/CONFIGURATION.md#read-only-mode` and `docs/CONFIGURATION.md#enabling--disabling-connector-writes`) in the read-only, write-policy, switch, startup configuration and missing-API-key messages. Only the message wording changes; error codes and behavior are unchanged.

### Fixed

- The HTTP access log writes control bytes in a request target as `\xNN` escapes, so terminal escape sequences and line breaks cannot reach the log line.

- Keep catalog documentation, paging examples, generated route and spec inventories, and client instruction sizes consistent with the registered network, network_services_proxy, protect_camera_recording, and system_log tools.

- Discovery search ignores leading “I need to” and “Help me” request framing so unrelated assistance vocabulary does not change tool rankings.

- Mask complete route-bound share links before credential-field masking in Fabric connector relay post-write errors, so query parameters cannot leave a share token exposed.

- Fix write acceptance route proofs to reject URL mutations and HTTP method changes, and keep cleanup and accounting failures visible in the hermetic selftest.

- Mask credential fields in upstream client and device record errors, including `get_client`, `execute_client_action`, `authorize_guest`, `revoke_guest_access`, and `set_client_user_group`, when secret redaction is enabled, including JSON-string IDs containing quotes.
- Mask credential fields in resolved Matter IDs for `rename_matter_node` and `remove_matter_node` when secret redaction is enabled.

- Correct demo site client counts to match the clients served by the mock API.

- `forget_device`, `unadopt_device`, `adopt_device` and `approve_pending_device` now drop the device's cached MAC lookup for every caller's keys, and a cached device id that answers HTTP 404 is looked up again from the device list. Before, a device re-adopted under a new id kept its old id for up to `UNIFI_CACHE_TTL_SECONDS`, so `get_device`, `restart_device`, `execute_port_action` and the other tools that take a device MAC answered HTTP 404.

- Discovery dispatch now preserves the target tool and records the calling meta-tool in the optional `via` field of write audit records.

- Testing documentation: restore the discovery gate recovery label and refresh coverage hashes for the acceptance and testability matrix updates.

- The MCP registry entry (`server.json`) declares `UNIFI_WRITE_POLICY` (`allow`, `dry-run` or `deny`; default `allow`) for both the PyPI and the container package, so registry clients show the same write policy setting as the client manifests.

- The fixture recorder now fakes the numeric half of `<uuid>:<number>` device ids and of lowercase console host ids, and no longer re-fakes its own host-id and UUID fakes in later passes. The fixture sanitization check now flags a recorded device id or console host id whose number is not a zero-padded fake.

- OAuth mode: a JWKS download that the identity provider accepts and never answers no longer blocks every later authentication until a restart. Each key refresh now runs on its own, so a later refresh can still reach the provider once it recovers and a caller that disconnects leaves the download to the others; at most four downloads wait on a stalled provider at once. The download still has no time limit and keeps its 1 MiB cap.

- Streamed HTTP requests with a disallowed Host now receive the same refusal as other requests.

- Server instructions keep each line at a sentence or clause boundary for clients that preserve newlines.

- Matter rename and removal errors redact credential fields in invalid native IDs before formatting, including values containing apostrophes.

- Reject selected ACL rules and firewall zones with invalid native IDs before sending a batch deletion, and correct the traffic statistics period example.
- Mask credential fields in WAN health errors when secret redaction is enabled.

- `describe_tool` in discovery mode now returns schemas with `$ref` definitions inlined, exactly as the full-mode `tools/list` entry. Before, eight tools (`fabric_connector_patch`, `fabric_connector_post`, `fabric_connector_put`, `set_protect_event_favorite`, `update_camera_private`, `update_device_radio`, `update_nvr`, `update_sensor_private`) were described with unresolved `$ref`/`$defs`, which clients without `$ref` support could not read.

- Documentation: the `search_tools` default limit is generated from the code, and the settings reference lists accepted log levels.

- The tool-usage guide now says the per-area write opt-outs (`UNIFI_WRITE_EXCEPTIONS` entries such as `family:network=deny`) are off by default, so every write is allowed until one is set; it said they were on. It also says read tools return credential fields (device passwords, VPN client configurations, WLAN, RADIUS, Dynamic DNS and VPN secrets) verbatim unless `UNIFI_REDACT_SECRETS` is set, that the connector relay raises a 429 instead of returning it, that relay attempts reach the audit stream only when `UNIFI_AUDIT_LOG` or `UNIFI_AUDIT_SINK` is configured, and that a blank value for a fixed-choice argument such as `session_type` is still refused.
- The coverage report now names the eight InnerSpace read tools it verified as the Integration-API ones, no longer says the internal `/proxy/innerspace/api/*` routes were deprecated (they still serve five reads and every InnerSpace write), and lists `list_all_sites_aggregated` and `search_across_sites` as always covering every API key, since neither takes `key_label`.

- `commission_matter_node`, `create_ssl_inspection_certificate` and `get_camera_adoption_qr` no longer describe their secret argument (the Matter setup code, the certificate private key and passphrase, the WiFi password) as scrubbed from errors: logs always scrub it, but returned errors and dry-run previews mask it only with `UNIFI_REDACT_SECRETS`, which is off by default.
- The 0.7.0 migration guide's dependency entry (change-079 in `docs/MIGRATING-0.7.md`) now gives 64 hash-locked runtime packages, the number the 0.7.0 runtime lock shipped. The 0.7.0 notes said 60 because that count skipped the four pins written with extras (`fastmcp-slim`, `py-key-value-aio`, `pydantic` and `pyjwt`).

- Keep synthetic IDs in tool examples while clarifying the Classic network ID required by `list_dhcp_leases` and `list_dhcp_excluded_ips`, the `host_name` field in `update_dynamic_dns`, and the mount values in `set_edge_storage_mount_state`. The Protect `analyze_footage_with_ai` and `update_protect_case` examples also retain synthetic IDs.

- Documentation: the official-only catalog is `UNIFI_EXCLUDE=unofficial,source:relay`, now
  given in the README, AGENTS.md, llms.txt and a new Official-only catalog section of
  docs/CONFIGURATION.md, with generated tool counts for full mode and for
  `UNIFI_WRITE_POLICY=deny`. `unofficial` alone keeps the generic `fabric_connector_*` relays,
  which can reach private routes, and the five relay descriptions now say so.

- The `UNIFI_PAGINATE_MAX_PAGES` documentation (settings tables, README and the pagination guide) now states that `query_traffic_flows` and `export_traffic_flows` are exempt from the page cap and always drain every page the console reports; bound them with `body.pageSize`. Earlier text described the cap as applying to every drain.

- Keep firewall policy schema descriptions within client size limits while retaining their complete shapes.

- The Rule 17(a) shape-clause check now requires an actual type outline immediately after a ``Shape:`` or ``Shape (legend):`` clause, so a description carrying the marker alone, or prose that merely mentions a type word, no longer counts as stating a shape.
- ``query_traffic_flows`` (network_nat_qos_traffic) states the shape of its ``direction``, ``action`` and ``risk`` parameters as ``string|string[]`` instead of in English, so an AI client reads the accepted form from the schema itself. The observed values and the forwarding note are unchanged.

- Harden `tests/test_tool_schema_contract.py` to validate shape alias definitions and schema format annotations. Recognize JSON object and array literals emitted in outlines.

- Explain invalid startup configuration before the refusal token.

- `update_traffic_rule` merges `payload` into the stored rule before the PUT, so a partial update such as `{"enabled": false}` keeps every other field (matching target, target devices, schedule) instead of replacing the whole rule; the result adds `_verified` from a read-back of the requested fields.
- `query_switch_mac_tables` sends the documented legacy `query` object `{mac, ports}` as a one-item array, so that call no longer answers HTTP 400.

- Correct network error hints and preserve the Wi-Fi raise-site inventory.
- Clarify network_clients_guests identifiers, local refusals, response warnings and read-after errors.
- Reject malformed network_device_operations device rows; document SSH action passthrough and power-off delay units.
- Validate network_dpi_policy batch identifiers, avoid requests for empty batches and front-load update routes.
- Clarify network_mobile_wan period choices and network_nat_qos_traffic pagination, examples and read-after errors.
- Scrub network_routing_topology error fields and document confirmed deletion; use the HTTP verb in network_security_diagnostics refusal audits.
- Clarify network_services_proxy credential masking and fresh-read updates, removing unreachable response handling.
- Document network_switching_power link identifiers and wrap legacy MAC queries; scrub its and network_vpn_dns upstream error identifiers.
- Audit all six network_wifi_radio dry-run preview paths and document quick-scan band choices.
- Clarify placement_snapshot duplicate handling and protect event bounds, body fields and error choices.
- Disable protect_camera_recording export preparation retries; clarify mount choices and use synthetic protect_device_lifecycle examples.
- Document protect_events_cases duplicate-field refusals and protect_recognition_search singular type choices.
- Correct protect_private unadopt verification and metadata descriptions.
- Repair protect_users_assets confirmation descriptions and indefinite notification mute verification.
- Scrub site_admin error values and preserve non-timestamp nulls in site_manager ISP queries.
- Include the converted timestamp in system_log warnings and clarify millisecond-looking input behavior.

- Correct device configuration dry-run previews and read-after verification, fleet aggregation deduplication, and key-labelled partial-result diagnostics.
- Honor opt-in credential redaction in clients, client_records, network_clients_guests, Matter, and connector error messages.
- Correct carrier_fabric write guards and paging counts, mobility paging diagnostics, and connector dry-run detection.
- Preserve InnerSpace fallback HTTP status and clarify innerspace_internal request-body handling.
- Clarify device_commands destination-site selection and device_mgmt paging limits.

- Tool descriptions now match the API and the code: `patch_firewall_policy` names `reportFlowEnabled` as patchable alongside `loggingEnabled`; the `update_dynamic_dns` example uses the native `host_name` field and the payload lists the native fields; `create_acl_rule` and `update_acl_rule` mark `index` as deprecated with no effect and point to `set_acl_rule_ordering`; and the Protect body blocks state each time unit (`update_light` `pirDuration` in milliseconds, liveview `cycleInterval` in seconds, plus `siren_play`, `relay_activate_output`, `alarm_hub_trigger_output`, `update_arm_profile` and `pos_ingest_transaction`).
- `get_camera_analytics` states that `step` is a bucket width in milliseconds, sent unconverted while `start` and `end` are epoch seconds. `get_camera_playback_history` states that `resolution` is the recording quality channel (0 high, 2 low), not a time span, and its example is no longer a millisecond value.
- Generated body-field notes keep an example after "e.g." (`pos_ingest_transaction` currency "e.g. USD"), carry the full text of a deprecated field, and state a bound a field narrows (`update_camera` `micVolume` minimum 1).
- The `confirm` parameter text of 14 Protect user, group, tag, file, ringtone and liveview tools (for example `update_protect_user`, `delete_protect_file` and `upload_ringtone`) is no longer cut off mid-sentence.
- `list_mobility_clients`, `list_mobility_devices` and `list_carrier_subscribers` now return `_count` when `limit` is set, as documented. `list_carrier_subscribers` documents that a single bare-array cursor page is returned as `{result: [...]}`.
- The epoch warnings for millisecond-sized or negative `start` and `end` values no longer say the value was "sent as given": they say it was not rescaled and was still multiplied by 1000 where the endpoint takes milliseconds. `list_network_events`, `list_ips_events` and `list_protect_events` say the same.
- Corrected tool text for `list_pending_devices` and `list_site_devices` (`limit` without `offset` gathers a total across pages), `query_traffic_flows` (single-page and multi-page results), `update_chime` (top-level keys), `start_wifi_quick_scan` (band values `ng`, `na`, `6e`), `set_edge_storage_mount_state` (`mounted` / `unmounted`), `update_protect_case` (a duplicated key is refused), `set_client_icon` (an unknown MAC is refused locally), `list_dhcp_leases` and `list_dhcp_excluded_ips` (Classic network `_id` only), `move_device_to_site` (where to read the Classic site `_id`), the three policy update tools (`update_policy_engine_rule`, `update_network_members_group`, `update_predefined_firewall_policy`), whose descriptions now open with the object they update, and the server instructions on paging arguments.

- OAuth over HTTP (`MCP_AUTH_MODE=oauth`) could not start on fastmcp 4.0.x or 4.1.0, because the JWKS verifier needs a lock that fastmcp added in 4.1.1; the dependency floor is now `fastmcp>=4.1.1,<5.0`, so an environment that already had an older fastmcp is upgraded on install.

- `create_vpn_server` now shows a documentation-reserved address (192.0.2.1/24, RFC 5737) in its `subnet` example and argument description.

- `create_traffic_rule`: when the console does not implement the v2 traffic-rules route (HTTP 501 `api.err.NotImplemented`), the error now says that no payload change will help and names the supported alternatives (`create_firewall_policy` with `create_traffic_matching_list`, `create_qos_rule`, `create_traffic_route`) instead of passing the bare upstream status through.
- `create_backup` now describes what it does: it writes one transient backup file on the console and returns its download path; no stored backup is added, so `list_backups` never shows it and the answer carries no filename or `backup_id`.
- `export_site`: the hint added to the controller's `api.err.BackupFailed` refusal now names the Network application's own reading of that code, a backup that could not be written, so free console storage is the first thing to check.
- `create_wifi_broadcast`: the access-point SSID-limit hint now says that creating the SSID disabled (`enabled: false`) does not avoid the limit.

### Security

- Audit log: JSON by default; `UNIFI_AUDIT_SINK`, `UNIFI_AUDIT_LEVEL` and `UNIFI_AUDIT_CALLS` choose where and what it records, and an `audit_unavailable` notice is returned when the sink fails. The `policy.startup` and `policy.refusal` records are written to stderr, and to the audit file when the sink is `file`, at every `UNIFI_AUDIT_LEVEL`, `off` included, and a free-text reason or error message is scrubbed of configured secrets before it is capped, so the cap never leaves part of a secret in the log. A new audit log file (`UNIFI_AUDIT_LOG`) is created with `UNIFI_AUDIT_LOG_MODE` (`0600` by default, or `0640`), whatever the umask; an existing file keeps its mode.

- Dockerfile: Refresh the pinned Python base image to include the updated APT package.

- Release images are signed and attested with newer actions: `sigstore/cosign-installer` v4.1.2 (cosign v3), `anchore/sbom-action` v0.24.3 and `actions/attest-build-provenance` v4.2.2. Cosign v3 stores an image's signature and SBOM attestation as Sigstore bundles attached through OCI referrers instead of `.sig` tags, so verify 0.7.1 and later images with cosign v3 or later (the image verification page states this).

- With `UNIFI_REDACT_SECRETS` on, each camera channel's RTSP stream alias (`rtspAlias`), the share link and webhook shortcut headers and basic-auth credentials are now masked wherever Protect returns a camera: `get_camera_private`, the private camera list, `get_protect_bootstrap` and camera updates. Before, only some of these routes masked them, and none masked the RTSP alias. The values are also kept out of logs and audit records.
- `create_camera_shortcut` now masks webhook headers and basic-auth credentials in its dry-run preview and keeps them out of logs and audit records, as `update_camera_shortcut` already did. With `UNIFI_REDACT_SECRETS` on, webhook headers and basic-auth credentials in Protect automation bodies and responses are masked too.

- The PyPI release upload uses `pypa/gh-action-pypi-publish` v1.14.3 (from v1.14.2), which fixes GHSA-5xjx-3w67-w9x9.

- The image, the runtime lock and the Homebrew formula install authlib 1.9.4 (from 1.9.1), which fixes GHSA-f3fg-34g9-v7jx, GHSA-gp2m-377p-m4j3 and GHSA-9qr6-8289-9j56, and dnspython 2.9.2 (from 2.9.1), which fixes GHSA-vvf4-9x63-8xvv. The server does not call the affected code.

- With `UNIFI_REDACT_SECRETS` on, "not found" and "ambiguous" errors that list the valid choices now mask credential fields in the upstream names and ids they show. Before, an upstream name or id that was an object, or a string holding a JSON object, appeared unmasked. This covers `get_vpn_server`, `get_radius_profile`, the WireGuard user, WAN SLA, WAN, device, client, guest, network, site, user group, Matter node, camera, Protect record, recognition group and InnerSpace plan lookups, and the per-key and per-site failure reasons of multi-key fleet and cross-site reads (`list_all_clients`). Plain names and ids appear exactly as before.

- Apply the same opt-in credential policy at the final tool-error boundary, including exception notes and fields embedded in JSON, Python representations, and credential pairs. Mask each upstream label before joining it into lookup errors; successful tool responses keep their pass-through behavior.

- In tool error text, a credential key is now read whole and decoded through its escape layers before the response redaction rules apply to it. Keys such as `1_password`, `service.auth_password`, `é_password` and an escaped `pass\u0077ord` inside a repr of JSON are now masked exactly as they are in a successful response.

- Tool modules whose lookup and validation errors now mask upstream values: `client_records`, `device_mgmt`, `device_radios`, `innerspace_internal`, `network_device_operations`, `network_mobile_wan`, `network_routing_topology`, `network_security_diagnostics`, `network_switching_power`, `network_vpn_dns`, `network_wifi_radio`, `protect_automation_backup`, `protect_private`, `protect_recognition_search`, `protect_users_assets`, `site_admin`, `site_config`, `site_manager`, `statistics`, and `aggregation` (`list_all_clients`).

- Preserve following identifiers and failure reasons when masking credential arrays with escaped quotes or brackets, and quoted credentials ending in literal backslashes, including nested JSON and Python representations.

- Parse complete JSON and Python representations before masking error credentials, keeping following identifiers and reasons intact even after prose apostrophes or escaped brackets.

- Keep complete credential containers masked inside prose quotes and nested string representations, and preserve error identifiers and reasons when malformed outer literals contain unhashable dictionaries.

- Decode nested JSON/repr error strings up to six layers and fail closed on unresolved credential spans or parser failures. Single-level identifiers and reasons survive; ambiguous nested errors may lose following diagnostics.

- Scan every decoded escape level through a fixed point (up to 128 iterations), including deeply escaped credential keys; withhold the whole error when the decoding bound is exhausted.

- Scan final structured error renderings at every decoded level so nested bytes, sets, and encoded strings cannot bypass masking. Require a key separator before masking credential words, preserving password-containing tool names and masked-only write refusals.

- Mask credential assignments after incomplete tool headers and preserve following identifiers and reasons after empty quoted credential values.

- `get_unifi_placement_snapshot` with `UNIFI_REDACT_SECRETS` on no longer emits the `smdev-` id of a device known only by its MAC. That id is an unkeyed hash of the MAC, so it let anyone recover the withheld MAC by trying every address of one vendor prefix. Such a device is now left out and counted under `_withheld` as `topology.record` / `hardware_address`. With redaction off, the id and the MAC are unchanged.

- The example ids in the parameter descriptions of the Protect event, case, case-asset and case-export tools (`get_protect_event`, `set_protect_event_favorite`, `update_protect_case`, `export_protect_case`, `analyze_footage_with_ai` and their siblings) are now zero-padded synthetic ids. Before, they were ids of real Protect records.

## [0.7.0] - 2026-11-01

Highlights: 786 tools (504 added, 1 removed); read-only mode (`UNIFI_READ_ONLY`); opt-in dry-run, audit log and credential redaction; setup for Claude Code, Claude Desktop, Codex, Antigravity and Gemini CLI. Breaking: tool results are returned verbatim (see the Breaking items below); input schemas changed for 97 tools.

**Breaking:** The default tool surface changes from all domain tools to five discovery meta-tools. **Upgrade note:** set `UNIFI_TOOL_MODE=full` to keep the previous behaviour. ContextForge and gateway deployments should explicitly select `full`.

- **Breaking (configuration)** Remove `UNIFI_REQUEST_TIMEOUT_SECONDS` or startup fails; no HTTP deadline, await completion/cancellation. [Migration details](docs/MIGRATING-0.7.md#request-deadline-compatibility).

[tool-categories]: https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#tool-categories

**Known limitations**

- `recover_switch_port` recovers only ports blocked by loop detection or BPDU guard; others get the console's HTTP 400 `api.err.InvalidTargetPort`. A real recovery is not live-tested (no such port; faults are not staged). Traffic rules return HTTP 501 `api.err.NotImplemented` on consoles without v2 trafficrules.

- `list_ptz_presets` returns the console's HTTP 500 for cameras without PTZ hardware; the route is verified only on PTZ hardware.
- `list_innerspace_doors` returns HTTP 502 without the console's Access app, which provides the door list.

### Added

- New tools in the catalog's Configuration category not named elsewhere in this section (31 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#configuration).
- New tools in the catalog's Create category not named elsewhere in this section (39 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#create).
- New tools in the catalog's Delete category not named elsewhere in this section (37 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#delete).
- New tools in the catalog's Device Control category not named elsewhere in this section (3 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#device-control).
- New tools in the catalog's Device Management category not named elsewhere in this section (7 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#device-management).
- New tools in the catalog's Execute & Actions category not named elsewhere in this section (4 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#execute--actions).
- New tools in the catalog's Listing & Discovery category not named elsewhere in this section (52 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#listing--discovery).
- New tools in the catalog's Other category not named elsewhere in this section (121 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#other).
- New tools in the catalog's Reading & Inspection category not named elsewhere in this section (91 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#reading--inspection).
- New tools in the catalog's Search category not named elsewhere in this section (2 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#search).
- New tools in the catalog's Update category not named elsewhere in this section (47 tools): see [tool list](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#update).

- Network controller administration (controller backup cancel, delete and restore, site import, test email, remote-access TURN credentials and cloud registration, SSO session refresh and account link, MFA code resend, own admin profile, system parameters, support files, firmware update check, firmware cache and latest firmware versions): see [tool list][tool-categories].

- Network device operations: WebRTC SSH sessions, switch and port counter clearing, port recovery and port LED locate, device config clone, PDU outlet control, UPS self-test, building-bridge alignment, rearrange and unpair, priority uplinks, remote-access VPN user disconnect, switch-port reset, adoption info, rolling-upgrade eligibility and time estimate, device replacement candidates and replace, battery locate/reboot and firmware update, device-tag assignment (managed-device MAC plus tag addition/removal arrays) and Classic bulk object updates (`bulk_update_objects`); see [tool list][tool-categories].

- Network mobile and WAN (LTE subscription, trial, device authorization, APN profile, SIM PIN, eSIM profiles, inactive SIM slot and data usage; LTE failover, WAN load balancing, WAN network groups, WAN insights and speed tests, WAN SLAs, enriched WAN/LAN/WLAN configuration and the gateway route table): see [tool list][tool-categories].

- Network clients, guests, DHCP and hotspot: guest authorize and revoke, client records, insights and observability, client icons and fingerprint overrides, DHCP leases, excluded IPs and options, hotspot settings, payments, authorizations, packages and portal files; see [tool list][tool-categories].

- Network VPN and DNS (static DNS records, DNS-over-HTTPS servers, IPsec settings, VPN users and connections, OpenVPN client configuration, VPN server restart, WireGuard users and used subnets, Teleport invitations and clients, Site Magic VPN list, site VPN create/delete/control): see [tool list][tool-categories].

- Network routing and topology (from `get_bgp_status` to `update_switch_stack`: BGP configurations, OSPF routers, global network configuration, mDNS settings, Layer 3 migration, network suggestions, VLAN plan generation, DHCP reservation import, orchestration detach, virtual networks, loop detection and recovery, MC-LAG groups, switch stacks): see [tool list][tool-categories]. Gateway BGP updates and deletes use the gateway configuration route; routing deletes report whether readback confirms removal.

- Network switching and power (such as `list_energy_saving_policies`, `update_power_supervisor` and `get_port_history`: energy-saving policies, PoE power supervisors and links, port and infrastructure history, MAC tables, port anomalies and logs, wireless links, transmit retries): see [tool list][tool-categories]. Energy-saving policy, power-supervisor and link updates and deletes read the list first: an unknown id fails with "not found", labels each valid id by its field (`id=` or `_id=`) and sends no write. Energy-policy updates omit inherited read-only metadata while preserving supplied fields.

- Network WiFi radio (radio-AI isolation matrix, preview and apply, radio history, WiFi connectivity and stats, WiFi Doctor optimization, tethering and uplink scans, WiFiman settings, WLAN capabilities, available channels, AP neighbors, spectrum and quick scans, WiFi-WAN configuration): see [tool list][tool-categories].

- Network security and diagnostics (SSL inspection, IPS, system log, packet capture, ping test and a unified IP/Thread topology): see [tool list][tool-categories].

- Network ProAV, Shadow Mode and sandbox tools (ProAV matrices, snapshots, groups and TV-wall calibration; Shadow Mode status and managed adoption; sandbox test configs; port-forward statistics; digital-twin layout; 5G topology; multicast insights): see [tool list][tool-categories]. Test-config operations resolve the controller's v2 `id` field.

- Network NAT, QoS, content-filtering and traffic observability (NAT rules, QoS rules and their order, content-filtering profiles and categories, traffic statistics, traffic-flow queries and exports, application traffic rates, PoE information, topology snapshots): see [tool list][tool-categories]. NAT, QoS and content-filter rule updates and deletes refuse an unknown id the same way. Network history, PoE, traffic, quick-scan, observability and statistics reads send what the console needs.

- `delete_policy_engine_rule` and `delete_network_members_group` resolve the id in the collection first and delete the record by its own id; an unknown id lists the valid ids and sends no write. Members-group writes take `type` `USERS` or `CLIENTS`. `list_vpn_clients` returns the complete networkconf envelope with `data` unchanged (every network, as upstream sent it); the VPN-client records are in the additive `_vpn_clients` list. Policy-preview HTTP 405 errors retain the upstream response and explain controller-version limitations. Legacy traffic-rule writes can return upstream HTTP 501 on Network 11.0.89; firewall-policy bodies use a different schema.

- Protect camera controls and edge recording (camera adoption QR, analytics, light level, playback history and visible WiFi networks; camera control, door lock, image-settings reset, resolution scale, management transfer, flashlight, WiFi setup and video codec; on-camera storage export, mount state, reformat and recording settings; recording deletion by time window): see [tool list][tool-categories]. Protect private-route tools send the routes and query values Protect 7.3.70 requires. NVR recording-retention durations accept integer milliseconds and strings.

- Protect automations, backups and cloud archive (automations list/create/update/delete/history/reset, system-notification receivers, backups list/create/delete/import/restore, database restore, cloud archive provider status/connect/disconnect/start/cancel, UniFi Video server connect and import listing, service-agreement acceptance): see [tool list][tool-categories]. Automation and backup ids match in any letter case and are sent as Protect lists them; `cancel_cloud_archive_task` sends `archive_id` only in the body.

- Protect users and assets (device tags, user groups, users and notifications, device password, files, ringtones, liveview delete): see [tool list][tool-categories]. Device-tag, user and user-group ids match in any letter case and are sent, in the path and in a body `id` naming the same record, as Protect lists them; an unlisted id is refused before any write with the valid ids. User and group updates send supplied changes without inherited read-only properties.

- Camera shortcut tools (`update_camera_shortcut`, `delete_camera_shortcut`, `trigger_camera_shortcut`) match shortcut and camera ids in any letter case and send them as the camera lists them; an unlisted shortcut id is refused before any write. Shortcut writes send the array body Protect requires.

- Protect recognition and detection search: create, update, delete, merge and assign recognition groups, set a group image, recognise an uploaded image, bulk-upload vehicle groups, natural-language detection search, detection statistics and AI false-positive reports; the argument docs carry a schema-valid recognition response example; see [tool list][tool-categories].

- InnerSpace project, import and console tools: see [tool list][tool-categories]. `update_innerspace_plan_map` and `delete_innerspace_plan` resolve the plan in the project's plan list first, as `update_innerspace_plan` does: an unknown or ambiguous id lists the valid plan ids and sends no write, and the plan id is sent in the listed spelling.

- Device commands, backups and scheduled-task writes: see [tool list][tool-categories]. `restart_device` accepts an optional `reboot_type` and `upgrade_device` an optional `firmware_url`; physical command previews explain their consequences and scheduled-task updates keep unmentioned fields. A controller backup returns the console path of its one transient backup file, and a site export the console cannot build names the next step.

- Thread and Matter: `list_thread_networks`, `list_matter_nodes`, `commission_matter_node`, `rename_matter_node`, `remove_matter_node`; see [tool list][tool-categories]. Responses keep the native upstream shape; the setup code is masked in dry-run previews and errors only with `UNIFI_REDACT_SECRETS` and is always scrubbed from logs and the audit log, for the typed tool and the generic relay alike. `rename_matter_node` and `remove_matter_node` resolve the node in the node list before any write and address it by its native id.

- `UNIFI_ENABLE_NETWORK_WRITE` (default on): set it to `0` to opt out of typed Network-area writes and Network mutations through the connector relay; the refusal comes before host and site resolution, and `UNIFI_READ_ONLY` still applies.

- Protect camera livestream share links: `enable_camera_share_link`, `get_camera_share_link`, `disable_camera_share_link`; see [tool list][tool-categories]. Each returns the upstream body verbatim; a share link is always scrubbed from logs and the audit log, and from errors and failed results only with `UNIFI_REDACT_SECRETS`.

- Protect recognition writes: hide or show the enhanced image of a face detection, apply a `recognize_image` result, and create an object recognition group; see [tool list][tool-categories].

- `get_scoped_system_log` reads the Network system log for one device or client MAC, admin activity or external id, and returns the body verbatim; a device or client MAC with surrounding whitespace is refused before any request. Network firewall batch deletes: `batch_delete_acl_rules`, `batch_delete_firewall_policies`, `batch_delete_firewall_zones`; each reads the list back and reports `deleted: false` when removal is not confirmed. `get_camera_snapshot` takes an optional `ts` to read a past moment from a recording. The scoped log scopes other than `device` and snapshot `ts` are not yet confirmed against live data.

- InnerSpace writes gain an opt-out, `UNIFI_ENABLE_INNERSPACE_WRITE` (on by default; `0` refuses every InnerSpace write, relay included). Every per-area opt-out refusal states the switch's current value and that no request was sent.

- Site configuration tools on the routes the controller's own UI uses: client user (bandwidth) groups (`list_user_groups`, `get_user_group`, `create_user_group`, `update_user_group`, `delete_user_group`, `set_client_user_group`), static routes (`get_static_route`, `create_static_route`, `update_static_route`, `delete_static_route`), local RADIUS accounts (`create_radius_account`, `update_radius_account`, `delete_radius_account`), RADIUS profiles (`update_radius_profile`, `delete_radius_profile`), AP groups (`list_ap_groups`, `get_ap_group`, `create_ap_group`, `update_ap_group`, `delete_ap_group`), port profiles (`create_port_profile`, `delete_port_profile`) and Dynamic DNS (`create_dynamic_dns`, `delete_dynamic_dns`). An unknown id fails before anything is sent, and a write that did not land as sent carries a `_warnings` entry.

- Claude Code plugin (`plugins/claude/`): runs this server locally through `uvx --from unifi-fabric-mcp-server==0.7.0 unifi-fabric-mcp` with the UniFi API key you enter when you enable it (kept in Claude Code's secure credential storage) and an optional Read-only mode switch (`UNIFI_READ_ONLY`, off by default). Install it from this repository's Claude marketplace (`.claude-plugin/marketplace.json`: `/plugin marketplace add swkstudios/unifi-fabric-mcp-server`, then `/plugin install unifi-fabric@unifi-fabric`). Its README lists what it runs, the hosts contacted and example prompts. New `PRIVACY.md` covers every integration.
- Setup for more MCP clients, each running this server locally with your own key: an OpenAI Codex plugin (`plugins/codex/`), a Google Antigravity plugin (`plugins/antigravity/`), a Gemini CLI extension (`gemini-extension.json`) and a Claude Desktop extension bundle (`plugins/claude-desktop/`, macOS and Windows). The README Quick Start has a "Choose your client" table and a section per client, and [docs/CHATGPT.md](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/CHATGPT.md) covers ChatGPT. Every manifest pins `unifi-fabric-mcp-server==0.7.0`.

- Discovery mode is now the default (`UNIFI_TOOL_MODE=discovery`): five meta-tools (`search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, `list_tool_families`) provide ranked search with caller-chosen limits and no hard cap, exact full-mode descriptions, accurate read/write hints and full schemas, and dispatch through the same registered tools and middleware. All selected tools remain reachable, and full mode serves the whole catalog (786 tools, about 1454 KB of `tools/list`); composes with `UNIFI_TOOL_FAMILIES`.
- An agent installation guide ([docs/INSTALL-AGENT.md](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/INSTALL-AGENT.md)) and installation examples checked against locally built package artifacts.
- Typed wireless-radio management for access points: `get_device_radios` reads each band's radio table and state, and `update_device_radio` changes channel, width, transmit power and minimum RSSI per band, checked against the device's reported capabilities, with dry-run previews and read-after verification. A DFS channel change can leave a radio in `DFS_WAIT` for about 60 seconds.

- Protect tools on the private routes the Protect web UI uses are marked `protect/private` in the tool catalog: see [tools by API source](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#tools-by-api-source).
- Startup guidance reports active read-only and dry-run modes; dry-run results include their status.
- Opt-in global read-only mode (`UNIFI_READ_ONLY`, default off) refuses every write/action across all areas (Network, device/client actions, Protect, connector relay, Carrier Fabric, Mobility, port profiles, vouchers, ...) before any upstream call, including pre-write reads. Refusals name the tool and variable; reads and independent per-area write opt-outs are unaffected.
- Off by default: a tool-family allowlist (`UNIFI_TOOL_FAMILIES`, e.g. `network,protect`) that advertises only the named families, a dry-run preview of every write (`UNIFI_DRY_RUN`) and a write audit log (`UNIFI_AUDIT_LOG`, `UNIFI_AUDIT_LOG_FORMAT` `text` or `json`). Dry-run and the audit log cover every write, including a `fabric_connector_*` POST, PUT, PATCH or DELETE whatever its path (including a relayed Classic `stat/…` POST); the typed `list_client_sessions` (`POST stat/session`) is a read. See [Tool-family allowlist](README.md#tool-family-allowlist-unifi_tool_families), [Dry-run preview](README.md#dry-run-preview-for-all-writes-unifi_dry_run) and [Optional audit log](README.md#optional-audit-log-unifi_audit_log).

- Opt-in credential redaction (`UNIFI_REDACT_SECRETS`, default off; with it off, no field is masked by name): credential fields in every tool response and quoted upstream error are masked, and a masked read fed back into a write leaves those fields out (`_redactedFieldsNotSent`). See [Credential redaction](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/CONFIGURATION.md#credential-redaction).

- Protect event and device-change collectors, `collect_protect_events` and `collect_protect_device_changes`: bounded-window polling tools that stand in for Protect's live event feeds, which the cloud connector does not carry. Set `poll_count` (the number of complete polls; the window is bounded by polls, never by elapsed time), `poll_interval_seconds` (the pause between polls; `0` polls back to back) and an optional `max_events` / `max_changes` early stop.

- `get_unifi_placement_snapshot`: a read-only 3D placement and topology snapshot (versioned `unifi.placement-snapshot/v1`, 120-second freshness) for floor-plan, map and dashboard consumers, built from InnerSpace, Protect and Site Manager reads. With `UNIFI_REDACT_SECRETS` on, addresses and asset URLs are left out and counted under `_withheld`. See [Placement snapshots](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/README.md#placement-snapshots) and the field reference in [docs/TOOL-USAGE.md](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOL-USAGE.md#placement-snapshot-fields).

- `unifi-fabric-mcp placement-snapshot --host <console>` exports the placement snapshot as JSON without starting the MCP server, and `unifi-fabric-mcp placement-snapshot-preflight --host <console>` reports whether the four required sources are granted (nonzero exit otherwise). Both follow `UNIFI_REDACT_SECRETS` like the tool and never print a secret.

- `forget_device` removes one or more adopted or pending devices from the controller by MAC, as the UI's "Forget device" does, and replaces the removed `reject_pending_device`. A list of MACs returns `{byMac, forgotten, errors}`. It is destructive and honours `UNIFI_READ_ONLY` and `UNIFI_DRY_RUN`.

- New optional, pass-through parameters (sent verbatim, only when given): `get_camera_snapshot` `channel` and `high_quality`; `get_isp_metrics` `duration`, `begin_timestamp`, `end_timestamp`; `list_devices` `time`; `list_all_devices` `host_ids` and `time`; `list_all_clients` `filter`; `get_site_inventory` `device_filter` / `client_filter`; `delete_network` and `delete_wifi_broadcast` `force`; `upload_protect_file` `content_type` (overrides the MIME type derived from the extension); `list_carrier_subscribers` `limit` (a total) / `cursor` (a native page; the default drains); `params` on `fabric_connector_post`, `fabric_connector_put`, `fabric_connector_patch` and `fabric_connector_delete` (also sent with the read-before / read-after); and `filter` on `list_firewall_zones_proxy`, `list_acl_rules`, `list_dns_policies`, `list_traffic_matching_lists`, `list_vpn_servers`, `list_site_to_site_tunnels`, `list_radius_profiles`, `list_hotspot_vouchers`, `list_countries`, `list_dpi_categories`, `list_dpi_applications` and `list_pending_devices`.
- New `offset` on `list_acl_rules`, `list_countries`, `list_pending_devices`, `list_site_to_site_tunnels` and `list_traffic_matching_lists`; new `limit` and `offset` on `list_wan_interfaces` and `list_wifi_broadcasts`. Network `limit` alone gathers a total with boundary verification; explicit `offset` fetches one native page. New `limit` and `offset` on `list_mobility_clients` and `list_mobility_devices` gather `limit` records starting at `offset`; offset alone fetches a native page. Repeated oversized pages cannot prove a nonzero requested window complete.
- `list_clients` `source` (`v2` reads the controller's v2 active-client list) with `include_traffic_usage`, `include_unifi_devices` and `include_matter_thread_clients`; `list_known_clients` `source` (`v2`) with the same three flags, `only_blocked`, `only_non_blocked` and `within_hours`; `get_innerspace_project` `user_email` and `site_id` (legacy project route). New tools `list_guests` (`source`) and `list_network_events` (`view`, `vpn_user_id`) take the same kind of options. `list_guests`, `get_system_log`, `list_network_events` and `list_ips_events` return a scalar upstream response verbatim.
- `get_controller_stats`, `get_observability_site_health` and `list_network_anomalies` add an epoch-unit `_warnings` entry beside the unchanged upstream body.
- `key_label` on `list_hosts`, `list_sites`, `list_sdwan_configs` and `list_devices` selects one API key; `page_size` on `list_hosts`, `list_sites` and `list_devices` returns that many records, gathered across pages.
- `get_innerspace_asset` `metadata_only` leaves out the image bytes: the result keeps its other keys (`_plan_id`, `_filename`, `path`, `content_type`, `size_bytes`) and `image_base64` is null.
- `update_carrier_subscriber` `clear_fields` clears nullable fields (`name`, `email`, `notes`, `service_address`, `plan_id`) by sending JSON null; `subscriber_number`, `metadata`, or a field that also has a value fail before any request.
- The connector relay preserves upstream `contentType`, charset-decoded text, and binary `bodyBase64`/`sizeBytes` responses for writes and read-before/read-after calls.
- Tool-list cache hints allow 300-second public reuse on MCP protocol 2026-07-28; `UNIFI_MCP_CACHE_TTL=0` disables reuse.
- Packaging adds PyPI metadata and a Homebrew formula template. A maintainer must set the release-archive checksum and publish a tap before Homebrew installation is available.

- In the tools added in this release, every object parameter without a published body shape says "Free-form object." in its description, and the Protect event and case tools open each description with a complete sentence.
- `list_local_sites` refreshes the console's cached site list after a complete, unfiltered drain, so `site` arguments resolve added, renamed or removed sites without waiting for the cache to expire; a manual page, a filtered listing or an incomplete drain leaves the cache unchanged.
- Writes answered by HTTP 502, 503 or 504, or failing in transport after the request was sent, keep the upstream status and body and append a warning that the outcome is unknown, the write was not retried, and which read tool verifies it. A failure before the request is sent (connect error, connect or pool timeout) is not reported as an unknown outcome, and read-POST queries are not writes.
- `create_carrier_subscriber` reports each field it sent under `changed` (`{from: null, to: value}`), an empty `metadata` included.
- With several API keys configured, `list_devices` with `host` reports the key that owns the console in `_key_labels`, like the multi-key listings.
- `search_across_sites` matches carry `_hostId` (their console), and `_keyLabel` when several API keys are configured, as `list_all_clients` records do.
- `get_device_port_state` refuses a negative `port_idx` before resolving the host or reading the device (0.6.2 read the device first, then reported the port missing); port `0` stays valid.
- API-source selection (`UNIFI_DISABLE_API_SOURCES`, opt-in; unset enables all): comma-separated selectors match any level of `<app>/<source>/<access>` (e.g. `network`, `network/private`, `network/private.classic`, `protect/write`, `*/write`, `*/private`) and omit covered tools. Disabled private dependencies also omit officially classified tools; disabling Protect official reads omits `get_unifi_placement_snapshot`. Connector tools are `relay/generic`: `relay` or `*/generic` omits all; `fabric_connector_get` is `relay/generic/read`, omitted by `*/read` or `relay/read`, kept by `*/write`. Unknown/repeated selectors fail startup with valid values; `UNIFI_READ_ONLY` is independent. See [API-source selection](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/README.md#api-source-selection-unifi_disable_api_sources).

- The Protect camera analytics, playback-history and recording-deletion tools add an epoch-unit `_warnings` entry only when the window's `start` or `end` is negative or looks like epoch milliseconds; a plausible window returns the upstream body unchanged.

- The device-command firmware and backup listings and the speed-test status read are read tools: `UNIFI_READ_ONLY` and `UNIFI_DRY_RUN` both send their Classic read command once and return the result. Only the exact command is a read (`list-available` or `list-cached` on `cmd/firmware`, `list-backups` on `cmd/backup`, `speedtest-status` on `cmd/devmgr`, with no other body field); every other command on those routes stays a write that dry-run previews and read-only refuses.

- Delete and revoke tools added in this release (Network, InnerSpace and Protect) return the same `{deleted: true, message, response}` result as every other delete tool, with the upstream body verbatim under `response`; a dry run returns `{status: "dry_run", deleted: false, message, response}` and sends nothing.

- The request-body shapes that tool input schemas declare (new in this release; see Changed) describe every field at every depth of nesting, including variant-specific types, required fields and enum choices and the fields the published API specification leaves undescribed, for example the fields of the `policy` argument of `create_firewall_policy` and `update_firewall_policy`.

- Agent skills: six workflow skills in `skills/`, also shipped in the Claude Code plugin: firewall zone and policy audit with a policy-order change, network and VLAN read-modify-write, device and client troubleshooting before any restart, Protect camera and event review, Wi-Fi radio change with the DFS wait, and a site health report. Each skill reads before it writes, shows the operator the exact change, uses a tool's dry-run preview where it has one, and reads back afterwards.

- Every tool parameter whose object or array structure the input schema leaves open (an object without fields, an array without item types, or a value that may be one of several types) now states its shape as a `Shape:` outline in its description, derived from the API specification or, where none is published, from the keys the server reads and sends; input validation is unchanged.

- Signed release images: public release images are signed keylessly with Cosign and carry an SPDX SBOM attestation and a GitHub build-provenance attestation; `docs/VERIFY-IMAGE.md` shows how to verify the digest.

- Console selectors now resolve reported MAC addresses and site internal-reference slugs; console names also tolerate collapsed internal whitespace. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/34, based on work by @SvenVanderwegen.

- `UNIFI_DISABLED_TOOL_FAMILIES` removes selected tool families after the allowlist and validates slugs at startup. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/39.

- Audit records now include tool, resolved host/site and duration fields, and `/dev/stderr` is documented for containers. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/40.

- `get_fleet_summary` adds `_keyTotals` when it covers several API keys: each answering key's host, site and device counts (with the status and type breakdowns), summing to the fleet totals; a console visible to several keys counts under the first key in configuration order, and a key that failed is listed under `errors` only. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/33, based on work by @SvenVanderwegen.

- Dry-run previews include `keyLabel`. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/38.

- Opt-in secret redaction recognizes common camelCase credential field names and inactive read-POST capture recipes document flow-query evidence collection. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/36, based on work by @SvenVanderwegen.

- Traffic-flow selectors use the console's epoch-millisecond timestamp window and list-valued filters, verified live 2026-10-26. Explicit body keys take precedence. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/36, based on work by @SvenVanderwegen.

- Every tool advertises all four MCP annotation hints, derived from its upstream routes: `readOnlyHint` and `destructiveHint` (every write is destructive), `idempotentHint` (true for reads and for writes whose only verb is PUT or DELETE) and `openWorldHint` (false only for tools that read local state). `docs/TOOLS.md` lists each tool's hints.

- The container image is published for `linux/arm64` as well as `linux/amd64` under the same tags. Each platform is built natively, and each platform's image is started and must answer an MCP `initialize` request before the release publishes it. The signature and attestations cover the multi-platform image index.

- Added Cursor and VS Code setup: one-click install links for both, the configuration file each client reads, and a stdio entry that runs the published container image. The smoke test sends protocol version `2024-11-05`, the version the README and the Docker guide use.

- The public release workflow also builds on a pushed `v*` tag and names the image after the repository it runs in, so a fork publishes its own images to its own GHCR namespace. Thanks to @elliotmatson (https://github.com/swkstudios/unifi-fabric-mcp-server/pull/30) for the fork-friendly release workflow suggestions.

- A size argument asks for that many records, gathered in requests no larger than the console's per-page maximum; the result holds that many records (or all, when fewer exist) and carries `_pageSize` with the requested and sent sizes. Tools: Network offset lists; Carrier Fabric `list_carrier_subscribers`; Mobility `list_mobility_devices` and `list_mobility_clients`; Protect `list_recognition_groups` and `list_recognition_detections`; Site Manager `list_hosts`, `list_sites` and `list_devices`; and the new Protect case-activity, controller site-overview, Teleport invitation, system-log and traffic-flow query and export tools.

- Console lookup by MAC address also matches a console whose long composite id starts with the MAC and which reports no MAC of its own. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/34, based on work by @SvenVanderwegen.

- Dry-run previews carry `sent: false` beside `status: "dry_run"` and `dryRun: true`, and the descriptions of the device, client, InnerSpace, Matter, RADIUS, scheduled-task, site, system-log, VPN-client, Network and Protect write tools name it. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/38. Rehearsal clean-tree overlays no longer emit a false apply warning.

- Traffic-flow queries and exports with a body `pageSize` above 5000, the largest page the console accepts, now return every result, fetched as pages of 5000 and drained, instead of the console's HTTP 400; the result carries `_pageSize` with the requested and sent sizes. A `pageSize` of 5000 or less is sent as given. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/36, based on work by @SvenVanderwegen.

- With `UNIFI_REDACT_SECRETS` on, string-valued `acctServerSecret`, `authToken`, `hashedPassword`, `wpaPsk`, SAE passwords and cloud device authentication material are masked. Pagination cursors (`nextToken`, `next_token`, `pageToken`, `page_token`, `continuationToken`, `continuation_token`) stay usable; exactly named credential fields holding null or an empty string stay unchanged. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/37.

- `docs/TOOLS.md` opens with a generated tool access index: every tool with its family and whether it reads or writes. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/35.


- With `UNIFI_READ_ONLY=1` the catalog lists the read tools plus `fabric_connector_get` (annotated `readOnlyHint` false because it can reach state-changing GET routes): write and action tools are hidden from `tools/list` in full mode and from discovery search, descriptions and family counts, and one called by name still gets the audited read-only refusal. Writes remain enabled by default. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/39.

- An area write opt-out set to `0` (`UNIFI_ENABLE_NETWORK_WRITE`, `UNIFI_PROTECT_MUTATIONS_ENABLED`, `UNIFI_ENABLE_MOBILITY_WRITE`, `UNIFI_ENABLE_CARRIER_FABRIC_WRITE`, `UNIFI_ENABLE_INNERSPACE_WRITE`, `UNIFI_ENABLE_CONNECTOR_WRITE`) hides that area's write tools from `tools/list` and discovery; read tools stay listed, and a hidden write called by name is still refused, naming the variable, and audited. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/39.

- Tool families are 13 product areas (`site_manager`, `network`, `firewall`, `devices`, `clients`, `hotspot`, `vpn`, `statistics`, `protect`, `innerspace`, `mobility`, `carrier`, `connector`), with `firewall` assigned by route. `UNIFI_TOOL_FAMILIES` advertises only the named families and `UNIFI_DISABLED_TOOL_FAMILIES` leaves families out after it; both take names separated by commas or whitespace in any letter case, and an unknown name fails startup listing the valid families. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/39.

- Traffic-flow queries are available in read-only mode and run normally in dry-run mode, backed by live query and configuration-digest evidence. Suggested by @elliotmatson in https://github.com/swkstudios/unifi-fabric-mcp-server/pull/36, based on work by @SvenVanderwegen.

- Traffic-flow exports send the Network UI's export Accept header for CSV responses, the per-application traffic-rate query documents its start/end query, and multicast-insight client and history queries pass their JSON bodies through unchanged. The pinned UI exposes both multicast routes; their minimum supported firmware remains unverified.

- Opaque cursor continuations retain their original physical size when callers change requested counts. Full final native cursor and numbered pages report their returned count explicitly; paging metadata records every actual request size separately from the observed console size. Traffic-flow continuations carry a logical record offset so changed sizes remain contiguous.

- Honour explicitly configured page caps for requested totals, including mobility, and validate system-log paging before sending a request. Private Protect events and detection searches preserve an explicit limit as one native request when no clamp is measured; unbounded drains follow short pages to an empty page or an upstream total. A `page_size` window that meets a repeated short page (a clamping console) is marked incomplete, never complete.

- The new `get_protect_case_activity` list uses `page` with `page_size=N` to select records `[(page-1)*N, page*N)`: exactly N when that many exist, fewer only at the end, never more. Resume from `_nextPage` with the same `page_size`; `page` without `page_size` returns one native console page.

- MCP Registry support: `server.json` metadata and the README `mcp-name` marker make the server discoverable.

- `update_predefined_firewall_policy` keeps the controller's complete refusal to replace a system-defined firewall policy and adds a hint to use `patch_firewall_policy` for its `loggingEnabled` setting.

- `create_camera_shortcut` and `update_camera_shortcut` describe the body Protect accepts: one array item with `placement` and `shortcut`, and a webhook shortcut carrying null `headers`, `body` and `auth`.

- `extend_guest` documents that the controller can store `qos_usage_quota: -1` on an extended guest record.

- A `page_size` window recognises a repeated page by record identity, so a console that clamps the page size and ignores the page number is reported incomplete even when a live field, such as a client count, changes between answers. Numbered and linked windows count each record once, even when a page repeats it.

### Changed

- Invalid voucher filters fail before host resolution; affected: `bulk_delete_hotspot_vouchers`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-086).

- Dry-run results include `status: "dry_run"`; affected: every write tool. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-087).

- `list_clients` and `list_known_clients` take an optional `source` (`v2` reads the controller's v2 active-client list); affected: `list_clients`, `list_known_clients`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-088).

- `get_site_statistics`, `get_site_health_summary` and `compare_site_performance` add an `_healthSummary` digest beside the unchanged body; affected: those three tools. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-089).

- `list_firewall_rules` and `get_firewall_rule` are documented as legacy, read-only; affected: those two tools. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-090).

- `get_innerspace_project` accepts optional `user_email` and `site_id`; affected: `get_innerspace_project`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-091).

- Caller-supplied credentials are always scrubbed from logs and audit lines, and from errors and failed or partial write results only with `UNIFI_REDACT_SECRETS`; affected: server-wide credential-bearing arguments. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-092).

- Uvicorn access logging is disabled for every HTTP transport; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-001).
- Breaking: image tools add MCP image content beside the unchanged metadata fields; affected: `get_camera_snapshot`, `get_recognition_group_image`, `get_thumbnail`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-002).
- The spec-drift watcher reports contract and breaking changes in the published API specs even without a version bump; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-003).
- Every tool explicitly advertises its title, read-only hint and destructive hint, both derived from the server's one read/write classification (values under "Tool annotations" below); affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-004).
- Enum shape notes include every allowed value; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-005).
- Claude installation guidance distinguishes Claude Code plugins from Claude Desktop and web or mobile connections; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-006).
- The README is a front page with a three-step Quick Start and a "Choose your client" table; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-007).
- Documentation corrections to the Claude Code setup files, the OAuth scope wording and the TLS notes; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-008).
- Arguments are refused before the request only for the server's own selector syntax, a constraint the vendored spec states, a closed set of values probed on a live controller, or JSON; a negative or millisecond-looking epoch is sent with a `_warnings` entry (an array result moves under `result`); affected: `create_port_forward`, `create_traffic_route`, `create_traffic_rule`, `get_historical_stats`, `list_client_sessions`, `list_protect_events`, `list_recognition_detections`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-009).
- Explicit-page requests to `list_protect_events` and `list_recognition_detections` follow the upstream page's shape; affected: `list_protect_events`, `list_recognition_detections`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-010).
- Selector resolution against an incomplete device or client enumeration carries its provenance into the tool result when matching a MAC; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-011).
- Breaking: `_incompleteReason` is returned for partial selector resolutions in 14 existing tools; affected: `compare_site_performance`, `execute_client_action`, `execute_device_action`, `execute_port_action`, `get_client`, `get_device`, `get_device_statistics`, `get_site_health_summary`, `get_site_inventory`, `locate_device`, `restart_device`, `search_across_sites`, `unadopt_device`, `upgrade_device`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-012).
- Classic device-tag memberships and port-profile exclusions validate upstream arrays and string elements before deriving writes; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-013).
- Numbered pagination follows continuation links through empty pages, including Recognition detections and groups; opt-in page caps retain incomplete-result provenance; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-014).
- Aggregation and site search collapse equivalent hex-case host IDs across configured keys, retaining the first configured key and upstream record; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-015).
- Historical Protect event drains preserve the upstream array key and first-page envelope fields; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-016).
- Placement preflight reports auth_denied when both InnerSpace fallback paths return 403; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-017).
- Mobility workspace selectors point to workspace_id from list_mobility_workspaces; affected: `list_mobility_workspaces`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-018).
- Tool input schemas describe 40 pinned-spec body shapes; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-019).
- Breaking: `list_protect_events` no longer sends `orderDirection=ASC` when `order_direction` is omitted, so the upstream's own order applies; pass `order_direction="ASC"` for the 0.6.2 oldest-first order; affected: `list_protect_events`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-020).
- The default gateway slug of the catalog audit is `unifi-fabric`; set `--gateway-slug` to compare another slug; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-021).
- Breaking: Protect object reads reject non-object bodies; affected: `get_alarm_hub`, `get_bridge`, `get_camera`, `get_chime`, `get_fob`, `get_light`, `get_link_station`, `get_liveview`, `get_nvr`, `get_protect_application_info`, `get_protect_user`, `get_recognition_group_counts`, `get_relay`, `get_rtsps_stream`, `get_sensor`, `get_siren`, `get_speaker`, `get_ulp_user`, `get_viewer`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-022).
- Breaking: Carrier service-plan and InnerSpace lists keep upstream keys; affected: `list_carrier_service_plans`, `list_innerspace_access_points`, `list_innerspace_floor_plans`, `list_innerspace_inventory`, `list_innerspace_switches`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-023).
- Breaking: no result invents a top-level key; affected: 42 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-024).
- Every tool description states its result shape, the Protect reads included; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-025).
- **Breaking (tool results): Classic REST tools and stat reads return the controller's `{meta, data}` body verbatim.** `meta` is relayed as received; tools that select records narrow `data`, and convenience views are `_` keys; affected: 43 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-026).
- **Breaking (tool results): the single-object reads return the upstream body verbatim.** `get_host`, `get_sdwan_config` and `get_sdwan_config_status` return `{data, httpStatusCode, traceId}` (they returned only `data`); the other single-object reads return the body as received. Read the resource at `data`; affected: `get_carrier_service_plan`, `get_carrier_subscriber`, `get_host`, `get_innerspace_project`, `get_mobility_device`, `get_sdwan_config`, `get_sdwan_config_status`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-027).
- **Breaking (tool results): `get_isp_metrics` and `query_isp_metrics` return the upstream body verbatim and cover every configured API key.** `get_isp_metrics` returns `{data, httpStatusCode, traceId}` and `query_isp_metrics` returns `{data: {metrics, ...}, httpStatusCode, traceId}`; affected: `get_isp_metrics`, `query_isp_metrics`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-028).
- **Breaking (tool results): `get_site_health_summary` returns the Classic `/stat/health` envelope verbatim** (was `{health, count}`), so `meta` (including `rc: "error"`) reaches the caller; `compare_site_performance` entries are those envelopes plus `_siteLabel`; affected: `compare_site_performance`, `get_site_health_summary`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-029).
- **Breaking (tool results): `list_traffic_rules` returns the v2 API's bare array verbatim** (was `{data, count}`), like `list_traffic_routes`; affected: `list_traffic_routes`, `list_traffic_rules`, `list_wan_interfaces`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-030).
- **Breaking (tool results): six Network Integration lists return the drained list `{data, totalCount}` instead of the first page.** They now drain every page, with `incomplete: true` and `incompleteReason` when a drain stopped short; affected: `list_acl_rules`, `list_countries`, `list_pending_devices`, `list_site_to_site_tunnels`, `list_traffic_matching_lists`, `list_wifi_broadcasts`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-031).
- **Breaking (tool results): a drained list's `totalCount` is the upstream total or `null`, never a computed count.** 0.6.2 put the number of records gathered (`len(data)`) in `totalCount` whenever it had no upstream total. Use `len(data)` for the records returned; affected: `list_clients`, `list_dns_policies`, `list_dpi_applications`, `list_dpi_categories`, `list_firewall_policies`, `list_firewall_zones_proxy`, `list_hotspot_vouchers`, `list_lags`, `list_local_sites`, `list_mc_lag_domains`, `list_networks`, `list_radius_profiles`, `list_site_devices`, `list_switch_stacks`, `list_vpn_servers`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-032).
- **Breaking (tool results): `list_devices` counts devices and `list_all_devices` returns device objects.** `list_devices` still returns the `/v1/devices` per-console wrappers verbatim, but `_count` is now the number of devices (0.6.2 `count` counted consoles) and `_consoleCount` the number of wrappers; affected: `list_all_devices`, `list_devices`, `search_device_fleet`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-033).
- **Breaking (tool results): every delete tool returns `{deleted: true, message, response}`.** The upstream DELETE body is verbatim under `response` (decoded JSON, raw text, or `null`); affected: `bulk_delete_hotspot_vouchers`, `delete_acl_rule`, `delete_arm_profile`, `delete_device_tag`, `delete_dns_policy`, `delete_firewall_policy`, `delete_firewall_zone_proxy`, `delete_hotspot_operator`, `delete_hotspot_voucher`, `delete_network`, `delete_port_forward`, `delete_rtsps_stream`, `delete_site_to_site_tunnel`, `delete_traffic_matching_list`, `delete_traffic_route`, `delete_traffic_rule`, `delete_vpn_server`, `delete_wifi_broadcast`, `unadopt_device`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-034).
- **Breaking (tool results): every Protect write and action tool returns `{status, response}`.** The upstream body is verbatim under `response` (JSON, text or `null`); affected: `alarm_hub_trigger_output`, `create_arm_profile`, `create_liveview`, `create_rtsps_stream`, `disable_arm`, `disable_camera_mic_permanently`, `enable_arm`, `pos_ingest_transaction`, `ptz_goto_preset`, `ptz_patrol_start`, `ptz_patrol_stop`, `relay_activate_output`, `siren_play`, `siren_stop`, `siren_test_sound`, `speaker_test_sound`, `start_talkback_session`, `trigger_alarm_webhook`, `upload_protect_file`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-035).
- Breaking: every Protect update tool returns one shape; affected: `update_alarm_hub`, `update_arm_profile`, `update_arm_profile_settings`, `update_bridge`, `update_camera`, `update_chime`, `update_fob`, `update_light`, `update_link_station`, `update_liveview`, `update_relay`, `update_sensor`, `update_siren`, `update_speaker`, `update_viewer`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-036).
- **Breaking (tool results): the three Mobility writes return `{status, changed, verified, device, response}`.** `changed` maps each sent field to `{from, to}` and `verified` is a map of field to bool, with a per-field null for unobservable fields (DHCP fields and password), or null when the read-after fails; affected: `update_mobility_device_name`, `update_mobility_device_network`, `update_mobility_device_wireless`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-037).
- Breaking: the seven Carrier Fabric writes embed bodies verbatim; affected: `assign_carrier_subscriber_plan`, `attach_carrier_subscriber_host`, `create_carrier_subscriber`, `detach_carrier_subscriber_host`, `resume_carrier_subscriber`, `suspend_carrier_subscriber`, `update_carrier_subscriber`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-038).
- **Breaking (tool results): an opted-out write area raises instead of returning `{status: "disabled", reason}`.** With `UNIFI_PROTECT_MUTATIONS_ENABLED`, `UNIFI_ENABLE_MOBILITY_WRITE` or `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` falsey, every write tool of the area fails before any request, naming the variable and the value that re-enables it; affected: 50 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-039).
- **Breaking (tool results): port-profile network fields are the controller's own values.** 0.6.2 replaced `excluded_networkconf_ids`, `native_networkconf_id` and `voice_networkconf_id` with `{id, name, vlan}` objects; they are now the bare ids again, with the resolution under `_resolved_networks`; affected: `allow_network_on_port_profile`, `exclude_network_on_port_profile`, `get_port_profile`, `list_port_profiles`, `update_port_profile`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-040).
- Breaking: `create_network` reports its warnings under `_warnings` (was `warnings`) and returns the created network verbatim; affected: `create_network`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-041).
- **Breaking (tool results): `create_vpn_server`, `update_vpn_server` and `create_radius_profile` return the upstream body verbatim** (0.6.2 unwrapped `data`), and send only the fields the caller passed: `create_vpn_server` `enabled` and `create_radius_profile` `acct_server_port` now default to unset; affected: `create_radius_profile`, `create_vpn_server`, `update_vpn_server`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-042).
- **Breaking (tool routes, inputs and results): the device-tag, VPN-server, site-to-site-tunnel, RADIUS-profile-create and WAN-update writes use the routes the controller's UI uses, and work (all 11 writes always failed in 0.6.2); affected: `create_device_tag`, `create_radius_profile`, `create_site_to_site_tunnel`, `create_vpn_server`, `delete_device_tag`, `delete_site_to_site_tunnel`, `delete_vpn_server`, `list_device_tags`, `update_device_tag`, `update_site_to_site_tunnel`, `update_vpn_server`, `update_wan_interface`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-043).
- **Breaking (tool route, input and result): `list_device_tags` lists the tags the Network UI shows.** The Integration route it read answers empty on Network 11.0.81 and its ids are not the `_id` the tag writes take. It now reads the v2 device-tags route and returns that bare array; the tool takes no `filter`; affected: `list_device_tags`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-044).
- **Breaking (device tools): `locate_device` and `upgrade_device` use the Classic device manager** (`cmd/devmgr` `set-locate` / `unset-locate` / `upgrade`), accept a device UUID or MAC and return the Classic envelope; affected: `locate_device`, `restart_device`, `upgrade_device`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-045).
- **Breaking (tool input): `approve_pending_device` requires `ignore_device_limit` and adopts by MAC.** It posts the spec's adoptDevice request (`POST /v1/sites/{siteId}/devices` with `macAddress` and `ignoreDeviceLimit`); `device_id` is the pending device MAC. Pass `ignore_device_limit: false` for an ordinary adoption; affected: `approve_pending_device`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-046).
- **Breaking (tool input): `execute_client_action` accepts only `AUTHORIZE_GUEST_ACCESS` and `UNAUTHORIZE_GUEST_ACCESS`** (the spec's actions); affected: `execute_client_action`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-047).
- **Breaking (tool input): `bulk_delete_hotspot_vouchers` requires `filter` in `filter_params`** (the spec marks it required); without it the call fails before any request; affected: `bulk_delete_hotspot_vouchers`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-048).
- Breaking: `get_setting` and `update_setting` reject a `setting_key` with characters other than letters, digits, `-` and `_`; affected: `get_setting`, `update_setting`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-049).
- Breaking: manual `offset`/`limit` values are forwarded unchanged; affected: `list_carrier_subscribers`, `list_clients`, `list_devices`, `list_firewall_policies`, `list_firewall_zones_proxy`, `list_hosts`, `list_lags`, `list_local_sites`, `list_mc_lag_domains`, `list_mobility_clients`, `list_mobility_devices`, `list_networks`, `list_protect_events`, `list_recognition_detections`, `list_recognition_groups`, `list_sdwan_configs`, `list_site_devices`, `list_sites`, `list_switch_stacks`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-050).
- Breaking: 97 of the 282 tools present in both versions change their input schema; affected: 97 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-051).
- Breaking: explicit null forwarding for Carrier and Mobility fields: `update_carrier_subscriber` forwards explicit null for `name`, `email`, `notes`, `service_address` and `plan_id`, `update_mobility_device_network` for `host_address`, `dhcp_mode`, `dhcp_range_start`, `dhcp_range_stop` and `dhcp_lease_time`; omitted fields stay omitted, and Mobility verification uses per-field null for unobservable fields (DHCP fields and password); affected: `update_carrier_subscriber`, `update_mobility_device_network`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-052).
- Breaking: no unrequested gates; write areas default on; `confirm` is accepted and ignored for every tool that required `confirm=true` in 0.6.2 (the arm-profile, Mobility and other guarded writes); affected: 42 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-053).
- Breaking: only a GET is retried on HTTP 429; affected: 122 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-054).
- **Breaking (behavior): `create_carrier_subscriber` never creates under the first configured key by default.** With several keys and no `key_label`, it routes to the key that owns `plan_id`, or fails before any request when there is no `plan_id`; affected: `create_carrier_subscriber`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-055).
- Breaking: `get_historical_stats` sends `attrs` only when given; affected: `get_historical_stats`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-056).
- **Breaking (tool results): org-scoped and fleet tools merge every configured API key.** 0.6.2 queried one key; without `key_label` these tools now merge every key (records tagged `_keyLabel`, per-key failures under `errors`); affected: `get_fleet_summary`, `get_sdwan_config`, `get_sdwan_config_status`, `list_all_clients`, `list_all_devices`, `list_all_sites_aggregated`, `list_carrier_service_plans`, `list_carrier_subscribers`, `list_devices`, `list_hosts`, `list_mobility_admins`, `list_mobility_clients`, `list_mobility_devices`, `list_mobility_workspaces`, `list_sdwan_configs`, `list_sites`, `search_across_sites`, `search_device_fleet`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-057).
- Breaking: with several API keys, a manual page needs `key_label`; affected: `list_carrier_subscribers`, `list_devices`, `list_hosts`, `list_sdwan_configs`, `list_sites`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-058).
- Breaking: `list_protect_events` keeps the controller's `sensor` field (the resolved id is now under `_resolved_sensor`), and the image tools report the upstream Content-Type, or `null` when none is sent; affected: `get_camera_snapshot`, `get_innerspace_asset`, `get_recognition_group_image`, `get_thumbnail`, `list_protect_events`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-059).
- Breaking: host and site resolution never guess; an unknown host or site fails listing the valid choices (0.6.2 fell back to the default key or the first match); affected: 276 tools, listed in the migration guide and tool catalog ([tool categories](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#tool-categories)). [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-060).
- Breaking: arguments are validated before any request; affected: `allow_network_on_port_profile`, `exclude_network_on_port_profile`, `get_device`, `get_device_statistics`, `get_sdwan_config`, `get_sdwan_config_status`, `list_client_sessions`, `list_devices`, `list_dpi_applications`, `list_dpi_categories`, `list_recognition_detections`, `locate_device`, `pos_ingest_transaction`, `query_isp_metrics`, `search_across_sites`, `upgrade_device`, `upload_protect_file`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-061).
- Breaking: update tools refuse a body with nothing to change; affected: 58 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-062).
- **Breaking (behavior): no-op and verification checks compare leaf by leaf, type-strictly.** The Protect updates, `update_arm_profile`, `update_setting`, the Carrier Fabric and Mobility writes compare only the leaves the request names, and `1` no longer equals `true`, so such a call now writes instead of returning `noop`; affected: `assign_carrier_subscriber_plan`, `attach_carrier_subscriber_host`, `detach_carrier_subscriber_host`, `fabric_connector_delete`, `fabric_connector_patch`, `fabric_connector_post`, `fabric_connector_put`, `resume_carrier_subscriber`, `suspend_carrier_subscriber`, `update_alarm_hub`, `update_arm_profile`, `update_arm_profile_settings`, `update_bridge`, `update_camera`, `update_carrier_subscriber`, `update_chime`, `update_fob`, `update_light`, `update_link_station`, `update_liveview`, `update_mobility_device_name`, `update_mobility_device_network`, `update_mobility_device_wireless`, `update_relay`, `update_sensor`, `update_setting`, `update_siren`, `update_speaker`, `update_viewer`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-063).
- Breaking: a call that reached nothing fails (`search_across_sites` and `list_all_clients` raise when no site could be queried, and the multi-key tools raise when every key or site fails; 0.6.2 returned an empty or error-only result); affected: 117 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-064).
- Breaking: the per-area write opt-outs apply to relayed writes; affected: `fabric_connector_delete`, `fabric_connector_patch`, `fabric_connector_post`, `fabric_connector_put`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-065).
- **Breaking (container image): streamable HTTP is stateless by default.** The image sets `FASTMCP_STATELESS_HTTP=true`, so no `Mcp-Session-Id` is sent and no per-client session is kept; set it to `false` for sessions (pip, uvx and Homebrew installs are unchanged); affected: the container image. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-066).
- **Breaking (CLI): `unifi-fabric-mcp` reads its command line.** An unknown subcommand exits with status 2 (0.6.2 started the server for any argument); affected: the `unifi-fabric-mcp` command. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-067).
- Breaking: a 3xx upstream response is an error; affected: all MCP tools. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-068).
- **Breaking (configuration): settings that would hang or fail later fail at startup, naming the variable.** Duplicate API key labels are rejected (0.6.2 sent the second key's calls with the first key); affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-069).
- **Breaking (configuration): credentials are validated at startup without showing the value.** `UNIFI_API_KEY`, every `UNIFI_API_KEYS` key and `MCP_BEARER_TOKEN` must be printable ASCII with no whitespace; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-070).
- **Breaking (configuration): a malformed setting fails at startup naming the expected format or choices.** `UNIFI_API_KEYS` must be a JSON list of `{"key", "label", "is_org_key"}` objects; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-071).
- Every tool parameter carries a JSON-schema `description` (from each docstring's `Args:` section) saying where each id comes from, its id space and, for writes, the request-body shape from the published specs with a worked example; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-072).
- Tool annotations: the 328 read-only tools advertise `readOnlyHint: true` and `destructiveHint: false`; the 458 write tools advertise `readOnlyHint: false` and `destructiveHint: true`; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-073).
- Invalid-argument errors name each bad parameter with its description, list the valid parameters and show an example call; the framework's raw validation report is replaced, and a value the server's own checks refuse is quoted whole, never truncated, so the always-on scrubber masks a configured secret in it (credential fields only with `UNIFI_REDACT_SECRETS`); affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-074).
- FastMCP 4.1.4 (MCP SDK 2.3.0; `fastmcp` range `>=4.0,<5.0`, 3.x unsupported); affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-075).
- Breaking: write tools drop server-added `_` keys; affected: 115 tools other than the connector relay, which sends its body as given ([tool categories](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#tool-categories)). [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-076).
- Breaking: 70 tools no longer declare an object `outputSchema`; affected: 70 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-077).
- Connector relay: every Classic `network/api` route is reachable (`set/setting/<key>`, `upd/`, `list/`, `group/`, `api/self`, `api/stat/sites`), not only `rest`/`cmd`/`stat`; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-078).
- Dependencies (`requirements-runtime.lock`, installed by the image and the Homebrew formula): 60 hash-locked runtime packages, with no test, lint or type-check packages (those stay in `requirements.lock` for development); every pin is refreshed, including fastmcp 4.1.4, authlib 1.9.1, cachetools 7.2.4, certifi 2026.10.23, pydantic-settings 2.16.1, starlette 1.9.0, httpx2/httpcore2 2.16.0 and truststore 0.10.5; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-079).
- `httpx2>=2.13.1` is a declared dependency; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-080).
- Published container images carry the unprefixed `X.Y.Z` and `X.Y` tags alongside `vX.Y.Z` and `latest`; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-081).
- Spec-drift baseline advanced to Network Integration API v10.6.106 and Protect v7.3.70 (no implemented endpoint changed); affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-083).
- Public files no longer carry internal path references; affected: server-wide behaviour. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-084).
- Every value limit the vendored specs state for an argument or a body field it carries (`minimum`/`maximum`, lengths, `pattern`, `enum`, item counts; the limits a spec states only in prose too) is checked before any request, exactly as the spec states it (for example `siren_play` duration 5, 10, 20 or 30 and `siren_test_sound` volume 1 to 100); affected: 68 tools, listed in the migration guide. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-085).

- The `body` argument of connector write tools is declared as any JSON value; affected: `fabric_connector_post`, `fabric_connector_put`, `fabric_connector_patch`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-094).

- The container image is built without emulation for either platform and no longer sets the base image's `PYTHON_VERSION`, `PYTHON_SHA256` and `GPG_KEY` variables; affected: the container image. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-096).

- A traffic-flow drain that fails on a later page returns the gathered records with incomplete status and the page, HTTP status and upstream error; wide windows drain every page without a cap, including when global pagination is capped; affected: traffic-flow query and export callers. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-097)

- Linked-page Protect recognition lists now use `page` with `page_size=N` to select records `[(page-1)*N, page*N)`: exactly N, fewer only at the end; 0.6.2 fetched one native page. Resume from `_nextPage` with the same `page_size`; `page_size` alone now returns the first N records with `_nextPage` instead of draining every page (0.6.2 used it as the drain page size); `page` without `page_size` still returns one native page; affected: `list_recognition_groups`, `list_recognition_detections`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-101).

- Breaking: `limit` values below 1 are now refused before any request, with or without `offset` (0.6.2 sent `limit=0` upstream unchanged); omit `limit` to read the whole collection; affected: the offset-paged list tools that take `limit`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-102).

- Reorganize the README around remote UniFi management, client setup and operator safety controls; generate product and verification tables from catalog and recorded live evidence.
- Add reproducible MSP demos with synthetic data, and document client-install checks for each release.
- Support Windows and macOS in the Claude Desktop bundle, and secret-scan its unpacked contents before attaching the release artifact.

### Removed

- **Breaking (tool removed): `reject_pending_device`.** Use `forget_device`, which removes a pending or adopted device by MAC; affected: `reject_pending_device`. [Migration details](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/MIGRATING-0.7.md#change-093).

### Fixed

- `restart_device`, `locate_device`, `upgrade_device`, `unadopt_device`, `execute_device_action` and `execute_port_action` name the field `device_id` is read from: `list_site_devices` `data[].id` or `data[].macAddress`.
- A 2xx Classic response with a `meta` envelope is a success only when `meta.rc` is `"ok"`; a 2xx body with no `meta`, and a Classic success's `{meta, data}` envelope, pass through unchanged. Before, a 200 with `meta.rc: "error"` could report a rejected write as done. Every tool on a Classic route (`.../proxy/network/api/...`) now raises it as an upstream error carrying the complete body verbatim, and the audit log records `outcome=classic_rc_error`. The generic relay still reports without raising: its result keeps `status` and `body` verbatim, adds `_classicRcError`, and draws no `noOp` / `changed` verdict from a rejected write or read.

- **Breaking (connector relay): bodies are verbatim.** `fabric_connector_get`, `fabric_connector_post`, `fabric_connector_put`, `fabric_connector_patch` and `fabric_connector_delete` no longer mask keys matching password/secret/key/token as `[REDACTED]` (0.6.2 did so unconditionally) or cut non-JSON bodies at 4000 characters; masking is only the opt-in `UNIFI_REDACT_SECRETS`. A non-JSON body is the text as received (was `{"text": ...}`) and an empty body is `null`.

  Affected tools: `fabric_connector_delete`, `fabric_connector_get`, `fabric_connector_patch`, `fabric_connector_post`, `fabric_connector_put`.

- Integer arguments reject booleans (0.6.2 accepted `true` / `false` as `1` / `0`).
- Missing API keys exit with one actionable line naming `UNIFI_API_KEY` and the key creation and setup instructions, without a Python traceback. A malformed key also exits with one line naming the variable and the problem, never the value. Upstream 401 and 403 errors retain their complete body and append key-specific authentication or permission guidance for single-key and multi-key configurations. Relay errors add `_hint` alongside the unchanged body/status, including read-before/read-after failures.
- OAuth discovery publishes and validates the issuer exactly as configured, including the presence or absence of a trailing slash on a root URL.

- Write verification and no-op detection distinguish a missing response field from an explicit JSON null. Fields the pinned specifications document as omitted when unset (including Carrier Fabric subscriber `serviceAddress`) still count as cleared.
- Multi-key host resolution chooses the best match tier across all configured keys and de-duplicates host IDs case-insensitively.
- Mobility verification reports every requested field: fields absent from the documented device detail, including DHCP settings and the wireless password, report `null` rather than disappearing from the verification map.
- Multi-key list and fleet aggregation validate each key's records before merging them. A malformed record appears in that key's errors and preserves other keys' results.
- InnerSpace namespace fallbacks require the documented HTTP status and reason; matching body text on another status preserves the original error.
- Device and client resolvers reject an ambiguous MAC or id instead of choosing the first matching record.
- Port-index resolution reports malformed `port_table` collections and non-object rows as response-shape errors instead of incorrectly reporting no valid port indices.
- The connector relay checks a missing `site` before resolving the host.
- The connector relay's `noOp` needs two 2xx reads and compares only the leaves the body requests: a server-side change to an unrequested sibling is no longer reported as `changed: true`. A body-less write compares the whole reads. A DELETE is `changed: true` only when its read-after is 404 (0.6.2 could report `noOp: true`); a read-after that still returns the resource is `noOp: null` with `noOpReason` "deletion not confirmed". When the requested leaves cannot be located (text or binary reads, a multi-record list) or are absent from both reads, `noOp` is null with `noOpReason`; `changed` is present only when `noOp` is non-null.
- `upload_protect_file` sends the spec MIME types (`.wav` `audio/wave`, `.caf` `audio/x-caf`).
- **Security: configuration errors never echo a supplied value.** An invalid enumerated setting (`MCP_AUTH_MODE`, `MCP_TLS_MODE`, `MCP_TLS_CERT_REQS`) reports the valid choices without the value (0.6.2 quoted it), as do the URL, port and scope checks; `MCP_*` transport settings are validated at startup, so a malformed one is a one-line CLI error, not an import traceback.
- **A failing read-after never fails an applied write.** The verified Protect, arm-profile and Mobility writes and `update_setting` return the write's result with `verified: null` and `readAfterError` instead of raising. `verified` is `true` only when the read-after confirms every requested field; `update_setting` reports `_verified` and `_unverifiedFields`, and the connector relay's read-before / read-after never raise.

- Every list drains every page by default, including `list_wan_interfaces`, `get_site_inventory`, `search_across_sites`, `list_all_clients`, `list_all_sites_aggregated` and the MAC-to-device lookup (which reported "MAC not found" past page one). A repeated or stalled page stops with `incomplete: true` and a reason (0.6.2 could loop), keeping what was gathered, and explicit paging no longer injects `limit=25`.

- Site Manager `/v1` drains send the published `pageSize` (was `limit`; none for `list_sdwan_configs`, which defines no query parameters), and `list_devices` filters by console with `hostIds[]` (was `hostId`, which the API ignored).
- With the opt-in `UNIFI_PAGINATE_MAX_PAGES` cap: a capped console or site list still resolves exact ids gathered (a name fails as ambiguous, also with `UNIFI_CACHE_TTL_SECONDS=0`); fleet, multi-key and site tools return what was gathered with `incomplete: true` and `incompleteReason` (naming the key) instead of failing or dropping a key; and a capped list is never cached.
- `UNIFI_CACHE_TTL_SECONDS=0` (no caching) works. In 0.6.2 every call that resolved a `host` or `site` failed with a `KeyError` (`KeyError: '__default__'` for a console lookup with one key).
- Fan-out tools skip nothing silently. `search_across_sites` and `list_all_clients` report site totals, successes, failures and every skipped site or host with its reason, report sites whose drain stopped at the cap under `_sitesIncomplete` with `incomplete: true`, search every key's sites and read each console site once (a record is never returned twice). `search_across_sites` returns with any number of sites: 0.6.2 never returned once the sites numbered `UNIFI_MAX_CONCURRENCY` (default 10) or more.
- `search_across_sites` matches the Integration field names (`macAddress`, `ipAddress`), so a search by MAC or IP finds devices and clients; a null field no longer matches `none`.
- Errors are complete. Upstream error messages include the real path and full body, with only credentials masked (0.6.2 replaced ids with `[REDACTED]` and cut bodies at 500 characters); connector 403 hints are appended after the upstream reason instead of replacing it; network-layer failures name the method, path and cause (TLS, DNS, dropped connection).
- "Not found" errors list every valid choice: `get_traffic_route`, `get_vpn_server`, `get_radius_profile`, `get_arm_profile` (and `update_arm_profile` and `delete_arm_profile`, which sent the PATCH / DELETE for an unknown id), the diagnostic tools and MAC lookups; an incomplete list read says so. Every update and delete on a Classic or v2 collection (port forwards, traffic rules and routes, hotspot operators, users, Dynamic DNS, WLAN configs, port profiles) resolves its id in that list first, addresses the record by its native `_id`, and writes nothing for an unknown id (the controller answered such a DELETE with 200, reported as deleted).
- `get_historical_stats` accepts every interval (`minute`, `5minutes`, `hourly`, `daily`, `monthly`, `archive`) and scope (`site`, `ap`, `user`, `gw`, `sw`, `device`, `speedtest`, `isp`) the controller accepts; another value fails listing them.
- `get_wlan_group` works: the controller rejects `GET /rest/wlangroup/{id}` with HTTP 400 for every id, so the tool reads the collection and returns the matching group (an unknown id lists the valid groups).
- Empty list results are explicit: a tool that returned an empty bare array reached the client as `content: []` with no structured content; list results now carry a JSON text block and `structuredContent: {"result": [...]}`.
- `restart_device`, `locate_device`, `upgrade_device`, `execute_device_action`, `execute_port_action` and `unadopt_device` accept a MAC (any separator style) as `device_id`: 0.6.2 refused a colon- or dot-separated MAC as an invalid id and sent a bare or hyphenated one as the id, which answered 404. An unknown MAC fails before any command is sent, listing the site's devices.
- The MAC-to-id cache is per client, bounded, expires after `UNIFI_CACHE_TTL_SECONDS` (default 15 minutes; `0` disables it), is dropped on unadopt, forget, adopt and approve, and a cached id answering 404 is re-resolved once (writes are never re-sent).
- `create_network`'s auto-exclusion warning (`D12_AUTO_EXCLUSION`) fires: 0.6.2 compared the new network's Integration id with the port profiles' Classic `_id`s, so it never matched, and dropped a failed check silently; a failed check now reports `D12_CHECK_FAILED` with the reason. `allow_network_on_port_profile` and `exclude_network_on_port_profile` accept either network id (the Integration id or the Classic `_id`).
- Protect action tools send no body to operations that define none (`start_talkback_session`, `disable_camera_mic_permanently`, the PTZ tools, `siren_stop`, `enable_arm`, `disable_arm`, `trigger_alarm_webhook`; they sent `{}`).
- No default limits on returned data: `get_innerspace_asset` returns any image size (was 10 MiB), `get_client_link_diagnostics` accepts any number of `client_ids` (was 64), and the Carrier subscriber drain has no 10,000-page cap.
- Carrier Fabric: a write answered with a stub or non-JSON body is read back with a GET instead of being taken for the subscriber, and `detach_carrier_subscriber_host` no longer requires a JSON body.
- `update_acl_rule` sends `index` (the write sanitizer dropped it); `update_vpn_server` and `update_hotspot_operator` accept body keys named `site`, `host`, `client` or `registry` (they raised `TypeError`); `create_arm_profile` and `create_liveview` accept `name` in `settings` (identical repeat accepted, conflict rejected), and Protect update settings keys that match a parameter name are sent; `update_hotspot_operator` drops empty-string list padding; `create_hotspot_operator` sends an empty `note`; `pos_ingest_transaction` accepts a whitespace-only `externalId`.
- Tool descriptions contain no angle-bracket placeholders, which some MCP gateways reject (0.6.2's `fabric_connector_get` carried `<path>`).
- Tool description corrections: `execute_port_action` gives the action as `POWER_CYCLE` (it showed `power-cycle`); `create_firewall_policy` uses the spec enums (`ALLOW`/`BLOCK`/`REJECT`, `IPV4_AND_IPV6`; it showed `DENY` and `BOTH`); `patch_firewall_policy` allows only `loggingEnabled`.

- A success with an empty (200/204) body returns an explicit `null` result (`structuredContent: {"result": null}`); 0.6.2 raised a "Non-JSON response" error for an empty-body POST, PUT or PATCH success.
- `block_client` / `unblock_client` / `reconnect_client` on a VPN or Teleport client say it has no MAC; the MAC sent is lowercase colon form.
- A host/site list holding bare values, null entries or wrong-typed fields (`meta=123`, a numeric `hostId`, `status=["a"]`) is an actionable shape error (no `AttributeError` in the fan-out tools); one malformed site record is skipped and reported, never the whole search or resolution.
- The server instructions list `query_isp_metrics`, the connector relays, `list_dpi_*` and `list_devices` under their real required and optional `host`/`site` scope, and no longer claim `create_network` defaults the API does not apply.
- `docs/PAGINATION.md` names the real `nextToken` cursor and describes the pagination loop detection exactly; the README no longer documents the unread `UNIFI_API_VERIFY_SSL`.
- The rate-limit error says "after 1 attempt" for a single attempt and names the method upper-cased.
- Names match exact, then NFC + case-insensitive, then with edge whitespace stripped, and hex ids (UUIDs, ObjectIds, console ids) case-insensitively, wherever ids and names are matched locally; a write that matched an id that way addresses the record by the id the upstream reported, in the URL and in a body `_id` / `id` naming it, never by the caller's spelling; a site mapped by label only on a capped console site list is refused; absolute URLs and percent-encoded traversal are refused.
- `update_carrier_subscriber` with `metadata={}` on a subscriber that has no metadata (the spec omits the key) is a no-op; 0.6.2 sent the PATCH.
- A `/v1/devices` wrapper whose `devices` is not an array or null, and an InnerSpace `shapes`/`plans` entry that is not an object, raise naming the shape in the device, summary and fleet tools (0.6.2 counted such a wrapper as a device record and skipped such an entry).
- The connector relay never loses a sent write: a transform or non-text `charset` (`idna`, `unicode_escape`, `rot13`, ...) or an undecodable body returns `bodyBase64`, and any post-write failure returns the status with `postWriteError`.
- `update_arm_profile_settings` resolves the id against `list_arm_profiles` before writing, like `update_arm_profile`: an unknown id fails before any PATCH (it was sent and reported `updated`), and an upper-case hex id that is already selected is a `noop` (it was PATCHed and reported `verified: false`); the body sends the listed spelling.
- Carrier Fabric writes compare plan and host ids with the shared id rule (hex ids case-insensitively): `assign_carrier_subscriber_plan`, `attach_carrier_subscriber_host` and `update_carrier_subscriber` (`plan_id`) treat an upper-case spelling of the current id as a `no_op` and verify a write the upstream stored in its own spelling (they sent the write again and reported `verified: false`). Every subscriber write and read-back addresses the subscriber by the id the read-before reported.
- The InnerSpace project tools (`get_innerspace_project`, `get_innerspace_summary`, `list_innerspace_devices`) keep the documented path's rejection when the legacy fallback then fails differently (a 403 followed by a 404 raised only the 404): the error now carries both upstream errors.
- `relay_activate_output` / `alarm_hub_trigger_output` accept `output_id` as the spec integer (`0` / `1`) as well as the decimal string, and `delete_rtsps_stream` accepts `qualities` as one channel string (spec `removedQualities`: a scalar or an array); 0.6.2 refused both spec forms.
- `ptz_patrol_start` describes `slot` as the patrol slot 0-4 (0.6.2 called it a preset slot).
- A console site that carries both a `description` and a `name` resolves by either one (every site and Site Manager mapping argument); before, the description hid the name. Two different sites matching through either label are still ambiguous, and a site-not-found error lists both labels.
- `fabric_connector_put` / `fabric_connector_patch` on Classic `network/api/s/{site}/rest/device/{id}` report a real `noOp` / `changed`: the controller has no GET on that route (404), so `readBefore` / `readAfter` `.body` hold the full `stat/device` list verbatim, the device's own records are in `comparisonRecords` (compared on the fields the body writes; `noOpBasis` says which), `twin` names the GET and `twinError` explains a resolution failure. 0.6.2 compared the two 404 bodies and reported `noOp: true` (`changed: false`) for a write that changed the device.
- `get_fleet_summary`, `get_site_inventory` and every bounded fan-out cancel their remaining upstream requests when one fails, instead of leaving them running after the error is returned.

- With several API keys, `list_all_clients` and `search_across_sites` report a key that failed and a site that failed in the same call together under `errors` (the failed keys first); the key error no longer lands under `_wrapperFields`.

- Documented container image tags now match the release version. Reported and fixed for 0.6.2 by @elliotmatson (https://github.com/swkstudios/unifi-fabric-mcp-server/pull/31); 0.7.0 generates the documented tags from the project version instead.

- Paging follows one shared contract across `site_manager`, `carrier_fabric` and the Network, Protect and Mobility lists: complete Network lists make no redundant terminal request; Protect requested totals and Mobility pagination metadata and totals are kept; traffic-flow queries stay contiguous across page-size clamps; `list_carrier_subscribers` continuations are retained. Classic and v2 write audit records name the resolved site.
- The `fabric_connector_*` `path` description no longer says a site value never appears in the result: `resolvedPath` reports the path as sent, with the substituted site slug or UUID; the console id and API key are never part of `path` or `resolvedPath`.
- `search_across_sites` and `list_all_clients` log only the site, request and HTTP status (or error type) when a site is skipped or a read fails, as documented for `UNIFI_LOG_LEVEL`; the result still carries the complete error.
- Server-added result keys (`_verified`, `incomplete` ...) never replace an upstream field of the same name: the upstream field stays verbatim and the server value goes in `_wrapperFields`. This covers the Protect, InnerSpace, device, system-log, firmware, fleet and Carrier Fabric tools and every partial-resolution marker; a multi-key merge keeps such a field in the key's `byKey` entry.
- Keep upstream `_redactedFieldsNotSent` values on object and array-record results when reporting dropped request fields; put a colliding server report in `_wrapperFields`. Preserve upstream metadata even on dry-run-shaped responses, and retain the fleet device envelope's field order when no keys collide.
- List pagination continues through short pages without completion evidence, and treats a repeated oversized response as a complete collection only when no total, page count or continuation shows records or pages outstanding. Offset requested windows verify a single-response continuation boundary; an ignored offset reports incomplete without a resume marker.
- Protect update no-op detection and verification recognize equivalent addressing IDs.
- `fabric_connector_delete` sends an explicit `body: null` as JSON null; an omitted body stays absent.
- `update_setting` returns the controller response when it is only partly applied or rejected, and reports read-after verification separately with the affected fields and an explanation.
- `update_port_profile` converts `native_networkconf_id`, `voice_networkconf_id` and `excluded_networkconf_ids` values given as `list_networks` Integration ids (or a unique network name) to the Classic networkconf `_id` before the PUT (0.6.2 sent them unchanged); an unknown value fails before any write, listing every network (name, `_id`, id); a stored non-string there no longer blocks it.
- Network, Protect and Site Manager tool descriptions and filter examples (including `list_sdwan_configs`) match the published contracts.

- Updated FastMCP to 4.1.4 for its session fixes: a stale client context no longer closes a newer session on the same connection, and mounted servers honor session visibility.

- Firewall policy batch deletes report verified deletions, unresolved outcomes, the failed identity and unattempted identities when a request fails.

- Fixed HTTP 421 responses behind reverse proxies and loopback sidecars introduced during 0.7.0 development. Bearer- and OAuth-authenticated servers now accept proxy Host headers by default in stateless and stateful streamable HTTP; browser Origin checks, explicit Host allowlists, and unauthenticated loopback protection remain enabled. The locked v0.6.2 release was unaffected.

- Report stalled cursors and contradictory offset pagination evidence, and avoid returning traffic flow sizing probes when window translation fails.

- Protect: reject boolean recording retention durations in `update_nvr`.

- `create_wifi_broadcast` keeps the controller's complete refusal and adds a hint to scope the SSID with `broadcastingDeviceFilter` when an access point is already at its SSID limit.

- Recognition assignment and merge retain their legacy native-body inputs alongside the typed arguments; switch-port reset retains its legacy route and body inputs.
- Legacy native query and port-reset bodies retain every supplied field and take precedence over the array alternatives.
- Nested recognition ID validation names the failing list element before any request, and argument parsing errors include the full nested argument path.
- Carrier subscriber updates preserve surrounding whitespace in the submitted subscriber number while validating its trimmed length and verifying the console's normalized value.
- Multi-switch MAC-table queries use the queries array parameter; the legacy query object schema is preserved. The canonical console command remains unifi-fabric-mcp.

- Restore the PyPI MCP Registry entry with a matching console alias; both command names launch the same server, and existing client integrations keep the canonical `unifi-fabric-mcp` command.

- Protect recognition group tools send the request bodies the Protect web app sends. `assign_detections_to_recognition_group` takes `detection_ids` and `group_id` and posts `{objectIds, groupId}`. `merge_recognition_groups` takes `to_group_id` and `from_group_ids` and posts `{fromGroupIds, toGroupId}`; it refuses to merge a group into itself.
- `query_switch_mac_tables` takes `queries` as a list of `{mac, ports}` objects and posts it as a JSON array.
- `query_app_traffic_rates` sends an empty JSON object when no body is given, as the console requires.
- `reset_switch_port` clears a port's remembered last connection. It takes `device` and a `ports` list of `{port_idx, unit_id?}` and posts to `ports/{mac}/reset`.
- The `create_camera_shortcut` description lists the field each shortcut type requires: `timeout` for a webhook, `linkedCameraId` for a linked camera and `linkedDoorId` for a linked door.

- **Carrier, Mobility, and Hotspot validation and normalization.** `update_hotspot_operator` enforces non-empty update bodies via `require_update_fields`. `list_carrier_subscribers` and Mobility `_drain` validate pagination limits and offsets, and `_drain` removes a dead branch. `update_carrier_subscriber` trims whitespace from `subscriberNumber`. `authorize_guest` normalizes `ap_mac` into colon format.
- **Virtual network updates.** `manage_virtual_network` in `network_routing_topology` assigns sanitized update leaves on update and permits identity fields on creation.
- **DPI policy validation.** `network_dpi_policy` body validation cleans update fields directly.
- **API source classification.** `authorize_guest` and `revoke_guest_access` include `network/private.classic` as a conservative fallback source.
- **Docker healthcheck.** The Docker container healthcheck dynamically respects `FASTMCP_PORT`.

- Preserve optional detection windows and periods, WiFi quick-scan bands, and PoE query parameters, forwarding legacy queries to the upstream unchanged. Supplied integer detection periods remain seconds converted to milliseconds; string periods pass through unchanged.

- Reduce peak memory when scrubbing large bodies with repeated escape sequences, while preserving secret matching and source-span masking.

- Port recovery: separate action/read-back verdicts.

- Camera shortcuts: opt-in per-type checks.

- Docs and validation errors: a registry cache TTL of 0 disables caching.

- Restore legacy switch-port reset precedence and preserve Protect lookup error bodies.

- Clarify system log paging and keep tool descriptions within client limits.
- Report an incomplete Carrier subscriber result when upstream signals more records without a usable continuation cursor.
- Preserve the single empty-array POST for empty ACL-rule and firewall-zone batch deletions.

### Security

- HTTP transports now bound request targets and header blocks before dispatch: the server's access middleware returns `414` for targets over 1024 bytes and `431` for header field blocks over 16 KiB, with a constant response body. Larger request heads get the HTTP parser's `400`. Neither path logs request bytes.

- **Security: configured secrets are scrubbed from errors and logs.** API keys, `MCP_BEARER_TOKEN` and `MCP_TLS_KEY_PASSWORD`, regardless of length, are replaced with `***` in every encoded form in transport errors, upstream error bodies and headers, tool errors, audit lines, logs and the CLI; successful (2xx) bodies otherwise remain unchanged. Startup errors and settings `repr()` no longer print `MCP_BEARER_TOKEN` or `MCP_TLS_KEY_PASSWORD`.

- **Security: malformed or hostile OAuth bearer tokens receive the standard 401 `invalid_token` response.** Missing segments, malformed base64, JSON or UTF-8, and excessive nesting are rejected in this server's preflight and FastMCP's decoding. Decoder `RecursionError` and `IndexError` failures are logged at warning level without token content, exception text or a traceback. Running out of memory is not treated as a token verdict; the HTTP server's header-size limit bounds the token.

- Startup warnings for HTTP deployments (`streamable-http`, `sse`); no posture is refused at startup. The server prints one `WARNING` line to stderr, naming the variables and a fix, when it serves HTTP on a non-loopback `FASTMCP_HOST` with no auth (the Docker image binds `0.0.0.0`); when `MCP_TLS_MODE=mtls` uses `MCP_TLS_CERT_REQS=optional` with no auth; when `MCP_BEARER_TOKEN` is shorter than 32 characters; and when `MCP_OAUTH_JWKS_URI` is plain `http://` to a host that is not loopback.
- The Docker quick start is bearer-first: the README generates a token with `openssl rand -hex 32` and sends it from the client (0.6.2's quick start ran the HTTP server with no auth). The unauthenticated variant moved to a section labelled "trusted network only". `server.json`, new in this release, declares `MCP_AUTH_MODE=bearer`, `MCP_BEARER_TOKEN` and the `Authorization` header.
- Host and Origin validation, on by default (DNS rebinding and cross-site requests). A request with no `Origin` passes. Any other `Origin` must be loopback, the `MCP_OAUTH_BASE_URL` origin or listed in the new `MCP_ALLOWED_ORIGINS`; anything else, `Origin: null` included, gets 403 naming the variable. FastMCP's Host check runs in `auto` mode, on every bind once the new `MCP_ALLOWED_HOSTS` is set (421 otherwise, naming `MCP_ALLOWED_HOSTS` so the allowlist can be corrected). `MCP_HOST_ORIGIN_PROTECTION=off` turns both off. A browser client on another origin now needs its origin in `MCP_ALLOWED_ORIGINS`.
- OAuth tokens: `exp` is required, and an `nbf` or `iat` more than 60 seconds in the future is rejected; the 401 names the claim. Before, a token with no `exp` never expired. Overflowing or non-finite `exp`/`nbf`/`iat` values get claim-specific 401s. The JWKS download is capped at 1 MiB decoded while streaming (gzip, deflate, and `br` when the optional `brotli` package is installed); a JWKS `Content-Length` is read only when it is plain ASCII digits, and one over the cap closes the response.
- OAuth scopes: the docs now state that every accepted token can call every tool. New opt-in `MCP_OAUTH_WRITE_SCOPE` (oauth mode; unset keeps today's behaviour) refuses write tools, before they run, for a token without that scope; setting it with another auth mode fails startup.
- `MCP_BEARER_TOKEN` is compared in constant time (`hmac.compare_digest`).
- Docker image: a builder stage builds the wheel with a hash-pinned `hatchling` (`requirements-build.lock`, no build isolation), and the runtime image has no pip (the base image's pip 25.0.1 had five fixable CVEs). CI scans the built image with Trivy and fails on any fixable MEDIUM or worse finding.

- The InnerSpace shared-project token in a request path (`innerspace/api/import/projects/{token}`, from `import_innerspace_shared_project` or the connector relay) is always scrubbed from logs and audit records (0.6.2's relay audit line logged the full path), and is masked in dry-run and relay metadata and in errors when `UNIFI_REDACT_SECRETS` is enabled. A connector relay GET to a known state-changing Protect route (`protect/api/cameras/{id}/enable-control` or `disable-control`) is a write: it obeys write authorization and the connector and area opt-outs, and is sent once on HTTP 429 (0.6.2 relayed it as an ungated read and retried it on 429).

- **Breaking (server credential protection):** every tool scrubs the server's own configured credentials from upstream bodies and headers, successful or error. Upstream credential fields of a successful body remain verbatim by default (field-name masking is the opt-in `UNIFI_REDACT_SECRETS`); with that opt-in, an error body also has the credential fields a route is registered to return masked as `***`, and a caller-sent credential echoed back (request body or `fabric_connector_get` query) masked by value; other error fields (e.g. `code`) stay verbatim. A dry-run preview echoes the caller's request body; with `UNIFI_REDACT_SECRETS`, its credential fields are masked like any result.

- Credentials a caller supplies (such as a Matter setup code or a device password) and the credential values a route is registered to send or return (such as a camera share link) are always scrubbed from logs and audit lines, for every tool that sends or returns one (for example `commission_matter_node`, `verify_sim_pin`, `send_test_email`, `adopt_third_party_camera`, `get_openvpn_client_config`, `get_protect_stream_url`) and for the generic connector relay. Upstream errors, error bodies, failed or partial write results and dry-run previews return them verbatim unless `UNIFI_REDACT_SECRETS` is enabled.

- Container image: the base image is now a python:3.12-slim-bookworm build whose ca-certificates package (20250419~deb12u2) distrusts the eMudhra roots named in the October 2026 CA incident (emSign Root TLS CA - G3, emSign Root CS CA - G3, emSign ECC Root CA - G3, and the Sectigo AAA Certificate Services cross-sign); the previous base still trusted two of them. The image build now fails if the runtime CA bundle trusts any of these roots (`scripts/check_ca_bundle.py`). The api.ui.com client uses certifi 2026.10.23.

- Scrub doorbell credential IDs in relay DELETE audit logs.

- **OpenVPN configuration credential redaction.** `openvpn_configuration` is recognized in `CREDENTIAL_FIELDS` and the Classic `networkconf` route secret mapping, masking OpenVPN client profile contents under `UNIFI_REDACT_SECRETS` and sanitizing test fixtures.
- **Hotspot voucher code scrub.** Hotspot voucher responses scrub the `code` field from diagnostic text and logs via route secrets without masking tool output.
- **Diagnostics and middleware error sanitization.** `device_radios` inspection errors omit full record dictionaries from exceptions. Connector read-after GET error formatting routes upstream bodies through `error_body_text` and scrubs configured secrets. Middleware tool caches avoid persisting `None` misses on unregistered tools.

- Mask access-log query values and credential fields in `protect_private` read-after and malformed-device error messages.

- Mask nested credential fields in malformed upstream identity error evidence when `UNIFI_REDACT_SECRETS` is enabled.

- `UNIFI_REDACT_SECRETS` now also masks the RADIUS server certificate private key (`server_certificate_key`) and the per-device `syslog_key`.

- SECURITY.md: vulnerability reporting, authentication, default redaction posture.

- Fix write verification, failed-action reporting, relay reads, paging, dedupe, validation, error hints and tool docs; keep secrets out of logs and previews; startup fails if enabled redaction cannot install.

Fixes #26, Fixes #27, Fixes #28, Fixes #29.

## [0.6.2] - 2026-08-16

### Added
- Optional `filter` argument on five Network Integration collection tools (`list_networks`, `list_clients`, `list_site_devices`, `list_firewall_policies`, `list_wifi_broadcasts`); expression forwarded unchanged to the upstream UniFi filter parameter; applied in both drain and single-page modes. (#187)
- Two port-profile VLAN-tagging tools: `allow_network_on_port_profile` (removes a network from a profile's exclusion list, atomically fixing the D12 auto-exclusion footgun) and `exclude_network_on_port_profile` (inverse). Both require `confirm=True`. (#197)
- Eight **Mobility** tools (workspace-scoped -- `workspace_id`/`device_id`, not host/site) for UMR mobile routers: 5 reads (`list_mobility_workspaces`, `list_mobility_admins`, `list_mobility_devices`, `get_mobility_device`, `list_mobility_clients`) and 3 guarded writes (`update_mobility_device_name`, `update_mobility_device_network`, `update_mobility_device_wireless`). Writes require `confirm=true` + `UNIFI_ENABLE_MOBILITY_WRITE` (default off, #186). (#196)
- Eleven **Carrier / ISP Fabric** subscriber tools (org-scoped, no host/site): 4 reads (`list_carrier_subscribers`, `get_carrier_subscriber`, `list_carrier_service_plans`, `get_carrier_service_plan`) and 7 guarded writes (`create_carrier_subscriber`, `update_carrier_subscriber`, `attach_carrier_subscriber_host`, `detach_carrier_subscriber_host`, `assign_carrier_subscriber_plan`, `suspend_carrier_subscriber`, `resume_carrier_subscriber`). Writes require `confirm=true` + `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` (default off). Not testable against the maintainer's live hardware; hermetic/spec-conformance tested only. (#201, #207)
- Five **Fabric connector relay** tools (`fabric_connector_get/post/put/patch/delete`) -- a guarded escape hatch to reach console routes without a typed wrapper. GET always available; mutations require `confirm=true` + `UNIFI_ENABLE_CONNECTOR_WRITE` (default off). Guards: Registry-only identity, namespace allowlist, positive-charset path validation, scope guard, credential-field redaction, per-mutation audit log. (#189)
- 41 **Protect Integration API** tools via the published v7.1.87 API: arm profiles (8), sirens (6), fobs (3), relays (4), speakers (4), bridges (3), link stations (3), alarm hubs (4), Protect users (2), ULP users (2), application metadata (1), POS ingestion (1). Write/action tools gated by `UNIFI_PROTECT_MUTATIONS_ENABLED` (default on); physical/irreversible actions additionally require `confirm=true`. (#185)
- Three read-only stat convenience tools (no new controller routes): `get_client_link_diagnostics` (per-client link/QoS record from `/stat/sta`), `get_device_port_state` (port table + LLDP + thermal/power from `/stat/device`), `get_device_stp_state` (per-device and per-port STP/RSTP fields). (#183, #184, #188)
- Five **InnerSpace** read tools completing the GET-only Integration API v1.3.23 coverage: `list_innerspace_floor_plans`, `list_innerspace_access_points`, `list_innerspace_switches`, `list_innerspace_inventory`, `get_innerspace_asset` (floor-plan image, base64 inline under 10 MiB cap).
- Catalog regression check (`unifi_fabric._catalog_audit`, `scripts/check_catalog_regression.py`) comparing registered tools against what the MCP gateway serves -- catches phantom/stale drift the static checks cannot see.
- Testing-procedure documentation: app-family testability matrix (noting which families cannot be live-tested on the maintainer's hardware) and namespace testing (`/v1` vs. `/ea`) sections.
- Testing procedure: added explicit Tier 2 rule prohibiting use of the MCP session tool list as gateway catalog evidence (session-start snapshot goes stale when a deployment lands mid-session); documented all three authoritative catalog sources with exact invocations (the deployed gateway's catalog database, the catalog-refresh job log, check_catalog_regression.py --live); added required verification protocol before filing a missing-tool finding; added new bullet to "What a reviewer must never do" for session-catalog escalation; added new "General Evidence Integrity Principle" section with three concrete dated examples of stale artifacts being mistaken for live state (2026-08-15). (#222)
- Spec-drift watcher (`unifi_fabric._spec_drift`, `scripts/check_spec_drift.py`) that tracks the published UniFi OpenAPI contracts per app family. It parses the `developer.ui.com/llms.txt` root index (so a **new** family publishing an API for the first time is detected, not just version bumps within known ones), fetches each service's OpenAPI spec, and diffs the signed path+method set against a committed baseline snapshot -- reporting NEW / CHANGED / REMOVED endpoints, VERSION_DRIFT, NEW/REMOVED services, and (informational) published-vs-console version gaps. A per-service coverage overlay flags a CHANGED/REMOVED endpoint we implement as breakage and a NEW write route on a covered family (e.g. the day InnerSpace grows one) as an unimplemented capability. Runs hermetically (`--snapshot`, CI-safe) or live (`--live`, public specs, no credentials), mirroring the `check_catalog_regression.py` precedent (#190 / PR #195). (#199)
- URL-pinning tests for all five Site Manager families asserting the exact `/v1/` path each tool constructs (in `test_site_manager.py`, `test_registry.py`, `test_aggregation.py`), so a future namespace regression fails at Tier 1 rather than in a live run. (#198)
- Testing procedure: documented Tier-2 host-scoped coverage requirements (required env vars per family, ephemeral run recipe); documented intentional exclusion of live VLAN CRUD under the standing no-live-mutation constraint, distinguishing it from STP reads and per-console Network reads that must run; added source-pinning section requiring all test claims to cite code at the build-under-test revision. (#228)

### Changed
- `allow_network_on_port_profile` and `exclude_network_on_port_profile` now require `confirm=True` -- each writes to a shared port profile affecting every assigned port. (#197)
- Port-profile tools (`list_port_profiles`, `get_port_profile`, `update_port_profile`) resolve networkconf id fields (`excluded_networkconf_ids`, `native_networkconf_id`, `voice_networkconf_id`) to `{id, name, vlan}` objects instead of bare 24-hex ids. Write path unchanged. (#197)
- `create_network` responses carry a `warnings.D12_AUTO_EXCLUSION` entry listing every custom-tagged port profile that UniFi silently auto-excluded the new network from. (#197)
- InnerSpace read tools now try the documented Integration API path first, falling back to the legacy `/api` path on a 403; error message now names both plausible causes and both attempted paths.
- `create_firewall_policy` / `update_firewall_policy` docstrings document the `trafficFilter` schema and the port-filter placement footgun (source vs. destination port targeting). ([swkstudios#17](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/17))
- `update_port_profile` and `execute_port_action` docstrings gained explicit scope guards (shared-profile and operational-action-only warnings respectively).
- `get_innerspace_asset` docstring clarifies that `plan_id` is the asset-group id from `image_url`, not the floor plan's own `id`.
- **Versioning scheme**: dev-branch pushes now cut semver pre-release tags
  (`vX.Y.Z-dev.N`) against the in-flight release target declared in `pyproject.toml`,
  instead of bumping the patch and cutting a full release tag on every push. The clean
  release tag (`vX.Y.Z`, no suffix) is cut only as a deliberate release step. Docker
  stable aliases (`:latest`, `:X.Y`) move only for clean releases; pre-release builds
  publish an immutable `:X.Y.Z-dev.N` image plus the `:dev` branch tag. The public
  release publish rejects pre-release tags outright.
- Migrated the five Site Manager endpoint families (`hosts`, `sites`, `devices`, `isp-metrics`, `sd-wan-configs`) from the Early Access `/ea/` namespace to the stable Official `/v1/` namespace **in place** — same tool names, no behavioral change. Call sites updated in `tools/site_manager.py`, `registry.py`, and `tools/aggregation.py`. Live-verified against a test console: `/ea/*` and `/v1/*` return identical response envelopes, and both `/ea/sites` and `/v1/sites` return the **same Fabric ObjectId** `siteId` (disproving the earlier assumption that `/v1/sites` returns a UUID — the UUID used in proxy URLs comes only from the per-console connector `/sites` endpoint and is unaffected). Codifies the standing policy: new Site Manager tools target `/v1/`; `/ea/` is permitted only where no `/v1/` equivalent is served and must carry an "Early Access — endpoint may change" note in its docstring. (#198, #192)
- `list_sites` / server tool guidance no longer describes `siteId` as an "EA-internal" ID; it is a Site Manager Fabric ObjectId served on `/v1/sites`. (#192)
- Reworded the `exclude_network_on_port_profile` docstring (and the generated `docs/TOOLS.md`) to describe it as the inverse of `allow_network_on_port_profile`; the paired `tools/network_services_proxy.py` implementation docstring was updated to match. Documentation-only cross-reference wording; no behavioral change.
- Replaced real captured InnerSpace asset-group and plan GUIDs in the `get_innerspace_asset` docstring example and test fixtures with synthetic RFC 4122 values; reworded the example so it is not presented as an observed live value; replaced a truncated fragment of the same real GUID in filename examples. Pre-publication hygiene; no behavior change. (#256)
- Replaced a QA label and possessive phrasing in tool docstrings, the AI-facing INSTRUCTIONS block, and a runtime gated-write message with plain language describing the testability limitation ("not testable against the maintainer's live hardware; hermetic/spec-conformance tested only") -- wording already used in the README. `docs/TOOLS.md` regenerated accordingly. The technical caveat (spec/hermetic-conformance tested, never exercised against real hardware) is preserved; no behavior change. (#259)

### Fixed
- `get_innerspace_asset` filename validation changed from a blocklist to a positive allowlist (`[A-Za-z0-9._-]` only), closing novel path-traversal sequences by construction. (#180)
- `get_innerspace_summary` now correctly recovers per-plan scale from the Integration API schema (indexed scale-type shapes) rather than reporting `null`; also surfaces `id`, `title`, `createdAt`, `updatedAt` from the project block.
- `set_firewall_policy_ordering` now forwards `sourceFirewallZoneId` and `destinationFirewallZoneId` as query parameters; previously dropped, causing every reorder call to fail with HTTP 400.
- `list_clients` `client_type` (WIRED/WIRELESS/ALL) was a silent no-op: it sent a `type` query parameter the UniFi Integration API ignores, so every value returned the full mixed client set (verified live: WIRED, WIRELESS and ALL all returned the identical 45-record dataset). It is now translated into the upstream `type.eq('WIRED'|'WIRELESS')` filter expression that actually narrows (live: WIRED -> 15 all-wired, WIRELESS -> 30 all-wireless). `client_type='ALL'` adds no filter. Because the upstream filter grammar has no conjunction operator (`and`/`&&` both HTTP 400), `client_type` and an explicit `filter` are now mutually exclusive and passing both raises `ValueError` rather than silently dropping one. (#223)
- Corrected filter-expression examples in tool docstrings (and the generated `docs/TOOLS.md`) that the upstream grammar rejects or that never match. `list_firewall_policies` documented `enabled.eq(true)` and `action.eq('ALLOW')` — both HTTP 400 `unknown filter property` (properties are per-schema; `enabled`/`action` are not filterable on firewall policies) — replaced with the live-verified `name.like('*guest*')` and `metadata.origin.eq('USER_DEFINED')`. `list_clients` documented `name.like('*phone*')` — `name` is HTTP 400 `unknown filter property` on the clients schema — replaced with `macAddress.eq(...)`. `list_networks` `metadata.origin.eq('USER')` (property valid, value never matched) corrected to `USER_DEFINED`; `list_site_devices` `model.eq('U7PG2')` (never matched the display-name field) corrected to `model.eq('U6 Pro')`. All published examples were re-verified live against the console. (#223)
- Test suite: scoped the module-wide `pytest.mark.asyncio(loop_scope="module")` in `test_console_integration.py` to the async test classes only. It was applied via `pytestmark` across the whole module, which stamped the five synchronous `TestKeyIsolation` tests and made pytest-asyncio emit "marked with '@pytest.mark.asyncio' but it is not an async function" on each when the suite runs with `UNIFI_API_KEY` set. The shared module-scoped event loop is preserved on the async classes; the sync tests are left unmarked (not converted to async). (#227)
- Publish workflow: fixed a GHCR blob-upload race condition where a semver-cron `create` trigger and a CI-success `workflow_run` trigger could fire concurrently against the same image layers. Concurrent runs are now serialized via a workflow-level `concurrency:` group. (#224)
- Corrected README domain-capability table: each of the 19 domain rows now matches the actual tool count from `docs/TOOLS.md` (server total unchanged at 283). Seven rows changed: Fleet & Aggregation 6→10, Device Management 16→21, DNS & Traffic 21→24, Protect 69→79, Hotspot 4→11, Settings & Monitoring 8→5, Utilities 7→6. The catch-all Other row (count 4) removed — those tools are accounted for in their proper domains. Domain descriptions updated to reflect additions. (#237)
- Publish workflow: added `timeout-minutes: 30` to the `publish` job in `.github/workflows/publish.yml`. Under the PR #224 concurrency fix (`cancel-in-progress: false`), a wedged buildx/push could head-of-line-block the Publish queue for up to GitHub's 6-hour default; a 30-minute job timeout reaps a stuck run in bounded time with generous headroom for legitimate builds (observed healthy runs complete in minutes). (#225)
- Spec-drift baseline writer (`write_snapshot_file()`) now synthesizes committed console version strings at the write boundary instead of persisting observed values: a synthetic build is derived deterministically from the published spec version alone (public input only); an observed value matching the published version is kept, a distinct value is replaced with the synthetic, and orphan services are dropped. Applied at the single persist boundary shared by every path including `--update-baseline`, so a live baseline refresh can no longer write a real running console version into the committed fixture. A fixed-point CI invariant asserts the committed baseline equals the synthesis rule, catching any distinct real value without a denylist. (#257)

### Removed
- InnerSpace write scaffold (`set_innerspace_wall_materials`, `UNIFI_ENABLE_INNERSPACE_WRITE`, `UNIFI_INNERSPACE_BACKUP_DIR`) -- the Integration API is read-only and the tool never had a working live-write path.
- Internal dead code in `tools/hotspot.py`: `_list_vouchers`, `_create_vouchers`, `_delete_voucher` (targeting `/ea/vouchers`, which the console does not serve). Live hotspot tools unaffected.

## [0.6.1] - 2026-08-08

### Changed
- Tool descriptions are the interface this server presents to the AI agents that call
  it, and were hardened across every tool so a caller can pick arguments correctly from
  the description alone:
  - Every required parameter is now named in its tool's description — not only in the
    machine-readable schema — with a pointer to where its value comes from. For example
    `list_recognition_detections` now states up front that `group_id` is required and is
    obtained from `list_recognition_groups`. A test enforces this for every tool.
  - Time parameters state their exact unit and type wherever they appear, and call out a
    deliberate inconsistency between tools: `list_protect_events`, `list_client_sessions`,
    `get_historical_stats` and `list_recognition_detections` take epoch **seconds** as
    integers, while `query_isp_metrics` takes ISO 8601 **strings**
    (e.g. `"2026-07-23T00:00:00Z"`). A value copied from one tool to another now errors
    clearly instead of misbehaving.
  - Enum-valued parameters enumerate their accepted values rather than implying them by a
    single example, and parameters the upstream API silently ignores on a bad value are
    flagged as such (a typo there reads as a clean but wrong result).
  - Similarly-named tools now cross-reference each other so the right one is easy to find
    (`get_isp_metrics` vs `query_isp_metrics`; the `list_hotspot_vouchers` family). There
    is no `list_vouchers` — the voucher-listing tool is `list_hotspot_vouchers`.
- Every `create_*` tool now applies one consistent required-field policy: it fails fast
  with a clear, self-correcting error naming the missing field(s) instead of forwarding an
  incomplete body and surfacing an opaque upstream error — or, on the Classic REST
  endpoints that enforce nothing server-side, silently creating a broken object. Each
  tool's required set was checked against a live controller and its description now lists
  exactly the fields it validates. Notable corrections: `create_port_forward` no longer
  lists `proto` as required (the controller defaults it); `create_traffic_rule` now
  documents and requires `target_devices` (previously undocumented) and no longer treats
  `description`/`enabled` as required; `create_traffic_route` documents its snake_case
  field names; the polymorphic tools (`create_network`, `create_wifi_broadcast`,
  `create_acl_rule`, `create_dns_policy`, `create_traffic_matching_list`) validate the
  discriminator the controller checks first and document the type-specific fields beyond it.
- `get_setting` and `update_setting` now document the common controller setting keys and
  their notable enum fields, explain that reading a setting group is how to discover what
  fields and values it accepts, and warn that the controller silently drops any field or
  enum value it does not recognise.

### Fixed
- When `update_setting` detects that the controller silently dropped a submitted value — a
  write that returns success but leaves the setting unchanged — the error now names the
  rejected field, explains the silent-drop behaviour, and points the caller at
  `get_setting` to read the valid current values before retrying.
- `query_isp_metrics` now rejects a `start_time`/`end_time` supplied as a bare epoch
  string (for example `"1690000000000"`) with a message showing the expected ISO 8601
  format, instead of forwarding a meaningless timestamp that the API silently ignored
  while returning the full default range.
- Write tools that accept a previously-read object now strip the empty-string
  placeholders the API pads list fields with, so a `get → modify → update`
  round-trip no longer fails validation. For example `get_network` returns
  `"dns_servers": ["192.168.1.1", "", ""]`; passing that straight back into
  `update_network` previously returned HTTP 400 `must be valid IPv4 address`.
  Real values are kept in order, a list that was entirely placeholders is sent as
  an empty list (clearing the field) rather than dropped, and scalar fields are
  left untouched. The same guard is applied across the network write tools
  (`update_network`, `update_wifi_broadcast`, `update_wan_interface`,
  `update_dns_policy`, `update_traffic_matching_list`, `update_port_forward`,
  `update_traffic_rule`, `update_traffic_route`, `update_user`, `update_setting`,
  `update_dynamic_dns`, `update_port_profile`, `update_wlan_config`,
  `update_firewall_policy`, `update_firewall_zone`, `update_acl_rule`), extending
  the earlier read-only-field stripping from public issue #17.
- Updating a firewall zone, firewall policy, ACL rule, WiFi broadcast, DNS policy,
  traffic-matching list, VPN server, or site-to-site tunnel by passing back an
  object you had just read now succeeds. These endpoints return server-managed
  fields (`id`, `metadata`, the network `default` flag, and the firewall/ACL
  ordering `index`) that the API rejects when they appear in a write body — a plain
  `get → modify → update` round-trip previously failed with HTTP 400
  `unknown-property`. Those fields are now stripped from the request (only at the
  top level, so nested references are untouched), matching what `update_network`
  already did and applying it consistently across every network write tool. Field
  ordering is changed through the dedicated `set_firewall_policy_ordering` /
  `set_acl_rule_ordering` tools, so dropping `index` from a normal update loses
  nothing.
- `update_setting` no longer misreports a successful write as a rejected one. When
  a setting group carried a list field that the controller pads with placeholder
  empty strings, resubmitting it unchanged — or changing a different field while it
  rode along — could raise a spurious "silent no-op" error even though the write
  was accepted. The before/after comparison now ignores that padding, so a real
  change is confirmed and a genuine no-op is recognised and skipped.
- Per-host tools (listing and acting on networks, clients, devices, and Protect
  cameras/sensors/lights and their siblings) now send their request on the API key
  that actually owns the target console instead of always using the first
  configured key. In a multi-key deployment a console owned by a non-first key
  previously failed with `403 forbidden: host not found`; it now routes on the
  correct key ([#19](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19)).
- The same owning-key routing now covers the remaining per-host tools: firewall
  policies, zones and ACL rules; DNS policies, traffic-matching lists, port forwards,
  traffic rules and routes, users, port profiles, WLAN configs and the other network
  services; VPN servers, site-to-site tunnels and RADIUS profiles; hotspot operators;
  face and vehicle recognition; per-site statistics; InnerSpace floor plans; and the
  Site Manager tools that act on a single console (host lookup, per-host device
  listing, site health summary, and site inventory). Every tool that targets a
  specific console now resolves the key that owns it and sends the request on that
  key, so a multi-key deployment can reach a console owned by any configured key, not
  just the first. Single-key deployments are unchanged — with one key there is
  nothing to disambiguate and every request rides that key exactly as before.
  Single-key deployments are unaffected.

## [0.6.0] - 2026-08-03

### Added
- `list_protect_events` gained server-side event filters, each verified against the
  live API to actually narrow the returned set (not silently accepted and ignored):
  - `smart_detect_types` — filter smart-detect events by subtype: `person`,
    `vehicle`, `animal`, `package`, `face`, `licensePlate`, and the audio-alarm
    subtypes `alrmSpeak`, `alrmSiren`, `alrmBark`, `alrmCarHorn`. This is a distinct
    parameter from `types`; the API only applies it when `types` is also set to the
    relevant event type(s), so passing it alone — which the API silently ignores —
    is rejected with a clear, actionable error instead of returning everything.
  - `categories` — filter by event category (for example `motion`, `smart`, `iot`,
    `admin`). Values the API does not recognise are ignored by the API upstream.
  - `without_descriptions` — opt-in flag to ask the API to omit each event's
    `description` block for a smaller payload. Off by default; full-fidelity records
    remain the default and descriptions are never dropped automatically.
  - `cameras` now accepts camera **names** as well as IDs, resolved case-insensitively
    (matching the name-or-ID convention already used for `host`). An unknown name
    raises a clear error listing the available cameras instead of silently matching
    nothing.
- Face and vehicle recognition tools for UniFi Protect consoles, surfacing Protect's
  built-in subject recognition through five read-only tools:
  - `list_recognition_groups` — list recognised subjects (for example enrolled faces),
    each with its label, sighting count, and first/last-seen timestamps. Supports
    filtering to named subjects only and server-side sorting; the complete set is
    returned by default rather than just the first page.
  - `get_recognition_group_counts` — aggregate totals (how many subjects exist, how
    many are named, and so on).
  - `get_recognition_group_image` — the reference crop for a subject, returned as a
    base64-encoded JPEG.
  - `list_recognition_detections` — every sighting of a subject, each with its match
    confidence and a thumbnail reference. Accepts an optional time window (verified
    against the live API to filter server-side), so a caller can ask for a specific
    range — the last hour, 30 days, or 90 days — directly; the complete set for the
    window is returned by default.
  - `get_thumbnail` — the crop for an individual sighting, returned as a base64-encoded
    JPEG.
- `Registry.resolve_key_for_host()` — resolves which configured API key owns a
  given host (by id, hostname, or name) for MSP multi-key deployments. Queries
  each key's cached host list concurrently with per-key failure isolation;
  raises only if every key fails. Single-key deployments short-circuit with no
  extra API calls. This is the foundation for threading the owning key through
  the per-host tools (follow-up).
- InnerSpace floor-plan tools (read-only) over the console connector proxy:
  - `get_innerspace_summary` — structural inventory (shape counts by type,
    per-floor plans and scales, product/material dictionary sizes) without the
    full payload.
  - `get_innerspace_project` — full project geometry, with a `mode` parameter
    (`2D`/`3D`, default `3D`; only 3D carries real metric device heights).
  - `list_innerspace_devices` — placed device shapes with position and rotation.
  - Responses are returned verbatim, including device `meta.mac`/`meta.ip` and
    floor-plan image/asset URLs (the server is a faithful pass-through). A
    truncated host id (which the API rejects with `403 forbidden: host not
    found`) now returns an explanation pointing at the composite host id rather
    than implying InnerSpace is unavailable.
- History and session tools (read-only) surfacing data beyond the live snapshot:
  - `list_client_sessions` — per-site session history via the classic REST
    `/stat/session` endpoint (~90-day retention, epoch-seconds timestamps).
  - `get_historical_stats` — bucketed traffic reports from `/stat/report`
    (5-minute, hourly, or daily buckets; timestamps are epoch-milliseconds at
    the wire level, but callers always pass epoch-seconds — conversion is
    handled internally).
  - `list_known_clients` — full per-site client roster including offline
    devices, from `/stat/alluser` (GET).
  - `list_protect_events` — historical Protect events via the private REST
    proxy path (the Integration API exposes events over WebSocket only; this
    tool uses the REST fallback). Sensor events promote `metadata.sensorId.text`
    to the top level for easier filtering.
  - All responses are returned verbatim, including MAC addresses, IPs,
    hostnames, and client names (the server is a faithful pass-through).
- Schema<->instructions cross-check: a test now parses every tool name referenced
  in the server `instructions` block and asserts each one is actually registered,
  so the agent-facing documentation can no longer advertise a tool that does not
  exist. Runs on every change with no live server needed; a live variant against a
  running server is also available for pre-publication checks.
- Parameter-scope cross-check: a second static test now parses the "Parameter Scope
  Quick Reference" buckets in the server `instructions` block and asserts each
  explicitly-named tool's declared host/site scope matches its registered schema, so a
  tool filed under the wrong bucket (e.g. "ID only" for a tool that actually requires
  `host`/`site`) fails CI. The phantom-name check's blind spot — it verifies tool
  *names*, not the *claims* around them — is now documented in the audit module and the
  testing procedure.

### Changed
- **Breaking (tool parameters): `get_radius_profile`, `update_vpn_server`,
  `delete_vpn_server`, `update_hotspot_operator`, and `delete_hotspot_operator`
  now require `host` and `site` arguments.** These tools previously took only an
  item ID because they targeted a (non-functional) global `/ea/` path. The
  working routes are per-console and per-site, so the console/site must now be
  named. `get_vpn_server` already required `host`/`site` and is unchanged.
  Callers of the affected tools must add `host` and `site`.
- **Response shape: recognition list tools stay resource-named, not `data`.**
  `list_recognition_groups` returns its array under `groups` (and
  `list_recognition_detections` under `detections`), matching the codebase
  convention of naming a list's array after its resource. This is deliberately
  left unchanged; only the Network Integration offset-paginated proxy lists use
  the `{data, totalCount}` shape. The `list_recognition_groups` docstring now
  states this explicitly so consumers key off `groups` rather than assuming `data`.
- **All tools now return complete upstream data, including identifier and
  credential fields.** The server is a faithful pass-through: whatever the
  UniFi API returns for a request is returned to the caller unchanged. Runtime
  response filtering has been removed everywhere it existed:
  - Client/session/roster and Protect event responses now include MAC
    addresses, IPs, hostnames, and client/sensor/subject names verbatim
    (previously replaced with `[REDACTED]`).
  - Controller settings, Dynamic DNS, WLAN configs, and RADIUS account
    responses now include credential fields such as `x_passphrase`,
    `x_password`, and API tokens verbatim (previously replaced with
    `[REDACTED]`).
  - InnerSpace project geometry now includes device `meta.mac`/`meta.ip` and
    floor-plan image/asset URLs verbatim (previously replaced with
    `[REDACTED]`, which broke floor-plan image retrieval).
  - Site Manager host records now include `reportedState` GPS coordinates
    (`latitude`, `longitude`, `geoInfo`) verbatim.

  **User-visible behavior change:** responses are larger and contain data
  earlier versions withheld. A deployment that needs to restrict what reaches a
  consumer should layer that policy on top of the server (a proxy or wrapper),
  which can always narrow a faithful response — whereas data the server chose
  to withhold could never be recovered downstream.
- **Removed the `include_secrets` parameter** from `list_dynamic_dns`,
  `get_dynamic_dns`, `list_wlan_configs`, `get_wlan_config`, `list_accounts`,
  and `get_account`, and the **`include_gps` parameter** from `list_hosts` and
  `get_host`. These opt-in flags gated the now-removed filtering and are
  redundant — the fields they exposed are always returned. Calls that passed
  either parameter should drop it. (Removing the `_token`-suffix credential
  match also fixes a latent bug where the pagination cursor `nextToken` was
  being replaced with `[REDACTED]`.)
- **List tools drain all pages by default and return the complete result set.**
  When called without explicit pagination parameters, list tools aggregate all
  available pages before returning. Typical queries — "list all sites", "list
  all devices" — complete without requiring callers to follow next-page tokens
  manually.

  To retrieve a **single page** instead, supply explicit pagination parameters:
  for cursor-based tools, pass `page_token=<token>` from a prior response; for
  offset-based tools, pass both `offset` and `limit`.

  When `UNIFI_PAGINATE_MAX_PAGES` is set and the page cap is reached before
  results are exhausted, the response includes `"incomplete": true` and an
  `"incompleteReason"` string. Callers should surface this to users so they
  know results may be partial.

  **User-visible behavior change: tools that silently stopped at one page now
  return every matching record.** Affected endpoints, each confirmed paginated
  against the live API:
  - `list_protect_events` — historical Protect events are offset-paginated; a
    wide time window can hold tens of thousands of events, and an unpaginated
    request times out on the device. The tool now pages through them (200 at a
    time) and returns the complete, time-ordered set. Pass `offset`/`limit` to
    fetch a single page instead.
  - `list_networks`, `list_firewall_zones`, `list_dns_policies`,
    `list_vpn_servers`, `list_radius_profiles`, and `list_hotspot_vouchers` —
    these per-site list endpoints are offset-paginated with a small native
    default page size (25–100 records); larger sites were silently truncated.
    They now drain all pages by default and return `{data, totalCount}`, and
    accept `offset`/`limit` for manual single-page access. A drain that hits the
    safety page cap is flagged `incomplete` rather than truncating silently.
  - Internal site-name resolution now drains all pages of the per-console sites
    list, so consoles with many local sites resolve site names past the first
    page instead of failing.
- `list_cameras` was investigated for the same truncation risk and confirmed
  **not** paginated against the live API (it returns a complete array with no
  pagination envelope or cursor, and offset/limit have no effect); this is now
  documented so it is not re-investigated.
- Protect's `allCameras` flag was investigated for potential tool exposure and
  confirmed a live no-op: passing `allCameras=true` and `allCameras=false` to
  the underlying API endpoint return identical results. The flag is not exposed
  as a tool parameter.

### Removed
- Internal dead code in ``tools/hotspot.py``: the unregistered ``_list_vouchers``,
  ``_create_vouchers``, and ``_delete_voucher`` helpers targeting ``/ea/vouchers`` (a
  path the console does not serve) were never wired as MCP tools. The live hotspot
  voucher tools (``list_hotspot_vouchers``, ``create_hotspot_vouchers``,
  ``bulk_delete_hotspot_vouchers``) go through the network-services proxy and are
  unaffected. No user-visible tool changes.

### Fixed
- The `instructions` "Parameter Scope Quick Reference" no longer lists `update_vpn_server`,
  `delete_vpn_server`, `update_hotspot_operator`, and `delete_hotspot_operator` under an
  "ID only (no host/site)" bucket. All four require `host` and `site`, and are already
  covered under "host + site required"; the stale bullet contradicted the general rule and
  the tools' own schemas, leaving an agent no recovery path.
- Recognition list tools now state their response shape in the agent-facing tool
  descriptions: `list_recognition_groups` returns its array under `groups` and
  `list_recognition_detections` under `detections` (not `data`, unlike the offset-proxy
  lists). Previously only the module docstring said this, which agents never see.
- `create_rtsps_stream` / `delete_rtsps_stream` now enumerate the accepted `qualities`
  channel names — `high`, `medium`, `low`, `package` (verified live; `package` only on
  package-camera doorbells). The prior example listed a non-existent `highest` channel and
  omitted `package`.
- `execute_port_action` now documents its `action` payload (`{'action': 'power-cycle'}` to
  PoE power-cycle a port) instead of an unexplained "port action payload", and notes the
  endpoint is write-only so its accepted set cannot be enumerated by inspection.
- `list_all_devices` now warns that `status_filter` is matched locally, so an unrecognised
  value returns an empty list — a typo reads as a healthy, problem-free fleet rather than an
  error. Mirrors the existing `session_type` silent-value warning.
- Recognition tool docstrings now explicitly state that the `type` parameter requires
  singular values (`face`, `vehicle`). Plural forms (`faces`, `vehicles`) return HTTP 400
  from the upstream Protect API. Two separate agents guessed plural and misread the 400 as
  "recognition not enabled." The fix applies to all four tools that accept `type`:
  `list_recognition_groups`, `get_recognition_group_counts`, `get_recognition_group_image`,
  and `list_recognition_detections`.
- **VPN server, RADIUS profile, and hotspot operator tools no longer target an
  unserved API path.** A family of tools was split across two API bases: the
  `list_*` siblings reached data over the working per-console proxy (VPN/RADIUS)
  or Classic REST (hotspot operators), while the corresponding `get_`/`update_`/
  `delete_`/`create_` tools pointed at Site Manager `/ea/` paths
  (`/ea/vpn-servers`, `/ea/radius-profiles`, `/ea/hotspot-operators`) that are
  not served on the console and answer `404 page not found` at the route level.
  Every such tool now uses the same base its working `list_*` sibling uses,
  verified live with real IDs obtained from the list tools:
  - `get_vpn_server` and `get_radius_profile` now drain the per-console proxy
    list (`/sites/{site}/vpn/servers`, `/sites/{site}/radius/profiles`) and filter
    by ID — the Network Integration API exposes these resources as collections
    only, with no item-level GET route — instead of filtering the unserved
    `/ea/` list (which made every call fail with a 404).
  - `update_vpn_server` and `delete_vpn_server` now issue `PUT`/`DELETE` against
    the per-console proxy item path (`/sites/{site}/vpn/servers/{id}`), matching
    `create_vpn_server` and the site-to-site tunnel tools, instead of the
    unserved `/ea/vpn-servers/{id}`.
  - `create_hotspot_operator`, `update_hotspot_operator`, and
    `delete_hotspot_operator` now use the console's Classic REST controller
    (`/rest/hotspotop`, `/rest/hotspotop/{id}`), the same base `list_hotspot_operators`
    reads from, instead of the unserved `/ea/hotspot-operators`. The create body
    now uses the controller's `x_password` field and no longer repeats host/site
    IDs in the body (they are addressed by the site slug in the URL).
- `list_protect_events` documentation listed smart-detect categories (`person`,
  `face`, `animal`) under the `types` parameter. Upstream these belong to a
  *different* query parameter (now exposed as `smart_detect_types`); passed as
  `types` they match no event type and quietly return an empty set. The docstring
  now documents the two parameters separately, with the accepted event types
  (`motion`, `smartDetectZone`, `smartAudioDetect`, `sensorOpened`, `sensorClosed`,
  `access`) verified against the live API.
- `query_isp_metrics` now applies the requested time range. The tool previously
  sent `start_time`/`end_time` as top-level body fields, which the UniFi Site
  Manager API silently ignores — so a call asking for a specific window returned
  the API's default range instead, with no error. **User-visible behavior change:
  results from earlier versions may not have honored the window you asked for.**
  The timestamps are now placed where the API actually reads them: per-site
  `beginTimestamp`/`endTimestamp` nested inside each entry of the `sites` array
  (ISO 8601 UTC). Verified against the live API — a nested window is honored
  exactly, whereas the old top-level form returned the full default range.
- `list_hosts`, `list_sites`, and `list_all_sites_aggregated` now aggregate
  across **all** configured API keys instead of silently returning only the
  first key's results in multi-key MSP deployments
  ([#19](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19)).
  Multi-key results carry a top-level `key_labels` list, annotate each record
  with its source `_keyLabel`, and use partial-failure semantics: a single
  failing key surfaces under `errors` rather than aborting the call;
  all-keys-fail raises. Single-key deployments are unchanged.
- `query_isp_metrics` now validates that a `sites` filter is provided and raises
  a descriptive `ValueError` if it is absent. Previously an unscoped call passed
  through to the API and returned an opaque HTTP 400 error.
- The server `instructions` block advertised `update_radius_profile` and
  `delete_radius_profile` in its parameter-scope reference, but no such tools exist
  and the Site Manager API exposes no RADIUS profile update or delete endpoint
  (verified live: the `/ea/radius-profiles` resource is not routed). An agent that
  read the instructions and called one got a `tool-not-found` with no recovery path.
  The two phantom references are removed and the RADIUS capability line now states
  the real surface (list/get/create only).
- Three tool parameters whose valid values were only implied by example are now
  enumerated from the value set, each established against the live API:
  - `session_type` on `list_client_sessions`: `all` (default; unfiltered), `user`,
    and `guest` are the values that narrow the result. An unrecognised value is not
    rejected and does not return an empty array — the endpoint silently ignores it
    and returns the full `all` set, so a typo yields everything rather than a visible
    error. Documented explicitly to prevent a wrong value passing as "no data".
  - `order_direction` on `list_recognition_groups`: `asc` or `desc`, case-insensitive;
    an unrecognised value is rejected upstream with HTTP 400. It takes effect only
    together with `order_by`, and defaults to descending when omitted.
  - `file_type` on `list_protect_files` / `upload_protect_file`: `sounds` and `images`
    are the known asset categories; the GET endpoint does not validate the value (an
    unknown category returns an empty list rather than an error), so the docstring now
    states this rather than implying a wrong value would surface.

### Credits

- Multi-key MSP aggregation gap reported and first prototyped by
  [@thuer-it](https://github.com/thuer-it)
  ([#19](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19),
  [fork](https://github.com/thuer-it/unifi-fabric-mcp-server)).
  This implementation reworks that prototype onto the current codebase with
  per-key error handling, cache-backed lookups, concurrent fan-out, and tests.

## [0.5.0] - 2026-07-31

### Added
- Eight read-only tools completing the official Network Integration API surface:
  application info, local sites, LAGs, MC-LAG domains, and switch stacks.
- Pagination and filter support for the new local-site and switching collection tools.

## [0.4.0] - 2026-06-29

Configurable authentication (none/bearer/OAuth) and TLS (HTTPS/mTLS) for HTTP transports.

### Added
- Auth/transport/TLS config selector matrix:
  - `MCP_AUTH_MODE` selector (`none`/`bearer`/`oauth`) plus OAuth descriptor
    vars (`MCP_OAUTH_ISSUER`, `MCP_OAUTH_JWKS_URI`, `MCP_OAUTH_AUDIENCE`,
    `MCP_OAUTH_BASE_URL`, `MCP_OAUTH_REQUIRED_SCOPES`, `MCP_OAUTH_ALGORITHM`,
    `MCP_OAUTH_AUTHORIZATION_SERVERS`).
  - `MCP_TLS_MODE` selector (`none`/`https`/`mtls`) plus `MCP_TLS_CERTFILE`,
    `MCP_TLS_KEYFILE`, `MCP_TLS_CA_CERTS`, `MCP_TLS_KEY_PASSWORD`,
    `MCP_TLS_CERT_REQS`.
  - Pure `build_auth` / `build_uvicorn_config` builders, plus fail-closed
    validation (`https`/`mtls` require cert + key, and a CA bundle for `mtls`;
    `oauth` requires issuer + JWKS URI + audience + base URL; auth/TLS settings
    are rejected at startup when `FASTMCP_TRANSPORT=stdio`).
- OAuth 2.0 resource-server mode (`MCP_AUTH_MODE=oauth`): verifies bearer JWTs from
  an external OIDC identity provider via JWKS; checks `iss`, `aud`, `exp`, and
  required-scope claims; auto-serves the RFC 9728 protected-resource discovery
  document naming the upstream authorization server. No login, consent, or dynamic
  client-registration logic runs in this server.
- In-server HTTPS (`MCP_TLS_MODE=https`) proven over a real socket:
  `build_uvicorn_config`'s `ssl_certfile`/`ssl_keyfile` kwargs are exercised
  end-to-end by `tests/test_tls_socket.py` with an in-memory `trustme` CA —
  a right-CA handshake succeeds and a wrong-CA handshake is rejected. Tests
  run in CI by default (tagged `@pytest.mark.tls`, no runtime skip).
- In-server mutual TLS (`MCP_TLS_MODE=mtls`) proven over a real socket:
  `tests/test_mtls_socket.py` asserts that a valid client certificate completes
  the handshake, while a missing client cert and a foreign-CA client cert are both
  rejected. mTLS is a transport boundary and composes with (not replaces)
  `MCP_AUTH_MODE`.
- `MCP_TLS_CERT_REQS` wired into `build_uvicorn_config`: maps
  `none`/`optional`/`required` to `ssl.CERT_NONE`/`CERT_OPTIONAL`/`CERT_REQUIRED`;
  under `mtls` defaults to `CERT_REQUIRED` and `none` is rejected fail-closed.
- In-process auth request-path test harness (`tests/test_auth_http.py`): drives
  the server's streamable-http ASGI app via `httpx.ASGITransport` (no sockets)
  and asserts the live auth status of a real MCP `initialize` request — `none`
  mode succeeds with no `Authorization` header, `bearer` mode returns 200 for a
  valid token and 401 for missing, wrong, or empty tokens.
- OAuth request-path tests (`tests/test_auth_oauth.py`): RSA-signed JWTs from
  `RSAKeyPair` with JWKS stubbed via `respx` — 200 for a valid token; 401 for
  missing, malformed, expired, wrong-audience, wrong-issuer, and
  insufficient-scope tokens; plus a discovery test pinning the
  protected-resource metadata path and contents.
- `docs/AUTH-OAUTH.md`: OAuth configuration guide covering OIDC provider setup,
  audience matching, and the protected-resource discovery URI.
- `docs/TLS.md`: HTTPS/mTLS setup guide — cert generation, `HEALTHCHECK`
  requirements, mTLS client-cert configuration, and the transport-vs-application-
  identity boundary.
- `.github/SECURITY.md` transport authentication posture matrix expanded to cover the
  complete auth × TLS grid (9 cells), including the bearer-is-not-a-public-
  internet-boundary warning and the internet-exposed = OAuth-over-HTTPS
  recommendation.
- `trustme` added as a dev/test-only dependency for real-socket TLS tests.
  No new runtime dependencies.

### Changed
- `MCP_AUTH_MODE=oauth` is now active: builds the resource-server auth provider
  instead of raising `NotImplementedError` at startup.
- Backward-compatible auth resolution: an unset `MCP_AUTH_MODE` with
  `MCP_BEARER_TOKEN` set resolves to `bearer`; otherwise `none`. Existing
  bearer-token deployments are unaffected.
- `auth_http_client` test fixture moved to `tests/conftest.py` for suite-wide reuse.
- `fastmcp` dependency constraint updated to `>=3.2,<3.5`.

### Notes
- `oauth` mode is **resource-server only**: this server verifies tokens issued by
  an external OIDC identity provider and does not run an authorization server
  (no login, consent, or dynamic client registration).
- `stdio` transport has no network surface; setting auth or TLS mode with `stdio`
  is rejected at startup rather than silently ignored.

## [0.3.155] - 2026-05-23

### Fixed
- `update_setting` now detects silent no-op writes and returns a clear
  error when the controller rejects a payload.
- `update_network` strips read-only fields from input, preventing
  HTTP 400 errors during get-modify-put workflows.

## [0.3.154] - 2026-05-16

### Fixed
- Pagination: preserve explicit zero params
- Validate network service path IDs

### Changed
- `fastmcp` dependency updated to `>=3.2,<3.4`
- Updated `docs/TOOLS.md`

## [0.3.153] - 2026-05-04

### Added
- Optional `MCP_BEARER_TOKEN` env var for bearer auth on HTTP transport.
- `UNIFI_LOG_LEVEL` env var for log verbosity control

### Changed
- IP redaction in `UniFiConnectionError` messages

### Removed
- `update_radius_profile` and `delete_radius_profile` (404 upstream — endpoints no longer exist)

---

## Earlier releases

v0.2.0 – v0.3.152: Initial features and iterative fixes. See git history for details.
