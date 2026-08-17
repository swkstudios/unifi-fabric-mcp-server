# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- Post-0.6.2 (0.6.3+) work goes here. -->

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
