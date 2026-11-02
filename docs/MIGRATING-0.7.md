# Migrating to 0.7.0

This guide preserves the complete 0.7.0 behaviour and compatibility notes. Each entry records the former behaviour, the new behaviour, affected tools, and the caller action where applicable.

## Tool discovery default

Previously, the server advertised the full tool surface by default. Starting in 0.7.0,
it defaults to discovery mode, advertising discovery tools instead of the full tool list.
To restore the previous behaviour after upgrading, set `UNIFI_TOOL_MODE=full`. Affected: every
tool (discovery mode lists five meta-tools in `tools/list` and reaches the others through
`call_read_tool` and `call_write_tool`). Clients that need every domain tool in `tools/list`,
such as ContextForge and other gateway deployments, should select `full`. Read-only mode
(`UNIFI_READ_ONLY`) hides `call_write_tool` in discovery mode, so the previous behaviour is
restored exactly only with read-only mode off.

## 0.7.0 behaviour changes

### change-001

- Uvicorn access logging is disabled for every HTTP transport. The server writes its
  own bounded access record to `unifi_fabric.access`, including client, method, target,
  HTTP version, and status without logging headers. A request target over 1,024 bytes
  is refused with 414 and a header block over 16 KiB with 431, before authentication;
  the access record then logs only the target size and a SHA-256 prefix. Other targets
  are scrubbed by the existing global scrubber. WebSocket upgrades are disabled.


### change-002

- **Breaking (image results):** `get_camera_snapshot`, `get_thumbnail` and
  `get_recognition_group_image` now include MCP ImageContent plus text and structured
  metadata. The existing `image_base64`, `content_type` and `size_bytes` fields remain;
  v0.6.2 returned only the metadata dictionary.


### change-003

- The spec-drift watcher fingerprints resolved request, response and parameter schemas, including enums, and reports field paths for contract changes and breaking changes even without a version bump. Spec info.version is shown alongside the llms.txt version; documentation-only edits are ignored. Its baseline uses the committed full OpenAPI specs. Schema comparisons preserve OpenAPI 3.1 reference sibling constraints and literal mapping keys, and include response headers. BREAKAGE follows request tightening and response widening across validation keywords and composition; removing request restrictions is not breakage.


### change-004

- Every tool explicitly advertises its title, read-only hint and destructive hint; the two
  hints derive from the server's one read/write classification (values in the "Tool
  annotations" entry, change-073). Delete and physical-action tool descriptions state the
  consequence (`Consequence:`), the connector relay writes state their return and
  refusal contract, and each discriminated body variant lists the keys it requires.
  Server instructions and every tool description fit Claude Code's 2,048-character
  default, including `fabric_connector_put` and `fabric_connector_patch` (2,022 characters
  each after argument documentation is extracted into parameter descriptions); full workflow guidance lives in `docs/TOOL-USAGE.md` and body shapes remain in
  parameter descriptions.

### change-005

- Enum shape notes include every allowed value.

### change-006

- Claude installation guidance distinguishes plugin servers in Claude Code from local
  servers configured for Claude Desktop chat and remote-only web/mobile connections.


### change-007

- The README is a front page: a one-line hook, the approved demo, a three-step Quick Start with a "Choose your client" table that fits a phone, and the safety defaults come first. Per-client setup (one-command PyPI install, Docker, source checkout), a read-only first-run recipe, a short "What is UniFi Fabric?" intro with Ubiquiti links and a one-line Homebrew note (formula planned, no tap yet) follow. Reference material moved out of it into `docs/CONFIGURATION.md`, `docs/AUTH-TLS.md`, `docs/PAGINATION.md`, `docs/RETRY.md` and `docs/COVERAGE.md`; the live-sweep figures there carry the sweep date. `docs/AUTH-OAUTH.md` image examples are updated from 0.5.0 to 0.7.0, and `tests/test_docs_currency.py` keeps documented versions, image tags, tool counts and install names in step with the code.

### change-008

- Documentation corrections: Claude Code setup names the files Claude Code reads (a project `.mcp.json`, or `claude mcp add --scope user`), not `settings.json`, which it ignores for MCP servers; `docs/AUTH-OAUTH.md`, `docs/CHATGPT.md` and `SECURITY.md` state that an OAuth scope admits a client to the whole server and does not turn write tools off (use a separate `UNIFI_READ_ONLY=1` instance); `docs/TLS.md` no longer says a sessionless `GET /mcp` hangs (it answers 400, or 405 when stateless); the read-only refusal tells local-install users where to unset the variable; `PRIVACY.md` covers every integration; and the repository gains a Code of Conduct, a pull request template and an issue-template chooser.


### change-009

- Arguments are refused before the request only for the server's own selector syntax, a
  constraint the vendored spec states, a closed set of values probed on a live controller,
  or JSON validity; everything else is sent for the upstream to judge, and an upstream
  error may get a hint appended (its text is kept). The registry of every such refusal is
  `unifi_fabric.refusals`, and a test feeds every tool blank, empty, out-of-range and
  incomplete arguments to hold the rule. Concretely, against 0.6.2:
  - An epoch-seconds argument (`list_protect_events`, `list_client_sessions`,
    `get_historical_stats`, `list_recognition_detections`) that is negative or of
    millisecond magnitude (>= 1e11) is sent as given (converted to milliseconds where the
    endpoint needs them) and an object result carries a `_warnings` entry naming it
    (`EPOCH_SECONDS_NEGATIVE` / `EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS`); 0.6.2 refused it.
  - The connector relay (`fabric_connector_*`) relays a valid path outside its mapped
    UniFi namespaces (for example `talk/...`, `connect/...`, `drive/...`) with
    `routeClass: "unclassified"`; 0.6.2 refused it as outside the namespace allowlist. A
    ordinary GET on it relays (a GET the server classifies as state-changing is treated as
    a mutation). A mutation on it relays unless a per-area write opt-out is active, meaning
    one of `UNIFI_ENABLE_NETWORK_WRITE`, `UNIFI_PROTECT_MUTATIONS_ENABLED`,
    `UNIFI_ENABLE_MOBILITY_WRITE`, `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` or
    `UNIFI_ENABLE_INNERSPACE_WRITE` is set to a false value (`0`, `false`, `no`, `off`,
    `f`, `n`; all five default to on); then it is refused, naming every active variable,
    because the path cannot be shown to lie outside the opted-out area.
  - `create_port_forward`, `create_traffic_rule` and `create_traffic_route` send a body
    without a documented field as given (these Classic / v2 endpoints publish no request
    schema); 0.6.2 refused it. The fields stay documented, and an upstream error gets a
    hint naming the missing ones. Writes whose published schema requires a field keep
    refusing a body without it.
  - `list_protect_events` sends `smart_detect_types` without `types` and adds a
    `_warnings` entry on an object result (`SMART_DETECT_TYPES_WITHOUT_TYPES`: the endpoint honours the subtype
    filter only together with `types`); 0.6.2 refused the call.

### change-010

- Explicit-page requests to `list_protect_events` and `list_recognition_detections`
  follow the upstream page's shape. A bare-list page is returned as that list without
  `_warnings`; on `list_protect_events` each sensor event in it gains the additive
  `_resolved_sensor` key, and `list_recognition_detections` returns it verbatim. An object
  page keeps every upstream top-level field verbatim and carries the epoch-unit `_warnings`
  (and, on `list_protect_events`, the smart-detect `_warnings`), as a drained result does.

### change-011

- Selector resolution against an incomplete device or client enumeration carries
  its provenance into the tool result when matching a MAC. A name matched while another
  API key's Site Manager listing failed also carries that failure. Exact host IDs,
  siteId/UUIDs and console internal references are complete resolutions even on a capped
  list; exact misses retain the cap reason. Partial enumeration lists and resolutions from them are never cached.

### change-012

- **Breaking (resolution provenance): `_incompleteReason` is returned for partial selector resolutions in 14 existing tools.**
  Compared with v0.6.2, object results can gain `_incomplete` / `_incompleteReason`, and
  non-dict results can become `{result, incomplete, incompleteReason}`. This applies only
  when a non-unique selector resolves from an incomplete enumeration, or a Site Manager
  name resolves while another key's listing failed:
  - Host-name selectors now require a complete host listing from every configured key;
    a failed or page-capped sibling key can conceal another matching console. Pass an
    exact console id to resolve despite that sibling-key failure or cap.
  - Network device MAC selectors: `execute_device_action`, `execute_port_action`, `get_device`,
    `get_device_statistics`, `locate_device`, `restart_device`, `unadopt_device`, `upgrade_device`.
  - Network client MAC selectors: `execute_client_action`, `get_client`.
  - Site Manager selectors: `compare_site_performance`, `get_site_health_summary`,
    `get_site_inventory`, `search_across_sites`.

### change-013

- Classic device-tag memberships and port-profile exclusions validate upstream arrays
  and string elements before deriving writes. Settings pre-reads and post-reads require
  the singleton record to carry the addressed setting key; malformed reads report shape errors.

### change-014

- Numbered pagination follows continuation links through empty pages, including Recognition
  detections and groups; opt-in page caps retain incomplete-result provenance.

### change-015

- Aggregation and site search collapse equivalent hex-case host IDs across configured keys,
  retaining the first configured key and upstream record.

### change-016

- Historical Protect event drains preserve the upstream array key and first-page envelope
  fields. Both Protect collectors report non-scalar IDs as shape errors; later polling
  failures retain already-collected records and incomplete-result provenance.

### change-017

- Placement preflight reports auth_denied when both InnerSpace fallback paths return 403.

### change-018

- Mobility workspace selectors point to workspace_id from list_mobility_workspaces.
  Port-profile notes are documented as conditional, Carrier metadata=null alone is
  documented as a no-op, and Protect smart-detection filters describe forwarding with a warning.

### change-019

- Tool input schemas describe 40 pinned-spec body shapes. Each body's top-level fields
  carry an advisory type and a one-line spec note (enum values, required keys, and the
  discriminator values with each variant's fields); nested fields are summarised as a
  compact TypeScript-like outline in the field description, for example
  `{zoneId:string(uuid),trafficFilter?:...}`. Local aliases such as `T1` refer to
  definitions in the outline's trailing `where T1=...` clause. Unknown fields remain allowed;
  no new validation constraints are added. The other 191 object parameters are
  explicitly described as free-form. The shapes are 72,208 bytes of compact JSON, and a
  size-budget test (`tests/test_catalog_size_budget.py`) holds the catalog to an average
  of 2,400 bytes per tool, any one tool's input schema to 10,000 bytes, the shapes to an
  average of 2,000 bytes and any one shape to 10,000 bytes.

### change-020

- `list_protect_events` no longer sends `orderDirection=ASC` when `order_direction` is
  omitted (its default is now unset, so the upstream's own order applies). The private
  events endpoint has no spec, so no default is sent on the caller's behalf; pass `order_direction="ASC"` for oldest-first results.
  `order_direction` is sent as given whenever it is passed.

### change-021

- `scripts/check_catalog_regression.py` and `unifi_fabric._catalog_audit`: the default gateway
  slug is now the generic `unifi-fabric`; set `--gateway-slug` to compare a gateway registered
  under another slug. For mixed catalogs with overlapping slugs, repeat
  `--other-gateway-slug` for the other known gateways (for example,
  `--other-gateway-slug unifi-fabric-lab`). The longest matching known slug owns each
  federated name; the Python helpers accept keyword-only `other_gateway_slugs`. This
  metadata is opt-in: without it, comparison keeps the existing prefix-only behaviour.
  For example, `unifi-fabric-lab-list-a` can mean `lab_list_a` under `unifi-fabric`
  or list_a under `unifi-fabric-lab`; the raw name alone cannot prove its owner.
  Server behaviour and tool names are unchanged.

### change-022

- **Breaking (unexpected result shapes): Protect object reads reject non-object bodies.**
  `get_camera`, `get_sensor`, `get_light`, `get_chime`, `get_viewer`, `get_liveview`,
  `get_nvr`, `get_rtsps_stream`, `get_protect_application_info`, `get_siren`,
  `get_fob`, `get_relay`, `get_speaker`, `get_bridge`, `get_link_station`,
  `get_alarm_hub`, `get_protect_user`, `get_ulp_user` and
  `get_recognition_group_counts` report an unexpected upstream shape instead of
  manufacturing a `data` wrapper around a non-object response.

### change-023

- **Breaking (tool results): Carrier service-plan and InnerSpace lists keep upstream keys.**
  `list_carrier_service_plans`, `list_innerspace_floor_plans`,
  `list_innerspace_access_points`, `list_innerspace_switches` and
  `list_innerspace_inventory` return the upstream body with additive `_count`
  metadata instead of the former `service_plans`, `floor_plans`, `access_points`,
  `switches` or `devices` wrapper and `count`. Bare arrays use `result`; object
  bodies retain their original fields.

### change-024

- **Breaking (tool results): no result invents a top-level key.** Every top-level key is
  an upstream key, an additive `_` key, or a documented envelope key (`status`,
  `response`, `deleted`, `errors`, `byKey`, `readAfter`, `incomplete`, ...). A bare-array
  list body is returned under `result` (except an explicit page the upstream sent as a
  bare array, which is returned unchanged), an enveloped one under its upstream key
  (`data`),
  and counts and other derived values are `_` keys (`count` is `_count`, `key_labels` is
  `_key_labels`, `key_label` is `_key_label`). Against 0.6.2:
  - Protect lists (`list_cameras`, `list_sensors`, `list_lights`, `list_chimes`,
    `list_viewers`, `list_liveviews`, `list_arm_profiles`, `list_sirens`,
    `list_fobs`, `list_relays`, `list_speakers`, `list_bridges`,
    `list_link_stations`, `list_alarm_hubs`,
    `list_protect_users`, `list_ulp_users`, `list_protect_events`) return
    `{result, _count}` (was `{<plural>, count}`); an explicit object page of
    `list_protect_events` instead retains its native `data`, `totalCount`, `offset` and
    every other upstream field, with only additive `_count` and `_warnings` metadata
    (0.6.2 returned `{events, count}` even for an explicit page). `list_protect_files` adds
    `_file_type`; recognition lists keep `groups` / `detections`, and `nextPage` is
    `_nextPage`.
  - Records move to `data` in `list_hosts`, `list_sites`, `list_all_sites_aggregated`,
    `list_sdwan_configs`, `list_devices`, `search_across_sites`, `list_all_devices`,
    `list_all_clients`, `search_device_fleet`, `list_mobility_workspaces`,
    `list_mobility_admins`, `list_mobility_devices`, `list_mobility_clients`,
    `list_carrier_subscribers` and `list_carrier_service_plans`;
    `query`, `filter`, `sitesQueried`, `sitesSearched` and the other site counters are
    `_`-prefixed.
  - List tools keep every upstream top-level key: single-GET lists (Mobility, Carrier
    service plans, InnerSpace) return the body verbatim plus `_count` (`incomplete` when
    its total exceeds the rows); drains keep the first page's envelope; merges keep
    `byKey`.
  - `compare_site_performance` returns `{_comparison, _count}`; `get_site_inventory`
    returns `{_siteId, _devices, _deviceCount, _clients, _clientCount, _devicesEnvelope,
    _clientsEnvelope}` (each envelope is that list's upstream envelope fields).
  - `list_innerspace_devices` returns `{shapes, _mode, _count}`; `get_innerspace_asset`
    reports `_plan_id` / `_filename`; Carrier host link/unlink report `_prev_host_id`.
  - `get_device_port_state` / `get_device_stp_state`: `device`, `port_idx`, `source`,
    `port`, `thermal_power`, `stp` and `ports` are `_`-prefixed, the complete selected
    `/stat/device` record is under `_device_record`, and the `/stat/device` `meta` is
    included; `port_table` and `lldp_table` are returned as sent (0.6.2 returned `[]` for
    an absent `lldp_table`; an absent table or `meta` now stays absent, as documented).

  The derived views `get_fleet_summary`, `get_innerspace_summary` and
  `list_configured_api_keys` (`{keys, count}`, as in 0.6.2) keep their shapes, except
  that `get_fleet_summary` reports `_key_label` / `_key_labels` (was `key_label`).

### change-025

- Every tool description states its result shape, the Protect reads included.

### change-026

- **Breaking (tool results): Classic REST tools and stat reads return the controller's
  `{meta, data}` body verbatim.** `meta` is relayed as received; tools that select records
  narrow `data`, and convenience views are `_` keys. 0.6.2 returned the bare `data` array
  from `list_users`, `get_user`, `update_user`, `list_settings`, `get_setting`,
  `list_dynamic_dns`, `get_dynamic_dns`, `update_dynamic_dns`, `list_port_profiles`,
  `get_port_profile`, `update_port_profile`, `list_routing_entries`, `list_wlan_configs`,
  `get_wlan_config`, `update_wlan_config`, `list_wlan_groups`, `get_wlan_group`,
  `list_rogue_aps`, `list_firewall_rules`, `get_firewall_rule`, `list_firewall_groups`,
  `get_firewall_group`, `list_accounts`, `get_account`, `list_hotspot_packages`,
  `get_hotspot_package`, `list_scheduled_tasks`, `get_scheduled_task`,
  `get_site_statistics`, `get_system_info`, `list_active_clients_stats`,
  `list_device_stats`, `list_client_sessions`, `get_historical_stats` and
  `list_known_clients`. Also: `get_channel_plan` returns the envelope even for an empty
  plan (was `{message, channelPlan: []}`); `get_client_link_diagnostics` returns the
  `/stat/sta` envelope narrowed to the selection (was the bare record or list);
  `update_setting` returns the PUT envelope (a no-op returns the GET envelope plus
  `_note`; was the bare `data` or `{data, note}`); `list_hotspot_operators` returns the
  envelope (was `{operators, count}`); `create_hotspot_operator` and
  `update_hotspot_operator` return the envelope (0.6.2 failed after the write was applied,
  "structured_content must be a dict"); `allow_network_on_port_profile` and
  `exclude_network_on_port_profile` return the PUT envelope with `_tagged_networks` and
  `_network` (was `{profile, tagged_networks}`).

### change-027

- **Breaking (tool results): the single-object reads return the upstream body
  verbatim.** `get_host`, `get_sdwan_config` and `get_sdwan_config_status` return
  `{data, httpStatusCode, traceId}` (they returned only `data`); `get_carrier_subscriber`
  (was `{subscriber: <data>}`), `get_carrier_service_plan` (was `{service_plan: <data>}`),
  `get_mobility_device` (was `{device: <data>}`) and `get_innerspace_project` (was
  `{mode, project: <data>}`) return the body as received. Read the resource at `data`.

### change-028

- **Breaking (tool results): `get_isp_metrics` and `query_isp_metrics` return the
  upstream body verbatim and cover every configured API key.** `get_isp_metrics` returns
  `{data, httpStatusCode, traceId}` (was the list under an invented `periods` key) and
  `query_isp_metrics` returns `{data: {metrics, ...}, httpStatusCode, traceId}` (was only
  `data`). 0.6.2 sent one request on the first key; now each site is routed to the key
  that owns its console, keys are queried concurrently, records carry `_keyLabel`, other
  keys' bodies are under `byKey.<label>`, and a failing key is reported under `errors`
  unless every key fails.

### change-029

- **Breaking (tool results): `get_site_health_summary` returns the Classic `/stat/health`
  envelope verbatim** (was `{health, count}`), so `meta` (including `rc: "error"`) reaches
  the caller; `compare_site_performance` entries are those envelopes plus `_siteLabel`.
  A `siteId` resolves on a partial site list (ids are unique); a name there is refused.
  The descriptions say the body holds per-subsystem health records, not alerts.

### change-030

- **Breaking (tool results): `list_traffic_rules` returns the v2 API's bare array
  verbatim** (was `{data, count}`), like `list_traffic_routes`. **`list_wan_interfaces`
  returns `{data, totalCount, _health}`** (was `{wans, count, wanHealth}`): the drained
  WAN list, its upstream `totalCount`, and the whole `/stat/health` body under `_health`
  (0.6.2 returned only the `wan` entries); a failed health read is under
  `_wanHealthError`.

### change-031

- **Breaking (tool results): six Network Integration lists return the drained list
  `{data, totalCount}` instead of the first page.** `list_countries`, `list_acl_rules`,
  `list_pending_devices`, `list_site_to_site_tunnels`, `list_traffic_matching_lists` and
  `list_wifi_broadcasts` returned the first page's `{offset, limit, count, totalCount,
  data}` (25 items, the rest missing; `totalCount` was the upstream total); they now
  drain every page, with `incomplete: true` and `incompleteReason` when a drain stopped
  short (see change-032 for what `totalCount` holds).

### change-032

- **Breaking (tool results): a drained list's `totalCount` is the upstream total or
  `null`, never a computed count.** 0.6.2 put the number of records gathered
  (`len(data)`) in `totalCount` whenever it had no upstream total: on every drain,
  complete or stopped by `UNIFI_PAGINATE_MAX_PAGES`, and on a page without one. Use
  `len(data)` for the records returned. Affected (15): `list_clients`,
  `list_dns_policies`, `list_dpi_applications`, `list_dpi_categories`,
  `list_firewall_policies`, `list_firewall_zones_proxy`, `list_hotspot_vouchers`,
  `list_lags`, `list_local_sites`, `list_mc_lag_domains`, `list_networks`,
  `list_radius_profiles`, `list_site_devices`, `list_switch_stacks`, `list_vpn_servers`.

### change-033

- **Breaking (tool results): `list_devices` counts devices and `list_all_devices` returns
  device objects.** `list_devices` still returns the `/v1/devices` per-console wrappers
  verbatim, but `_count` is now the number of devices (0.6.2's `count` counted consoles)
  and `_consoleCount` the number of wrappers (a wrapper whose `devices` is null, missing or
  `[]` counts 0 and is never a device record). `list_all_devices` returned the wrappers, so
  `status_filter` matched nothing; it now returns the device objects, and each device from
  `list_all_devices` and `search_device_fleet` carries its wrapper's fields as `_hostId`,
  `_hostName` and `_updatedAt`.

### change-034

- **Breaking (tool results): every delete tool returns `{deleted: true, message,
  response}`.** The upstream DELETE body is verbatim under `response` (decoded JSON,
  raw text, or `null`). 0.6.2 returned a bare confirmation string from `delete_network`,
  `delete_wifi_broadcast`, `delete_firewall_policy`, `delete_firewall_zone_proxy`,
  `delete_acl_rule`, `delete_dns_policy`, `delete_traffic_matching_list`,
  `delete_hotspot_voucher`, `bulk_delete_hotspot_vouchers`, `delete_rtsps_stream`,
  `delete_port_forward`, `delete_traffic_rule`, `delete_traffic_route`,
  `unadopt_device`, `delete_vpn_server` and `delete_hotspot_operator`;
  `delete_device_tag` returned `{deleted, tagId}`, `delete_site_to_site_tunnel`
  `{deleted, tunnelId}` and `delete_arm_profile` `{status: "deleted", id}`.

### change-035

- **Breaking (tool results): every Protect write and action tool returns
  `{status, response}`.** The upstream body is verbatim under `response` (JSON, text or
  `null`). 0.6.2 returned the body itself, wrapped a non-object body as `{"data": ...}`
  or returned `{"status": "ok"}` for actions, and raised after the action had happened
  when the body was empty or not JSON. `status` is `"created"` for `create_rtsps_stream`,
  `create_liveview` and `create_arm_profile`, `"uploaded"` for `upload_protect_file`,
  and `"sent"` for the actions (`start_talkback_session`,
  `disable_camera_mic_permanently`, the PTZ tools, `trigger_alarm_webhook`,
  `enable_arm`, `disable_arm`, the siren, speaker, relay and alarm-hub actions,
  `pos_ingest_transaction`).

  Affected tools: `alarm_hub_trigger_output`, `create_arm_profile`, `create_liveview`,
  `create_rtsps_stream`, `disable_arm`, `disable_camera_mic_permanently`, `enable_arm`,
  `pos_ingest_transaction`, `ptz_goto_preset`, `ptz_patrol_start`, `ptz_patrol_stop`,
  `relay_activate_output`, `siren_play`, `siren_stop`, `siren_test_sound`,
  `speaker_test_sound`, `start_talkback_session`, `trigger_alarm_webhook`,
  `upload_protect_file`.

### change-036

- **Breaking (tool results): every Protect update tool returns one shape.**
  `update_camera`, `update_sensor`, `update_light`, `update_chime`, `update_viewer` and
  `update_liveview` now read the object before and after the PATCH, like the other
  Protect updates, returning `{status: "updated", verified, before, after, response}` or
  `{status: "noop", reason, resource}` with no PATCH when nothing would change (0.6.2
  returned the PATCH body and always sent it). The verified updates and
  `update_arm_profile` / `update_arm_profile_settings` include the PATCH body under
  `response`, and `update_arm_profile_settings` reports its no-op object under `resource`
  (was `arm_mode`).

  Affected tools: `update_alarm_hub`, `update_arm_profile`, `update_arm_profile_settings`,
  `update_bridge`, `update_camera`, `update_chime`, `update_fob`, `update_light`,
  `update_link_station`, `update_liveview`, `update_relay`, `update_sensor`,
  `update_siren`, `update_speaker`, `update_viewer`.

### change-037

- **Breaking (tool results): the three Mobility writes return `{status, changed,
  verified, device, response}`.** `changed` maps each sent field to `{from, to}` and
  `verified` is a map of field to bool, with a
  per-field null for unobservable fields (DHCP fields and password), or null when the read-after fails
  (`update_mobility_device_name` returned `verified` as a bare bool; `update_mobility_device_network`
  omitted it without `host_address` and no longer returns its `note` key;
  `update_mobility_device_wireless` no longer echoes `"password": "updated"`). `device`
  is the full device-detail GET body of the read-after (0.6.2 returned only its `data`).
  A write that changes nothing returns `{status: "no_op", reason, device}` and a call under
  `UNIFI_DRY_RUN` returns `{status: "dry_run", device, response}`.

### change-038

- **Breaking (tool results): the seven Carrier Fabric writes embed bodies verbatim.**
  Affected tools: `create_carrier_subscriber`, `update_carrier_subscriber`,
  `attach_carrier_subscriber_host`, `detach_carrier_subscriber_host`,
  `assign_carrier_subscriber_plan`, `suspend_carrier_subscriber` and
  `resume_carrier_subscriber`.
  `subscriber` is the full body of the read-after (the write response when it carries the
  subscriber, otherwise a read-back GET; `create_carrier_subscriber` the 201 body, or
  `null` when it carries no subscriber), and the write body is under `response` (0.6.2
  returned only `data`). `suspend_carrier_subscriber` and `resume_carrier_subscriber`
  report `changed`, `create_carrier_subscriber` reports every sent field in `changed`,
  and `update_carrier_subscriber` reports `verified`. A write that changes nothing returns
  `status: "no_op"` and a call under `UNIFI_DRY_RUN` returns `status: "dry_run"`, each with
  `subscriber`. Read the resource at `subscriber.data` (Mobility: `device.data`).

### change-039

- **Breaking (tool results): an opted-out write area raises instead of returning
  `{status: "disabled", reason}`.** With `UNIFI_PROTECT_MUTATIONS_ENABLED`,
  `UNIFI_ENABLE_MOBILITY_WRITE` or `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` falsey, every write
  tool of the area fails before any request or argument check, naming the variable, its
  value, the value that re-enables it and where it is set. 0.6.2 returned that object as
  a success (Mobility and Carrier Fabric after a read). Affected: Protect
  (`UNIFI_PROTECT_MUTATIONS_ENABLED`) `alarm_hub_trigger_output`, `create_arm_profile`,
  `delete_arm_profile`, `disable_arm`, `enable_arm`, `pos_ingest_transaction`,
  `relay_activate_output`, `siren_play`, `siren_stop`, `siren_test_sound`,
  `speaker_test_sound`, `update_alarm_hub`, `update_arm_profile`,
  `update_arm_profile_settings`, `update_bridge`, `update_fob`, `update_link_station`,
  `update_relay`, `update_siren` and `update_speaker`; the three Mobility writes; the
  seven Carrier Fabric writes. These Protect tools ignored the flag in 0.6.2 and now
  raise when it is off: `ptz_goto_preset`, `ptz_patrol_start`, `ptz_patrol_stop`,
  `start_talkback_session`, `disable_camera_mic_permanently`, `update_camera`,
  `create_rtsps_stream`, `delete_rtsps_stream`, `update_sensor`, `update_light`,
  `update_chime`, `update_viewer`, `create_liveview`, `update_liveview`,
  `upload_protect_file` and `trigger_alarm_webhook`. The `UNIFI_ENABLE_CONNECTOR_WRITE`
  refusal is worded the same way. The write tools of an opted-out area are also omitted
  from `tools/list` and from discovery search; calling one by name raises the error.

  Affected tools: `alarm_hub_trigger_output`, `assign_carrier_subscriber_plan`,
  `attach_carrier_subscriber_host`, `create_arm_profile`, `create_carrier_subscriber`,
  `create_liveview`, `create_rtsps_stream`, `delete_arm_profile`, `delete_rtsps_stream`,
  `detach_carrier_subscriber_host`, `disable_arm`, `disable_camera_mic_permanently`,
  `enable_arm`, `fabric_connector_delete`, `fabric_connector_patch`,
  `fabric_connector_post`, `fabric_connector_put`, `pos_ingest_transaction`,
  `ptz_goto_preset`, `ptz_patrol_start`, `ptz_patrol_stop`, `relay_activate_output`,
  `resume_carrier_subscriber`, `siren_play`, `siren_stop`, `siren_test_sound`,
  `speaker_test_sound`, `start_talkback_session`, `suspend_carrier_subscriber`,
  `trigger_alarm_webhook`, `update_alarm_hub`, `update_arm_profile`,
  `update_arm_profile_settings`, `update_bridge`, `update_camera`,
  `update_carrier_subscriber`, `update_chime`, `update_fob`, `update_light`,
  `update_link_station`, `update_liveview`, `update_mobility_device_name`,
  `update_mobility_device_network`, `update_mobility_device_wireless`, `update_relay`,
  `update_sensor`, `update_siren`, `update_speaker`, `update_viewer`,
  `upload_protect_file`.

### change-040

- **Breaking (tool results): port-profile network fields are the controller's own
  values.** 0.6.2 replaced `excluded_networkconf_ids`, `native_networkconf_id` and
  `voice_networkconf_id` with `{id, name, vlan}` objects in `list_port_profiles`,
  `get_port_profile`, `update_port_profile` and the two port-profile network tools, so a
  read could not be written back. They are now the bare ids, with the resolution under
  `_resolved_networks`; a failed name lookup is reported under `_resolvedNetworksError`
  and never fails the call (writes included), and a PUT answer without the profile is
  reported under `_profileNote`.

  Affected tools: `allow_network_on_port_profile`, `exclude_network_on_port_profile`,
  `get_port_profile`, `list_port_profiles`, `update_port_profile`.

### change-041

- **Breaking (tool results): server-added keys are `_`-prefixed.** `create_network`
  reports its D12 warnings under `_warnings` (was `warnings`, merged into any upstream
  field) and returns the created network verbatim.

### change-042

- **Breaking (tool results): `create_vpn_server`, `update_vpn_server` and
  `create_radius_profile` return the upstream body verbatim** (0.6.2 unwrapped `data`),
  and send only the fields the caller passed: `create_vpn_server` `enabled` (was `true`)
  and `create_radius_profile` `acct_server_port` (was `1813`) now default to unset.


### change-043

- **Breaking (tool routes, inputs and results): the device-tag, VPN-server,
  site-to-site-tunnel, RADIUS-profile-create and WAN-update writes use the routes the
  controller's UI uses, and work.** The Network Integration API serves these collections
  GET-only (POST answers 405, PUT/DELETE 404), so all 11 writes always failed in 0.6.2.
  - `create_device_tag`, `update_device_tag` and `delete_device_tag` use the v2 API with
    v2 bodies (create: `name`, `member_device_macs`; update: `device_mac_additions`,
    `device_mac_removals`, or an edited `list_device_tags` entry whose
    `member_device_macs` is turned into those, MACs normalized; a body that is neither
    form is sent verbatim, and an upstream error, such as the bare HTTP 500 the
    controller answers without additions and removals, gets a hint naming the forms).
    `tag_id` is the v2 `_id` or the name (exact, then
    case-insensitive, then edge-whitespace stripped); update and delete read the site's
    tags first and fail listing every tag for an unknown or ambiguous value (the
    controller answers a DELETE for an unknown id with 200).
    Create and update return the v2 tag object verbatim; delete returns the standard
    delete result with the upstream body under `response` (or `null` for HTTP 204).
  - `create_vpn_server`, `update_vpn_server`, `delete_vpn_server`,
    `create_site_to_site_tunnel`, `update_site_to_site_tunnel`,
    `delete_site_to_site_tunnel` and `update_wan_interface` write Classic `networkconf`
    records with native snake_case fields (not the Integration camelCase shape); the tools
    pin `purpose` (an absent or null one is sent as the record's purpose; another one is
    sent as given, and an upstream error gets a hint naming the tool's purpose; a body of
    only `purpose` is empty), accept the Integration id (matched
    against `external_id`) or the Classic `_id` among records of that purpose only, and
    return the Classic envelope for create/update. Deletes return the standard
    delete result with the upstream body under `response` (or `null` for HTTP 204).
    `create_vpn_server` maps `vpn_type`
    wireguard/openvpn/l2tp/pptp to the controller's `*-server` values, sends `subnet` as
    `ip_subnet` and gains `fields`; `create_site_to_site_tunnel` takes `name` and
    `vpn_type` (`ipsec-vpn`, `openvpn-vpn`, `wireguard-vpn`) in the body, sent as given
    (an upstream error gets a hint naming a missing one).
  - `create_radius_profile` posts Classic `rest/radiusprofile` with
    `auth_servers: [{ip, port, x_secret}]` and, when `acct_server_ip` is given,
    `acct_servers` (an accounting port or secret without it is sent in an
    `acct_servers` entry without `ip`, and an upstream error gets a hint), and gains
    `fields`.

### change-044

- **Breaking (tool route, input and result): `list_device_tags` lists the tags the
  Network UI shows.** The Integration route it read answers empty on Network 11.0.81 and
  its ids are not the `_id` the tag writes take. It now reads the v2
  `GET /proxy/network/v2/api/site/{site}/device-tags` and returns that bare array
  (`{_id, name, member_device_macs}`); 0.6.2's first-page envelope is gone. The tool still
  takes only `host` and `site`.

### change-045

- **Breaking (device tools): `locate_device` and `upgrade_device` use the Classic device
  manager** (`cmd/devmgr` `set-locate` / `unset-locate` / `upgrade`), accept a device
  UUID or MAC and return the Classic envelope; the Integration route rejects every action
  but `RESTART`, so both always failed. `restart_device` sends the spec value `RESTART`
  (it sent `restart`, which the controller rejects).

### change-046

- **Breaking (tool input): `approve_pending_device` requires `ignore_device_limit` and
  adopts by MAC.** It posts the spec's adoptDevice request (`POST /v1/sites/{siteId}/devices`
  with `macAddress` and `ignoreDeviceLimit`), so `device_id` is the pending device's MAC.
  0.6.2 posted `{"action": "approve"}` to the device-actions route, which the controller
  rejects. Pass `"ignore_device_limit": false` for an ordinary adoption.

### change-047

- **Breaking (tool input): `execute_client_action` accepts only `AUTHORIZE_GUEST_ACCESS`
  and `UNAUTHORIZE_GUEST_ACCESS`** (the spec's actions). The `block` / `unblock` /
  `reconnect` its description named fail before any request, naming the valid actions.
  The description documents the authorize options (`timeLimitMinutes`,
  `dataUsageLimitMBytes`, `rxRateLimitKbps`, `txRateLimitKbps`).

### change-048

- **Breaking (tool input): `bulk_delete_hotspot_vouchers` requires `filter` in
  `filter_params`** (the spec marks it required); without it the call fails before any
  request.

### change-049

- **Breaking (tool input): `get_setting` and `update_setting` validate `setting_key`.**
  A key with characters other than letters, digits, `-` and `_` fails instead of changing
  the request path or query. Documented keys are unaffected.

### change-050

- **Breaking (tool input): `limit` above 200 is accepted and gathers that many records.**
  `list_local_sites`, `list_networks`, `list_lags`, `list_mc_lag_domains` and
  `list_switch_stacks` no longer reject a `limit` above 200: without `offset`, `limit` is
  the total to gather, fetched in wire pages of at most 200 (`limit=500` makes three
  requests). A negative `limit` or `offset`, and a `limit` of 0, are still refused before
  any request. Passing `offset` (with or without `limit`) sends exactly one native page.
  The first request sends only the paging parameters given, in every list tool: a
  `limit` without `offset` sends no `offset` (Mobility lists included), a `page_token`
  or `page` alone sends no `pageSize`; `page_size` on the Protect page-number lists also
  sends `page=1`. An explicit `offset` on `list_clients`,
  `list_site_devices`, `list_firewall_policies` and `list_firewall_zones_proxy` returns
  the controller's native page. Mobility uses `offset` alone for a native page;
  with `limit`, it gathers that total starting at `offset` (zero included). A
  native-page call with an explicit `offset`, `page`,
  `page_token` or `cursor` for a page the upstream sends as a bare JSON array returns
  that array unchanged (cursor, offset, page-number,
  Mobility and Carrier lists: `list_hosts`, `list_sites`, `list_devices`,
  `list_sdwan_configs`, `list_protect_events`, `list_recognition_groups`,
  `list_recognition_detections`, `list_mobility_devices`, `list_mobility_clients`,
  `list_carrier_subscribers` among them), never wrapped in a `data`, `groups`,
  `detections` or `result` object and never refused as a shape error. A `limit` without
  `offset`, or a `page_size`, asks for a total and returns the tool's usual envelope
  (`data` or the tool's own list key, with `_pageSize`).

### change-051

- **Breaking (tool inputs): input schemas compared with 0.6.2.** The catalog grows from
  283 to 786 tools (504 additions listed under Added; `reject_pending_device` removed). Added is the 0.7.0 section of `CHANGELOG.md` that lists them.
  97 of the 282 tools in both catalogs change their input schema (descriptions aside):
  `adopt_device`, `alarm_hub_trigger_output`, `approve_pending_device`,
  `bulk_delete_hotspot_vouchers`, `create_acl_rule`, `create_arm_profile`,
  `create_carrier_subscriber`, `create_dns_policy`, `create_firewall_policy`,
  `create_firewall_zone_proxy`, `create_hotspot_vouchers`, `create_liveview`, `create_network`,
  `create_radius_profile`, `create_traffic_matching_list`, `create_vpn_server`,
  `create_wifi_broadcast`, `delete_network`, `delete_rtsps_stream`, `delete_wifi_broadcast`,
  `disable_camera_mic_permanently`, `execute_client_action`, `execute_device_action`,
  `execute_port_action`, `fabric_connector_delete`, `fabric_connector_patch`,
  `fabric_connector_post`, `fabric_connector_put`, `get_camera_snapshot`, `get_innerspace_asset`,
  `get_innerspace_project`, `get_isp_metrics`, `get_site_inventory`, `list_acl_rules`, `list_all_clients`, `list_all_devices`,
  `list_carrier_subscribers`, `list_clients`, `list_countries`, `list_devices`, `list_dns_policies`,
  `list_dpi_applications`, `list_dpi_categories`, `list_firewall_zones_proxy`, `list_hosts`, `list_hotspot_vouchers`,
  `list_known_clients`, `list_mobility_clients`, `list_mobility_devices`, `list_pending_devices`,
  `list_protect_events`, `list_radius_profiles`, `list_sdwan_configs`, `list_site_to_site_tunnels`,
  `list_sites`, `list_traffic_matching_lists`, `list_vpn_servers`, `list_wan_interfaces`,
  `list_wifi_broadcasts`, `locate_device`, `patch_firewall_policy`, `pos_ingest_transaction`,
  `ptz_goto_preset`, `ptz_patrol_start`, `ptz_patrol_stop`, `query_isp_metrics`,
  `relay_activate_output`, `restart_device`, `set_acl_rule_ordering`,
  `set_firewall_policy_ordering`, `start_talkback_session`, `unadopt_device`, `update_acl_rule`,
  `update_alarm_hub`, `update_arm_profile`, `update_bridge`, `update_camera`,
  `update_carrier_subscriber`, `update_chime`, `update_dns_policy`, `update_firewall_policy`,
  `update_firewall_zone_proxy`, `update_fob`, `update_light`, `update_link_station`,
  `update_liveview`, `update_mobility_device_network`, `update_network`, `update_relay`,
  `update_sensor`, `update_siren`, `update_speaker`, `update_traffic_matching_list`,
  `update_viewer`, `update_wifi_broadcast`, `upgrade_device`, `upload_protect_file`. `relay_activate_output` and `alarm_hub_trigger_output`
  `output_id` also accept the spec integer (a decimal string still works), and
  `delete_rtsps_stream` `qualities` also accepts one channel as a string (the spec scalar
  form); `approve_pending_device` gains the required `ignore_device_limit`;
  `create_radius_profile` `acct_server_port` and `create_vpn_server` `enabled` lose their
  defaults; `list_protect_events` `order_direction` loses its `"ASC"` default (nothing is
  sent unless given); `create_radius_profile` and `create_vpn_server` gain `fields`; the optional
  `site` of `list_dpi_categories` and `list_dpi_applications` defaults to null; 15 tools
  gain the ignored `confirm` (see change-053); 40 tools gain the other new optional
  parameters, each listed under Added in the 0.7.0 section of `CHANGELOG.md`; `create_carrier_subscriber`,
  `update_carrier_subscriber` and `update_mobility_device_network` no longer advertise a
  null default for their nullable fields (an explicit null is forwarded, an omitted one
  stays omitted: see the explicit-null entry); and `query_isp_metrics` `sites` entries
  may be null (sent as given).

### change-052

- **Breaking (behavior): explicit null forwarding for Carrier and Mobility fields.**
  `update_carrier_subscriber` forwards `name`, `email`, `notes`, `service_address`,
  `plan_id` and `metadata` as null to clear the field when explicitly passed as null; 0.6.2
  dropped `None`. `update_mobility_device_network` also forwards explicit null for
  `host_address`, `dhcp_mode`, `dhcp_range_start`, `dhcp_range_stop` and
  `dhcp_lease_time`. Omitted arguments remain omitted. Carrier `serviceAddress`,
  `suspendReason` and `metadata`, which the spec omits when unset, still compare an
  omitted field as cleared.
- **Breaking (behavior): the connector relay sends an explicit `null` body.**
  `fabric_connector_post`, `fabric_connector_put`, `fabric_connector_patch` and
  `fabric_connector_delete` called with `"body": null` send the JSON body `null`; 0.6.2
  sent no body for the same call. An omitted `body` still sends none. Caller action: many
  clients serialize an unset optional argument as `null`, so omit `body` (do not pass
  `null`) to send no body.

### change-053

- **Breaking (behavior): no unrequested gates; write areas default on.** The tools that
  refused without `confirm=true` in 0.6.2 act without it: `alarm_hub_trigger_output`, `allow_network_on_port_profile`, `assign_carrier_subscriber_plan`, `attach_carrier_subscriber_host`, `create_carrier_subscriber`, `delete_arm_profile`, `detach_carrier_subscriber_host`, `disable_arm`, `enable_arm`, `exclude_network_on_port_profile`, `fabric_connector_delete`, `fabric_connector_patch`, `fabric_connector_post`, `fabric_connector_put`, `pos_ingest_transaction`, `relay_activate_output`, `resume_carrier_subscriber`, `siren_play`, `siren_stop`, `siren_test_sound`, `speaker_test_sound`, `suspend_carrier_subscriber`, `trigger_alarm_webhook`, `update_carrier_subscriber`, `update_mobility_device_name`, `update_mobility_device_network`, `update_mobility_device_wireless`.
  `confirm` is still accepted but ignored, on every tool and not only those listed here:
  it is dropped before argument validation, so the connector relay's audit line always
  logs `confirm=False`, even when a caller sent `true`. The 27 tools above keep it in
  their schema, 15 more advertise it
  (`adopt_device`, `approve_pending_device`,
  `bulk_delete_hotspot_vouchers`, `disable_camera_mic_permanently`,
  `execute_client_action`, `execute_device_action`, `execute_port_action`,
  `locate_device`, `ptz_goto_preset`, `ptz_patrol_start`, `ptz_patrol_stop`,
  `restart_device`, `start_talkback_session`, `unadopt_device`, `upgrade_device`), and
  many of the new tools advertise it too (such as `forget_device`; see Added in the 0.7.0
  section of `CHANGELOG.md`). Use `UNIFI_DRY_RUN` for a no-send check.
  Because `confirm` is ignored, the connector relay results (`fabric_connector_post`,
  `fabric_connector_put`, `fabric_connector_patch`, `fabric_connector_delete`) no longer
  carry the `confirmed` key that 0.6.2 echoed; read `status` and `writeEnabled` instead. `UNIFI_ENABLE_CONNECTOR_WRITE`,
  `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` and `UNIFI_ENABLE_MOBILITY_WRITE` now default on
  (0.6.2: off); set `=0` to make an area read-only. `UNIFI_PROTECT_MUTATIONS_ENABLED`
  stays on.

### change-054

- **Breaking (behavior): only a GET is retried on HTTP 429.** Every other request is sent
  once, as is a GET of a state-changing route (the Protect camera enable-control and
  disable-control routes, reached through `fabric_connector_get`, which is still retried for
  every other route, or through `set_camera_control_enabled`), and the 429 is raised with its body, so no write or physical action (device
  restart, PoE power cycle, PTZ, talkback, alarm webhook, relayed mutation) is sent
  twice. 0.6.2 retried creates, updates, deletes, client and device actions, the PTZ,
  talkback, disable-mic and alarm-webhook actions, and query POSTs up to five times. A
  GET still limited after every retry reports the last 429 body.

  Affected tools: `adopt_device`, `alarm_hub_trigger_output`,
  `allow_network_on_port_profile`, `approve_pending_device`,
  `assign_carrier_subscriber_plan`, `attach_carrier_subscriber_host`, `block_client`,
  `bulk_delete_hotspot_vouchers`, `create_acl_rule`, `create_arm_profile`,
  `create_carrier_subscriber`, `create_device_tag`, `create_dns_policy`,
  `create_firewall_policy`, `create_firewall_zone_proxy`, `create_hotspot_operator`,
  `create_hotspot_vouchers`, `create_liveview`, `create_network`, `create_port_forward`,
  `create_radius_profile`, `create_rtsps_stream`, `create_site_to_site_tunnel`,
  `create_traffic_matching_list`, `create_traffic_route`, `create_traffic_rule`,
  `create_vpn_server`, `create_wifi_broadcast`, `delete_acl_rule`, `delete_arm_profile`,
  `delete_device_tag`, `delete_dns_policy`, `delete_firewall_policy`,
  `delete_firewall_zone_proxy`, `delete_hotspot_operator`, `delete_hotspot_voucher`,
  `delete_network`, `delete_port_forward`, `delete_rtsps_stream`,
  `delete_site_to_site_tunnel`, `delete_traffic_matching_list`, `delete_traffic_route`,
  `delete_traffic_rule`, `delete_vpn_server`, `delete_wifi_broadcast`,
  `detach_carrier_subscriber_host`, `disable_arm`, `disable_camera_mic_permanently`,
  `enable_arm`, `exclude_network_on_port_profile`, `execute_client_action`,
  `execute_device_action`, `execute_port_action`, `fabric_connector_delete`,
  `fabric_connector_patch`, `fabric_connector_post`, `fabric_connector_put`,
  `get_historical_stats`, `list_client_sessions`, `locate_device`,
  `patch_firewall_policy`, `pos_ingest_transaction`, `ptz_goto_preset`,
  `ptz_patrol_start`, `ptz_patrol_stop`, `query_isp_metrics`, `reconnect_client`,
  `relay_activate_output`, `restart_device`, `resume_carrier_subscriber`,
  `set_acl_rule_ordering`, `set_firewall_policy_ordering`, `siren_play`, `siren_stop`,
  `siren_test_sound`, `speaker_test_sound`, `start_talkback_session`,
  `suspend_carrier_subscriber`, `trigger_alarm_webhook`, `unadopt_device`,
  `unblock_client`, `update_acl_rule`, `update_alarm_hub`, `update_arm_profile`,
  `update_arm_profile_settings`, `update_bridge`, `update_camera`,
  `update_carrier_subscriber`, `update_chime`, `update_device_tag`, `update_dns_policy`,
  `update_dynamic_dns`, `update_firewall_policy`, `update_firewall_zone_proxy`,
  `update_fob`, `update_hotspot_operator`, `update_light`, `update_link_station`,
  `update_liveview`, `update_mobility_device_name`, `update_mobility_device_network`,
  `update_mobility_device_wireless`, `update_network`, `update_port_forward`,
  `update_port_profile`, `update_relay`, `update_sensor`, `update_setting`,
  `update_siren`, `update_site_to_site_tunnel`, `update_speaker`,
  `update_traffic_matching_list`, `update_traffic_route`, `update_traffic_rule`,
  `update_user`, `update_viewer`, `update_vpn_server`, `update_wan_interface`,
  `update_wifi_broadcast`, `update_wlan_config`, `upgrade_device`, `upload_protect_file`.

### change-055

- **Breaking (behavior): `create_carrier_subscriber` never creates under the first
  configured key by default.** With several keys and no `key_label`, it routes to the key
  that owns `plan_id`, or fails before any request listing the labels when there is no
  `plan_id`. Single-key deployments and calls with `key_label` are unchanged.

### change-056

- **Breaking (behavior): `get_historical_stats` sends `attrs` only when given.** 0.6.2
  always sent `attrs`, defaulting to `num_sta`, `rx_bytes` and `tx_bytes`; without it the
  controller chooses the fields.

### change-057

- **Breaking (tool results): org-scoped and fleet tools merge every configured API
  key.** 0.6.2 queried one key: `list_all_clients`, `list_mobility_workspaces`, `list_mobility_admins`,
  `list_mobility_devices`, `list_mobility_clients`, `list_carrier_subscribers`,
  `list_carrier_service_plans`, `list_all_devices`, `get_fleet_summary` and
  `search_device_fleet` the default key
  unless `key_label` named another; `list_devices` (which had no `key_label`) the
  default key, or with `host` the key owning that console; `list_sdwan_configs` (no
  `key_label` either) always the default key. Without `key_label`, all of them now
  merge every key (records tagged `_keyLabel`, per-key failures under `errors`; one
  key's malformed list is that key's error), so their results hold more records, and a console visible to
  several keys is counted once, under the first key in configuration order. Every
  multi-key result reports `_key_labels` as the keys whose results are included (the
  same labels as its `byKey` keys, when it has `byKey`), with each failed key under
  `errors` as `<label>: <reason>` (`search_across_sites` entries are objects
  `{key, siteId, scope, reason}`, scope `"sites"` for a key's failed site list).
  `list_hosts`, `list_sites` and `list_all_sites_aggregated` list a console seen by several keys once (they returned it
  once per key). Gets and writes use the key that owns the object (`get_sdwan_config`
  and `get_sdwan_config_status` use the key that answers); an unknown `key_label` lists
  the configured labels.

### change-058

- **Breaking (tool input): with several API keys, a manual page needs `key_label`.** A
  cursor belongs to one key's listing, so `page_token` on `list_hosts`, `list_sites`,
  `list_sdwan_configs` and `list_devices` (without `host`), and the new `page_size`, fail
  before any request without `key_label`, listing the configured labels. 0.6.2 ignored
  `page_token` on `list_hosts` and `list_sites` and returned every key's merged list, and
  paged `list_devices` and `list_sdwan_configs` on the default key. With one key, the
  default key is paged, as before. The new `list_carrier_subscribers` `cursor` / `limit`
  follow the same rule.

### change-059

- **Breaking (tool results): values are passed through as sent.** `list_protect_events` keeps the
  controller's `sensor` field (0.6.2 replaced a null `sensor` with the id from
  `metadata.sensorId.text`; the resolved id is now under `_resolved_sensor`). `get_camera_snapshot`, `get_recognition_group_image`, `get_thumbnail` and
  `get_innerspace_asset` report the upstream Content-Type, or `null` when none is sent
  (0.6.2's `get_camera_snapshot`, `get_recognition_group_image` and `get_thumbnail`
  always reported `image/jpeg`; `get_innerspace_asset` reported the
  upstream type but `application/octet-stream` when none was sent).

### change-060

- **Breaking (behavior): host and site resolution never guess.** An unknown `host` fails
  listing every console across all keys, noting a key whose console list was capped
  (0.6.2 fell back to the default key, and `resolve_host_id` sent the string upstream as
  an id); a name shared by two consoles fails listing them. Multi-key matching uses the
  same identifiers as single-key, a display name (`reportedState.name`) also resolves and
  a null hostname no longer raises `AttributeError`. Site Manager sites are matched by
  `meta.name` / `meta.desc` (the real object shape; 0.6.2 matched top-level
  `siteName`/`description`, which the objects lack) or `siteId`, and mapped to the
  console site by internal reference; a site that maps to no console site or to several
  fails listing the valid sites (0.6.2 used a single-site console's only site, or the
  first match). Shared site names fail listing each match; camera names match exactly, then
  NFC-normalized and casefolded, then stripped, and a tie fails listing each match.
  `query_isp_metrics` resolves `host`+`site` to the Site Manager `siteId` (0.6.2 used the
  console UUID and got an empty result), resolves a console name in raw `sites[]`, and
  rejects an unknown `siteId`.

  Affected tools: `adopt_device`, `alarm_hub_trigger_output`, `allow_network_on_port_profile`, `approve_pending_device`, `assign_carrier_subscriber_plan`, `attach_carrier_subscriber_host`, `block_client`, `bulk_delete_hotspot_vouchers`, `compare_site_performance`, `create_acl_rule`, `create_arm_profile`, `create_carrier_subscriber`, `create_device_tag`, `create_dns_policy`, `create_firewall_policy`, `create_firewall_zone_proxy`, `create_hotspot_operator`, `create_hotspot_vouchers`, `create_liveview`, `create_network`, `create_port_forward`, `create_radius_profile`, `create_rtsps_stream`, `create_site_to_site_tunnel`, `create_traffic_matching_list`, `create_traffic_route`, `create_traffic_rule`, `create_vpn_server`, `create_wifi_broadcast`, `delete_acl_rule`, `delete_arm_profile`, `delete_device_tag`, `delete_dns_policy`, `delete_firewall_policy`, `delete_firewall_zone_proxy`, `delete_hotspot_operator`, `delete_hotspot_voucher`, `delete_network`, `delete_port_forward`, `delete_rtsps_stream`, `delete_site_to_site_tunnel`, `delete_traffic_matching_list`, `delete_traffic_route`, `delete_traffic_rule`, `delete_vpn_server`, `delete_wifi_broadcast`, `detach_carrier_subscriber_host`, `disable_arm`, `disable_camera_mic_permanently`, `enable_arm`, `exclude_network_on_port_profile`, `execute_client_action`, `execute_device_action`, `execute_port_action`, `fabric_connector_delete`, `fabric_connector_get`, `fabric_connector_patch`, `fabric_connector_post`, `fabric_connector_put`, `get_account`, `get_acl_rule`, `get_acl_rule_ordering`, `get_alarm_hub`, `get_arm_profile`, `get_bridge`, `get_camera`, `get_camera_snapshot`, `get_carrier_service_plan`, `get_carrier_subscriber`, `get_channel_plan`, `get_chime`, `get_client`, `get_client_link_diagnostics`, `get_device`, `get_device_port_state`, `get_device_statistics`, `get_device_stp_state`, `get_dns_policy`, `get_dynamic_dns`, `get_firewall_group`, `get_firewall_policy`, `get_firewall_policy_ordering`, `get_firewall_rule`, `get_firewall_zone_proxy`, `get_fleet_summary`, `get_fob`, `get_historical_stats`, `get_host`, `get_hotspot_package`, `get_hotspot_voucher`, `get_innerspace_asset`, `get_innerspace_project`, `get_innerspace_summary`, `get_lag`, `get_light`, `get_link_station`, `get_liveview`, `get_mc_lag_domain`, `get_mobility_device`, `get_network`, `get_network_application_info`, `get_network_references`, `get_nvr`, `get_port_profile`, `get_protect_application_info`, `get_protect_user`, `get_radius_profile`, `get_recognition_group_counts`, `get_recognition_group_image`, `get_relay`, `get_rtsps_stream`, `get_scheduled_task`, `get_sensor`, `get_setting`, `get_siren`, `get_site_health_summary`, `get_site_inventory`, `get_site_statistics`, `get_speaker`, `get_switch_stack`, `get_system_info`, `get_thumbnail`, `get_traffic_matching_list`, `get_traffic_route`, `get_ulp_user`, `get_user`, `get_viewer`, `get_vpn_server`, `get_wifi_broadcast`, `get_wlan_config`, `get_wlan_group`, `list_accounts`, `list_acl_rules`, `list_active_clients_stats`, `list_alarm_hubs`, `list_all_clients`, `list_all_devices`, `list_arm_profiles`, `list_bridges`, `list_cameras`, `list_carrier_service_plans`, `list_carrier_subscribers`, `list_chimes`, `list_client_sessions`, `list_clients`, `list_countries`, `list_device_stats`, `list_device_tags`, `list_devices`, `list_dns_policies`, `list_dpi_applications`, `list_dpi_categories`, `list_dynamic_dns`, `list_firewall_groups`, `list_firewall_policies`, `list_firewall_rules`, `list_firewall_zones_proxy`, `list_fobs`, `list_hosts`, `list_hotspot_operators`, `list_hotspot_packages`, `list_hotspot_vouchers`, `list_innerspace_access_points`, `list_innerspace_devices`, `list_innerspace_floor_plans`, `list_innerspace_inventory`, `list_innerspace_switches`, `list_known_clients`, `list_lags`, `list_lights`, `list_link_stations`, `list_liveviews`, `list_local_sites`, `list_mc_lag_domains`, `list_mobility_admins`, `list_mobility_clients`, `list_mobility_devices`, `list_mobility_workspaces`, `list_networks`, `list_pending_devices`, `list_port_forwards`, `list_port_profiles`, `list_protect_events`, `list_protect_files`, `list_protect_users`, `list_radius_profiles`, `list_recognition_detections`, `list_recognition_groups`, `list_relays`, `list_rogue_aps`, `list_routing_entries`, `list_scheduled_tasks`, `list_sdwan_configs`, `list_sensors`, `list_settings`, `list_sirens`, `list_site_devices`, `list_site_to_site_tunnels`, `list_sites`, `list_speakers`, `list_switch_stacks`, `list_traffic_matching_lists`, `list_traffic_routes`, `list_traffic_rules`, `list_ulp_users`, `list_users`, `list_viewers`, `list_vpn_servers`, `list_wan_interfaces`, `list_wifi_broadcasts`, `list_wlan_configs`, `list_wlan_groups`, `locate_device`, `patch_firewall_policy`, `pos_ingest_transaction`, `ptz_goto_preset`, `ptz_patrol_start`, `ptz_patrol_stop`, `query_isp_metrics`, `reconnect_client`, `relay_activate_output`, `restart_device`, `resume_carrier_subscriber`, `search_device_fleet`, `set_acl_rule_ordering`, `set_firewall_policy_ordering`, `siren_play`, `siren_stop`, `siren_test_sound`, `speaker_test_sound`, `start_talkback_session`, `suspend_carrier_subscriber`, `trigger_alarm_webhook`, `unadopt_device`, `unblock_client`, `update_acl_rule`, `update_alarm_hub`, `update_arm_profile`, `update_arm_profile_settings`, `update_bridge`, `update_camera`, `update_carrier_subscriber`, `update_chime`, `update_device_tag`, `update_dns_policy`, `update_dynamic_dns`, `update_firewall_policy`, `update_firewall_zone_proxy`, `update_fob`, `update_hotspot_operator`, `update_light`, `update_link_station`, `update_liveview`, `update_mobility_device_name`, `update_mobility_device_network`, `update_mobility_device_wireless`, `update_network`, `update_port_forward`, `update_port_profile`, `update_relay`, `update_sensor`, `update_setting`, `update_siren`, `update_site_to_site_tunnel`, `update_speaker`, `update_traffic_matching_list`, `update_traffic_route`, `update_traffic_rule`, `update_user`, `update_viewer`, `update_vpn_server`, `update_wan_interface`, `update_wifi_broadcast`, `update_wlan_config`, `upgrade_device`, `upload_protect_file`.

### change-061

- **Breaking (tool input): arguments are validated before any request.** Calls 0.6.2 sent
  now fail first, naming the problem: ids, MACs, host ids, camera ids, relay paths and
  asset filenames with a trailing newline (the patterns matched before a final `\n`;
  they anchor with `\Z` now), site UUIDs and free-form selectors likewise; a malformed
  `host`, `site`, `key_label`, `device_id` or `client_id` (empty, padded, a control
  character; one MAC rule, so a padded MAC fails everywhere), on every tool, also inside
  list/dict arguments (`sites[i].hostId`, ...) and as one string (`cameras`, `mac`; a
  camera name may carry spaces)
  (`list_devices(host="")` returned the fleet-wide list); an unknown
  `list_client_sessions` `session_type` (`all`, `user`, `guest`, `voucher`; 0.6.2
  returned every session); a `site` that does not exist on the console for
  `list_dpi_categories` and `list_dpi_applications` (0.6.2 ignored it; their optional
  `site` now defaults to null, where 0.6.2 defaulted to an empty string); the
  `query_isp_metrics` interval, window (`""` is an error), `sites` with `host`+`site`,
  and every `sites[]` entry (all checked before any is resolved; a null timestamp is absent); the `list_recognition_detections` window; `get_device` /
  `get_device_statistics` / `locate_device` / `upgrade_device` `device_id`, the
  diagnostic tools' selectors, the firewall-ordering zone ids (UUIDs, per the spec) and
  `file_type`; an empty `qualities` on the RTSPS tools (minItems 1); a `pos_ingest_transaction`
  `transaction.amount` that is not a finite number >= 0 (null included); NaN or Infinity in any
  argument; an unknown
  `key_label` on any tool, any key count; a relay path placeholder other than `{site}` / `{site_id}`; a `.` / `..` path
  segment; ids by their spec, not stricter rules (Carrier `host_id` up to 128 characters,
  `plan_id` a UUID; `arm_profile_id`, `host_ids`; a spec-string path id such as
  `alarmTriggerId` or an asset filename is any string, percent-encoded); an
  `upload_protect_file` extension other
  than the spec's or content that is not valid base64 (line-wrapped base64 is accepted);
  an `allow_network_on_port_profile` / `exclude_network_on_port_profile` network id that
  does not exist (every network is listed, before any write); and Carrier Fabric text
  over its limit counted in UTF-8 bytes, `metadata` whose serialized JSON exceeds 8192
  bytes, or a
  `subscriber_number` outside 1-32 characters (after trimming on update), as the spec states.

  Affected tools: the 280 tools that exist in 0.6.2 and declare input properties, which
  include `get_sdwan_config`, `get_sdwan_config_status` and `search_across_sites`; see the
  [public tool catalog](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#tool-categories)
  for the full surface.

### change-062

- **Breaking (behavior): update tools refuse a body with nothing to change.** An empty
  body, or one of only `_` keys, ids (`_id`, `id`, `site_id`; `key` for `update_setting`; `purpose` for
  `update_vpn_server`, `update_wan_interface` and `update_site_to_site_tunnel`), masked
  values or empty objects, fails before any request
  with "No fields provided" for every write taking one object body (updates,
  `set_*_ordering`, creates, actions; a create or action error names the keys its
  published request schema requires; an ordering without its `ordered*Ids` list too; the Protect updates
  sent `PATCH {}` and reported `updated`), and an Integration update given only
  server-managed fields (`id`, `metadata`, `default`, `index` except on ACL rules) is
  refused instead of sending an empty body.

  Affected tools: `adopt_device`, `create_acl_rule`,
  `create_arm_profile`, `create_device_tag`, `create_dns_policy`,
  `create_firewall_policy`, `create_firewall_zone_proxy`, `create_hotspot_vouchers`,
  `create_network`, `create_port_forward`, `create_site_to_site_tunnel`,
  `create_traffic_matching_list`, `create_traffic_route`, `create_traffic_rule`,
  `create_wifi_broadcast`, `execute_client_action`, `execute_device_action`,
  `execute_port_action`, `patch_firewall_policy`, `pos_ingest_transaction`,
  `set_acl_rule_ordering`, `set_firewall_policy_ordering`, `update_acl_rule`,
  `update_alarm_hub`, `update_arm_profile`, `update_bridge`, `update_camera`,
  `update_carrier_subscriber`, `update_chime`, `update_device_tag`, `update_dns_policy`,
  `update_dynamic_dns`, `update_firewall_policy`, `update_firewall_zone_proxy`,
  `update_fob`, `update_hotspot_operator`, `update_light`, `update_link_station`,
  `update_liveview`, `update_mobility_device_network`, `update_network`,
  `update_port_forward`, `update_port_profile`, `update_relay`, `update_sensor`,
  `update_setting`, `update_siren`, `update_site_to_site_tunnel`, `update_speaker`,
  `update_traffic_matching_list`, `update_traffic_route`, `update_traffic_rule`,
  `update_user`, `update_viewer`, `update_vpn_server`, `update_wan_interface`,
  `update_wifi_broadcast`, `update_wlan_config`.

### change-063

- **Breaking (behavior): no-op and verification checks compare leaf by leaf,
  type-strictly.** The Protect updates, `update_arm_profile`, `update_setting`, the Carrier
  Fabric and Mobility writes compare only the leaves the request names (a partial nested
  update such as `osdSettings={"isDateEnabled": true}` reported `verified: false`, and
  `update_setting` raised a spurious "silent no-op"), and `1` no longer equals `true`, so
  such a call now writes instead of returning `noop`. `update_setting`'s post-write check
  walks the request leaf by leaf too: a requested leaf left unchanged by the write is
  reported, not raised. `update_setting` returns the PUT response with `_verified: false`,
  `_unverifiedFields` naming every rejected leaf as a dotted path (`radius.port`) and
  `_verificationNote` naming the leaves that were applied, so a nested object with one leaf
  applied and a sibling silently dropped is reported instead of returned as success
  (`_verified` is `null` with `_readAfterError` when the read after the write failed; the
  write was still sent). 0.6.2 raised an error for a rejected field; a caller that
  caught that error must check that `update_setting` returns `_verified: true` instead. `suspend_carrier_subscriber` sends
  the suspend when the reason differs (it returned `no_op`) and verifies the requested
  reason as well as the suspended state. The connector relay reports
  `noOp` only for a write the upstream accepted (0.6.2 compared its reads whatever the
  write's status).

  Affected tools: `assign_carrier_subscriber_plan`, `attach_carrier_subscriber_host`,
  `detach_carrier_subscriber_host`, `fabric_connector_delete`, `fabric_connector_patch`,
  `fabric_connector_post`, `fabric_connector_put`, `resume_carrier_subscriber`,
  `suspend_carrier_subscriber`, `update_alarm_hub`, `update_arm_profile`,
  `update_arm_profile_settings`, `update_bridge`, `update_camera`,
  `update_carrier_subscriber`, `update_chime`, `update_fob`, `update_light`,
  `update_link_station`, `update_liveview`, `update_mobility_device_name`,
  `update_mobility_device_network`, `update_mobility_device_wireless`, `update_relay`,
  `update_sensor`, `update_setting`, `update_siren`, `update_speaker`, `update_viewer`.

### change-064

- **Breaking (behavior): a call that reached nothing fails.** `search_across_sites` and
  `list_all_clients` raise when no site could be queried, and `list_all_clients`,
  `compare_site_performance` and the affected multi-key tools raise when every key or
  site fails, with every reason (0.6.2 returned an empty or error-only result).
  Unexpected response shapes raise naming the shape received instead of reading as
  empty or being wrapped as `{"data": ...}`. `get_innerspace_summary` no longer counts a
  missing collection as 0, and reports `attenuation_object_type_count: null` when the
  document has none.

  Affected tools: `compare_site_performance`, `delete_arm_profile`, `execute_client_action`, `execute_device_action`, `execute_port_action`, `get_alarm_hub`, `get_arm_profile`, `get_bridge`, `get_camera`, `get_chime`, `get_client`, `get_device`, `get_device_statistics`, `get_fleet_summary`, `get_fob`, `get_host`, `get_innerspace_summary`, `get_isp_metrics`, `get_light`, `get_link_station`, `get_liveview`, `get_nvr`, `get_protect_application_info`, `get_protect_user`, `get_radius_profile`, `get_relay`, `get_rtsps_stream`, `get_sdwan_config`, `get_sdwan_config_status`, `get_sensor`, `get_siren`, `get_site_health_summary`, `get_site_inventory`, `get_speaker`, `get_ulp_user`, `get_viewer`, `get_vpn_server`, `list_acl_rules`, `list_alarm_hubs`, `list_all_clients`, `list_all_devices`, `list_all_sites_aggregated`, `list_arm_profiles`, `list_bridges`, `list_cameras`, `list_chimes`, `list_clients`, `list_countries`, `list_devices`, `list_dns_policies`, `list_dpi_applications`, `list_dpi_categories`, `list_firewall_policies`, `list_firewall_zones_proxy`, `list_fobs`, `list_hosts`, `list_hotspot_vouchers`, `list_innerspace_access_points`, `list_innerspace_devices`, `list_innerspace_floor_plans`, `list_innerspace_inventory`, `list_innerspace_switches`, `list_lags`, `list_lights`, `list_link_stations`, `list_liveviews`, `list_local_sites`, `list_mc_lag_domains`, `list_mobility_admins`, `list_mobility_clients`, `list_mobility_devices`, `list_mobility_workspaces`, `list_networks`, `list_pending_devices`, `list_protect_events`, `list_protect_files`, `list_protect_users`, `list_radius_profiles`, `list_recognition_detections`, `list_recognition_groups`, `list_relays`, `list_sdwan_configs`, `list_sensors`, `list_sirens`, `list_site_devices`, `list_site_to_site_tunnels`, `list_sites`, `list_speakers`, `list_switch_stacks`, `list_traffic_matching_lists`, `list_ulp_users`, `list_viewers`, `list_vpn_servers`, `list_wan_interfaces`, `list_wifi_broadcasts`, `locate_device`, `query_isp_metrics`, `restart_device`, `search_across_sites`, `search_device_fleet`, `unadopt_device`, `update_alarm_hub`, `update_arm_profile`, `update_arm_profile_settings`, `update_bridge`, `update_camera`, `update_chime`, `update_fob`, `update_light`, `update_link_station`, `update_liveview`, `update_relay`, `update_sensor`, `update_siren`, `update_speaker`, `update_viewer`, `upgrade_device`.

### change-065

- **Breaking (connector relay): the per-area write opt-outs apply to relayed writes.**
  `UNIFI_ENABLE_NETWORK_WRITE` (network routes), `UNIFI_PROTECT_MUTATIONS_ENABLED`
  (Protect routes) and `UNIFI_ENABLE_INNERSPACE_WRITE` (InnerSpace routes) refuse a
  relayed write to their area before any request, as do the Mobility and Carrier Fabric
  switches for routes of those areas (0.6.2 checked only `UNIFI_ENABLE_CONNECTOR_WRITE`).
  A write to a route in no mapped namespace (`talk/`, `connect/`, `drive/`) is refused
  while any of these opt-outs is active (see change-009). Relay reads are unaffected.
  Affected tools: `fabric_connector_post`, `fabric_connector_put`,
  `fabric_connector_patch`, `fabric_connector_delete`.

### change-066

- **Breaking (container image): streamable HTTP is stateless by default.** The image
  sets `FASTMCP_STATELESS_HTTP=true` (0.6.2's image did not set it, so FastMCP kept a
  session per client): the server sends no `Mcp-Session-Id` and keeps no per-client
  session, so any replica can answer any request and a client that expects a session id
  does not get one. Set `FASTMCP_STATELESS_HTTP=false` for per-client sessions; SSE and
  stdio are unaffected.

### change-067

- **Breaking (CLI): `unifi-fabric-mcp` reads its command line.** An unknown subcommand
  exits with status 2, suggesting the closest valid command and listing them (0.6.2
  started the server for any argument); `--help` and `--version` work without
  configuration, and dash flags still reach the server.

### change-068

- **Breaking (HTTP): a 3xx upstream response is an error.** Redirects are not followed and
  raise with the status, `Location` and a pointer to `UNIFI_API_BASE_URL`, so a write is
  never re-sent elsewhere and the key never leaves the configured origin. The connector
  relay still returns a 3xx for inspection, with its response headers (`Location`
  included, cookies and credentials excluded) under `headers`. A redirected write is
  audited as `http_3xx`.

### Protect collector completion

`collect_protect_events` and `collect_protect_device_changes` are new in 0.7.0. They poll
`poll_count` times (a positive integer, default 6), spaced by `poll_interval_seconds`
(default 2); there is no `window_seconds` argument. Each poll drains its requests to
completion; `poll_interval_seconds` only spaces completed polls. The result reports
requested `_poll_count` and completed `_polls`. Optional `max_events`/`max_changes` still
stop early with `_truncated`; partial upstream failures retain their incomplete metadata.
No elapsed window or active-request deadline remains. At least two snapshots are
needed to detect device changes. There is no arbitrary upper cap on requested work.

### Request deadline compatibility

`UNIFI_REQUEST_TIMEOUT_SECONDS` no longer limits HTTP calls. 0.6.2 applied a 30 second
default; 0.7.0 sets no HTTP timeout, so a call to an unresponsive console waits until it
completes or the client cancels it. Delete the variable before upgrading: a nonempty
legacy environment variable or constructor value fails startup with a nonsecret
migration error, while an unset, empty or whitespace-only value is accepted. Put any
deadline in your MCP client, reverse proxy or orchestrator. Peer and proxy failures
retain their existing error classification; no retry or byte/shape safety policy
changes.

### change-069

- **Breaking (configuration): settings that would hang or fail later fail at startup,
  naming the variable.** Duplicate API key labels are rejected (0.6.2 sent the second
  key's calls with the first key's key), as is one key under two labels; a key labelled
  `__default__` no longer shares the default path's cache.
  `UNIFI_MAX_CONCURRENCY`, `UNIFI_CACHE_MAX_HOSTS`, `UNIFI_CACHE_MAX_SITES`,
  `UNIFI_PAGINATE_MAX_PAGES` must be at least 1 and
  `UNIFI_CACHE_TTL_SECONDS` must be a whole number of seconds at least 0, in ASCII digits (no sign, `_` or Unicode digit); 0 disables registry caching. An empty or whitespace-only value for any
  `UNIFI_*` / `MCP_*` setting means unset (0.6.2 failed validation, or used a string
  setting as given). Validation errors never show the rejected value (a value set in
  the wrong variable may be a credential): a message names the variable, the
  requirement and the valid choices, and an item's position in a comma-separated list.

### change-070

- **Breaking (configuration): credentials are validated at startup without showing the
  value.** `UNIFI_API_KEY`, every `UNIFI_API_KEYS` key and `MCP_BEARER_TOKEN` must be
  printable ASCII with no whitespace (a stray newline or trailing space is reported, never
  stripped); every `UNIFI_API_KEYS[i].label` must pass the `key_label` rule;
  `MCP_TLS_KEY_PASSWORD` may not hold a control character.

### change-071

- **Breaking (configuration): a malformed setting fails at startup naming the expected
  format or choices.** `UNIFI_API_KEYS` must be a JSON list of
  `{"key", "label", "is_org_key"}` objects; an unknown field in an entry fails naming
  `UNIFI_API_KEYS[i]` and how many unknown fields it has, never their names (a key pasted
  as a field name is not printed) (0.6.2 rejected it too, with pydantic's
  `api_keys.<i>.<field>` "Extra inputs are not permitted"). Every boolean setting, including
  `UNIFI_PROTECT_MUTATIONS_ENABLED`, `UNIFI_ENABLE_MOBILITY_WRITE` and
  `UNIFI_ENABLE_CARRIER_FABRIC_WRITE`, is parsed by one function, at startup and at call
  time: `1`/`true`/`yes`/`on`/`t`/`y` or `0`/`false`/`no`/`off`/`f`/`n`
  (case-insensitive), anything else fails (0.6.2 read any unrecognised Protect value,
  `f` and `n` included, as on, and any unrecognised Mobility or Carrier value as off).
  `UNIFI_LOG_LEVEL` must be `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`,
  `UNIFI_AUDIT_LOG_FORMAT` `text` or `json`, `MCP_AUTH_MODE` / `MCP_TLS_MODE` /
  `MCP_TLS_CERT_REQS` one of their values, every one of these (like the booleans and
  `UNIFI_TOOL_FAMILIES`) case-insensitive with edge whitespace ignored (only
  `MCP_OAUTH_ALGORITHM` stays case-sensitive, as JWT `alg` values are), and
  `UNIFI_API_BASE_URL` an absolute
  `http(s)` URL with a host and no user info, query, fragment or whitespace. API key entries are no longer filled from bare `KEY` / `LABEL` /
  `IS_ORG_KEY` variables.

### change-072

- Every tool parameter carries a JSON-schema `description` (from each docstring's
  `Args:` section) saying where each id comes from, its id space and, for writes, the
  request-body shape from the published specs with a worked example. Tool descriptions
  state return shapes and name the write tool and parameter a read result feeds; a test
  checks every such hand-off.

### change-073

- Tool annotations: the 328 read-only tools advertise `readOnlyHint: true` and
  `destructiveHint: false`; the 458 write tools advertise `readOnlyHint: false` and
  `destructiveHint: true`. 0.6.2 sent none, so clients showed every tool as a
  destructive write. Fifteen tools with read-style names are still annotated as writes
  because their upstream route is a POST not yet proven read-only: `get_inactive_sim_slot`,
  `get_lte_subscription_status`, `get_multicast_insights`,
  `get_remote_access_turn_credentials`, `get_rolling_upgrade_plan`, `get_sites_overview`,
  `get_system_log`, `list_guests`, `list_ips_events`, `list_network_events`,
  `query_app_traffic_rates`, `query_port_system_logs`, `query_power_supervisor_logs`,
  `query_switch_mac_tables` and `query_teleport_invitations`.

### change-074

- Invalid-argument errors name each bad parameter with its description, list the valid
  parameters and show an example call. The framework's raw validation report is replaced;
  a value the server's own checks refuse is quoted whole, never truncated, so the secret
  scrubber masks any secret in it.

### change-075

- FastMCP 4.1.4 (MCP SDK 2.3.0; `fastmcp` range `>=4.0,<5.0`, 3.x unsupported). The
  server supports MCP protocol 2026-07-28 and still accepts 2024-11-05 through 2025-11-25.
  Visible differences: each tool has a display `title`; `serverInfo.version` is the
  package version; older-protocol `initialize` capabilities drop the empty `experimental`
  object and the `io.modelcontextprotocol/ui` extension, and advertise
  `prompts.listChanged` and `resources.listChanged` as `true` (0.6.2: `false`); a request with no
  `Authorization` header gets a bare `WWW-Authenticate: Bearer` challenge; OAuth JWKS
  fetches verify against the OS trust store (`SSL_CERT_FILE` / `SSL_CERT_DIR` still
  apply).

### change-076

- **Breaking (tool input): write tools drop server-added `_` keys** (`_keyLabel`,
  `_resolved_networks`, `_note`, ...) from a request body (0.6.2 sent them), keeping the
  Classic `_id`, so a read result fed back into an update round-trips; no-op and verification checks ignore them too. The connector relay
  sends its body exactly as given.

  Affected tools: 115 tools other than the connector relay (the write tools that exist in 0.6.2); see the [public tool catalog](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#tool-categories).

### change-077

- **Breaking (tools/list): 70 tools no longer declare an object `outputSchema`.** One
  body-decode rule applies everywhere: a 2xx body is parsed JSON, else the verbatim text,
  and an empty or 204 body is `null`. A tool that returns such a body verbatim can return
  a non-object (an array, a string, `null`), which an object `outputSchema` forbids, so
  `tools/list` no longer declares one for 70 tools; compared with
  0.6.2's `tools/list`, those tools declared an object result. For tools returning the
  body verbatim, a write answered with 204, an empty or a text body failed in FastMCP
  after it had applied. Port-profile writes now return non-object PUT bodies unchanged
  rather than wrapping them under `response`. The 16 delete tools that declared a string
  result (`{result: string}`) now declare and return an object (see [change-034](#change-034)).

  Affected tools: `adopt_device`, `allow_network_on_port_profile`,
  `approve_pending_device`, `block_client`,
  `create_acl_rule`, `create_device_tag`, `create_dns_policy`, `create_firewall_policy`,
  `create_firewall_zone_proxy`, `create_hotspot_operator`, `create_hotspot_vouchers`,
  `create_network`, `create_port_forward`, `create_radius_profile`,
  `create_site_to_site_tunnel`, `create_traffic_matching_list`, `create_traffic_rule`,
  `create_vpn_server`, `create_wifi_broadcast`, `exclude_network_on_port_profile`,
  `execute_client_action`, `execute_device_action`, `execute_port_action`, `get_acl_rule`, `get_acl_rule_ordering`,
  `get_camera_snapshot`, `get_client`, `get_device`, `get_device_statistics`,
  `get_dns_policy`, `get_firewall_policy`, `get_firewall_policy_ordering`,
  `get_firewall_zone_proxy`, `get_hotspot_voucher`, `get_lag`, `get_mc_lag_domain`,
  `get_network`, `get_network_application_info`, `get_network_references`,
  `get_recognition_group_image`, `get_switch_stack`, `get_thumbnail`,
  `get_traffic_matching_list`, `get_wifi_broadcast`, `list_device_tags`,
  `list_hotspot_operators`, `list_port_forwards`, `list_traffic_rules`, `locate_device`,
  `patch_firewall_policy`, `reconnect_client`, `restart_device`, `set_acl_rule_ordering`,
  `set_firewall_policy_ordering`, `unblock_client`, `update_acl_rule`,
  `update_device_tag`, `update_dns_policy`, `update_firewall_policy`,
  `update_firewall_zone_proxy`, `update_hotspot_operator`, `update_network`,
  `update_port_forward`, `update_site_to_site_tunnel`, `update_traffic_matching_list`,
  `update_traffic_rule`, `update_vpn_server`, `update_wan_interface`,
  `update_wifi_broadcast`, `upgrade_device`.

### change-078

- Connector relay: every Classic `network/api` route is reachable (`set/setting/<key>`,
  `upd/`, `list/`, `group/`, `api/self`, `api/stat/sites`), not only `rest`/`cmd`/`stat`.

### change-079

- Dependencies (`requirements-runtime.lock`, installed by the image): 60 hash-locked packages, the server's runtime dependencies only. The `dev`
  extra's test, lint and type-check packages (pytest, mypy, ruff, hypothesis, coverage,
  respx, trustme and the rest) are not installed by the image; they are
  pinned in `requirements.lock`, the development and test environment, which carries the
  same runtime pins and hashes. Most runtime pins are refreshed (44 of the 59 carried over changed). Major upgrades (0.6.2 version to 0.7.0 version):
  cryptography 46.0.7 to 50.0.2, cyclopts 4.10.2 to 5.3.0, fastmcp 3.2.4 to 4.1.4,
  mcp 1.27.0 to 2.3.0, rich-rst 1.3.2 to 2.2.0, rpds-py 0.30.0 to 2026.9.1,
  websockets 16.0 to 17.3. Also upgraded: aiofile 3.12.3, annotated-types 0.8.0,
  anyio 4.15.1, authlib 1.9.1, beartype 0.23.1, cachetools 7.2.4, caio 0.12.10,
  certifi 2026.10.23, cffi 2.1.1, click 8.5.0, dnspython 2.9.0, griffelib 2.4.1,
  idna 3.20, joserfc 1.7.7, jsonschema-path 0.5.0,
  markdown-it-py 4.2.0, openapi-pydantic 0.6.0,
  opentelemetry-api 1.45.1, packaging 26.3, pathable 0.6.0, platformdirs 4.13.5,
  py-key-value-aio 0.4.6, pycparser 3.12, pydantic 2.14.1, pydantic-core 2.50.1,
  pydantic-settings 2.16.1, pygments 2.21.0, pyjwt 2.15.1, python-dotenv 1.2.4,
  python-multipart 0.0.32, sse-starlette 3.5.0, starlette 1.9.0, typing-extensions 4.16.0,
  typing-inspection 0.4.4, uncalled-for 0.4.1, uvicorn 0.54.0, watchfiles 1.3.0. New:
  fastmcp-slim 4.1.4, httpcore2 2.16.0, httpx2 2.16.0, mcp-types 2.3.0, truststore 0.10.5.
  Dropped: docutils, httpx-sse,
  importlib-metadata, jaraco-classes, jaraco-context, jaraco-functools, jeepney, keyring,
  more-itertools, secretstorage, zipp.

### change-080

- `httpx2>=2.13.1` is a declared dependency. The server imports it directly for the
  capped JWKS download, whose decoded-size limit relies on the bounded decoders httpx2
  gained in 2.12; fastmcp alone admits httpx2 2.5.

### change-081

- Container base image `python:3.12-slim-bookworm` is pinned by digest (Python 3.12.15),
  the publish workflow pins every action by commit SHA, and published images carry the
  unprefixed `X.Y.Z` and `X.Y` tags alongside `vX.Y.Z` and `latest`, so the README's
  `:0.7.0` references resolve (the `:0.7` tag is published as well).

### change-083

- Spec-drift baseline advanced to Network Integration API v10.6.106 and Protect v7.3.70
  (no implemented endpoint changed); `LAST_AUDITED.md` records the per-surface audit.

### change-084

- Public files no longer carry internal or private path references.

### change-085

- Every value limit the vendored specs state for an argument or a body field it carries
  (`minimum`/`maximum`, lengths, `pattern`, `enum`, item counts; the limits a spec states
  only in prose, applied the same way: `ptz_patrol_start` slot 0-4, `ptz_goto_preset` slot
  >= -1 with -1 = home, relay / alarm-hub `output_id` 0 or 1, and the `update_sensor`
  light / humidity / temperature `highThreshold` ranges) is checked before any request, exactly as the spec states
  it (68 tools, e.g. `siren_play` duration 5/10/20/30, `siren_test_sound` volume 1-100,
  POS `externalId` <= 255 and `currency` `^[A-Z]{3}$`, suspend `reason` <= 1024, Carrier
  PATCH `name` non-empty after trimming). A length the spec counts after trimming
  (`update_carrier_subscriber` `subscriber_number`, 1-32) is checked on the trimmed value,
  never the raw one. The limit table is generated from the specs and test-pinned.
  The 68 tools: `alarm_hub_trigger_output`, `attach_carrier_subscriber_host`, `create_acl_rule`, `create_arm_profile`, `create_carrier_subscriber`, `create_firewall_policy`, `create_hotspot_vouchers`, `create_liveview`, `create_network`, `create_rtsps_stream`, `create_traffic_matching_list`, `create_wifi_broadcast`, `delete_rtsps_stream`, `get_camera_snapshot`, `get_innerspace_asset`, `list_acl_rules`, `list_carrier_subscribers`, `list_clients`, `list_countries`, `list_dns_policies`, `list_dpi_applications`, `list_dpi_categories`, `list_firewall_policies`, `list_firewall_zones_proxy`, `list_hotspot_vouchers`, `list_lags`, `list_local_sites`, `list_mc_lag_domains`, `list_mobility_clients`, `list_mobility_devices`, `list_networks`, `list_pending_devices`, `list_protect_files`, `list_radius_profiles`, `list_site_devices`, `list_site_to_site_tunnels`, `list_switch_stacks`, `list_traffic_matching_lists`, `list_vpn_servers`, `list_wan_interfaces`, `list_wifi_broadcasts`, `pos_ingest_transaction`, `ptz_goto_preset`, `ptz_patrol_start`, `relay_activate_output`, `siren_play`, `siren_test_sound`, `speaker_test_sound`, `suspend_carrier_subscriber`, `update_acl_rule`, `update_arm_profile`, `update_camera`, `update_carrier_subscriber`, `update_chime`, `update_firewall_policy`, `update_light`, `update_liveview`, `update_mobility_device_name`, `update_mobility_device_network`, `update_mobility_device_wireless`, `update_network`, `update_predefined_firewall_policy`, `update_sensor`, `update_siren`, `update_speaker`, `update_traffic_matching_list`, `update_wifi_broadcast`, `upload_protect_file`.

### change-086

- Invalid voucher filters fail before host resolution. Affected tool:
  `bulk_delete_hotspot_vouchers`.

### change-087

- Dry-run previews include `status: "dry_run"` for every write tool.

### change-088

- `list_guests`, `list_clients` and `list_known_clients` accept an optional `source`:
  `classic` (default) or `v2` for `list_guests` and `list_known_clients`, `integration`
  (default) or `v2` for `list_clients`; arguments that apply to only one source select it
  and conflict with the other. `list_network_events` accepts `view` (the system-log class,
  default `all`) and `vpn_user_id` (that VPN user's connection log, which takes no `view`
  or time window).

### change-089

- `get_site_statistics`, `get_site_health_summary` and `compare_site_performance` add an
  `_healthSummary` digest beside the unchanged upstream body.

### change-090

- `list_firewall_rules` and `get_firewall_rule` are legacy read-only interfaces.

### change-091

- `get_innerspace_project` accepts optional `user_email` and `site_id` selectors; either one
  switches to the legacy `/api/project` route, which returns the project itself rather
  than a `data` envelope.

### change-092

- Caller-supplied credentials (setup code, SIM PIN, share link and pairing password) are
  always scrubbed from logs and audit records. Errors and failed or partial write results
  mask them only with `UNIFI_REDACT_SECRETS`; otherwise they carry them verbatim.

### change-093

- **Breaking (tool removed):** `reject_pending_device` is unavailable because no upstream
  route performs that action. Use `forget_device`.

### change-094

- Connector write-tool `body` arguments accept any JSON value; values accepted before
  remain accepted.

### change-096

- The container image is assembled in one stage and copied into an empty image, so it no
  longer sets the base image's `PYTHON_VERSION`, `PYTHON_SHA256` and `GPG_KEY` environment
  variables; a derived image that reads them should set its own. Python, `tini`, the `mcp`
  user, the entry point, ports and the other environment defaults are unchanged.

### change-097

`query_traffic_flows` and `export_traffic_flows`, called without `body.pageSize`, drain
every page reported by the controller, even when `UNIFI_PAGINATE_MAX_PAGES` is
configured. Wide windows can be expensive: one recorded console gathered 215,000 flows
in 43 pages before the next page returned HTTP 408. To bound the work, send
`body.pageSize` (a record count; sizes above 5000 are sent as 5000 per request): the call
returns that many records and a `_nextPage {offset, pageSize}` object to pass back as
`body.pageNumber`. A later-page upstream error now returns the gathered `data` with `_pages`,
`incomplete: true`, and `incompleteReason` naming the zero-based page, status and
upstream error text. Check `incomplete` before treating a result as complete. A failure
on the first page still raises because no records have been gathered.

### change-101

Affected tools: `list_recognition_groups`, `list_recognition_detections`.
The new `get_protect_case_activity` tool follows the same logical-window contract.

- **Before (0.6.2):** `page` and `page_size` were sent to the console and returned
  that one native console page, whose size the console could clamp. `page_size`
  without `page` set each request's size and still drained every page.
- **After (0.7.0):** `page` with `page_size=N` returns the logical record window
  `[(page-1)*N, page*N)`: exactly N when that many exist, fewer only at the end,
  never more. `page_size` alone selects the first logical window. Resume from
  `_nextPage` with the same `page_size`. A `page` without `page_size` still returns
  one native console page. Omit both to drain every page.
- **Caller action:** replace computed native console positions with logical
  window numbers in units of the requested `page_size`; retain that same
  `page_size` while following `_nextPage`.

Site Manager `list_hosts`, `list_sites` and `list_devices` gain `page_size` in
this release as a requested record count gathered across native pages. Unlike the
logical windows above, the result can exceed it by up to the rest of the last native
page; `_pageSize` reports the requested, sent, effective and returned counts. Pass the
returned `_continuation` string (not the native `nextToken`) as `page_token` when you
change `page_size`. With several API keys, paging needs `key_label`.

### change-102

Affected tools: `list_acl_rules`, `list_clients`, `list_countries`, `list_dns_policies`, `list_dpi_applications`, `list_dpi_categories`, `list_firewall_policies`, `list_firewall_zones_proxy`, `list_hotspot_vouchers`, `list_lags`, `list_local_sites`, `list_mc_lag_domains`, `list_networks`, `list_pending_devices`, `list_protect_events`, `list_radius_profiles`, `list_site_devices`, `list_site_to_site_tunnels`, `list_switch_stacks`, `list_traffic_matching_lists`, `list_vpn_servers`, `list_wan_interfaces`, `list_wifi_broadcasts`.

- **Before (0.6.2):** a `limit` of 0 was sent upstream unchanged, so the console
  answered whatever it does for `limit=0`.
- **After (0.7.0):** `limit=0` and other `limit` values below 1 are refused before any
  request, with or without `offset`, with the message
  "limit must be a positive integer (1 or more); got 0. Omit limit to read the whole
  collection." Every `limit` of 1 or more is sent as given; there is no upper bound.
- **Caller action:** omit `limit` to read the whole collection, or pass a `limit` of
  1 or more.

## Python client API

Embedding applications using `UniFiClient` directly should account for these changes:

- `UniFiClient.get_bytes` was removed. Use `UniFiClient.get_binary` and take the first element of its result.
- `UniFiClient.get_binary` now returns `None` for a missing Content-Type instead of defaulting to
  `application/octet-stream`; supply that fallback in the caller if needed.
- HTTP verb helpers return text for non-JSON responses instead of raising a JSON decoding error.
- `request(max_retries=None)` now selects the method-specific default: five retries for
  read-only GET requests and zero for other requests. Set an explicit value when different behavior is required.
- `gather` now cancels sibling operations when one fails.
