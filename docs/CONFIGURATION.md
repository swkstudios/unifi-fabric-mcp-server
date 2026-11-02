# Configuration reference

Every setting is an environment variable. Set them where the server starts: in the `env` block of your MCP client's server entry, in the shell that starts the client, or in the `environment:` block of a Docker or Compose service. The [README](../README.md#configuration) lists the settings most people touch; this page is the complete reference. Authentication and TLS settings (`MCP_*`), the Host and Origin checks (`MCP_ALLOWED_ORIGINS`, `MCP_ALLOWED_HOSTS`, `MCP_HOST_ORIGIN_PROTECTION`) and the startup warnings are in [AUTH-TLS.md](AUTH-TLS.md); the OAuth write scope (`MCP_OAUTH_WRITE_SCOPE`) is in [AUTH-OAUTH.md](AUTH-OAUTH.md#scopes-and-write-access).

**Upgrading from 0.5.x or earlier:** the `include_secrets` and `include_gps` parameters were removed and all fields are always returned; drop those parameters from your calls (see the [CHANGELOG](../CHANGELOG.md)).

## UniFi API Settings

All UniFi-specific settings are loaded from environment variables with the `UNIFI_` prefix.
An empty or whitespace-only value counts as unset (the default) for settings (`UNIFI_*`
and `MCP_*`), except `MCP_OAUTH_AUDIENCE`: a value with other characters keeps its spaces exactly, while an empty or whitespace-only value is still unset. A malformed value or one outside a setting's range fails startup with a message
naming the variable and the expected format or the valid choices. Boolean settings accept
`1`/`true`/`yes`/`on`/`t`/`y` or `0`/`false`/`no`/`off`/`f`/`n` (case-insensitive).
Credential values are checked as given, never stripped: an API key or `MCP_BEARER_TOKEN`
must be printable ASCII with no whitespace (no space, tab or line break, no control or
non-ASCII character), and `MCP_TLS_KEY_PASSWORD` must hold no control character; every
credential must be encodable as UTF-8 (no lone surrogate from a non-UTF-8 byte); a bad
value fails startup naming the variable (or the `UNIFI_API_KEYS` entry and label), never
showing the value. Every other `UNIFI_*` / `MCP_*` setting is checked at load too (URLs,
file paths, scopes, `MCP_OAUTH_ALGORITHM`, `UNIFI_TOOL_FAMILIES`, `UNIFI_DISABLED_TOOL_FAMILIES`,
`UNIFI_DISABLE_API_SOURCES`), naming the variable. No
configured secret (an API key, `MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`) ever appears in
an error message, the audit log or a log line: each is replaced by `***`. The scrubber covers
error text, exception messages, logs, the audit log, and the body and headers of every
upstream response, including successful (2xx) echoes. Unrelated upstream credential fields
remain verbatim unless `UNIFI_REDACT_SECRETS` is enabled. Dry-run previews also always
replace configured server secrets with `***`, including in paths, query parameters, bodies
and multipart metadata. JSON string values and keys are scrubbed without altering numbers,
booleans, null or JSON structure. Recognized
media types and charset names remain protocol metadata. A binary body is never decoded or
re-encoded by the scrubber (it works on the bytes). Every configured secret is scrubbed
whatever its length. A secret of 12 or more characters is masked wherever it appears, including inside a longer string.
A shorter secret is masked only as a whole token: no letter or digit directly before or after it, except that an escape sequence
right before it (`%20`, `%2520`, `\n`, `\x0a`, `\u00e9`, octal `\012` ...) is a boundary too, so
a key after `%20` in a `Location` header or after `\n` in a JSON-escaped message is masked. A
short secret is therefore also masked where the same text stands alone as a word in an error or
log line.

| Variable | Required | Default | Description |
|---|---|---|---|
| `UNIFI_API_KEY` | Yes (if `UNIFI_API_KEYS` not set) | — | Single API key shorthand |
| `UNIFI_API_KEYS` | No | — | JSON list of key configs for multi-console MSP setups: `[{"key": "...", "label": "...", "is_org_key": false}]`. Every `label` must be unique and pass the same rule as a `key_label` argument (non-empty, no surrounding whitespace, no control character; the error names `UNIFI_API_KEYS[i].label`), so every accepted label is selectable, and each key may appear only once; startup fails naming any duplicate label, or the labels sharing one key. |
| `UNIFI_API_BASE_URL` | No | `https://api.ui.com` | UniFi Site Manager API base URL (an absolute `http(s)` URL with a host and no user info, query, fragment or whitespace). Redirects are never followed: a 3xx answer is an error naming its `Location`. |
| `UNIFI_CACHE_TTL_SECONDS` | No | `900` | TTL for the host/site registry cache and the device MAC -> id lookup cache (seconds, 0 or more; 0 disables both, so every call re-reads the lists) |
| `UNIFI_CACHE_MAX_HOSTS` | No | `512` | Max entries in the hosts TTLCache (bounds memory use; 1 or more) |
| `UNIFI_CACHE_MAX_SITES` | No | `2048` | Max entries in the per-console sites TTLCache (1 or more) |
| `UNIFI_MAX_CONCURRENCY` | No | `10` | Max concurrent outbound requests to api.ui.com (1 or more) |
| `UNIFI_REQUEST_TIMEOUT_SECONDS` | No | unset | Removed; nonempty legacy values fail startup with a migration error. Delete the setting before upgrading. HTTP calls await completion or lifecycle cancellation without an elapsed-time deadline. |
| `UNIFI_PAGINATE_MAX_PAGES` | No | unset (unlimited) | Hard cap on pages drained per call (1 or more). By default list tools drain all pages automatically; set this to limit drain depth. When the cap is hit the response includes `"incomplete": true` and `"incompleteReason"`, plus the resume marker for that paging style (`_continuation`, or `_nextOffset`, `_nextCursor` or `_nextPage`) when one applies, so the caller can continue from where the drain stopped. A stalled cursor is flagged the same way, without a resume marker. |
| `UNIFI_LOG_LEVEL` | No | `INFO` | Logging verbosity. Accepts standard Python levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive); any other value fails startup listing them. Logs go to stderr only — request/response bodies are never logged. |
| `UNIFI_ENABLE_CONNECTOR_WRITE` | No | `true` | Capability flag for the mutating generic connector relay (`fabric_connector_post/put/patch/delete`), a `fabric_connector_get` call to a known state-changing GET route (Protect camera `enable-control` / `disable-control`), and these typed tools: `update_device_radio`; the Wi-Fi radio tools `preview_radio_ai_optimization`, `apply_radio_ai_optimization`, `control_wifi_doctor_optimization`, `start_wifi_quick_scan`, `start_spectrum_scan` and `configure_wifi_wan`; and the Protect private-API writes `update_camera_private`, `update_nvr`, `update_sensor_private`, `reboot_protect_device`, `adopt_protect_device`, `unadopt_protect_device`, `reboot_nvr` and `clear_sensor_tamper`. **Read + write on by default: unset → writes ENABLED.** Set to `0`/`false` for a read-only deployment: these write tools are then hidden from `tools/list` and discovery at startup and refused if called by name. The `confirm` argument on these tools is accepted and ignored. Ordinary GET reads through `fabric_connector_get` stay available. See [Enabling / disabling connector writes](../README.md#enabling--disabling-connector-writes). |
| `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` | No | `true` | Capability flag for the guarded Carrier / ISP Fabric write tools (`create_carrier_subscriber`, `update_carrier_subscriber`, `attach/detach_carrier_subscriber_host`, `assign_carrier_subscriber_plan`, `suspend/resume_carrier_subscriber`). Read + write on by default; set to `0`/`false` for a read-only Carrier Fabric deployment: the `carrier` family's write tools are then hidden from `tools/list` and discovery at startup and refused if called by name. The `confirm` argument is accepted and ignored. Reads are always available. |
| `UNIFI_ENABLE_MOBILITY_WRITE` | No | `true` | Capability flag for the guarded Mobility write tools (`update_mobility_device_name`, `update_mobility_device_network`, `update_mobility_device_wireless`). Read + write on by default; set to `0`/`false` for a read-only Mobility deployment: the `mobility` family's write tools are then hidden from `tools/list` and discovery at startup and refused if called by name. The `confirm` argument is accepted and ignored. Reads are always available. |
| `UNIFI_PROTECT_MUTATIONS_ENABLED` | No | `true` | Deployment-level kill switch for all Protect mutation and physical-action tools. Default ON — set to `false` to disable all Protect writes and actions (settings writes, siren/speaker/relay/alarm-hub activations, arm enable/disable, profile deletion, POS ingestion): the `protect` family's write tools are then hidden from `tools/list` and discovery at startup and refused if called by name. The `confirm` argument on these tools is accepted and ignored. |
| `UNIFI_ENABLE_NETWORK_WRITE` | No | `true` | Network write opt-out. Read + write on by default; set to `0`/`false` to refuse every Network write: the write tools of the `network`, `firewall`, `devices`, `clients`, `vpn`, `hotspot` and `statistics` families are hidden from `tools/list` and discovery at startup and refused if called by name, and any write request to a Network console route, the connector relay included, is refused before it is sent. Reads are always available. |
| `UNIFI_ENABLE_INNERSPACE_WRITE` | No | `true` | InnerSpace write opt-out. Read + write on by default; set to `0`/`false` to refuse every InnerSpace write: the InnerSpace write tools (floor plans, plan assets and maps, project and shape updates, imports, backup export, storage clean-up; the `innerspace` family) are hidden from `tools/list` and discovery at startup and refused if called by name, and any write request to an InnerSpace console route, the connector relay included, is refused before it is sent. Reads are always available. |
| `UNIFI_READ_ONLY` | No | `false` | **Opt-in global read-only switch.** Default off → read+write on (byte-identical to prior behaviour). Set to `1`/`true`/`yes`/`on` to hide annotated write/action tools (the mixed `fabric_connector_get` relay stays visible for ordinary reads) from `tools/list` and discovery search, descriptions and family counts at startup, and refuse it if called by name before any upstream call, with an actionable error naming this variable; read tools are unaffected, except that a `fabric_connector_get` call to a known state-changing GET route (Protect camera `enable-control` / `disable-control`) is a write and is refused too. Applied after the tool-family allowlist and opt-out list and the API-source disable list; discovery retains its read meta-tools and hides `call_write_tool`. Independent of and additive to the per-area write flags above. See [Read-only mode](../README.md#read-only-mode). |
| `UNIFI_REDACT_SECRETS` | No | `false` | **Opt-in credential redaction, OFF by default.** Unset/`0` -> the server is a faithful pass-through and returns upstream responses verbatim, except that the server's own configured secrets are always replaced by `***` (see above). Set to `1`/`true`/`yes`/`on` to mask documented credential fields in **every** tool response (applied server-wide at one shared point: WLAN/WiFi broadcast PSKs, Dynamic DNS and account passwords, RADIUS secrets, SSH passwords, VPN pre-shared keys, API tokens, private keys, and the generic connector GET relay). Fields are matched by three documented, anchored rules: an explicit list of exact key names, string values under keys ending in `_api_key`, `_private_key`, `_secret`, `_token`, `_password` or `_passphrase` (such as `google_maps_api_key`), and string values under the controller's hidden `x_` credential fields (such as `x_authkey`, `x_stripe_api_key`). See [Credential redaction](#credential-redaction). **Operator note:** with the opt-in on, credential reads return `***REDACTED***` and masked values in write bodies are dropped (not written), so writes need fresh values to change or set a credential. |
| `UNIFI_TOOL_MODE` | No | `discovery` (default) | `full` advertises every selected tool; `discovery` advertises five meta-tools by default (four with `UNIFI_READ_ONLY=1`) (`search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, `list_tool_families`) that reach every selected tool. Empty or whitespace means the default; other values fail startup naming the variable and both modes. |
| `UNIFI_TOOL_FAMILIES` | No | all families | Product families to advertise, separated by commas and/or whitespace, any letter case: `carrier`, `clients`, `connector`, `devices`, `firewall`, `hotspot`, `innerspace`, `mobility`, `network`, `protect`, `site_manager`, `statistics`, `vpn`. Every other tool is de-registered at startup; an unknown name fails startup listing the valid families. Shrinks `tools/list` for clients that cap or pay per tool. See [Tool-family allowlist](../README.md#tool-family-allowlist-unifi_tool_families). |
| `UNIFI_DISABLED_TOOL_FAMILIES` | No | none | Product families to leave out, same syntax and names as `UNIFI_TOOL_FAMILIES`, applied after it; an unknown name fails startup listing the valid families. See [Tool-family allowlist](../README.md#tool-family-allowlist-unifi_tool_families). |
| `UNIFI_DISABLE_API_SOURCES` | No | unset (every source enabled) | Comma-separated API-source selectors (`network`, `network/private`, `network/private.classic`, `network/private.v2`, `protect/private`, `protect/write`, `*/write`, ...); every tool a selector covers is de-registered at startup. An unknown or repeated selector fails startup listing the valid values. See [API-source selection](../README.md#api-source-selection-unifi_disable_api_sources). |
| `UNIFI_DRY_RUN` | No | `false` | **Opt-in preview of every write.** Set to `1`/`true`/`yes`/`on` and a write/action tool returns a labelled preview instead of sending anything. See [Dry-run preview](../README.md#dry-run-preview-for-all-writes-unifi_dry_run). |
| `UNIFI_AUDIT_LOG` | No | unset (no file) | File path (or `/dev/stderr` in a container) that receives one record per write attempt (time, method, path, outcome, status; never a body or a key). Best-effort: a write failure logs a warning and the call continues. See [Audit log](../README.md#optional-audit-log-unifi_audit_log). |
| `UNIFI_AUDIT_LOG_FORMAT` | No | `text` | `text` (key=value line) or `json` (one object per line) for `UNIFI_AUDIT_LOG`; any other value fails startup. |
| `FASTMCP_HOST` | No | `127.0.0.1` from source, `0.0.0.0` in the image | Address the HTTP transports bind to. A non-loopback address with `MCP_AUTH_MODE=none` prints a startup warning ([AUTH-TLS.md](AUTH-TLS.md#startup-warnings)). An unauthenticated loopback bind requires a loopback `Host` unless allowlisted; authenticated servers accept proxy hosts by default ([Host and Origin validation](AUTH-TLS.md#host-and-origin-validation)). |
| `FASTMCP_PORT` | No | `8000` from source, `3000` in the image | Port the HTTP transports listen on. |
| `UNIFI_MCP_CACHE_TTL` | No | `300` | Seconds an MCP client may reuse `tools/list` (and the other list results) before fetching it again. Sent as a public cache hint (`ttlMs`, `cacheScope: public`) to clients that negotiate MCP protocol 2026-07-28; clients on older protocol revisions ignore it. The tool list is the same for every caller (it depends only on server configuration), so it is safe to share. Set `0` to send no cache hint (clients do not reuse the result). |

### Settings reference (generated)

Every setting read at startup, written from `unifi_fabric.config.Settings`; the table above is the editorial guide.

<!-- BEGIN GENERATED: settings-reference -->
| Variable | Default | Accepted | Meaning |
|---|---|---|---|
| `UNIFI_API_BASE_URL` | `https://api.ui.com` | text | UniFi Site Manager API base URL. |
| `UNIFI_API_KEYS` | unset | text | List of API key configs. |
| `UNIFI_API_KEY` | unset | text | Single API key shorthand. |
| `UNIFI_CACHE_TTL_SECONDS` | `900` | integer, 0 or more | TTL for host/site registry cache (default 15 min). |
| `UNIFI_CACHE_MAX_HOSTS` | `512` | integer, 1 or more | Max entries in the hosts TTLCache (default 512). |
| `UNIFI_CACHE_MAX_SITES` | `2048` | integer, 1 or more | Max entries in the sites TTLCache (default 2048). |
| `UNIFI_MAX_CONCURRENCY` | `10` | integer, 1 or more | Max concurrent requests for cross-site aggregation. |
| `UNIFI_REQUEST_TIMEOUT_SECONDS` | unset | removed | Removed setting. |
| `UNIFI_PAGINATE_MAX_PAGES` | unset | integer, 1 or more | Hard cap on pagination page count (defense-in-depth backstop). |
| `UNIFI_LOG_LEVEL` | `INFO` | text | Logging level for the server. |
| `UNIFI_ENABLE_CONNECTOR_WRITE` | `true` | boolean | Capability flag for the guarded generic Fabric connector WRITE relay (fabric_connector_post/put/patch/delete). |
| `UNIFI_REDACT_SECRETS` | `false` | boolean | Opt-in credential redaction for responses. |
| `UNIFI_DRY_RUN` | `false` | boolean | Opt-in dry-run preview for ALL write/action tools. |
| `UNIFI_AUDIT_LOG` | unset | text | Opt-in audit-log file path for ALL write/action operations. |
| `UNIFI_AUDIT_LOG_FORMAT` | `text` | text | Format for the opt-in audit log. |
| `UNIFI_READ_ONLY` | `false` | boolean | Global read-only switch (UNIFI_READ_ONLY). |
| `UNIFI_PROTECT_MUTATIONS_ENABLED` | `true` | boolean | Protect mutation opt-out (UNIFI_PROTECT_MUTATIONS_ENABLED). |
| `UNIFI_ENABLE_NETWORK_WRITE` | `true` | boolean | Network write opt-out (UNIFI_ENABLE_NETWORK_WRITE). |
| `UNIFI_ENABLE_MOBILITY_WRITE` | `true` | boolean | Mobility write opt-out (UNIFI_ENABLE_MOBILITY_WRITE). |
| `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` | `true` | boolean | Carrier Fabric write opt-out (UNIFI_ENABLE_CARRIER_FABRIC_WRITE). |
| `UNIFI_ENABLE_INNERSPACE_WRITE` | `true` | boolean | InnerSpace write opt-out (UNIFI_ENABLE_INNERSPACE_WRITE). |
| `UNIFI_TOOL_MODE` | `discovery` | `full` or `discovery` | Tool catalog mode (UNIFI_TOOL_MODE): full advertises every selected tool; discovery advertises compact search, describe and registered-dispatch meta-tools. |
| `UNIFI_TOOL_FAMILIES` | unset | text | Opt-in tool-family allowlist. |
| `UNIFI_DISABLED_TOOL_FAMILIES` | unset | text | Opt-out tool-family list. |
| `UNIFI_DISABLE_API_SOURCES` | unset | text | Opt-in API-source disable list. |
<!-- END GENERATED -->

## Tool families

`UNIFI_TOOL_FAMILIES` (an allowlist) and `UNIFI_DISABLED_TOOL_FAMILIES` (an opt-out list,
applied after it) take these 13 names, separated by commas and/or whitespace in any letter
case. Each tool is in exactly one family. `firewall` is assigned by route: every tool that
calls a firewall policy, firewall zone, ACL rule or classic firewall rule or group route is
in `firewall`, whatever module defines it. An unknown name fails at startup with the list of
valid families. Counts at 0.7.0 (written by `scripts/gen_catalog_figures.py`):

| Family | Tools | Write tools | Covers |
|---|---:|---:|---|
| `carrier` | 11 | 7 | Carrier / ISP Fabric subscribers and service plans |
| `clients` | 14 | 12 | Connected and known clients, client actions and records |
| `connector` | 5 | 5 | The generic Fabric connector relay |
| `devices` | 34 | 26 | Device adoption, actions, radios, tags and scheduled tasks |
| `firewall` | 32 | 18 | Firewall policies and zones, ACL rules, classic firewall rules and groups, app blocks |
| `hotspot` | 4 | 3 | Hotspot vouchers, packages and operators |
| `innerspace` | 32 | 18 | InnerSpace projects, floor plans and placement snapshots |
| `mobility` | 8 | 3 | Mobility workspaces, devices and clients |
| `network` | 347 | 194 | Networks, Wi-Fi, switching, routing, DNS, DHCP, RADIUS, port profiles and settings |
| `protect` | 227 | 142 | Protect cameras, NVRs, sensors, events, PTZ, recognition and search |
| `site_manager` | 19 | 0 | Site Manager hosts, sites, fleet summaries and cross-site health |
| `statistics` | 14 | 3 | Statistics, history, ISP metrics and system logs |
| `vpn` | 39 | 27 | VPN servers, clients and site-to-site tunnels, RADIUS profiles |

## Write switches

<!-- BEGIN GENERATED: write-switches -->
- `UNIFI_ENABLE_NETWORK_WRITE` (default on): the write tools of `network`, `firewall`, `clients`, `devices`, `vpn`, `hotspot`, `statistics`
- `UNIFI_PROTECT_MUTATIONS_ENABLED` (default on): the write tools of `protect`
- `UNIFI_ENABLE_MOBILITY_WRITE` (default on): the write tools of `mobility`
- `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` (default on): the write tools of `carrier`
- `UNIFI_ENABLE_INNERSPACE_WRITE` (default on): the write tools of `innerspace`
- `UNIFI_ENABLE_CONNECTOR_WRITE` (default on): the connector relay's write tools and the typed tools it also governs
<!-- END GENERATED -->

The README section "Enabling / disabling connector writes" summarizes these switches; refusal messages point there.

Connector writes are governed by the deployment-level capability flag `UNIFI_ENABLE_CONNECTOR_WRITE` and, for a route in a Network or InnerSpace area, that area's flag (see below). Read and write are enabled by default.

1. **Default — writes ENABLED.** With the variable unset, `fabric_connector_post/put/patch/delete` are enabled. No action is needed to have write capability.
2. **To disable (deliberate read-only deployment)** — set the variable to `"0"` in the environment of the process that starts the server. The server reads it from its environment, so for a Compose deployment that is the **service's `environment:` block of the docker-compose file that deploys this server**; for a local install it is the client's server `env` block or a shell `export` before the client starts. It is not set in the application source. Compose example: under `services:` → `unifi-fabric-mcp:` → `environment:` add `UNIFI_ENABLE_CONNECTOR_WRITE: "0"`.

   Then recreate the container (e.g. `docker compose up -d`). If this server is deployed alongside a sidecar that shares its network namespace (e.g. a `ghostunnel` proxy using `network_mode: "service:..."` or a shared pod), restart the **whole compose group together**, not the app container alone — restarting only the app can leave the sidecar bound to a stale namespace.
3. **To re-enable** — remove the variable or set it to `"1"`, then recreate the container with the same restart rule.
4. **`confirm` is accepted and ignored.** The mutating relay tools still accept a `confirm` argument so existing callers do not break, but it no longer gates anything: the connector flag no longer needs `confirm`. The mutation runs once `UNIFI_ENABLE_CONNECTOR_WRITE` is enabled, whether or not `confirm` is passed, provided `UNIFI_READ_ONLY`, `UNIFI_DRY_RUN` and the opt-out of the target route area also allow it.

Accepted values (case-insensitive): unset / `1` / `true` / `yes` / `on` / `t` / `y` → **enabled**; `0` / `false` / `no` / `off` / `f` / `n` → **disabled**. When disabled, the write tools it governs are hidden from `tools/list` and discovery at startup; a mutating call by name is refused before the console is touched and audited, and the refusal message names this variable and points back to the README section "Enabling / disabling connector writes".

**Scope.** `UNIFI_ENABLE_CONNECTOR_WRITE` governs the four generic connector relay mutation tools (`fabric_connector_post`, `fabric_connector_put`, `fabric_connector_patch`, `fabric_connector_delete`), a `fabric_connector_get` call to a known state-changing GET route (Protect camera `enable-control` / `disable-control`), and these typed tools: `update_device_radio`; the Wi-Fi radio tools `preview_radio_ai_optimization`, `apply_radio_ai_optimization`, `control_wifi_doctor_optimization`, `start_wifi_quick_scan`, `start_spectrum_scan` and `configure_wifi_wan`; and the Protect private-API writes `update_camera_private`, `update_nvr`, `update_sensor_private`, `reboot_protect_device`, `adopt_protect_device`, `unadopt_protect_device`, `reboot_nvr` and `clear_sensor_tamper` (each also follows its own area's opt-out). All are enabled by default and are refused when `UNIFI_ENABLE_CONNECTOR_WRITE` is set falsey or `UNIFI_READ_ONLY` is on. The InnerSpace typed write tools are not governed by this flag; they follow `UNIFI_ENABLE_INNERSPACE_WRITE` (and `UNIFI_READ_ONLY`). An InnerSpace write path reached through the generic relay (the `innerspace/integration/v1` and `innerspace/api` namespaces map to InnerSpace route classes) is a relay mutation like any other and follows both `UNIFI_ENABLE_CONNECTOR_WRITE` and `UNIFI_ENABLE_INNERSPACE_WRITE`.

**Catalog visibility.** `UNIFI_READ_ONLY`, the per-area write flags,
`UNIFI_TOOL_FAMILIES` and `UNIFI_DISABLED_TOOL_FAMILIES` decide at startup which tools
`tools/list` and discovery show, so a client that caches the tool list should refresh it
after the server restarts with a changed setting. A hidden write called by name, directly
or through `call_write_tool`, is still refused with the variable named, and the refusal
is audited.

**One boolean parser.** Every boolean switch (`UNIFI_READ_ONLY`, `UNIFI_DRY_RUN`,
`UNIFI_REDACT_SECRETS`, `UNIFI_ENABLE_CONNECTOR_WRITE`, `UNIFI_ENABLE_NETWORK_WRITE`,
`UNIFI_PROTECT_MUTATIONS_ENABLED`, `UNIFI_ENABLE_MOBILITY_WRITE`,
`UNIFI_ENABLE_CARRIER_FABRIC_WRITE`, `UNIFI_ENABLE_INNERSPACE_WRITE`) accepts the same
spellings, case-insensitive with surrounding whitespace ignored: `1`/`true`/`yes`/`on`/`t`/`y`
(true) or `0`/`false`/`no`/`off`/`f`/`n` (false); unset or empty keeps the default. The
startup settings and the switches read at call time use the same parser, so they always
agree; any other value fails naming the variable.

**Other per-area write flags.** The Network (`UNIFI_ENABLE_NETWORK_WRITE`), Carrier Fabric (`UNIFI_ENABLE_CARRIER_FABRIC_WRITE`), Mobility (`UNIFI_ENABLE_MOBILITY_WRITE`), InnerSpace (`UNIFI_ENABLE_INNERSPACE_WRITE`), and Protect mutation (`UNIFI_PROTECT_MUTATIONS_ENABLED`) areas each have their own read + write-on-by-default opt-out flag that works exactly like the mechanism above: set it to a falsey value (`0`/`false`/`no`/`off`/`f`/`n`, case-insensitive) in the server's environment to make that one area read-only: for a Compose deployment the **service's `environment:` block of the deploy docker-compose file**, then recreate the container (restart the whole compose group if a sidecar shares its network namespace); for a local install the client's server `env` block or a shell `export` before the client starts. When an area is opted out, its refusal names the variable, its current value, and this compose location, and points back to the README section "Enabling / disabling connector writes" — so a read-only refusal is always actionable without reading the source. An area opt-out binds every write into its area: the area's write tools are hidden from `tools/list` and discovery search, descriptions and family counts at startup, and refused before they run if called by name (no request at all; the refusal is audited), and the shared request path refuses any write request to the area's routes (Network, Protect and InnerSpace console routes, the Mobility and Carrier Fabric cloud routes) whichever tool or relay call sends it. As with read-only mode, the opt-out wins over `UNIFI_DRY_RUN`: a refused write returns the refusal, not a preview.

## Credential redaction

By default the server is a faithful pass-through: upstream responses are returned
verbatim, including plaintext credential fields such as WLAN `x_passphrase`, Dynamic
DNS `x_password`, RADIUS shared secrets, SSH passwords and VPN pre-shared keys. The one
change made whatever this setting is: the server's own configured secrets (its API keys,
`MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`) are replaced by `***` wherever a response
echoes them (see [UniFi API Settings](#unifi-api-settings)).

If redaction is enabled but the framework exposes no tool handlers to protect, startup
fails with an error naming `UNIFI_REDACT_SECRETS`.

Operators who prefer secrets masked can opt in by setting `UNIFI_REDACT_SECRETS` to
a truthy value (`1`/`true`/`yes`/`on`/`t`/`y`, case-insensitive) in the environment of the process that starts the server (the client's server `env` block, a shell export, or a Compose service's `environment:` block):

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-1 mode=non-executable reason=deployment-or-client-interaction -->
```yaml
services:
  unifi-fabric-mcp:
    environment:
      UNIFI_REDACT_SECRETS: "1"   # mask credential fields in every response
```

When enabled, redaction is applied **server-wide at one shared point** — every tool
response (read and write), including `get_setting`/`list_settings`, `get_system_info`,
the generic `fabric_connector_get` relay, VPN, WLAN, Dynamic DNS, RADIUS, hotspot and
account tools — has the value of every credential field replaced with
`***REDACTED***`; all other fields are returned unchanged, except in the placement
snapshot (`get_unifi_placement_snapshot`): it is a projection, and with redaction on it
also leaves out URLs, IP and MAC addresses and strings carrying credential markers,
counting them under `_withheld` (see below). A key is a credential field
when it matches one of three rules, all case-insensitive and anchored to the whole key
name (never a free substring search), so the behaviour is predictable and testable:

1. **Explicit names.** The exact key names in the table below. The value is masked
   whatever its type, except `null` or the empty string `""`, which hold nothing to
   mask and are returned unchanged. The camelCase names
   `acctServerSecret`, `authToken`, `hashedPassword` and `wpaPsk` are explicit names
   too, masked only when the value is a non-empty string.
2. **Credential suffixes.** A key ending in `_api_key`, `_private_key`, `_secret`,
   `_token`, `_password` or `_passphrase`, for example `google_maps_api_key`,
   `wireguard_private_key`, `utm_token`, `guest_token`.
   The underscore is part of the suffix, so camelCase identifiers such as Protect's
   `profileToken` (a stream-profile id) and look-alikes such as `token_count` or
   `key_id` are not matched.
3. **Hidden `x_` credential fields.** A key starting with `x_` (other than an `x_has_`
   presence flag) whose name ends in `key`, `psk`, `passphrase`, `password`, `passwd`,
   `secret`, `token` or `signature`, for example `x_authkey`, `x_inform_authkey`,
   `x_mgmt_key`, `x_vwirekey`, `x_wireguard_private_key`, `x_openvpn_password`,
   `x_stripe_api_key`,
   `x_quickpay_apikey`, `x_paypal_signature`, `x_ssh_sha512passwd`, `x_sso_token`.
   Other `x_` fields stay verbatim: identifiers (`x_ssh_username`,
   `x_quickpay_merchantid`), flags (`x_ssh_enabled`, `x_ssh_auth_password_enabled`,
   `x_has_ssh_hostkey`), SSIDs (`x_mesh_essid`) and public material
   (`x_certificate_pem`, `x_ssh_keys`, `x_ssh_hostkey_fingerprint`).

Pagination cursors are never credential fields, under any rule: `nextToken`,
`next_token`, `pageToken`, `page_token`, `continuationToken` and `continuation_token`
are returned unchanged, so a redacted page can still be followed.

Rules 2 and 3 mask string values only: a boolean, number or null under a matching key
(for example the WLAN flag `radius_macacl_empty_password: false`) is a setting, not a
credential, and is returned unchanged; an object or list under such a key is searched
field by field instead of being replaced.

| Class | Masked fields (rule 1, exact key names) |
|---|---|
| WLAN / WiFi broadcast PSKs | `x_passphrase`, `x_password`, `x_iapp_key`, `x_wep`, `wpa_psk`, `sae_psk` (including password lists), `x_mesh_psk`, `passphrase`, `password` |
| WPA-Enterprise / cert key material | `x_ca_crt`, `x_ca_key`, `x_certificate_crt`, `x_certificate_key`, `server_certificate_key`, `x_private_key`, `private_key`, `privatekey` |
| RADIUS shared secrets | `x_secret`, `x_radius_secret`, `radius_secret`, `secret` |
| SSH / device management | `x_ssh_password`, `ssh_password`, `x_ssh_sudopassword`, `syslog_key` |
| VPN pre-shared keys / tunnel secrets | `x_ipsec_pre_shared_key`, `ipsec_pre_shared_key`, `pre_shared_key`, `preshared_key`, `presharedkey`, `psk`, `x_psk` |
| VPN client credentials | `x_wireguard_private_key`, `x_openvpn_password`, `openvpn_configuration` |
| API tokens / auth / cloud access | `api_token`, `x_api_token`, `api_key`, `apikey`, `auth_token`, `x_auth_token`, `access_token`, `refresh_token`, `device_auth`, `token` |
| Controller camelCase and `x_` aliases | `sharedsecret`, `authserversecret`, `wanpassword`, `wireguardprivatekey`, `clientsecret`, `bearertoken`, `apitoken`, `accesstoken`, `refreshtoken`, `radiussecret`, `pppoepassword`, `sshpassword`, `x_shared_secret`, `x_auth_server_secret`, `x_wan_password`, `x_client_secret`, `x_bearer_token`, `x_access_token`, `x_refresh_token`, `x_pppoe_password` |

When enabled, the same fields are also masked inside upstream error bodies quoted in
error messages. Error messages otherwise carry the real request path and the complete
upstream error body: identifiers (console ids, UUIDs) are not secrets and are never masked,
and nothing is truncated.

In ordinary tool responses, the listed credential fields become `***REDACTED***` and all other fields stay unchanged. Registered route-secret fields (including an echoed request field) use that same token. This is strictly opt-in for structured data: successful writes, GET results and dry-run previews (including a read-before snapshot) remain verbatim when it is off. Logs and audit lines always scrub the registered route-secret values and credential arguments of the call, whatever the setting. Errors and hints, and the result of a failed or partial write or other non-2xx upstream response (its body, read-before/read-after snapshots, reasons and post-write error), mask them only when it is on; when it is off they carry them verbatim. The placement snapshot is a projection, not a whole upstream body, so it is the one exception: with `UNIFI_REDACT_SECRETS` on, it also leaves out URLs, IP and MAC addresses and strings containing credential markers, counting them under `_withheld` (with redaction off, `_withheld` is never present). See [Placement snapshots](../README.md#placement-snapshots).

Redaction is an output transform applied after the upstream call; it does not add a
confirmation prompt or otherwise change which calls are made. Leave `UNIFI_REDACT_SECRETS`
unset for the default faithful pass-through behaviour.

**Writing a redacted object back.** With `UNIFI_REDACT_SECRETS` on, a redacted read can be passed straight to its update
tool (`get_setting` -> `update_setting`, `list_wlan_configs` -> `update_wlan_config`,
`list_dynamic_dns` -> `update_dynamic_dns`, hotspot operators, VPN servers, the connector
relay, ...) without overwriting the stored secret with the literal mask. In the client's
single write path, every body field whose value is exactly `***REDACTED***` is left out
of the request, at any nesting depth (inside nested objects and objects in lists), so the
controller keeps its existing value. Every other field is sent. A body left with
nothing to send once the masks are dropped is refused before any request, with an error
naming the masked fields (`No fields provided: every provided ... field held the redaction
mask`): a relayed body made only of masked values, or an update tool's body whose only
fields to change are masked.
The tool result lists the dropped field paths under the additive key
`_redactedFieldsNotSent` (for example `["x_passphrase", "radius_profile.x_secret",
"peers[0].private_key"]`); bare arrays keep their shape, with metadata inside each
returned object record. Arrays with no object records stay unchanged; scalar results
are returned under `result` beside that key. The drop applies only when
`UNIFI_REDACT_SECRETS` is enabled in the server process that receives the write. With it off, a body
field equal to `***REDACTED***` is sent upstream as that literal string and nothing is reported under
`_redactedFieldsNotSent`, so do not write a masked read to a server that has redaction off.
Read-merge writes, including RADIUS account batch updates and AP group updates, retain
the fetched stored value wherever the caller supplies a mask, so full-replacement
requests still carry that field. Other endpoints that require the field on every write
answer with their own validation error when it is left out; send the real value in that
case. To change a secret, send its real new value.

## Transport Configuration

The MCP server communicates with clients using the FastMCP transport protocol. By default, the Docker image uses `streamable-http`, but you can override this for different deployment scenarios.

**`FASTMCP_TRANSPORT`**: Sets the communication protocol between the MCP server and clients.

| Transport | Use Case | Port | Notes |
|---|---|---|---|
| `streamable-http` | Docker containers, HTTP load balancers, reverse proxies | `3000` | Default; recommended for containerized deployments |
| `sse` | Server-sent events; browser clients, long-polling scenarios | `3000` | Stateful, requires connection persistence |
| `stdio` | Process-to-process communication, local development | — | No network port; requires parent process stdin/stdout |

### Reverse proxies and loopback sidecars

A proxy may forward its public or internal service hostname while connecting to
`FASTMCP_HOST=127.0.0.1`. With bearer or OAuth authentication, this works without
a Host override in either stateless or stateful streamable HTTP. Authentication
still validates every MCP request and browser Origin checks remain enabled.
An explicit `MCP_ALLOWED_HOSTS` restricts accepted hosts for every authentication
mode; use the hostname and port in the forwarded HTTP `Host`, which can differ
from the sidecar's TLS certificate name. Unauthenticated loopback listeners keep
automatic Host validation. See [Host and Origin validation](AUTH-TLS.md#host-and-origin-validation)
for the policy and browser-origin settings.

### Override Transport via Docker

To use a different transport, override the environment variable at runtime:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-2 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# SSE transport
docker run -e UNIFI_API_KEY="your-api-key-here" -e FASTMCP_TRANSPORT=sse -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0
```

MCP clients connect to the `/sse` endpoint — note the path differs from the streamable-http default (`/mcp`):

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-3 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "sse",
      "url": "http://localhost:3000/sse"
    }
  }
}
```

**Verify SSE is up:**

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-4 mode=non-executable reason=deployment-or-client-interaction -->
```bash
curl --include --no-buffer --silent --show-error http://localhost:3000/sse
```

An `HTTP 200` response header and the initial SSE endpoint event confirm the server is listening.
The stream continues delivering events until the connection closes or you stop it with Ctrl-C
after inspecting the response.

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-5 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# Stdio transport
docker run --no-healthcheck --rm -i -e UNIFI_API_KEY="your-api-key-here" -e FASTMCP_TRANSPORT=stdio ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0
```

With stdio transport the MCP client must **spawn** the container as a subprocess (the same as [Track A](../README.md#track-a--local-stdio)), not connect over HTTP. Pass `--rm -i` so the container receives stdin and is removed on exit. The corresponding client config uses `command`/`args`, not `type`/`url`:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-6 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "command": "docker",
      "args": ["run", "--no-healthcheck", "--rm", "-i",
               "-e", "UNIFI_API_KEY=your-api-key-here",
               "-e", "FASTMCP_TRANSPORT=stdio",
               "ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0"]
    }
  }
}
```

> **HEALTHCHECK note:** When `FASTMCP_TRANSPORT=stdio`, no port 3000 is bound. The Dockerfile's built-in TCP healthcheck will fail permanently. Pass `--no-healthcheck` to suppress the misleading `(unhealthy)` status: `docker run --no-healthcheck --rm -i ...`.

### Override Transport in Docker Compose

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-7 mode=non-executable reason=deployment-or-client-interaction -->
```yaml
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0
    environment:
      UNIFI_API_KEY: your-api-key-here
      FASTMCP_TRANSPORT: sse  # or stdio
    ports:
      - "3000:3000"  # remove this entry when using stdio
```

**Note:** The server exposes port 3000 for `streamable-http` and `sse` transports. If using `stdio`, no port is exposed; the server communicates exclusively via stdin/stdout. When switching to `stdio`, remove the `ports:` mapping and disable the built-in TCP healthcheck (which will fail permanently when nothing binds port 3000) by adding:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-8 mode=non-executable reason=deployment-or-client-interaction -->
```yaml
    healthcheck:
      disable: true
```

With `stdio`, remove `ports:`, disable the healthcheck, and configure your MCP client to spawn `docker compose -f /absolute/path/to/compose.yml run --rm --no-deps -T unifi-fabric-mcp`. Detached `docker compose up` does not provide the client's stdin/stdout connection: the server exits with code 0 when nothing is attached.

### Stateless HTTP (`FASTMCP_STATELESS_HTTP`)

The Docker image sets `FASTMCP_STATELESS_HTTP=true`, so the `streamable-http` transport
serves every request on its own, with no MCP session kept on the server. Any replica
behind a load balancer can answer any request, and a container restart drops no client
state. Clients still send `initialize` first and get the same result; the response just
carries no `Mcp-Session-Id` header, and later requests need none. Clients that negotiate
MCP protocol 2026-07-28 are stateless by design and work the same either way.

To restore per-client sessions, override the variable:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-9 mode=non-executable reason=deployment-or-client-interaction -->
```bash
docker run -e UNIFI_API_KEY="your-api-key-here" -e FASTMCP_STATELESS_HTTP=false -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0
```

The `sse` transport is session-based by nature; with `FASTMCP_TRANSPORT=sse` the
stateless setting is ignored. Running from source (`pip install`), the FastMCP default
applies (sessions on) unless you set the variable yourself.

## Single key setup

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-10 mode=non-executable reason=deployment-or-client-interaction -->
```bash
export UNIFI_API_KEY="your-api-key-here"
```

## Multi-key MSP setup

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 support=0.7.0 citation=file:src/unifi_fabric/config.py@sha256:5e8bcdf0f74c062cdd783f0630fd37548419f5b233c5a46c149c958657b996b3 -->
<!-- install-case: docs-configuration-11 mode=non-executable reason=deployment-or-client-interaction -->
```bash
export UNIFI_API_KEYS='[{"key": "key-a", "label": "org-east", "is_org_key": true}, {"key": "key-b", "label": "org-west"}]'
```

Organization keys (`is_org_key: true`) cover all sites under the org. Personal keys only access consoles owned by the key holder.

> **Shell vs env-file quoting:** use single quotes around the JSON in a shell `export`. For
> `docker run --env-file`, omit surrounding quotes because the Docker CLI preserves them
> literally (the quote characters become part of the value and JSON parsing fails with a
> `SettingsError`). Compose `env_file:` normally removes surrounding quotes; `format: raw`
> preserves them. An unquoted line such as
> `UNIFI_API_KEYS=[{"key":"...","label":"default"}]` works with both. Do not put `export`
> in an env file.

> **Per-host key routing:** Per-host operations (any tool that accepts a `host` parameter) resolve the API key that owns the target console and send the request on that key, so a console owned by any configured key in `UNIFI_API_KEYS` is reachable, not only one owned by the first key. The multi-key tools aggregate across every key unless a `key_label` argument names one: `list_hosts`, `list_sites`, `list_all_sites_aggregated`, `list_all_devices`, `list_all_clients`, `get_fleet_summary`, `search_device_fleet`, `search_across_sites`, `list_devices` without `host`, `list_mobility_workspaces`, `list_mobility_admins`, `list_mobility_devices`, `list_mobility_clients`, `list_carrier_subscribers`, `list_carrier_service_plans` and `list_sdwan_configs`; records are tagged `_keyLabel`, a console visible to several keys is counted once (under the first key in configuration order), and a key that fails is reported under `errors` while the others still answer; `list_configured_api_keys` returns the valid `key_label` values (see [MIGRATING-0.7.md](MIGRATING-0.7.md#change-057)). Single-key deployments are unaffected: with one configured key there is nothing to disambiguate and every request rides that key exactly as before. (The fleet-wide Site Manager query endpoints that take a list of `{hostId, siteId}` rather than a single `host` — e.g. `query_isp_metrics` — are scoped by the request body, not by per-host key routing.)


### API-source selection

`UNIFI_DISABLE_API_SOURCES` is an optional comma-separated list of selectors. Unset or
blank enables every source. Select an app (`network`), a source (`network/private.classic`,
`protect/private`), a private group (`network/private`), or an access level
(`network/private/write`, `protect/write`, `*/write`). `*/private` disables all private
surfaces; `*/generic` selects generic relays and `*/local` selects tools with no upstream
request. Unknown or repeated selectors fail at startup and list valid choices.

The `fabric_connector_*` tools are `relay/generic` and can reach any route, including
private APIs. `*/private` does not disable them. Use `relay` or `*/generic` to disable
those tools explicitly; `*/read` and `relay/read` also remove `fabric_connector_get` (class `relay/generic/read`, the only GET relay), and `*/write` keeps it. A write selector (`*/write`, `protect/write`) therefore leaves the Protect camera `enable-control` and `disable-control` GET routes reachable through `fabric_connector_get`; to block them, use `UNIFI_READ_ONLY`, `UNIFI_ENABLE_CONNECTOR_WRITE=0` or the `relay` selector. This selector does not filter the routes an enabled relay may
reach. `UNIFI_READ_ONLY` is an independent setting.

## Tool catalog mode (UNIFI_TOOL_MODE)

`UNIFI_TOOL_MODE=discovery` is the default and, with read-only mode off, advertises five compact meta-tools: `search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, and `list_tool_families`. Use `search_tools` to find a domain tool, inspect its exact schema with `describe_tool`, then dispatch it with the read or write wrapper. Set `UNIFI_TOOL_MODE=full` for clients that require every domain tool directly in `tools/list`; with read-only mode off, full mode preserves the full catalog byte-for-byte. With `UNIFI_READ_ONLY=1`, only the four read meta-tools are advertised (`call_write_tool` is hidden), and searches, descriptions and family counts include only annotated reads. Hidden write calls still receive the audited read-only refusal. For a complete inventory in discovery mode call `search_tools` with `{"query":"","limit":null}`; an omitted limit returns ten results.
