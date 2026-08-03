# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- Add entries here as work lands on dev -->

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
