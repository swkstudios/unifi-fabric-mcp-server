# Configuration reference

Every setting is an environment variable. Set them where the server starts: in the `env` block of your MCP client's server entry, in the shell that starts the client, or in the `environment:` block of a Docker or Compose service. The [README](../README.md) covers the settings most setups need; this page is the complete reference. Authentication and TLS settings (`MCP_*`), the Host and Origin checks (`MCP_ALLOWED_ORIGINS`, `MCP_ALLOWED_HOSTS`, `MCP_HOST_ORIGIN_PROTECTION`) and the startup warnings are in [AUTH-TLS.md](AUTH-TLS.md); the OAuth write scope (`MCP_OAUTH_WRITE_SCOPE`) is in [AUTH-OAUTH.md](AUTH-OAUTH.md#scopes-and-write-access). UniFi API keys come from `UNIFI_API_KEY` or `UNIFI_API_KEYS` (or from a [key file or helper command](#key-files-and-helper-commands)) unless `UNIFI_KEY_MODE=header` takes them from each request instead ([Header key mode](#header-key-mode-unifi_key_mode)), and any request can tighten the write and exposure settings for itself ([Request policy headers](#request-policy-headers)).

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
file paths, scopes, `MCP_OAUTH_ALGORITHM`, `UNIFI_WRITE_POLICY`, `UNIFI_WRITE_EXCEPTIONS`,
`UNIFI_FAMILY_ALLOW`, `UNIFI_EXCLUDE`), naming the variable. No
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

The generated [settings reference](#settings-reference-generated) below lists every `UNIFI_*` setting with its code default and accepted values, and [Write switches](#write-switches) lists the per-area `UNIFI_WRITE_EXCEPTIONS` entries; `scripts/gen_reference_blocks.py` renders both from the code. This table is the editorial guide; the same script checks its Default column against the code.

| Variable | Required | Default | Description |
|---|---|---|---|
| `UNIFI_API_KEY` | Yes in the default `environment` key mode, unless `UNIFI_API_KEYS` or a [key file or helper command](#key-files-and-helper-commands) is set | — | Single API key shorthand. Ignored, with a startup warning, under `UNIFI_KEY_MODE=header`. |
| `UNIFI_API_KEYS` | No | — | JSON list of key configs for multi-console MSP setups: `[{"key": "...", "label": "...", "is_org_key": false}]`. Every `label` must be unique and pass the same rule as a `key_label` argument (non-empty, no surrounding whitespace, no control character; the error names `UNIFI_API_KEYS[i].label`), so every accepted label is selectable, and each key may appear only once; startup fails naming any duplicate label, or the labels sharing one key. Ignored, with a startup warning, under `UNIFI_KEY_MODE=header`. |
| `UNIFI_API_KEY_FILE` | No | unset | Absolute path of a file holding the single API key, read once at startup instead of `UNIFI_API_KEY`; a trailing line break is removed. See [Key files and helper commands](#key-files-and-helper-commands). |
| `UNIFI_API_KEY_COMMAND` | No | unset | Helper command whose standard output is the single API key, run once at startup without a shell. See [Key files and helper commands](#key-files-and-helper-commands). |
| `UNIFI_API_KEYS_FILE` | No | unset | Absolute path of a file holding the `UNIFI_API_KEYS` JSON list, read once at startup. See [Key files and helper commands](#key-files-and-helper-commands). |
| `UNIFI_API_KEYS_COMMAND` | No | unset | Helper command whose standard output is the `UNIFI_API_KEYS` JSON list, run once at startup without a shell. See [Key files and helper commands](#key-files-and-helper-commands). |
| `UNIFI_KEY_MODE` | No | `environment` | Where UniFi API keys come from: `environment` uses `UNIFI_API_KEY` / `UNIFI_API_KEYS`; `header` stores no key and takes each tool call's keys from its `X-UniFi-Api-Key` request header, on the HTTP transports only. Case-sensitive; unlike other settings a blank value is not treated as unset: a blank or other value fails startup with `startup:UNIFI_KEY_MODE`. See [Header key mode](#header-key-mode-unifi_key_mode). |
| `UNIFI_API_BASE_URL` | No | `https://api.ui.com` | UniFi Site Manager API base URL (an absolute `http(s)` URL with a host and no user info, query, fragment or whitespace). Redirects are never followed: a 3xx answer is an error naming its `Location`. |
| `UNIFI_CACHE_TTL_SECONDS` | No | `900` | TTL for the host/site registry cache and the device MAC -> id lookup cache (seconds, 0 or more; 0 disables both, so every call re-reads the lists) |
| `UNIFI_CACHE_MAX_HOSTS` | No | `512` | Max entries in the hosts TTLCache (bounds memory use; 1 or more) |
| `UNIFI_CACHE_MAX_SITES` | No | `2048` | Max entries in the per-console sites TTLCache (1 or more) |
| `UNIFI_MAX_CONCURRENCY` | No | `10` | Max concurrent outbound requests to api.ui.com (1 or more) |
| `UNIFI_REQUEST_TIMEOUT_SECONDS` | No | unset | Removed; nonempty legacy values fail startup with a migration error. Delete the setting before upgrading. HTTP calls await completion or lifecycle cancellation without an elapsed-time deadline. |
| `UNIFI_PAGINATE_MAX_PAGES` | No | unset (unlimited) | Hard cap on pages drained per call (1 or more). By default list tools drain all pages automatically; set this to limit drain depth. `query_traffic_flows` and `export_traffic_flows` are exempt: they drain every page the console reports even with this set, so bound them with `body.pageSize` ([Partial results when a page cap is set](PAGINATION.md#partial-results-when-a-page-cap-is-set)). When the cap is hit the response includes `"incomplete": true` and `"incompleteReason"`, plus the resume marker for that paging style (`_continuation`, or `_nextOffset`, `_nextCursor` or `_nextPage`) when one applies, so the caller can continue from where the drain stopped. A stalled cursor is flagged the same way, without a resume marker. |
| `UNIFI_LOG_LEVEL` | No | `INFO` | Logging verbosity. Accepts standard Python levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive); any other value fails startup listing them. Logs go to stderr only — request/response bodies are never logged. |
| `UNIFI_WRITE_POLICY` | No | unset (`allow`) | **Global write policy:** `allow` (the default), `dry-run` or `deny`, case-sensitive. `deny` is read-only mode: annotated write/action tools (the mixed `fabric_connector_get` relay stays visible for ordinary reads) are hidden from `tools/list` and discovery search, descriptions and family counts at startup, and refused with `write_denied` if called by name before any upstream call; read tools are unaffected, except that a `fabric_connector_get` call to a known state-changing GET route (Protect camera `enable-control` / `disable-control`) is a write and is refused too. `dry-run` makes every write return a labelled preview instead of sending anything ([Dry-run preview](#dry-run-behavior)). Discovery retains its read meta-tools and hides `call_write_tool` under `deny`. A blank or other value fails startup naming the setting. See [Read-only mode](#read-only-mode). |
| `UNIFI_WRITE_EXCEPTIONS` | No | unset (none) | **Per-family and per-tool write exceptions:** one semicolon-separated list of `<target>=deny` or `<target>=dry-run`, the target `family:<family-id>` or `tool:<tool-name>`, for example `family:protect=deny;tool:fabric_connector_post=dry-run`. Each write gets the strictest of `UNIFI_WRITE_POLICY` and every matching entry (`allow` < `dry-run` < `deny`); there is no `allow` entry. A `deny` entry for one of the six areas (network, protect, mobility, carrier, innerspace, connector) hides the write tools it covers from `tools/list` and discovery at startup and refuses them if called by name; any other `family:<id>=deny` and every `tool:<name>=deny` entry keeps the tools listed and refuses them (`write_denied`) when called. `family:network=deny` keeps the reach of the Network area: the write tools of the `network`, `firewall`, `devices`, `clients`, `vpn`, `hotspot` and `statistics` families and every write request to a Network console route, the connector relay included. Every other `family:<id>=deny` covers its own family (Protect, InnerSpace, Mobility and Carrier Fabric also cover every write request to their console or cloud routes); `family:connector=deny` covers the connector relay and the typed tools listed under [Write switches](#write-switches). A `family:<id>=dry-run` entry reaches exactly the writes the same entry set to `deny` refuses, and previews them instead. A blank, malformed, duplicate or unknown target fails startup naming the setting. |
| `UNIFI_REDACT_SECRETS` | No | `false` | **Opt-in credential redaction, OFF by default.** Unset/`0` -> the server is a faithful pass-through and returns upstream responses verbatim, except that the server's own configured secrets are always replaced by `***` (see above). Set to `1`/`true`/`yes`/`on` to mask documented credential fields in **every** tool response (applied server-wide at one shared point: WLAN/WiFi broadcast PSKs, Dynamic DNS and account passwords, RADIUS secrets, SSH passwords, VPN pre-shared keys, API tokens, private keys, and the generic connector GET relay). Fields are matched by three documented, anchored rules: an explicit list of exact key names, string values under keys ending in `_api_key`, `_private_key`, `_secret`, `_token`, `_password` or `_passphrase` (such as `google_maps_api_key`), and string values under the controller's hidden `x_` credential fields (such as `x_authkey`, `x_stripe_api_key`). See [Credential redaction](#credential-redaction). **Operator note:** with the opt-in on, credential reads return `***REDACTED***` and masked values in write bodies are dropped (not written), so writes need fresh values to change or set a credential. |
| `UNIFI_TOOL_MODE` | No | `discovery` (default) | `full` advertises every selected tool; `discovery` advertises five meta-tools by default (four with `UNIFI_WRITE_POLICY=deny`) (`search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, `list_tool_families`) that reach every selected tool; `codemode` (experimental, read-only) advertises `search_tools`, `describe_tool` and `execute`. Empty or whitespace means the default; other values fail startup naming the variable and the modes. |
| `UNIFI_FAMILY_ALLOW` | No | unset (all families) | Product family IDs to advertise, comma-separated, lower case and case-sensitive: `carrier`, `clients`, `connector`, `devices`, `firewall`, `hotspot`, `innerspace`, `mobility`, `network`, `protect`, `site_manager`, `statistics`, `vpn`. Every other domain tool is de-registered at startup; the discovery meta-tools are never removed. An unknown ID, `meta`, a blank value or a repeated or empty entry fails startup naming the setting. Shrinks `tools/list` for clients that cap or pay per tool. See [Tool-family allowlist](#tool-families). |
| `UNIFI_EXCLUDE` | No | unset (nothing excluded) | One comma-separated list of exclusions, applied after `UNIFI_FAMILY_ALLOW`: `family:<id>`, `tool:<name>`, `source:<selector>` (the API-source selectors below, case-sensitive) and `unofficial` (every tool whose primary API source is private). Every covered tool is de-registered at startup. No entry removes a discovery meta-tool or `list_configured_api_keys`: `tool:` naming one fails startup. A blank, unknown or repeated entry fails startup naming the setting. See [Exclusions and API-source selection](#api-source-selection). |
| `UNIFI_AUDIT_LOG` | No | unset (no file) | File path (or `/dev/stderr` in a container) that receives one record per write attempt (time, method, path, outcome, status; never a key, and a body only at `UNIFI_AUDIT_LEVEL=debug`). `/dev/stderr` works when standard error is separate from standard output; a symlink to anything other than this process's standard error is refused, and a FIFO or device named directly must belong to the server's user (so `/dev/null` or `/dev/tty` as a non-root user is refused). Best-effort and fail-open: a write failure adds the `audit_unavailable` notice to every response until the sink recovers. See [Audit log](CONFIGURATION.md). |
| `UNIFI_AUDIT_LOG_FORMAT` | No | `json` | `json` (one canonical JSON object per line, the typed schema) or `text` (key=value line); any other value fails startup. Earlier releases defaulted to `text`; set `text` to keep those lines. |
| `UNIFI_AUDIT_SINK` | No | unset | `none`, `stderr`, `file` or `remote`. Unset means `file` when `UNIFI_AUDIT_LOG` is set, else `none`. `file` needs `UNIFI_AUDIT_LOG`; `none` or `stderr` with `UNIFI_AUDIT_LOG` set fails startup. `remote` ships JSON records to a log collector over HTTPS and, with `UNIFI_AUDIT_LOG` set, also writes that local file first: see [Remote audit sink](#remote-audit-sink-unifi_audit_sinkremote). |
| `UNIFI_AUDIT_REMOTE_URL` | With `UNIFI_AUDIT_SINK=remote` | unset | Collector endpoint: an absolute `https://` URL (`http://` only with `UNIFI_AUDIT_REMOTE_PLAINTEXT=true`) with no user information, query string or fragment. Records are POSTed as NDJSON batches over TLS 1.3. Logs and records name only its `scheme://host:port`. Any `UNIFI_AUDIT_REMOTE_*` setting without `UNIFI_AUDIT_SINK=remote` fails startup. |
| `UNIFI_AUDIT_REMOTE_PLAINTEXT` | No | `false` | `true` allows an `http://` collector URL (no encryption, no server or client authentication) and requires the three TLS file settings unset. TLS is the default; plaintext is the operator's explicit choice and prints no warning. |
| `UNIFI_AUDIT_REMOTE_CA_FILE` | No | unset (platform trust store) | PEM bundle of the CAs trusted for the collector certificate. When set, only these CAs are trusted. Certificate chain and host name are always verified; there is no setting that turns verification off. |
| `UNIFI_AUDIT_REMOTE_CERT_FILE` | For mutual TLS | unset | PEM client certificate chain presented to the collector. Set together with `UNIFI_AUDIT_REMOTE_KEY_FILE` or not at all. |
| `UNIFI_AUDIT_REMOTE_KEY_FILE` | For mutual TLS | unset | Unencrypted PEM private key of `UNIFI_AUDIT_REMOTE_CERT_FILE`, read at every connection attempt (an unreadable file fails that attempt). Its path and contents are never logged. |
| `UNIFI_AUDIT_REMOTE_MAX_ATTEMPTS` | No | `5` | Attempts per batch, the first included. Transport and TLS errors, 408, 429 and 5xx are retried; any other status drops the batch. |
| `UNIFI_AUDIT_REMOTE_RETRY_BACKOFF_SECONDS` | No | `1` | Base `b` of the retry schedule: attempt `n` waits `b*2^(n-2)` seconds (1, 2, 4, 8 by default). |
| `UNIFI_AUDIT_REMOTE_BATCH_MAX_RECORDS` | No | `100` | Most records per batch. |
| `UNIFI_AUDIT_REMOTE_BATCH_MAX_BYTES` | No | `1048576` | Most body bytes per batch (at least `1024`). A larger record is dropped and counted. |
| `UNIFI_AUDIT_REMOTE_FLUSH_INTERVAL_SECONDS` | No | `1` | Seconds between delivery rounds; each round sends everything buffered, in batches. |
| `UNIFI_AUDIT_REMOTE_BUFFER_MAX_RECORDS` | No | `10000` | Most unacknowledged records held in memory. When full, the arriving record is dropped (drop-newest) and counted. |
| `UNIFI_AUDIT_REMOTE_BUFFER_MAX_BYTES` | No | `16777216` | Most unacknowledged bytes held in memory. |
| `UNIFI_AUDIT_HMAC_IDENTIFIERS` | No | `false` | `true` writes client MAC addresses and user identifiers in audit records as `hmac:<32 hex>` (HMAC-SHA256 under `UNIFI_AUDIT_HMAC_KEY`, which it requires): one stable token per identifier, never the clear value. See [Pseudonymised identifiers](#pseudonymised-identifiers-unifi_audit_hmac_identifiers). |
| `UNIFI_AUDIT_LEVEL` | No | `normal` | `off` (only the two policy records), `normal` (metadata only) or `debug` (adds the request body of a write sent to the HTTP chokepoint and the arguments of a call record, credential fields masked and secrets scrubbed; a call refused before it builds a request has no body). |
| `UNIFI_AUDIT_CALLS` | No | `false` | Per-call records: one `call` record per completed tool call, one `error` record per failed one. |
| `UNIFI_AUDIT_LOG_MODE` | No | `0600` | Permission bits of a new audit file: `0600` (owner only) or `0640` (owner and group read). An existing file keeps its mode. Earlier releases created it with the process umask (often `0644`). |
| `UNIFI_AUDIT_CHAIN` | No | `false` | Opt-in tamper evidence for the JSON audit file: a keyed HMAC-SHA256 hash chain over every record, checked offline with `unifi-fabric-audit-verify`. Needs `UNIFI_AUDIT_LOG_FORMAT=json`, the file sink (`UNIFI_AUDIT_LOG`) and `UNIFI_AUDIT_CHAIN_KEY`; otherwise startup fails naming the setting. Off, the audit stream is byte-identical to earlier releases. Tamper-evident, not tamper-proof: see [Tamper evidence](#tamper-evidence-unifi_audit_chain). |
| `UNIFI_AUDIT_CHAIN_KEY` | With `UNIFI_AUDIT_CHAIN` | unset | Operator-provisioned audit hash-chain key: canonical unpadded base64url for exactly 32 bytes, different from `UNIFI_AUDIT_HMAC_KEY` (startup refuses the same key, naming both settings). Every replica writing one audit file needs the same key. Keep it in the deployment's secret store; the server never generates, persists or logs it and scrubs it like every configured secret. Set while `UNIFI_AUDIT_CHAIN` is off it has no effect beyond a startup warning. |
| `UNIFI_AUDIT_HMAC_KEY` | Code Mode or `UNIFI_AUDIT_HMAC_IDENTIFIERS` | unset | Operator-provisioned per-installation key used to correlate Code Mode argument sets and (with `UNIFI_AUDIT_HMAC_IDENTIFIERS=true`) audit identifiers without recording them: canonical unpadded base64url for exactly 32 bytes. Required when `UNIFI_TOOL_MODE=codemode` or `UNIFI_AUDIT_HMAC_IDENTIFIERS=true`; every replica in one installation needs the same key. Keep it in the deployment's secret store, use a distinct key per installation, and rotate it to end correlation. The server never generates or persists this key. |
| `FASTMCP_HOST` | No | `127.0.0.1` from source, `0.0.0.0` in the image | Address the HTTP transports bind to. A non-loopback address with `MCP_AUTH_MODE=none` prints a startup warning ([AUTH-TLS.md](AUTH-TLS.md#startup-warnings)). An unauthenticated loopback bind requires a loopback `Host` unless allowlisted; authenticated servers accept proxy hosts by default ([Host and Origin validation](AUTH-TLS.md#host-and-origin-validation)). |
| `FASTMCP_PORT` | No | `8000` from source, `3000` in the image | Port the HTTP transports listen on. |
| `MCP_HEALTH_ROUTE` | No | `off` | `on` adds an unauthenticated `GET /health` route to the HTTP transports that answers `ok` or `degraded:<reason>`. It never contacts a console. See [Health route](#health-route-mcp_health_route). |
| `UNIFI_MCP_CACHE_TTL` | No | `300` | Seconds an MCP client may reuse `tools/list` (and the other list results) before fetching it again. Sent as a public cache hint (`ttlMs`, `cacheScope: public`) to clients that negotiate MCP protocol 2026-07-28; clients on older protocol revisions ignore it. The tool list is the same for every caller (it depends only on server configuration), so it is safe to share. Set `0` to send no cache hint (clients do not reuse the result). |

### Settings reference (generated)

Every setting read at startup, written from `unifi_fabric.config.Settings`; the table above is the editorial guide.

<!-- BEGIN GENERATED: settings-reference -->
| Variable | Default | Accepted | Meaning |
|---|---|---|---|
| `UNIFI_API_BASE_URL` | `https://api.ui.com` | absolute `http://` or `https://` URL | UniFi Site Manager API base URL. |
| `UNIFI_API_KEYS` | unset | text | List of API key configs. |
| `UNIFI_API_KEY` | unset | text | Single API key shorthand. |
| `UNIFI_API_KEY_FILE` | unset | text | Absolute path of a file holding the single API key (UNIFI_API_KEY_FILE), read once at startup; a trailing line break is removed. |
| `UNIFI_API_KEY_COMMAND` | unset | text | Helper command whose standard output is the single API key (UNIFI_API_KEY_COMMAND), run once at startup without a shell: POSIX-quoted words, the first an absolute path or a name on PATH. |
| `UNIFI_API_KEYS_FILE` | unset | text | Absolute path of a file holding the UNIFI_API_KEYS JSON list (UNIFI_API_KEYS_FILE), read once at startup. |
| `UNIFI_API_KEYS_COMMAND` | unset | text | Helper command whose standard output is the UNIFI_API_KEYS JSON list (UNIFI_API_KEYS_COMMAND), run once at startup without a shell, like UNIFI_API_KEY_COMMAND. |
| `UNIFI_CACHE_TTL_SECONDS` | `900` | integer, 0 or more | TTL for host/site registry cache (default 15 min). |
| `UNIFI_CACHE_MAX_HOSTS` | `512` | integer, 1 or more | Max entries in the hosts TTLCache (default 512). |
| `UNIFI_CACHE_MAX_SITES` | `2048` | integer, 1 or more | Max entries in the sites TTLCache (default 2048). |
| `UNIFI_MAX_CONCURRENCY` | `10` | integer, 1 or more | Max concurrent requests for cross-site aggregation. |
| `UNIFI_REQUEST_TIMEOUT_SECONDS` | unset | removed | Removed setting. |
| `UNIFI_PAGINATE_MAX_PAGES` | unset | integer, 1 or more | Hard cap on pages drained per list call; query_traffic_flows and export_traffic_flows are exempt and always drain every page. |
| `UNIFI_LOG_LEVEL` | `INFO` | `DEBUG` or `INFO` or `WARNING` or `ERROR` or `CRITICAL` | Logging level for the server. |
| `UNIFI_REDACT_SECRETS` | `false` | boolean | Opt-in credential redaction for responses. |
| `UNIFI_AUDIT_LOG` | unset | text | Opt-in audit-log file path for ALL write/action operations. |
| `UNIFI_AUDIT_LOG_FORMAT` | `json` | `text` or `json` | Format of the audit stream. |
| `UNIFI_AUDIT_SINK` | unset | `none` or `stderr` or `file` or `remote` | Audit stream sink. |
| `UNIFI_AUDIT_LEVEL` | `normal` | `off` or `normal` or `debug` | Audit stream level. |
| `UNIFI_AUDIT_CALLS` | `false` | boolean | Per-call audit records. |
| `UNIFI_AUDIT_LOG_MODE` | `0600` | `0600` or `0640` | Permission bits of a NEW audit file. |
| `UNIFI_AUDIT_REMOTE_URL` | unset | text | Collector endpoint of the remote audit sink. |
| `UNIFI_AUDIT_REMOTE_PLAINTEXT` | `false` | boolean | Plain HTTP for the remote audit sink. |
| `UNIFI_AUDIT_REMOTE_CA_FILE` | unset | text | PEM bundle of the CAs trusted for the collector certificate. |
| `UNIFI_AUDIT_REMOTE_CERT_FILE` | unset | text | PEM client certificate chain for mutual TLS to the collector. |
| `UNIFI_AUDIT_REMOTE_KEY_FILE` | unset | text | PEM private key (unencrypted) of UNIFI_AUDIT_REMOTE_CERT_FILE. |
| `UNIFI_AUDIT_REMOTE_MAX_ATTEMPTS` | `5` | integer, 1 or more | Delivery attempts per remote audit batch, the first included. |
| `UNIFI_AUDIT_REMOTE_RETRY_BACKOFF_SECONDS` | `1` | number above 0 | Base b of the remote audit retry schedule: attempt n waits b*2^(n-2) seconds. |
| `UNIFI_AUDIT_REMOTE_BATCH_MAX_RECORDS` | `100` | integer, 1 or more | Most records in one remote audit batch. |
| `UNIFI_AUDIT_REMOTE_BATCH_MAX_BYTES` | `1048576` | integer, 1 or more | Most body bytes in one remote audit batch (each record plus its newline). |
| `UNIFI_AUDIT_REMOTE_FLUSH_INTERVAL_SECONDS` | `1` | number above 0 | Seconds between remote audit delivery rounds (each sends all buffered). |
| `UNIFI_AUDIT_REMOTE_BUFFER_MAX_RECORDS` | `10000` | integer, 1 or more | Most unacknowledged remote audit records held in memory. |
| `UNIFI_AUDIT_REMOTE_BUFFER_MAX_BYTES` | `16777216` | integer, 1 or more | Most unacknowledged remote audit bytes held in memory. |
| `UNIFI_AUDIT_HMAC_IDENTIFIERS` | `false` | boolean | Pseudonymised identifiers in audit records. |
| `UNIFI_AUDIT_HMAC_KEY` | unset | text | Per-installation audit HMAC key (Code Mode argument audit and pseudonymised audit identifiers). |
| `UNIFI_AUDIT_CHAIN` | `false` | boolean | Opt-in tamper evidence for the JSON audit file. |
| `UNIFI_AUDIT_CHAIN_KEY` | unset | text | Audit hash-chain key. |
| `UNIFI_TOOL_MODE` | `discovery` | `full` or `discovery` or `codemode` | Tool catalog mode (UNIFI_TOOL_MODE): full advertises every selected tool; discovery advertises compact search, describe and registered-dispatch meta-tools; codemode (experimental, read-only, opt-in) advertises search_tools, describe_tool and execute, which runs a sandboxed Python script over the read tools. |
| `UNIFI_WRITE_POLICY` | unset | text | Global write policy (UNIFI_WRITE_POLICY): allow (default), dry-run or deny. |
| `UNIFI_WRITE_EXCEPTIONS` | unset | text | Per-family and per-tool write exceptions (UNIFI_WRITE_EXCEPTIONS): one semicolon list of <target>=deny or <target>=dry-run, the target family:<family-id> or tool:<public-name>, e.g. |
| `UNIFI_FAMILY_ALLOW` | unset | text | Tool-family allowlist (UNIFI_FAMILY_ALLOW): a comma set of family IDs (unifi_fabric.families.ALL_FAMILIES). |
| `UNIFI_EXCLUDE` | unset | text | Exclusions (UNIFI_EXCLUDE): one comma list of family:<id>, tool:<name>, source:<selector> (unifi_fabric.api_sources.valid_selectors(), case-sensitive) and unofficial (every tool whose primary API source is private). |
<!-- END GENERATED -->

## Tool families

`UNIFI_FAMILY_ALLOW` (an allowlist) and the `family:<id>` entries of `UNIFI_EXCLUDE` (applied
after it) take these 13 IDs, comma-separated, lower case and case-sensitive. Each tool is in exactly one family. `firewall` is assigned by route: every tool that
calls a firewall policy, firewall zone, ACL rule or classic firewall rule or group route is
in `firewall`, whatever module defines it. An unknown ID fails at startup naming the
setting. Counts in this release (written by `scripts/gen_catalog_figures.py`):

| Family | Tools | Write tools | Covers |
|---|---:|---:|---|
| `carrier` | 11 | 7 | Carrier / ISP Fabric subscribers and service plans |
| `clients` | 15 | 12 | Connected and known clients, client actions and records |
| `connector` | 5 | 5 | The generic Fabric connector relay |
| `devices` | 39 | 27 | Device adoption, actions, radios, tags and scheduled tasks |
| `firewall` | 33 | 19 | Firewall policies and zones, ACL rules, classic firewall rules and groups, app blocks |
| `hotspot` | 4 | 3 | Hotspot vouchers, packages and operators |
| `innerspace` | 32 | 18 | InnerSpace projects, floor plans and placement snapshots |
| `mobility` | 8 | 3 | Mobility workspaces, devices and clients |
| `network` | 345 | 193 | Networks, Wi-Fi, switching, routing, DNS, DHCP, RADIUS, port profiles and settings |
| `protect` | 225 | 138 | Protect cameras, NVRs, sensors, events, PTZ, recognition and search |
| `site_manager` | 20 | 0 | Site Manager hosts, sites, fleet summaries and cross-site health |
| `statistics` | 19 | 3 | Statistics, history, ISP metrics and system logs |
| `vpn` | 42 | 27 | VPN servers, clients and site-to-site tunnels, RADIUS profiles |

`manage_device_ssh_session` accepts the aliases `build`, `sdp_answer` and `close`,
and also forwards any other action as an arbitrary Classic devmgr command. The SSH
aliases do not restrict the command set; write policy gates the whole tool. Inspect
the command and its consequences before allowing it.

## Read-only mode

Set `UNIFI_WRITE_POLICY=deny` to hide write and action tools and refuse calls before they reach UniFi. Reads remain available. Set the Claude Code plugin's Write policy option to `deny`, add the variable to a client configuration or pass `-e UNIFI_WRITE_POLICY=deny` to Docker. Remove it (the default is `allow`) or set the plugin option back to `allow` and restart to enable writes again.

For example, with Claude Code:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-12 mode=non-executable reason=deployment-or-client-interaction -->
```bash
export UNIFI_API_KEY="your-api-key-here"
claude mcp add unifi-fabric -e UNIFI_API_KEY="$UNIFI_API_KEY" -e UNIFI_WRITE_POLICY=deny -- uvx --from unifi-fabric-mcp-server==0.7.2 unifi-fabric-mcp
```

The command stores the key in Claude Code's MCP configuration in plain text; keep it private.

### Read-only mode details

`UNIFI_WRITE_POLICY=deny` is the single, global, opt-in setting that makes the whole server read-only. The policy is **`allow` by default** — unset means read + write is on and behaviour is byte-identical to a build without the setting.

1. **Default — writes ENABLED.** With the variable unset, every tool works as usual.
2. **To enable read-only** — set `UNIFI_WRITE_POLICY=deny` in the environment of the process that starts the server:

   - **Claude Code plugin:** set the plugin's **Write policy** option to `deny`.
   - **Other local (stdio) clients:** add `UNIFI_WRITE_POLICY=deny` to the server's `env` block in the client configuration, or pass `-e UNIFI_WRITE_POLICY=deny` to `claude mcp add` or `--env UNIFI_WRITE_POLICY=deny` to `codex mcp add`. Antigravity reads it from the shell that starts the client; Codex does so only when the variable is listed in the server's `env_vars` (as in the [Codex setup](CLIENT-SETUP.md#use-with-openai-codex)).
   - **Docker Compose:** set it in the service's `environment:` block, then recreate the container (if a sidecar shares this server's network namespace, restart the **whole compose group together**, as for the connector-write entries in [Write switches](#write-switches)), as in this service fragment:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
```yaml
services:
  unifi-fabric-mcp:
    environment:
      UNIFI_WRITE_POLICY: "deny"   # hide and refuse every write/action tool; reads still work
```

3. **To return to read + write** — local install: unset `UNIFI_WRITE_POLICY` in the client config's `env` (or set the plugin's Write policy option to `allow`) and restart the server; Docker: remove the variable or set it to `allow`, then recreate the container.

When enabled, write/action tools are hidden from `tools/list` and from discovery search, descriptions and family counts at startup; a client that calls a hidden write by name still receives the audited read-only refusal. This includes the discovery `call_write_tool` dispatcher; the read discovery meta-tools stay available. Filters compose in order: the family allowlist (`UNIFI_FAMILY_ALLOW`), the exclusions (`UNIFI_EXCLUDE`), read-only selection, then the per-area `deny` entries of `UNIFI_WRITE_EXCEPTIONS`, using the tools' derived annotations. Every write/action tool across all areas — Network create/update/delete, device and client actions, Protect, the generic connector relay, Carrier Fabric, Mobility, port-profiles, and vouchers — is refused **before any upstream call**, and the refusal (`write_denied`) names the setting, says where to change it, and points back to this section. Read tools are unaffected, including the allowlisted read-POST queries (the Network v2 traffic-flows query, Classic `stat/session` and `stat/report`, and the ISP-metrics query) and the four Classic read commands (`cmd/firmware` with `list-available` or `list-cached`, `cmd/backup` with `list-backups`, `cmd/devmgr` with `speedtest-status`). A `fabric_connector_get` call to a known state-changing GET route (Protect camera `enable-control` / `disable-control`) is a write and is refused.

The policy combines with `UNIFI_WRITE_EXCEPTIONS` (per-family entries such as `family:network=deny` and per-tool entries such as `tool:fabric_connector_post=dry-run`): a write gets the strictest of the policy and every matching entry, in the order `allow` < `dry-run` < `deny`. So a write is refused if **either** the policy is `deny` **or** a matching entry is `deny`, and a refusal wins over a dry-run: a refused write returns the refusal, never a dry-run preview. Only the six area entries (`family:network=deny`, `family:protect=deny`, `family:mobility=deny`, `family:carrier=deny`, `family:innerspace=deny` and `family:connector=deny`) also hide the write tools they cover; any other `family:<id>=deny` and every `tool:<name>=deny` entry keeps the tools listed and refuses them when called.

Accepted values (lower case): unset or `allow` → **read + write on**; `dry-run` → **every write previewed**; `deny` → **read-only**. A blank or any other value stops the server from starting, naming the setting.

## Write switches

<!-- BEGIN GENERATED: write-switch-names -->
The area entries of `UNIFI_WRITE_EXCEPTIONS` are `family:network=deny`, `family:protect=deny`, `family:mobility=deny`, `family:carrier=deny`, `family:innerspace=deny`, `family:connector=deny`.
<!-- END GENERATED -->

<!-- BEGIN GENERATED: write-switches -->
- `family:network=deny`: the write tools of `network`, `firewall`, `clients`, `devices`, `vpn`, `hotspot`, `statistics` and every write request to its console routes, the connector relay included
- `family:protect=deny`: the write tools of `protect` and every write request to its console routes, the connector relay included
- `family:mobility=deny`: the write tools of `mobility` and every write request to its console routes, the connector relay included
- `family:carrier=deny`: the write tools of `carrier` and every write request to its console routes, the connector relay included
- `family:innerspace=deny`: the write tools of `innerspace` and every write request to its console routes, the connector relay included
- `family:connector=deny`: the connector relay's write tools and the typed tools it also governs
Each is one entry of `UNIFI_WRITE_EXCEPTIONS` (unset by default: every write allowed); `dry-run` in place of `deny` previews the same writes instead of refusing them.
<!-- END GENERATED -->

The [Enabling / disabling connector writes](#enabling--disabling-connector-writes) summary below lists how many tools each entry hides.

Every per-area opt-out is one entry of `UNIFI_WRITE_EXCEPTIONS`, a semicolon-separated list of `<target>=deny` or `<target>=dry-run`. Read and write are enabled by default: with `UNIFI_WRITE_EXCEPTIONS` unset, every area writes.

1. **Default — writes ENABLED.** With no entry, `fabric_connector_post/put/patch/delete` and every area's write tools are enabled. No action is needed to have write capability.
2. **To deny one area (deliberate read-only deployment of that area)** — add its entry, for example `family:connector=deny`, in the environment of the process that starts the server. The server reads it from its environment, so for a Compose deployment that is the **service's `environment:` block of the docker-compose file that deploys this server**; for a local install it is the client's server `env` block or a shell `export` before the client starts. It is not set in the application source. Compose example: under `services:` → `unifi-fabric-mcp:` → `environment:` add `UNIFI_WRITE_EXCEPTIONS: "family:connector=deny"`; several entries share one value, for example `"family:connector=deny;family:protect=deny"`.

   Then recreate the container (e.g. `docker compose up -d`). If this server is deployed alongside a sidecar that shares its network namespace (e.g. a `ghostunnel` proxy using `network_mode: "service:..."` or a shared pod), restart the **whole compose group together**, not the app container alone — restarting only the app can leave the sidecar bound to a stale namespace.
3. **To re-enable** — remove the entry (or the whole variable), then recreate the container with the same restart rule. `dry-run` in place of `deny` previews the area's writes instead of refusing them.
4. **`confirm` is accepted and ignored.** The mutating relay tools still accept a `confirm` argument so existing callers do not break, but it gates nothing. The mutation runs whether or not `confirm` is passed, provided `UNIFI_WRITE_POLICY` and every matching `UNIFI_WRITE_EXCEPTIONS` entry (the connector entry and the entry of the target route's area) allow it.

Values are case-sensitive; a blank value, an unknown family or tool, a duplicate target or an `allow` entry fails startup naming the setting. With one of the six area `deny` entries, the write tools it governs are hidden from `tools/list` and discovery at startup (any other `family:<id>=deny` and every `tool:<name>=deny` entry keeps its tools listed); a mutating call by name is refused (`write_denied`) before the console is touched and audited, and the refusal message names the entry and points to [Enabling / disabling connector writes](#enabling--disabling-connector-writes) on this page.

**Scope of `family:connector=deny`.** It governs the four generic connector relay mutation tools (`fabric_connector_post`, `fabric_connector_put`, `fabric_connector_patch`, `fabric_connector_delete`), a `fabric_connector_get` call to a known state-changing GET route (Protect camera `enable-control` / `disable-control`), and these typed tools: `update_device_radio` and `update_switch_port_overrides`; the Wi-Fi radio tools `preview_radio_ai_optimization`, `apply_radio_ai_optimization`, `control_wifi_doctor_optimization`, `start_wifi_quick_scan`, `start_spectrum_scan` and `configure_wifi_wan`; and the Protect private-API writes `update_camera_private`, `update_nvr`, `update_sensor_private`, `reboot_protect_device`, `adopt_protect_device`, `unadopt_protect_device` and `clear_sensor_tamper` (each also follows its own area's entry). All are enabled by default and are refused when `family:connector=deny` is set or `UNIFI_WRITE_POLICY=deny`. The InnerSpace typed write tools are not governed by this entry; they follow `family:innerspace=deny` (and `UNIFI_WRITE_POLICY`). An InnerSpace write path reached through the generic relay (the `innerspace/integration/v1` and `innerspace/api` namespaces map to InnerSpace route classes) is a relay mutation like any other and follows both `family:connector=deny` and `family:innerspace=deny`.

**Catalog visibility.** `UNIFI_WRITE_POLICY`, the six area `deny` entries of `UNIFI_WRITE_EXCEPTIONS`,
`UNIFI_FAMILY_ALLOW` and `UNIFI_EXCLUDE` decide at startup which tools `tools/list` and
discovery show, so a client that caches the tool list should refresh it after the server
restarts with a changed setting. A hidden write called by name, directly or through
`call_write_tool`, is still refused with the setting named, and the refusal is audited.

**One grammar.** `UNIFI_WRITE_POLICY`, `UNIFI_WRITE_EXCEPTIONS`, `UNIFI_FAMILY_ALLOW` and
`UNIFI_EXCLUDE` are checked once at startup with one grammar: entries are trimmed of
surrounding spaces, values and IDs are case-sensitive lower case, and an empty, trailing or
doubled separator, a blank value or an unknown entry fails startup naming the setting, never
the value. The startup check and the decisions made at call time read the same settings, so
they always agree.

**Area reach.** Each of the six area entries (`family:network=deny`, `family:protect=deny`, `family:mobility=deny`, `family:carrier=deny`, `family:innerspace=deny`, `family:connector=deny`) hides its area's write tools from `tools/list` and discovery search, descriptions and family counts at startup, and refuses them before they run if called by name (no request at all; the refusal is audited). The shared request path also refuses any write request to the area's routes (Network, Protect and InnerSpace console routes, the Mobility and Carrier Fabric cloud routes) whichever tool or relay call sends it. `family:network=deny` keeps the reach of the Network area: besides the `network` family it covers the write tools of `firewall`, `devices`, `clients`, `vpn`, `hotspot` and `statistics`. The refusal names the entry and the compose location and points to [Enabling / disabling connector writes](#enabling--disabling-connector-writes) on this page, so a refusal is always actionable without reading the source. A `deny` entry wins over `UNIFI_WRITE_POLICY=dry-run`: a refused write returns the refusal, not a preview.

### Enabling / disabling connector writes

Connector writes and each area's writes are enabled by default. To make one area read-only, add its entry to `UNIFI_WRITE_EXCEPTIONS` (one semicolon-separated list, for example `family:network=deny;family:protect=deny`) in the server's environment: the service's `environment:` block of the docker-compose file that deploys this server (then recreate the container, restarting the whole compose group if a sidecar shares its network namespace), or for a local install the client's server `env` block or a shell `export` before the client starts (Codex forwards only the variables listed in the server’s `env_vars`; the Codex plugin forwards `UNIFI_API_KEY`, `UNIFI_WRITE_POLICY` and `UNIFI_TOOL_MODE` only). At startup an opted-out area's write tools are hidden from `tools/list` and from discovery search, descriptions and family counts, so a client sees only tools it can call. A client that calls a hidden write by name still gets the refusal, which names the entry, and the refusal is audited. `confirm` is accepted and ignored. What each entry governs (including a `fabric_connector_get` of a state-changing route), the grammar and an example are in [Write switches](#write-switches) above.

The six area entries hide the write tools they cover: `family:network=deny` keeps the reach of the Network area and covers `network`, `firewall`, `devices`, `clients`, `vpn`, `hotspot` and `statistics` plus every write to a Network console route (the relay included); `family:protect=deny`, `family:mobility=deny`, `family:carrier=deny` and `family:innerspace=deny` each cover their own family and routes; and `family:connector=deny` covers the relay's write tools and the typed tools it also governs (listed under **Scope of `family:connector=deny`** above). Any other `family:<id>=deny` (for example `family:vpn=deny`) and every `tool:<name>=deny` entry keeps its tools listed and refuses them when called. Tool counts in this release are the same in full mode and in discovery search:

| Setting | Write tools hidden | Tools listed |
|---|---:|---:|
| none (default) | 0 | 798 |
| `UNIFI_WRITE_EXCEPTIONS=family:network=deny` | 284 | 514 |
| `UNIFI_WRITE_EXCEPTIONS=family:protect=deny` | 138 | 660 |
| `UNIFI_WRITE_EXCEPTIONS=family:mobility=deny` | 3 | 795 |
| `UNIFI_WRITE_EXCEPTIONS=family:carrier=deny` | 7 | 791 |
| `UNIFI_WRITE_EXCEPTIONS=family:innerspace=deny` | 18 | 780 |
| `UNIFI_WRITE_EXCEPTIONS=family:connector=deny` | 19 | 779 |
| `UNIFI_WRITE_POLICY=deny` | 454 | 344 |

Under `UNIFI_WRITE_POLICY=deny`, 454 of the 455 write-annotated tools are hidden. The 455th, `fabric_connector_get`, stays listed because most of its calls are reads; it is refused per call for its state-changing routes (Protect camera `enable-control` and `disable-control`).

## Credential redaction

By default the server is a faithful pass-through: upstream responses are returned
verbatim, including plaintext credential fields such as WLAN `x_passphrase`, Dynamic
DNS `x_password`, RADIUS shared secrets, SSH passwords and VPN pre-shared keys. The one
change made whatever this setting is: the server's own configured secrets (its API keys,
`MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`) are replaced by `***` wherever a response
echoes them (see [UniFi API Settings](#unifi-api-settings)).

Where the server needs to tell API keys apart (to spot a duplicate key at startup, to label a per-request credential, or to key an in-memory cache) it uses a fingerprint, never the key. A fingerprint is a keyed hash made with a random key drawn at each server start, so it changes on every restart, cannot be guessed offline and cannot be compared across restarts.

If redaction is enabled but the framework exposes no tool handlers to protect, startup
fails with an error naming `UNIFI_REDACT_SECRETS`.

Operators who prefer secrets masked can opt in by setting `UNIFI_REDACT_SECRETS` to
a truthy value (`1`/`true`/`yes`/`on`/`t`/`y`, case-insensitive) in the environment of the process that starts the server (the client's server `env` block, a shell export, or a Compose service's `environment:` block):

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
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
| VPN client credentials | `x_wireguard_private_key`, `x_openvpn_password`, `openvpn_configuration`, `wireguard_client_configuration_file`, `wireguard_client_preshared_key` |
| API tokens / auth / cloud access | `api_token`, `x_api_token`, `api_key`, `apikey`, `auth_token`, `x_auth_token`, `access_token`, `refresh_token`, `device_auth`, `token` |
| Controller camelCase and `x_` aliases | `sharedsecret`, `authserversecret`, `wanpassword`, `wireguardprivatekey`, `wireguardclientconfigurationfile`, `wireguardclientpresharedkey`, `clientsecret`, `bearertoken`, `apitoken`, `accesstoken`, `refreshtoken`, `radiussecret`, `pppoepassword`, `sshpassword`, `x_shared_secret`, `x_auth_server_secret`, `x_wan_password`, `x_client_secret`, `x_bearer_token`, `x_access_token`, `x_refresh_token`, `x_pppoe_password` |

When enabled, the same fields are also masked inside upstream error bodies quoted in
error messages. Error messages otherwise carry the real request path and the complete
upstream error body: identifiers (console ids, UUIDs) are not secrets and are never masked,
and nothing is truncated.

Error text decodes nested JSON and Python string representations up to six layers before applying the same credential predicate. Single-level JSON and Python representations preserve identifiers and reasons. Ambiguous or unresolved credential spans fail closed through the end of the message, so nested or malformed errors may lose following diagnostics; masking never raises a parser error. The fallback scans the final rendering, including all parsed containers, at every escape-decoded level until a fixed point, up to 128 decoding iterations. A credential word must be followed by a key-value separator (after an optional closing quote and whitespace); prose and tool names remain intact. If decoding still changes the text at that bound, it withholds the whole message.

In ordinary tool responses, the listed credential fields become `***REDACTED***` and all other fields stay unchanged. Registered route-secret fields (including an echoed request field) use that same token. This is strictly opt-in for structured data: successful writes, GET results and dry-run previews (including a read-before snapshot) remain verbatim when it is off. Logs and audit lines always scrub the registered route-secret values and credential arguments of the call, whatever the setting. Errors and hints, and the result of a failed or partial write or other non-2xx upstream response (its body, read-before/read-after snapshots, reasons and post-write error), mask them only when it is on; when it is off they carry them verbatim. The placement snapshot is a projection, not a whole upstream body, so it is the one exception: with `UNIFI_REDACT_SECRETS` on, it also leaves out URLs, IP and MAC addresses and strings containing credential markers, counting them under `_withheld` (with redaction off, `_withheld` is never present). See [Placement snapshots](TOOLS.md#get_unifi_placement_snapshot).

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

### Health route (`MCP_HEALTH_ROUTE`)

Off by default. With `MCP_HEALTH_ROUTE=on`, the `streamable-http` and `sse` transports serve `GET /health` on the same port as the MCP endpoint; `stdio` has no HTTP listener and serves nothing. The route reports this process only and returns one line: `ok` with status `200` when the server lifespan is running with its settings loaded and the audit file (`UNIFI_AUDIT_LOG`, when set) is writable, otherwise `degraded:config-not-loaded`, `degraded:server-not-started` or `degraded:audit-sink-unwritable` with status `503`. It never calls a UniFi console, uses no API key, and returns no counts or statistics; there is no `/metrics` route. The route needs no MCP token in any `MCP_AUTH_MODE`, including when the MCP endpoint requires one (a presented but invalid OAuth token is still rejected); the Host and Origin checks apply to it as they do to the MCP endpoint ([Host and Origin validation](AUTH-TLS.md#host-and-origin-validation)). Because `degraded:audit-sink-unwritable` tells any caller that audit logging is failing, expose `/health` only to the network that runs the probe, not publicly. "Writable" means the file permissions allow appending; a full disk still reads as `ok`. `server-not-started` means the server lifespan is not running.

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

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-2 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# SSE transport (UNIFI_API_KEY exported; -e with no value passes it from your shell)
docker run -e UNIFI_API_KEY -e FASTMCP_TRANSPORT=sse -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
```

MCP clients connect to the `/sse` endpoint — note the path differs from the streamable-http default (`/mcp`):

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
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

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-4 mode=non-executable reason=deployment-or-client-interaction -->
```bash
curl --include --no-buffer --silent --show-error http://localhost:3000/sse
```

An `HTTP 200` response header and the initial SSE endpoint event confirm the server is listening.
The stream continues delivering events until the connection closes or you stop it with Ctrl-C
after inspecting the response.

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-5 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# Stdio transport (UNIFI_API_KEY exported; -e with no value passes it from your shell)
docker run --no-healthcheck --rm -i -e UNIFI_API_KEY -e FASTMCP_TRANSPORT=stdio ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
```

With stdio transport the MCP client must **spawn** the container as a subprocess (the same as [Track A](CLIENT-SETUP.md#track-a--local-stdio)), not connect over HTTP. Pass `--rm -i` so the container receives stdin and is removed on exit. The corresponding client config uses `command`/`args`, not `type`/`url`. The key sits in `env`, which the client hands to `docker`, and `-e UNIFI_API_KEY` with no value passes it on, so it is never part of the command line:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-6 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "command": "docker",
      "args": ["run", "--no-healthcheck", "--rm", "-i",
               "-e", "UNIFI_API_KEY",
               "-e", "FASTMCP_TRANSPORT=stdio",
               "ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2"],
      "env": { "UNIFI_API_KEY": "your-api-key-here" }
    }
  }
}
```

> **HEALTHCHECK note:** When `FASTMCP_TRANSPORT=stdio`, no port 3000 is bound. The Dockerfile's built-in TCP healthcheck will fail permanently. Pass `--no-healthcheck` to suppress the misleading `(unhealthy)` status: `docker run --no-healthcheck --rm -i ...`.

### Override Transport in Docker Compose

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-7 mode=non-executable reason=deployment-or-client-interaction -->
```yaml
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
    environment:
      UNIFI_API_KEY: your-api-key-here
      FASTMCP_TRANSPORT: sse  # or stdio
    ports:
      - "3000:3000"  # remove this entry when using stdio
```

**Note:** The server exposes port 3000 for `streamable-http` and `sse` transports. If using `stdio`, no port is exposed; the server communicates exclusively via stdin/stdout. When switching to `stdio`, remove the `ports:` mapping and disable the built-in TCP healthcheck (which will fail permanently when nothing binds port 3000) by adding:

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
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

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-9 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# UNIFI_API_KEY exported; -e with no value passes it from your shell
docker run -e UNIFI_API_KEY -e FASTMCP_STATELESS_HTTP=false -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
```

The `sse` transport is session-based by nature; with `FASTMCP_TRANSPORT=sse` the
stateless setting is ignored. Running from source (`pip install`), the FastMCP default
applies (sessions on) unless you set the variable yourself.

## Single key setup

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
<!-- install-case: docs-configuration-10 mode=non-executable reason=deployment-or-client-interaction -->
```bash
export UNIFI_API_KEY="your-api-key-here"
```

## Multi-key MSP setup

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
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


## Key files and helper commands

Instead of putting a key in the server's environment, point the server at where the key is kept.
Each setting is read once, while the server starts, and only from the server's own environment:
a tool argument or a request header can never name a file or a command, run a helper or change
these keys.

| Instead of | File | Helper command |
|---|---|---|
| `UNIFI_API_KEY` | `UNIFI_API_KEY_FILE` | `UNIFI_API_KEY_COMMAND` |
| `UNIFI_API_KEYS` | `UNIFI_API_KEYS_FILE` | `UNIFI_API_KEYS_COMMAND` |

<!-- doc-provenance: source=file:src/unifi_fabric/credential_providers.py@sha256:3e4c8e36bd84fe2b6b92b410da50f47e68c806b8f25d38398a982c3e7b2c0240 support=0.7.2 citation=file:src/unifi_fabric/credential_providers.py@sha256:3e4c8e36bd84fe2b6b92b410da50f47e68c806b8f25d38398a982c3e7b2c0240 -->
<!-- install-case: docs-configuration-key-providers mode=non-executable reason=deployment-or-client-interaction -->
```bash
# A Docker or Kubernetes secret file holding one key
export UNIFI_API_KEY_FILE=/run/secrets/unifi_api_key
# Or a password-manager helper that prints the key
export UNIFI_API_KEY_COMMAND="/usr/local/bin/op read 'op://Infra/UniFi API key/credential'"
```

- **One source per setting.** Set exactly one of `UNIFI_API_KEY`, `UNIFI_API_KEY_FILE` or
  `UNIFI_API_KEY_COMMAND`, and exactly one of `UNIFI_API_KEYS`, `UNIFI_API_KEYS_FILE` or
  `UNIFI_API_KEYS_COMMAND`; setting two fails startup naming them. A key file or helper of one
  row cannot be combined with any setting of the other row either. As before, when only
  `UNIFI_API_KEY` and `UNIFI_API_KEYS` are both set, `UNIFI_API_KEYS` is used. All of this is
  checked before any file is read or helper is run.
- **Files.** The path must be absolute (`~` is expanded). A symbolic link is followed, so a
  Docker or Kubernetes secret mount works; the target must be a regular file of at most 1 MiB,
  readable by the server's user, in UTF-8. Keep it readable only by that user (for example
  `chmod 400`); the server does not change or check its mode.
- **Helper commands.** The value is split into words with POSIX shell quoting (single or double
  quotes and backslashes group words) and run directly, never through a shell: `$VARIABLES`,
  `~`, wildcards, pipes, `;` and redirections are passed to the helper as plain text. The first
  word is the helper, an absolute path or a bare name found on `PATH`; a relative path such as
  `bin/helper` is refused, and so is a bare name that `PATH` resolves through an empty or `.` entry. The server logs a warning (naming the setting only) when a key file or the helper, or the helper's directory, is writable by group or others. The helper runs with the server's environment minus its secrets (the API key settings, `MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`, `UNIFI_AUDIT_HMAC_KEY` and any other `UNIFI_` or `MCP_` variable whose name contains KEY, TOKEN, SECRET, PASSWORD or PASSPHRASE, and the OpenTelemetry collector credentials `OTEL_EXPORTER_OTLP_HEADERS` and its per-signal forms; `PATH`, `HOME`, locale and your password manager's own variables are kept), in the directory `/`,
  with standard input from the null device; its standard error is discarded, because a helper may
  print the key there. The helper's command line, arguments included, is visible to other local users of
  the machine in the process list (`ps`) while it runs, so its arguments are not secret: pass the
  name of the item or file the key is stored in, and put no credential in the arguments. The server waits for it to finish, with no time limit, like every other
  operation of this server, so a helper that waits for input or never exits keeps the server from
  starting. The server reads the helper's output until the stream closes, so a background process
  the helper leaves running with its standard output still open (a wrapper script that starts a
  daemon without redirecting it) keeps the server from starting even after the helper itself
  exits; redirect that process's output (`> /dev/null 2>&1`) or detach it. The helper must exit
  with status 0 and print at most 1 MiB.
- **What the value must look like.** For `UNIFI_API_KEY_FILE` and `UNIFI_API_KEY_COMMAND` the
  content is the key on one line: any number of trailing line breaks (`\n` or `\r` characters at
  the end) and a UTF-8 byte order mark are removed and nothing else, so a value with spaces around
  it or a second line holding text fails startup instead of being trimmed. For `UNIFI_API_KEYS_FILE` and `UNIFI_API_KEYS_COMMAND` the
  content is the `UNIFI_API_KEYS` JSON list, checked exactly like that setting (its errors name
  `UNIFI_API_KEYS` entries).
- **Errors.** A missing, unreadable, empty or malformed file, a helper that cannot be found or
  started, exits with a non-zero status or prints nothing, and a value that is not a valid key all
  fail startup with one line naming the setting and the problem. Like every other setting, the
  value is never shown (a key pasted into the wrong variable would otherwise be printed): not the
  path, the helper or its arguments, nor the file content or the helper's output.
- **Secrets.** A key read this way is a configured secret like `UNIFI_API_KEY`: it is replaced by
  `***` in every error, log line and audit record.
- **Header key mode.** Under `UNIFI_KEY_MODE=header` these settings are ignored like the other key
  settings: no file is read and no helper is run, and the startup warning names them.
- **Windows.** The helper command follows POSIX quoting rules; on Windows prefer the file setting.

Design credit: the file and helper-command providers of [sirkirby/unifi-mcp](https://github.com/sirkirby/unifi-mcp) by Tyler Mowbrey.

### Dry-run behavior

The Mobility and Carrier Fabric tools are registered and follow this setting like every other family, so the rules below cover them too.

Set `UNIFI_WRITE_POLICY=dry-run` to make **every** write/action tool — across all
product areas (network, Protect, hotspot, device management, clients, Carrier Fabric,
Mobility, port profiles, settings, the connector relay, ...) — return a clearly-labeled
preview (`status: "dry_run"`, `dryRun: true`, `sent: false`, with `preview: {method, path, params, body}`, where `params` is
the query string the write would carry, or `null`) of the intended mutation and perform
**no upstream write**. This
is enforced at the shared HTTP chokepoint: a request is treated as a write when its method
is PUT/PATCH/DELETE, when it is a GET to a known state-changing route (the Protect camera
`enable-control` / `disable-control` routes), or when it is a POST other than the read-only
POSTs, which still execute normally. The read-only POSTs are the four query routes on the
read-POST allowlist (the Network v2 `.../v2/api/site/<site>/traffic-flows` query, the Network
Classic `.../api/s/<site>/stat/session` and `.../stat/report/<interval>.<scope>` queries, and Site Manager
`/v1/isp-metrics/{interval}/query`) and four Classic read commands, each a read only with
exactly its one-field body: `.../cmd/firmware` with `{"cmd": "list-available"}` or
`{"cmd": "list-cached"}`, `.../cmd/backup` with `{"cmd": "list-backups"}` and
`.../cmd/devmgr` with `{"cmd": "speedtest-status"}`. Any other POST, a relayed POST
included, is a write: previewed under dry-run and audited. A `deny` from the policy or a matching `UNIFI_WRITE_EXCEPTIONS` entry wins over dry-run: a refused write returns the refusal, not a preview. A `dry-run` entry (for example `family:protect=dry-run` or `tool:fabric_connector_post=dry-run`) previews only the writes it matches. The default policy is `allow`: writes execute as usual and the request path is byte-identical.

Tools that verify their write (`update_setting`'s silent-no-op check, the Protect, Mobility and Carrier Fabric read-before / write / read-after flows, and the connector relay's read-after) return the preview without verifying: nothing was written, so there is nothing to verify. `update_setting` returns the preview itself; the others return `status: "dry_run"` with the read-before (Protect `before`, Mobility `device`, Carrier Fabric `subscriber`) and the preview under `response`. The connector relay returns the preview under `body` and the read-before under `readBefore`. This holds when the change is already applied too: under dry-run the no-op short-circuit never stands in for the preview, so the result always shows what would be sent. A multipart upload (`upload_protect_file`) previews its parts under `preview.multipart` (`field`, `filename`, `contentType`, `sizeBytes`), never the file content.

Preview credential masking is opt-in under `UNIFI_REDACT_SECRETS`. When enabled,
credential-named fields in its `body` and `params` (`password`, `passphrase`,
`x_passphrase`, `psk`, `x_psk`, `x_private_key`, `secret`, `token`, ... — the list in
[Credential redaction](#credential-redaction)) are shown as `***REDACTED***`.
With the default setting off, the preview contains the caller's values unchanged except
that configured server secrets are always replaced with `***`, including in the preview's
path, body, query parameters and multipart metadata.
(A bare `key` field is not masked: in Classic settings bodies it is the setting group's name.) The connector relay's dry-run result says
`status: "dry_run"`, never an HTTP status.

No dry-run result claims that a write happened. Delete tools return `{status: "dry_run",
deleted: false, message, response}` (never `deleted: true`), Protect writes and actions
return `status: "dry_run"` (never `created` / `triggered`), a multi-MAC `forget_device`
returns `{status: "dry_run", byMac, errors}` with each MAC's preview (no `forgotten`), and
the port-profile writes (`update_port_profile`, `allow_network_on_port_profile`,
`exclude_network_on_port_profile`) return the bare preview with none of their additive
keys and no follow-up read.

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
```yaml
    environment:
      UNIFI_WRITE_POLICY: "dry-run"   # preview every write, never execute them
```


### API-source selection

Tools classified as `unofficial` use console-internal paths that Ubiquiti can restrict without notice. `UNIFI_EXCLUDE=unofficial` alone excludes those tools but retains generic relays; use `UNIFI_EXCLUDE=unofficial,source:relay` for the official-only API profile.

The `source:<selector>` entries of `UNIFI_EXCLUDE` select tools by API source. Unset
enables every source; a blank `UNIFI_EXCLUDE` fails startup. Select an app (`network`), a source (`network/private.classic`,
`protect/private`), a private group (`network/private`), or an access level
(`network/private/write`, `protect/write`, `*/write`). `*/private` disables all private
surfaces; `*/generic` selects generic relays and `*/local` selects tools with no upstream
request. Selectors are case-sensitive. Unknown or repeated selectors fail at startup naming the
setting. `unofficial` excludes every tool whose primary API source is private; no
`source:` or `unofficial` entry removes a discovery meta-tool.

The `fabric_connector_*` tools are `relay/generic` and can reach any route, including
private APIs. `*/private` does not disable them. Use `source:relay` or `source:*/generic` to disable
those tools explicitly; `*/read` and `relay/read` also remove `fabric_connector_get` (class `relay/generic/read`, the only GET relay), and `*/write` keeps it. A write selector (`*/write`, `protect/write`) therefore leaves the Protect camera `enable-control` and `disable-control` GET routes reachable through `fabric_connector_get`; to block them, use `UNIFI_WRITE_POLICY=deny`, the `UNIFI_WRITE_EXCEPTIONS` entry `family:connector=deny` or `source:relay`. This selector does not filter the routes an enabled relay may
reach. `UNIFI_WRITE_POLICY` is an independent setting.

### Official-only catalog

For official per-site client data, use `list_all_clients`: it queries the official client route for every site and labels each record with `_hostId` and `_siteId`, so select the desired site from its results. `list_clients` is excluded by `unofficial` because its optional `include_*` arguments can use private v2 routes.

Under `unofficial` the 5 generic relays (`fabric_connector_*`) stay: their API status is `local` (source `relay/generic`), not `unofficial`, although they can reach private routes. Exclude them too with `UNIFI_EXCLUDE=unofficial,source:relay`.

To keep only the tools that call published Ubiquiti APIs, exclude both the unofficial tools
and the generic relays with `UNIFI_EXCLUDE=unofficial,source:relay`.

In full mode 194 tools remain and 604 are excluded, and 113 tools remain and 685 are excluded
under `UNIFI_WRITE_POLICY=deny`. Every tool left calls an official API source, except
`list_configured_api_keys` (source `server/local`) and the discovery meta-tools, which make
no upstream request and reach only the tools that remain.

Both entries are needed. `unofficial` removes every tool whose primary API source is private.
Under `unofficial` alone the 5 generic relays (`fabric_connector_*`) stay: their API status is
`local` (source `relay/generic`), not `unofficial`, but they relay any console route, private
APIs included. With `UNIFI_EXCLUDE=unofficial` alone, `fabric_connector_get` with path
`network/api/s/default/stat/sta` still returns the Classic private client list.
`source:relay` removes the relays.

The request header `X-UniFi-Exclude: unofficial,source:relay` applies the same exclusion to a single request, on top of whatever `UNIFI_EXCLUDE` already removes; any `source:` selector works in the header too. A request can add exclusions, never remove one (see [Request policy headers](#request-policy-headers)).


## Header key mode (`UNIFI_KEY_MODE`)

`UNIFI_KEY_MODE=environment` is the default: every call uses the keys in `UNIFI_API_KEY` or
`UNIFI_API_KEYS`. With `UNIFI_KEY_MODE=header` the server starts with no UniFi key and stores none:
each `tools/call` carries its keys in one `X-UniFi-Api-Key` request header whose value is a JSON
object of label to key, for example `X-UniFi-Api-Key: {"east":"<key-a>","west":"<key-b>"}`, and
the call uses those keys for its own duration only. A configured `UNIFI_API_KEY` or
`UNIFI_API_KEYS`, or a [key file or helper command](#key-files-and-helper-commands) setting, is
ignored, with a startup warning: no key file is read and no helper is run.

- **HTTP transports only.** stdio carries no request headers, so `UNIFI_KEY_MODE=header` with the
  stdio transport fails at startup with `startup:UNIFI_KEY_MODE`, as does a blank or unknown value.
- **The header.** Send it once; header names are case-insensitive, so two spellings are two
  copies. Every label must be unique and pass the same rule as a `key_label` argument (non-empty,
  no surrounding whitespace, no control character), and every key must be a non-empty ASCII string
  with no surrounding whitespace or control character. A header that is repeated, not valid JSON,
  not an object, empty, or has an invalid or repeated label or an invalid key is refused with
  `invalid_api_key_header`. A `tools/call` without the header is refused with
  `missing_api_key_header`. `initialize`, `ping` and `tools/list` do not read it. A refusal
  names at most the position of the bad member, never the header value or a key.
- **Which key a call uses.** The header's keys take the place of `UNIFI_API_KEYS` for that call, in
  header order: per-host operations use the key that owns the console, the multi-key tools listed
  under [Multi-key MSP setup](#multi-key-msp-setup) aggregate across all of them, and other calls
  without a `host` use the first. The `key_label` argument is refused with `key_label_not_allowed`;
  the header decides which keys a call may use.
- **Credential cache.** The server keeps one set of HTTP connections per key identity (the label
  and a SHA-256 digest of the key), and caches host, site and device lookups per identity, so two
  different keys never share an entry. It holds at most 256 key identities at once. At that bound
  the least recently used identity that is not serving a call is dropped and its connections are
  closed; when all 256 are serving calls, a call that brings a new key is refused with
  `credential_cache_saturated`. A key stays in process memory while its identity is held, and is
  discarded when the server stops; it is never written to disk.
- **Secrets.** Like a configured key, a header key is replaced by `***` in that call's responses,
  errors and logs, and never reaches the audit log. A write refused at the header check writes one
  `outcome=refused` audit record whose reason is the refusal code.
- **Default mode.** In `environment` mode a key is never taken from a request: a `tools/call` that
  sends `X-UniFi-Api-Key` is refused with `invalid_api_key_header`, and `tools/list` ignores it.
- **Deployment.** Header mode does not authenticate the caller: whoever the transport admits can
  send any key. Run it with `MCP_AUTH_MODE=bearer` or `oauth` and over TLS (`MCP_TLS_MODE=https`
  or a TLS-terminating proxy), because every request carries UniFi keys, and make sure a proxy in
  front of the server does not log request headers. See
  [SECURITY.md](../.github/SECURITY.md#header-key-mode).

## Request policy headers

In either key mode a request can tighten, never loosen, the operator's write and exposure settings
for itself with three request headers that take the same values as the settings:

| Header | Values | Combined with the setting |
|---|---|---|
| `X-UniFi-Write-Policy` | as `UNIFI_WRITE_POLICY`: `allow`, `dry-run` or `deny` | The stricter policy applies (`allow` < `dry-run` < `deny`) |
| `X-UniFi-Family-Allow` | as `UNIFI_FAMILY_ALLOW` | The two family sets intersect |
| `X-UniFi-Exclude` | as `UNIFI_EXCLUDE`, `source:` selectors and `unofficial` included | The two exclusion lists unite |

A request adds no write exception, and a valid value that would loosen the operator policy is
ignored. A blank, malformed or repeated policy header, or one the setting would refuse at startup
(for example `X-UniFi-Exclude: tool:search_tools`), is refused with `invalid_policy_header`. A call
to a tool the effective policy does not expose is refused with `tool_not_exposed`, and a write it
denies with `write_denied`, both before any console call. Under an effective `dry-run` a write
returns its dry-run preview and sends no change. `tools/list` and `search_tools` list only the
tools the request may call; a bad policy header on `tools/list` is a JSON-RPC error. `initialize`
and `ping` do not read these headers.

The client chooses these headers, so they are a safeguard a client applies to itself, not an
access control: a client that omits them gets the operator policy. To limit what a caller can do,
use the settings, `MCP_OAUTH_WRITE_SCOPE` or separate instances, or have a reverse proxy you
control set the headers on every request it forwards; a client copy the proxy leaves in place makes
the header repeated, and the call is refused.

## Tool catalog mode (UNIFI_TOOL_MODE)

`UNIFI_TOOL_MODE=discovery` is the default and, with read-only mode off, advertises five compact meta-tools: `search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, and `list_tool_families`. Use `search_tools` to find a domain tool, inspect its exact schema with `describe_tool`, then dispatch it with the read or write wrapper. Set `UNIFI_TOOL_MODE=full` for clients that require every domain tool directly in `tools/list`; with read-only mode off, full mode preserves the full catalog byte-for-byte. With `UNIFI_WRITE_POLICY=deny`, only the four read meta-tools are advertised (`call_write_tool` is hidden), and searches, descriptions and family counts include only annotated reads. Hidden write calls still receive the audited read-only refusal. For a complete inventory in discovery mode call `search_tools` with `{"query":"","limit":null}`; an omitted limit returns ten results. Each search result reports `more_available` and `total_matched` beside the list, so a client can tell when the limit cut it.

Claude Code and Codex already defer tool loading, so some users prefer `full` with their native discovery.
Behind an MCP gateway (a shared or hosted endpoint that registers this server's tools for several clients), pin `UNIFI_TOOL_MODE=full` when the gateway must list every
domain tool individually, for example for per-tool allow-lists ([migration notes](MIGRATING-0.7.md)). With discovery left on, the gateway registers the five meta-tools
(four with `UNIFI_WRITE_POLICY=deny`) under its own prefix, for example `<prefix>-search-tools`, and the `name` argument inside each wrapper stays the raw tool name, such as `list_hosts`.
The discovery route through a gateway is: `list_tool_families`, then `search_tools` with a plain-language query, then `describe_tool` for the chosen tool's input schema, then
`call_read_tool` (or `call_write_tool`) with that `name` and its `arguments`.

### Code Mode (experimental)

Code Mode is an opt-in, read-only experimental feature. It may change without a deprecation cycle. There is no compatibility promise for execute()'s schema or output shape until graduation.

`UNIFI_TOOL_MODE=codemode` advertises three tools: `search_tools` and `describe_tool` over the enabled read tools, and `execute(code)`. It also requires `UNIFI_AUDIT_HMAC_KEY`, an operator-provisioned, per-installation 32-byte key encoded as canonical unpadded base64url. Give every replica in one installation the same secret-store value; a different installation needs a different key, and rotation intentionally ends correlation across the rotation. The server does not generate or persist the key, and it fails startup naming only the setting when the value is missing or malformed.

`execute` runs a Python script in a pydantic-monty sandbox worker; inside it, `await call_tool(name, arguments)` calls one read tool through the same exposure, read-only, per-area opt-out and write-route checks as `call_read_tool`, and returns `{"ok": true, "result": ...}` or `{"ok": false, "error": {"code", "message"}}`. A write is always refused, whatever the write switches or dry-run say; any other tool called directly is refused with `tool_not_exposed`. The sandbox has no credentials, environment, network, filesystem or process access. The server logs the experimental notice at startup in this mode.

Limits, all byte limits in UTF-8 bytes: script source 32,768 bytes (`code_mode_invalid_source`); 32 attempted tool calls per script, refusals included (the 33rd ends the script with `code_mode_limit_exceeded`); each tool response 262,144 bytes and all responses together 2,097,152 bytes (`code_mode_limit_exceeded` naming the call, no partial answer; use a tool's continuation for large pages); interpreter memory 64 MiB, recursion depth 64 and 30 seconds of interpreter execution time (waits on the console are not counted and never capped); output 65,536 bytes, where longer output is cut on a character boundary and ends with `...[truncated]`; one script at a time per server process (`code_mode_busy`). Response limits count the tool's own response (its result, or its error object) serialized as compact UTF-8 JSON; the `{"ok": ...}` envelope is not counted. Text that is not valid UTF-8 (an unpaired surrogate) in a tool response is refused with `code_mode_invalid_text` naming the call; inside the sandbox the interpreter itself turns an unpaired surrogate into U+FFFD, so script output is always valid UTF-8 (the host check on the output stays as a backstop). A `fabric_connector_get` route is refused only when it is a known state-changing route, the same rule `call_read_tool` applies. Each run writes one log record with the script's SHA-256 digest, the tools it called, one installation-key HMAC per attempted argument object and its outcome. Raw arguments, the script text, results and HMAC key are never recorded; invalid or over-budget arguments use a fixed `invalid` marker.

## Audit log

Audit logging is best-effort and fails open: when the audit sink cannot be written (a full disk, a permission or read-only error, a missing directory) the call continues, and every tool response carries the `audit_unavailable` notice in its `_meta` until the sink recovers; the first record after recovery is an `audit.recovered` record counting the records lost. Point `UNIFI_AUDIT_LOG` at a file path to append a structured record for **every write attempt** (all tools, via the same shared chokepoint): timestamp (UTC), HTTP method, resolved path, outcome and upstream status, plus `tool`, `resolvedHost`, `resolvedSite` and `duration_ms` when known. A write refused before it is sent is recorded as `outcome=refused`. Its `reason` names the gate (`UNIFI_WRITE_POLICY`, the denying `UNIFI_WRITE_EXCEPTIONS` entry such as `family:connector=deny`, `empty_update` / `required_body_fields`), or for any other refusal (an argument check, an unknown id, relay validation) it is the refusal message. A refusal made before the request is resolved has no method or path (`-` in text, `null` in JSON). Other outcomes include `dry_run`, `error` and `rate_limited`. `UNIFI_AUDIT_LOG_FORMAT` selects `json` (default: one canonical JSON object per line carrying `schema_version`, `event` and `timestamp_utc`) or `text` (the 0.7.2 key=value line); any other value fails startup listing the two. **Unset (the default) writes no audit file.** A new audit file is created with mode `0600` (`UNIFI_AUDIT_LOG_MODE=0640` adds group read); an existing file keeps its mode. `UNIFI_AUDIT_SINK=stderr` writes the same records to standard error instead of a file, `UNIFI_AUDIT_CALLS=true` adds one `call` or `error` record per tool call, and `UNIFI_AUDIT_LEVEL` is `normal` (default, metadata only), `off`, or `debug`, which adds the request body of a write and the arguments of a call record with every credential field masked and every configured secret scrubbed. The API key value is never recorded. Every audit setting is in the [settings table](#unifi-api-settings). Container deployments may use `UNIFI_AUDIT_LOG=/dev/stderr`; use a persistent writable directory when audit history must survive container replacement. `UNIFI_AUDIT_CHAIN=true` adds an opt-in, tamper-evident (not tamper-proof) hash chain to the JSON file: see [Tamper evidence](#tamper-evidence-unifi_audit_chain).

<!-- BEGIN GENERATED: audit-schema -->
Every record carries `schema_version` `1`; the fields of each event (rendered from `src/unifi_fabric/audit.py`):

| Event | Required fields | Optional fields |
|---|---|---|
| `startup` | `schema_version`, `event`, `timestamp_utc`, `version`, `sink`, `level`, `format`, `calls` | `file_mode`, `remote_endpoint`, `identifiers` |
| `audit` | `schema_version`, `event`, `timestamp_utc`, `method`, `path`, `outcome`, `status` | `tool`, `reason`, `resolvedHost`, `resolvedSite`, `duration_ms`, `body`, `via` |
| `call` | `schema_version`, `event`, `timestamp_utc`, `tool`, `outcome`, `duration_ms` | `arguments` |
| `error` | `schema_version`, `event`, `timestamp_utc`, `tool`, `error_type`, `duration_ms` | `message` |
| `audit.recovered` | `schema_version`, `event`, `timestamp_utc`, `lost_records`, `fault` | none |
| `audit.chain_start` | `schema_version`, `event`, `timestamp_utc`, `kid`, `prev_chain`, `prev_seq`, `prev_mac`, `chain`, `seq`, `prev`, `mac` | none |
| `audit.seal` | `schema_version`, `event`, `timestamp_utc`, `sealed_sha256`, `chain`, `seq`, `prev`, `mac` | none |

The policy records `policy.startup`, `policy.refusal` share the stream. An `audit` record's `outcome` is one of `success`, `no_response`, `rate_limited`, `classic_rc_error`, `upstream_error_body`, `error`, `dry_run`, `refused`, or `http_<status>` for a non-2xx upstream status; a `call` record's is `ok`, `error`. `UNIFI_AUDIT_LOG_FORMAT`: `text`, `json`; `UNIFI_AUDIT_SINK`: `none`, `stderr`, `file`, `remote`; `UNIFI_AUDIT_LEVEL`: `off`, `normal`, `debug`; `UNIFI_AUDIT_LOG_MODE`: `0600`, `0640`.
<!-- END GENERATED -->

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
```yaml
    environment:
      UNIFI_AUDIT_LOG: "/var/log/unifi-fabric/audit.log"
      UNIFI_AUDIT_LOG_FORMAT: "json"
```

## Trace export (OTLP)

Optional, off by default. FastMCP opens an OpenTelemetry span for every MCP request (`initialize`, `tools/list`, `tools/call <tool>`, ...). With an OTLP endpoint configured, the server exports those spans to an OpenTelemetry collector you run; audit logging is unchanged and still the record of writes. Install the optional packages first: `pip install "unifi-fabric-mcp-server[otel]"` for OTLP/HTTP (protobuf), or `[otel-grpc]` for OTLP/gRPC. The container image and the default install do not include them.

| Variable | Meaning |
|---|---|
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | The traces endpoint, used exactly as given (for HTTP, include the path, for example `http://collector:4318/v1/traces`). Wins over `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | The collector's base URL; for HTTP the server appends `v1/traces` (`http://collector:4318` sends to `http://collector:4318/v1/traces`). |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | `http/protobuf` (the default) or `grpc`. Wins over `OTEL_EXPORTER_OTLP_PROTOCOL`. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | The same choice for every signal. |
| `OTEL_SDK_DISABLED` | `true` turns trace export off. |
| `OTEL_TRACES_EXPORTER` | `none` turns trace export off; a list without `otlp` (for example `console`) is not supported and leaves export off. |
| `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | Resource attributes; the defaults are `service.name=unifi-fabric-mcp-server` and the package version. |

An empty value counts as unset. The OpenTelemetry SDK reads the other standard `OTEL_*` variables itself: `OTEL_EXPORTER_OTLP_HEADERS` (collector authentication), timeouts, compression, certificates and the sampler. Endpoints must be `http://` or `https://` URLs with a host, and must not contain user information, a query string or a fragment (the OpenTelemetry SDK logs the endpoint when an export fails, so put collector credentials in `OTEL_EXPORTER_OTLP_HEADERS` instead). An `http://` endpoint is plaintext for **both** protocols (OTLP/HTTP and gRPC): spans and the collector authentication headers travel unencrypted, so use `https://` unless the collector is on a trusted local network.

**Behavior.**

- **No endpoint, or export turned off:** nothing is loaded or created: no SDK, no exporter, no tracer provider and no connection to any collector, whether or not the optional packages are installed. The server prints nothing about tracing.
- **Exporting:** one stderr line at startup, `unifi-fabric-mcp: trace export: OTLP <protocol> to <scheme>://<host>:<port> (from <variable>)`. The endpoint's path, query and user information and the headers are never printed.
- **Configured but unusable:** an unsupported protocol or exporter selection, an endpoint that is not an `http://` or `https://` URL with a host or that carries user information, a query or a fragment, the packages not installed, or an exporter that fails to start prints one stderr line beginning `unifi-fabric-mcp: trace export is off:` that names the variable or the extra to install (never a value), and the server starts and serves normally without trace export.
- **Collector failures** (unreachable, refusing, slow) are handled by the SDK's background exporter: spans may be dropped, and tool calls and their results are not affected.
- **Once per process.** The pipeline is installed once at startup and shut down when the server exits, which first flushes spans still waiting to be sent.
- **Existing provider.** If another tracer provider is already installed in the process (for example by `opentelemetry-instrument`), the server leaves it in place, adds no exporter of its own and prints `trace export: a tracer provider is already installed`. That pipeline, and what it exports, is then yours to configure: **the allowlist below does not apply** to it, so FastMCP's raw span attributes (caller identity, MCP session id, resource URIs, tool names and error text) and any spans from auto-instrumentation (including the server's UniFi HTTP requests with their full URLs) reach whatever that pipeline exports.

**What is exported.** Only these span attributes leave the process: `mcp.method.name`, `mcp.protocol.version`, `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.prompt.name`, `jsonrpc.request.id`, `error.type`, `rpc.response.status_code`, `fastmcp.server.name`, `fastmcp.component.type`, `fastmcp.provider.type` and `fastmcp.span.seam`; exception events keep only `exception.type`. Everything else is dropped before export, including the caller identity (`enduser.id`, `enduser.scope`), the MCP session id, resource URIs (`mcp.resource.uri` and `fastmcp.component.key`), URLs and headers. Text a caller chooses is exported only from a closed set: `mcp.method.name` only for a method defined by the MCP specification (otherwise `unknown`), `gen_ai.tool.name` and `gen_ai.prompt.name` only for a tool or prompt this server has registered (otherwise omitted), `mcp.protocol.version` only as a date (otherwise `unknown`), and `jsonrpc.request.id` only when it is an integer. A caller's W3C `tracestate` is not exported (the trace and span ids and the `traceparent` flags are). Status descriptions, exception messages and stack traces are never exported, so neither API keys, authorization headers, request headers nor response bodies reach the collector. Spans name the MCP method and a registered tool (`tools/call list_hosts`), never a resource URI or an unrecognized name; spans from other instrumentation keep their names with configured secrets masked. Tool arguments and results are never recorded in spans. Span and trace ids, timing, kind and status codes are exported unchanged, and an incoming W3C trace context in a request's `_meta` continues the caller's trace. The resource attributes sent with every batch are `service.name`, `service.version`, `service.instance.id` (a random id for the process) and `telemetry.sdk.*`, plus anything you set in `OTEL_RESOURCE_ATTRIBUTES`.

**Trust boundary.** Trace export is configured only by the server's own environment at startup. No tool argument, request `_meta` field or request header can select a collector or change the export settings, and trace export changes no tool list, annotation, authorization or write policy.

Design reference credit: the OpenTelemetry project and the sirkirby/unifi-mcp maintainers and contributors, including Alexander Zimmermann's optional MCP span export integration.

### Tamper evidence (`UNIFI_AUDIT_CHAIN`)

The audit file is **tamper-evident, not tamper-proof**. With `UNIFI_AUDIT_CHAIN=true`, someone who holds the key can detect a change to the file afterwards; nothing stops the change being made. The chain is off by default, and off, nothing in this section applies: the audit stream is byte-identical to earlier releases. `schema_version` stays `1`; a consumer that allow-lists audit events must add `audit.chain_start` and `audit.seal`.

**What is written.** Every JSON record carries four more fields: `chain` (random per server start), `seq` (0, 1, 2 and so on within the chain), `prev` (the `mac` of the record before it) and `mac`, an HMAC-SHA256 over the exact bytes of the line as written (the `mac` member left out), under a key derived from `UNIFI_AUDIT_CHAIN_KEY`. Each server start begins a new chain with an `audit.chain_start` record. It carries `kid`, a short fingerprint that names the key without revealing it, and a link to the last chained record already in the file (`prev_chain`, `prev_seq`, `prev_mac`). The link is null when there is no such record, or when the audit path is not a regular file owned by the server's user (a FIFO, a device or `/dev/stderr` is never read). Policy records keep their exact bytes, so each one is followed by an `audit.seal` record holding its SHA-256 (`sealed_sha256`), at every `UNIFI_AUDIT_LEVEL`, `off` included. `schema_version` stays `1`; a consumer that allow-lists events must add `audit.chain_start` and `audit.seal`.

**Requirements.** The chain needs `UNIFI_AUDIT_LOG_FORMAT=json`, the file sink (`UNIFI_AUDIT_LOG`) and `UNIFI_AUDIT_CHAIN_KEY`, a key different from `UNIFI_AUDIT_HMAC_KEY`. Startup fails naming the setting when one is missing. Every replica writing one file needs the same key. Provide the key from your secret store as an environment variable, like `UNIFI_AUDIT_HMAC_KEY`: the server never generates, stores or logs it, and scrubs it from every record and log line. Rotating the key starts a new chain at the next restart; keep the old keys for the verifier.

**Verifying.** `unifi-fabric-audit-verify FILE...` (or `python -m unifi_fabric.audit_verify`) checks the files offline, oldest first, using the Python standard library only. The key comes from `UNIFI_AUDIT_CHAIN_KEY` or from `--key-file PATH`, a file with one key per line that must be a regular file you own, not a symlink, with no group or other permission bits (`0600` or `0400`). No option takes a key. The command exits 0 when it finds no tamper evidence, 1 when it finds some, and 2 on a usage or key error. Its findings are `BAD_MAC`, `SEQ_GAP`, `PREV_MISMATCH`, `DUP_SEQ`, `UNCHAINED_LINE`, `MISSING_SEAL`, `ORPHAN_SEAL`, `MALFORMED_LINE`, `UNKNOWN_KID`, `CHAIN_PREFIX_MISSING`, `ANCHOR_MISSING` and `ANCHOR_MISMATCH`. Lines before the first chained record are counted as unverified legacy lines. A record cut short by a write fault, or a policy line whose seal the fault lost, is accepted only when an `audit.recovered` record follows it, and only as many such lines as that record's `lost_records` count; any further unsealed or malformed line before it is a finding. A chain whose start is not in the files given (an earlier rotated file left out, or a deleted prefix) is `CHAIN_PREFIX_MISSING`; `--allow-rotated-prefix` reports it as a warning instead and still prints the count. The verifier is a separate command: it is not an MCP tool, and the server never runs it.

**Anchors.** The server logs the chain head (`CHAIN:SEQ:MAC`, not secret) at INFO when a chain starts, every 100 records and at clean shutdown. If `UNIFI_LOG_LEVEL` is above INFO, startup warns that these lines are not logged. Collect the server log separately from the audit file, or run `unifi-fabric-audit-verify --print-head` on a schedule and keep its output where the server host cannot rewrite it (another host, a write-once bucket). `--expect-head CHAIN:SEQ:MAC` then reports `ANCHOR_MISSING` or `ANCHOR_MISMATCH` if that record is gone or changed. Heads are not published anywhere automatically. With `UNIFI_AUDIT_LOG=/dev/stderr` the head lines and the records share one stream, so the head lines are not an independent anchor.

**What it does not detect.**

1. A cut tail. Deleting the last records leaves a shorter chain that still verifies; only an anchor taken after the cut shows it.
2. The whole file replaced by an older valid copy, or deleted. Again, only an anchor shows it.
3. Forgery by anyone who holds the key. The MAC is symmetric (HMAC-SHA256): whoever can read the key (the server's user, root, the secret store, the process environment) can write a valid chain. The verifier therefore gives no non-repudiation, and nobody can run it without the key. Keep anchors where a key holder on the server host cannot rewrite them.
4. Records that were never written: `UNIFI_AUDIT_LEVEL=off`, per-call records left off (`UNIFI_AUDIT_CALLS`), and records lost to a write fault (the chained `audit.recovered` record counts those).
5. Whether a record is true, and who may read it. The chain covers neither.
6. Lines written before the chain was turned on. They are reported as unverified legacy lines and not checked.

**Rotation.** Use `create`-style rotation (logrotate `create`): the server opens the file for every record, so the chain continues into the new file, and the verifier checks the files together, oldest first. `copytruncate` can lose lines written between the copy and the truncate; the loss shows up as `SEQ_GAP`. The file sink assumes single-host `O_APPEND` writes, so NFS and other shared volumes are outside this feature.

### Remote audit sink (`UNIFI_AUDIT_SINK=remote`)

`UNIFI_AUDIT_SINK=remote` sends every audit record (the same JSON records, policy records included) to a log collector. With `UNIFI_AUDIT_LOG` also set (recommended), the local file is written first, synchronously, with the file sink's usual fail-open behaviour, and the same line is then handed to the collector queue: a collector outage, stall or drop never loses a local record. Without `UNIFI_AUDIT_LOG`, the collector copy is the only one. It needs `UNIFI_AUDIT_LOG_FORMAT=json` and `UNIFI_AUDIT_REMOTE_URL`. The server POSTs batches of up to 100 records as NDJSON (`Content-Type: application/x-ndjson`, one canonical JSON record per line, each ending in a newline) with these headers: `X-Audit-Schema-Version` (`1`), `X-Audit-Stream-Id` (random per server start), `X-Audit-Batch-Id` (random per batch, unchanged on a retry), `X-Audit-First-Seq` and `X-Audit-Record-Count`. A `2xx` response acknowledges the whole batch. Redirects are not followed.

**TLS by default, and it fails closed.** The connection offers TLS 1.3 only (a collector that cannot negotiate it is unreachable and the batch is dropped after its attempts) and always verifies the collector certificate chain and host name. To trust a private CA, set `UNIFI_AUDIT_REMOTE_CA_FILE`; that bundle then replaces the platform trust store. For mutual TLS, set `UNIFI_AUDIT_REMOTE_CERT_FILE` and `UNIFI_AUDIT_REMOTE_KEY_FILE`. A handshake or verification failure fails that attempt: the batch is retried and then dropped. It is never sent unverified or over plain HTTP. `HTTPS_PROXY` and the other proxy variables are not honoured: the server connects to the collector directly. Keep the client key file readable by the server user only (mode `0400` or `0600`); an encrypted key is a failed attempt, never a password prompt. A plain `http://` collector needs `UNIFI_AUDIT_REMOTE_PLAINTEXT=true`. That choice is the operator's: records then travel unencrypted and unauthenticated, and no warning is printed.

**Delivery.** Transport and TLS errors, `408`, `429` and `5xx` are retried up to `UNIFI_AUDIT_REMOTE_MAX_ATTEMPTS` times with a doubling wait (1, 2, 4 and 8 seconds by default; `Retry-After` is ignored). Any other status drops the batch. Delivery is at-least-once: a collector should deduplicate on stream id plus batch id. One batch is in flight at a time, in order. A collector that never answers, or stalls the TLS handshake, holds up delivery. The server sets no timer on it: it counts instead, and once a full batch of records (`UNIFI_AUDIT_REMOTE_BATCH_MAX_RECORDS`) is waiting behind the batch in flight, the sink counts as failing and the notice below appears, long before the buffer fills.

**Bounded memory, fail open.** Records wait in memory up to `UNIFI_AUDIT_REMOTE_BUFFER_MAX_RECORDS` records or `UNIFI_AUDIT_REMOTE_BUFFER_MAX_BYTES` bytes. When the buffer is full, the arriving record is dropped (drop-newest). A tool call never waits for the collector. Every drop is counted in an `audit_remote_dropped` record (`reason`: `buffer_full`, `record_too_large`, `unserializable`, `attempts_exhausted` or `rejected`, plus `dropped_count`). From the first failed attempt or drop until the next acknowledgment, every tool response carries the `audit_unavailable` notice; the first acknowledgment afterwards writes an `audit_remote_recovered` record. Records still buffered when the server stops are lost from the collector copy (the count is logged at shutdown): there is no disk spool. With `UNIFI_AUDIT_LOG` set they are already in the local file; without it, add a file or a log shipper when every record must survive a restart. A record that cannot be serialized as strict UTF-8 JSON (for example a lone surrogate in a caller-supplied field) is not shipped: only an `audit_remote_dropped` count with reason `unserializable` reaches the collector, and the local file keeps the record.

**What never leaves.** Errors, log lines and records name the collector only as `scheme://host:port` (the startup record's `remote_endpoint`). They never include the URL path, the TLS file paths or contents, request bodies or collector responses. A configuration error names the setting, never its value.

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
```yaml
    environment:
      UNIFI_AUDIT_SINK: "remote"
      UNIFI_AUDIT_REMOTE_URL: "https://collector.example.com:8443/audit"
      UNIFI_AUDIT_REMOTE_CA_FILE: "/run/secrets/audit-ca.pem"
      UNIFI_AUDIT_REMOTE_CERT_FILE: "/run/secrets/audit-client.pem"
      UNIFI_AUDIT_REMOTE_KEY_FILE: "/run/secrets/audit-client.key"
```

### Pseudonymised identifiers (`UNIFI_AUDIT_HMAC_IDENTIFIERS`)

`UNIFI_AUDIT_HMAC_IDENTIFIERS=true` (off by default) replaces client MAC addresses and user identifiers in audit records with `hmac:<32 hex>`: the first 128 bits of HMAC-SHA256 under the per-installation `UNIFI_AUDIT_HMAC_KEY`. The flag requires that key and fails startup naming the setting when it is missing. One identifier always gives the same token within an installation, so records still correlate. A different key (another installation, or a rotation) gives different tokens. The startup record carries `identifiers: "hmac"` while the flag is on. The flag applies to both formats and every sink.

- **MAC addresses** are replaced in every field, in the `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` and URL-encoded `aa%3Abb%3A...` forms, in any letter case. A bare `aabbccddeeff` is replaced when it is a whole path segment or the value of a MAC-named field (`mac`, `clientMac`, `sta_mac` and similar). Every form of one address gives the same token.
- **User identifiers** are replaced as the value of a user-named field (`user`, `user_id`, `username`, `admin_id`, `email` and similar) and as the path segment after `user`, `users`, `admin` or `admins` when it contains a digit or `@`.
- Free-text fields (`reason`, `message`) are covered for MAC shapes only. A user identifier in prose has no reliable shape.

The key is operator-provisioned, like Code Mode's: the server never generates, stores or logs it, and the token construction is domain-separated, so a token never equals a Code Mode argument HMAC.
