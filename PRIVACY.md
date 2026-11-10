# Privacy Policy

This policy covers the UniFi Fabric MCP Server (the `unifi-fabric-mcp-server` package), its container image, and the Claude Code, Claude Desktop, Codex, Antigravity and Gemini CLI integrations, published by SWK Studios as open-source software under the MIT license.

## Summary

The server runs on infrastructure you control: your own computer (stdio, including the Claude Code, Claude Desktop, Codex, Antigravity and Gemini CLI integrations) or your own container host. SWK Studios does not operate a hosted service for it and receives no data from it. There is no telemetry, analytics, crash reporting, or update check. Optional trace export sends request spans only to an OpenTelemetry collector you configure, and is off unless you set an endpoint.

## What the server sends, and where

- **Ubiquiti's UniFi cloud API (`api.ui.com`).** Every UniFi request goes over HTTPS to `https://api.ui.com`, authenticated with the UniFi API key you provide. Requests for your consoles (Network, Protect, InnerSpace, and the generic connector tools) are relayed by Ubiquiti's cloud connector under `https://api.ui.com/v1/connector/consoles/...`. Ubiquiti's own privacy policy applies to that traffic.
- **An address you configure.** If you set `UNIFI_API_BASE_URL`, requests go there instead of `api.ui.com`. If you run the HTTP transport with OAuth (`MCP_AUTH_MODE=oauth`), the server fetches signing keys from the JWKS address you configure (`MCP_OAUTH_JWKS_URI`).
- **A trace collector you run.** Only if you set `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and install the `otel` extra: request spans (MCP method, the name of a tool or prompt this server registers, timing and status codes; never API keys, headers, arguments, results, error text, resource URIs or names a caller invents) go to that collector. `http://` endpoints are unencrypted for both OTLP protocols, and if another tracer provider is already installed in the process (for example by `opentelemetry-instrument`) the server adds no exporter and this restriction does not apply to what that provider exports. See [trace export](docs/CONFIGURATION.md#trace-export-otlp).
- **Nothing else.** Some responses contain URLs (for example Ubiquiti product images on `static.ui.com` or console asset links). The server returns them as text and does not fetch them.

## What the server stores

- **Your API key** is read from the environment when the server starts and kept in memory only. With the Claude Code plugin, Claude Code keeps the key in its secure credential storage (the macOS Keychain, or a credentials file in your Claude Code configuration folder where no supported keychain exists), not in a settings file. The key is never logged or written to the audit log.
- **Keys sent per request.** If you run the HTTP transport with `UNIFI_KEY_MODE=header`, the server starts with no key: each tool call sends its keys in the `X-UniFi-Api-Key` request header. The server keeps them in memory only, inside the connections it opens for them, for at most 256 label and key pairs at once (the least recently used idle pair is dropped first), and discards them when it stops. They are never logged or written to disk or the audit log. A reverse proxy in front of the server may log request headers; configure it not to.
- **Short-lived in-memory caches** of host lists, per-console site lists, Site Manager site lists and device MAC-to-id lookups (`UNIFI_CACHE_TTL_SECONDS`), discarded when the server stops. HTTP access records include client, method, target and status; query values are masked. See [HTTP access records](docs/AUTH-TLS.md#http-request-bounds-and-access-records).
- **An optional audit log** on your own disk, only if you set `UNIFI_AUDIT_LOG`. It records one entry per write attempt (time, method, path, outcome, status), never the API key, and the request body only when you set `UNIFI_AUDIT_LEVEL=debug` (credential fields masked, configured secrets scrubbed). It is off by default. Audit logging is best-effort: an I/O failure produces a warning on stderr and the tool call continues; create a writable parent directory before enabling it, and for Docker mount a writable persistent directory if logs must survive container replacement.

- **The diagnostic bundle** (`get_server_diagnostic_bundle`) is returned in the tool response only. The server does not save it or send it anywhere; you decide whether to share it. By default it makes no UniFi request; see [the diagnostic bundle](docs/TOOL-USAGE.md#get_server_diagnostic_bundle).

Nothing is stored by SWK Studios.

## What your AI client sees

Tool results are returned to the MCP client that called the tool (for example Claude Code) and become part of that conversation, under your agreement with that client's provider. By default the server passes UniFi's responses through unchanged, including any credential fields (Wi-Fi passphrases, RADIUS secrets, VPN keys), client names, IP and MAC addresses, GPS coordinates, and Protect recognition data. The one exception is the server's own configuration: if a response echoes one of its configured secrets (your API key, `MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`), that value is always replaced by `***`. Set `UNIFI_REDACT_SECRETS=1` to mask a documented list of credential fields in every response. Writes are enabled by default; set `UNIFI_WRITE_POLICY=deny` (or the plugin's Read-only mode option) to refuse every write and action.

## Retention and deletion

The server keeps no data after it stops, apart from the optional audit log, which you control and can delete at any time. To stop all access, remove the plugin or server and revoke the API key in UniFi Site Manager.

## Contact

Questions: open an issue at https://github.com/swkstudios/unifi-fabric-mcp-server/issues. Security problems: follow [SECURITY.md](.github/SECURITY.md) and report privately.

## Changes

Changes to this policy are made in this file and recorded in the repository history.
