# MSP workflows

UniFi Fabric MCP can work across multiple client accounts from one MCP server. Configure
a key for each account, ask for a fleet-wide view, and use a separate read-only server
for staff who should investigate without making changes.

## Connect client accounts

Set `UNIFI_API_KEYS` to a JSON array. Each label is unique and identifies a key in
tool results; `is_org_key` identifies an organization key when applicable.

<!-- doc-provenance: source=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db support=0.7.2 citation=file:src/unifi_fabric/config.py@sha256:caa830b748df7d33902ce9aeedbedbcc81066ba0b9f5e6908764426b497cb5db -->
```json
[
  {"key": "YOUR_EAST_KEY", "label": "east", "is_org_key": true},
  {"key": "YOUR_WEST_KEY", "label": "west", "is_org_key": true}
]
```

Supply the JSON as the `UNIFI_API_KEYS` environment variable in your MCP client or
server deployment. Store actual keys in your secret manager and grant each only the
access it needs. `UNIFI_API_KEY` is the single-key shorthand. The server aggregates
supported fleet tools across keys and routes per-host operations to the key that owns
the console. Results identify their key with `_keyLabel`; a failed key is reported
alongside successful results. See [multi-key configuration](CONFIGURATION.md#multi-key-msp-setup)
for details and limitations.

To keep customer keys off the server, run an HTTP transport with `UNIFI_KEY_MODE=header`: the
server stores no key, and each client sends the keys it may use in the `X-UniFi-Api-Key` request
header, a JSON object of label to key, so one server can serve technicians who hold different
customers' keys. Run it behind MCP authentication and over TLS. See
[Header key mode](CONFIGURATION.md#header-key-mode-unifi_key_mode).

## Write controls for staff

Writes are enabled by default. Use `UNIFI_WRITE_POLICY=dry-run` to preview writes and
review the network assignment, security configuration and site before applying a change.
Dry-run applies to the whole server process; applying a change requires a separate session
with dry-run disabled. A client of a write-enabled server can request its own preview with
`X-UniFi-Write-Policy: dry-run`.

Read-only mode is a server-wide control, not a per-user role. Give staff who should not
write a separately configured server and protect access to any write-enabled server. A
client can request `X-UniFi-Write-Policy: deny`, but because the client chooses that
header it is a safeguard, not an access control. See
[request policy headers](CONFIGURATION.md#request-policy-headers).

## Audit and operating controls

Set `UNIFI_AUDIT_LOG` to a writable file path, or `/dev/stderr` for a container,
and optionally set `UNIFI_AUDIT_LOG_FORMAT=json`. The server records write attempts
and refusals without request bodies or keys. Logging is best effort: a log write
failure produces a warning and does not stop the call. Restrict access to logs and
arrange collection and retention in your deployment. See
[configuration](CONFIGURATION.md) for read-only mode, dry-run, audit fields and
additional write controls.
