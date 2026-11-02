# Docker deployment

The server ships as a Docker image. When pinning deployments for production use,
reference the image by digest rather than a mutable tag to ensure reproducibility
and guard against tag mutation:

<!-- install-case: readme-docker-01 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.0 case=readme-docker-01 -->
```bash
# Pull by digest instead of :latest or a version tag
docker pull ghcr.io/swkstudios/unifi-fabric-mcp-server@sha256:<digest>
```

You can find the digest for a given release on the package page or via (the image must be present locally; run `docker pull` first):

<!-- install-case: readme-docker-02 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.0 case=readme-docker-02 -->
```bash
docker pull ghcr.io/swkstudios/unifi-fabric-mcp-server:latest
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/swkstudios/unifi-fabric-mcp-server:latest
```

### Stateless Design (No Persistent Volumes)

**By design, this container is stateless and does not require persistent volumes.** These statements describe the default deployment; an enabled audit log (`UNIFI_AUDIT_LOG`) needs writable storage (see below). The MCP server:

- Makes API calls to the UniFi Fabric API in Ubiquiti's cloud (`api.ui.com`)
- Does not maintain local state between requests
- Does not store credentials, configurations, or cached data on disk
- Uses in-memory caching only: the host/site registry and the device MAC -> id lookups (`UNIFI_CACHE_TTL_SECONDS`, default 900 seconds; `0` disables both)
- Has no dependencies on local storage, databases, or filesystem persistence

**Why stateless?** With the image default, MCP requests do not depend on server-side MCP session state. UniFi data is reached through the UniFi Fabric API in Ubiquiti's cloud. Configure storage for any files you choose to keep, such as optional audit logs.

**Audit log.** Audit logging is best-effort: an I/O failure produces a warning on stderr and the tool call continues. Create a writable parent directory before enabling it. For Docker, mount a persistent directory writable by uid 10001 (the image's `mcp` user); otherwise every record is lost with only a stderr warning.

**Implications:**
- Cache is reset on container restart (this is safe and expected)
- Multiple server instances can run in parallel without coordination (streamable-http is stateless in the image; `sse` and `FASTMCP_STATELESS_HTTP=false` keep per-client sessions, so a load balancer needs sticky sessions)
- No data loss risk from container updates or replacements
- Scaling is stateless and simple


### Track B: Docker (HTTP)

Run the server as a container. The MCP client connects over HTTP to the `/mcp` endpoint and sends a bearer token, so only clients that hold the token can use your UniFi key.

<!-- install-case: readme-install-24 mode=docker -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.0 case=readme-install-24 -->
```bash
# Generate a random token once and keep it: the server checks it and your MCP client sends it.
export MCP_BEARER_TOKEN="$(openssl rand -hex 32)"
docker run -e UNIFI_API_KEY="your-api-key-here" -e MCP_AUTH_MODE=bearer -e MCP_BEARER_TOKEN \
  -p 127.0.0.1:3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0
```

`-e MCP_BEARER_TOKEN` with no `=value` passes the variable from your shell, so the token is not written into the command. `-p 127.0.0.1:3000:3000` publishes the port on this machine only; use `-p 3000:3000` to serve other machines, and add TLS for anything beyond a trusted LAN ([AUTH-TLS.md](AUTH-TLS.md)).

> **Tip:** The explicit image tag above pins this release. `:latest` and the short form `:X.Y` move **only** when a clean release tag (`vX.Y.Z`, no pre-release suffix) is published; a pre-release tag never moves them. For production deployments, pin by digest instead; see [Docker Deployment](../README.md#docker-deployment).

For Claude Code, put this in `.mcp.json` at your project root (Claude Code asks you to approve it on first use, and expands `${MCP_BEARER_TOKEN}` from the environment it starts in). For all projects, use the user-scoped configuration supported by your client, keeping the token in the environment rather than passing its value as a command argument. Supported locations are documented by [Claude Code](https://code.claude.com/docs/en/mcp). Other clients take the same `Authorization` header in their HTTP server entry.

<!-- install-case: readme-install-25 mode=docker -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.0 case=readme-install-25 -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "http://localhost:3000/mcp",
      "headers": { "Authorization": "Bearer ${MCP_BEARER_TOKEN}" }
    }
  }
}
```

**Verify it works:**

<!-- install-case: readme-install-26 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.0 case=readme-install-26 -->
```bash
curl -s -w "\nHTTP:%{http_code}\n" \
  -X POST -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H @<(printf "%s\n" "Authorization: Bearer $MCP_BEARER_TOKEN") \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}' \
  http://localhost:3000/mcp
```

`HTTP:200` on the last line confirms the server is up and accepted the token; `HTTP:401` means the token is missing or differs from the server's. The `data:` line above it will contain a JSON object with `"protocolVersion":"2024-11-05"`. (A bare GET to `/mcp` is not a health check: with the image default `FASTMCP_STATELESS_HTTP=true` it returns `405 Method Not Allowed`, and with sessions on (`FASTMCP_STATELESS_HTTP=false`) `400 Bad Request`. Always use this POST form for smoke tests.) Then ask your AI assistant to run `list_hosts` to get live data from your UniFi console.

See [`config/mcp-server.example.json`](../config/mcp-server.example.json) for examples covering plain-HTTP, SSE, HTTPS, and bearer-auth client configurations, including environment-variable substitution forms (e.g. `${MCP_BEARER_TOKEN}`) for use in templated deployments.

A browser page on another site cannot drive the server: a request whose `Origin` header is not loopback, the `MCP_OAUTH_BASE_URL` origin or listed in `MCP_ALLOWED_ORIGINS` gets `403` ([Host and Origin validation](AUTH-TLS.md#host-and-origin-validation)). Clients that send no `Origin` (every desktop and CLI client) are unaffected.

#### Unauthenticated HTTP (trusted network only)

Without `MCP_AUTH_MODE` and `MCP_BEARER_TOKEN` the server accepts every request: anyone who can reach the port can call every tool, writes included, with your UniFi key. Use it only on loopback or on a network where every host is trusted. When it serves HTTP on a non-loopback address with no auth (the image binds `0.0.0.0`), the server prints a startup `WARNING` naming the fix.

<!-- install-case: readme-install-27 mode=docker -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.0 case=readme-install-27 -->
```bash
docker run -e UNIFI_API_KEY="your-api-key-here" -p 127.0.0.1:3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0
```

The client entry is the one above without `headers`, and the `curl` check without the `Authorization` line.

> **Network deployments:** By default the MCP server listens on plain HTTP. For non-localhost deployments, run it behind a TLS-terminating reverse proxy (e.g., Traefik, Caddy, nginx) or turn on in-server TLS with `MCP_TLS_MODE=https` or `mtls` ([AUTH-TLS.md](AUTH-TLS.md)).

### Reverse proxies and sidecars

With bearer or OAuth authentication enabled, the server accepts the proxy Host header by default, including when FASTMCP_HOST=127.0.0.1 behind a sidecar. The HTTP Host describes the client-facing endpoint, not the loopback socket. Keep authentication enabled and forward the client Authorization header. Browser Origin validation stays on; configure `MCP_ALLOWED_ORIGINS` for a browser client.

For an explicit Host restriction, set `MCP_ALLOWED_HOSTS` to the host and port the proxy actually forwards, such as `mcp.example.com` or `mcp-proxy:4444`. An unauthenticated loopback server still requires a loopback Host unless you set this allowlist. These rules apply to both stateless and stateful streamable HTTP. See [Host and Origin validation](AUTH-TLS.md#host-and-origin-validation).
