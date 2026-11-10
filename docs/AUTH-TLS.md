# Authentication and TLS

How to protect the HTTP transports (`streamable-http` and `sse`): a shared bearer token, in-server HTTPS or mutual TLS, and the nine combinations of auth mode and TLS mode. These settings do not apply to the `stdio` transport, which has no network surface. For the OAuth resource-server mode see [AUTH-OAUTH.md](AUTH-OAUTH.md); for certificates and mTLS client setup see [TLS.md](TLS.md); for the security posture of each mode see [SECURITY.md](../.github/SECURITY.md).

## HTTP request bounds and access records

All HTTP transports disable Uvicorn's built-in access logger and unused WebSocket
upgrades. MCP exposes no WebSocket routes; disabling upgrades also prevents
Uvicorn's pre-authentication WebSocket error logger from logging request targets.
The server's outermost ASGI access logger writes records to `unifi_fabric.access` with the client, method,
target, HTTP version, and response status. It never logs request headers. The logged
target is the ASGI `scope["raw_path"]`, followed by `?` and the query string when one is
present. Every query value is masked before logging: each `name=value` parameter is
written as `name=***`, and a parameter without `=` is kept as received. Targets within
the bound are then scrubbed by the existing global scrubber before they are written.

The server's access middleware applies these limits to every request head that
reaches it, before calling the application:

| Limit | Condition | Response | Logging behavior |
| --- | --- | --- | --- |
| Target | target is over 1024 bytes | `414` | constant response body; target is withheld and represented by its byte length and a 16-character SHA-256 prefix |
| Header field block | `name + ": " + value + CRLF` for each field, plus the final `CRLF`, is over 16 KiB | `431` | constant response body; target is withheld and represented by its byte length and a 16-character SHA-256 prefix |

The target limit includes the HTTP delimiter (`?`) when a query string is present.
Requests at or below 1024 bytes and header blocks at or below 16 KiB are dispatched
normally. Requests the middleware rejects never reach application routing, so their
handlers are not called.

The `414` and `431` responses apply only to request heads the HTTP parser accepts.
A request head beyond the parser's own limit (Uvicorn/h11 incomplete-head limit,
for example a 128 KiB target) is rejected earlier by the parser with `400` and never
reaches the middleware; this `400` is the expected, specified status. Neither path
logs request bytes: the middleware withholds the target as described above, and the
parser logs only the constant `Invalid HTTP request received.` warning. Do not rely on the parser limit as
the application boundary; complete request heads can exceed 16 KiB depending on
transport and parser state.

## Bearer Token Authentication (Optional)

Set `MCP_BEARER_TOKEN` (with `MCP_AUTH_MODE=bearer`, or with `MCP_AUTH_MODE` unset) to require all incoming MCP requests to include an `Authorization: Bearer <token>` header. Requests with a missing or incorrect token receive a 401 response. The token is compared in constant time. It must be printable ASCII with no whitespace or control character; otherwise startup fails with a message naming the variable (the value is never shown). The token alone enables bearer authentication only when `MCP_AUTH_MODE` is unset; an explicit `MCP_AUTH_MODE` always wins, so `MCP_AUTH_MODE=none` with a token set runs without bearer authentication.

Generate the token rather than choosing one, and give the same value to the server and to your MCP clients:

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-1 mode=non-executable reason=deployment-or-client-interaction -->
```bash
openssl rand -hex 32
```

`my-secret-token` in the examples below stands for that value. In bearer mode on an HTTP transport, a token shorter than 32 characters is accepted but prints a startup `WARNING` (see [Startup warnings](#startup-warnings)); stdio has no HTTP listener and prints no startup warnings, and other auth modes do not check the token length.

> **Note:** For new deployments, prefer setting `MCP_AUTH_MODE=bearer` explicitly alongside `MCP_BEARER_TOKEN`. Setting only `MCP_BEARER_TOKEN` (without `MCP_AUTH_MODE`) is supported for backward compatibility — the server automatically resolves to bearer mode when `MCP_BEARER_TOKEN` is non-empty and `MCP_AUTH_MODE` is unset — but explicit `MCP_AUTH_MODE=bearer` is the preferred selector going forward.

When unset (the default), the server runs without transport-layer authentication — the same behavior as previous versions. Serving HTTP that way on a non-loopback address (the Docker image binds `0.0.0.0`) prints a startup `WARNING`: anyone who can reach the port can call every tool, writes included.

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-2 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# Docker: with UNIFI_API_KEY and MCP_BEARER_TOKEN exported, -e NAME with no value passes each from your shell
docker run -e UNIFI_API_KEY -e MCP_AUTH_MODE=bearer -e MCP_BEARER_TOKEN -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
```

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-3 mode=non-executable reason=deployment-or-client-interaction -->
```yaml
# Docker Compose
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
    environment:
      UNIFI_API_KEY: your-api-key-here
      MCP_AUTH_MODE: bearer
      MCP_BEARER_TOKEN: my-secret-token
    ports:
      - "3000:3000"
```

**Client configuration with bearer auth:**

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-4 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "http://localhost:3000/mcp",
      "headers": { "Authorization": "Bearer my-secret-token" }
    }
  }
}
```

For `FASTMCP_TRANSPORT=sse`, use the `sse` client type pointing at the `/sse` endpoint with the same `Authorization` header:

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-5 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "sse",
      "url": "http://localhost:3000/sse",
      "headers": { "Authorization": "Bearer my-secret-token" }
    }
  }
}
```

This uses FastMCP's `StaticTokenVerifier` — a single shared-secret pattern designed for LAN/VPN deployments where network-level access control is already in place. It is not intended as a standalone security boundary for public-internet deployments; for public-internet use, see the OAuth mode below.

### Bearer + HTTPS (Recommended for LAN/VPN)

Combine `MCP_BEARER_TOKEN` with `MCP_TLS_MODE=https` to add transport encryption on top of the shared-secret check — this is the recommended posture for private-network deployments:

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-6 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# Docker — bearer auth with in-server HTTPS (UNIFI_API_KEY and MCP_BEARER_TOKEN exported)
docker run \
  -e UNIFI_API_KEY \
  -e MCP_AUTH_MODE=bearer \
  -e MCP_BEARER_TOKEN \
  -e MCP_TLS_MODE=https \
  -e MCP_TLS_CERTFILE=/certs/cert.pem \
  -e MCP_TLS_KEYFILE=/certs/key.pem \
  -v /path/to/certs:/certs:ro \
  -p 3000:3000 \
  ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
```

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-7 mode=non-executable reason=deployment-or-client-interaction -->
```yaml
# Docker Compose — bearer auth with in-server HTTPS
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
    environment:
      UNIFI_API_KEY: your-api-key-here
      MCP_AUTH_MODE: bearer
      MCP_BEARER_TOKEN: my-secret-token
      MCP_TLS_MODE: https
      MCP_TLS_CERTFILE: /certs/cert.pem
      MCP_TLS_KEYFILE: /certs/key.pem
    volumes:
      - /path/to/certs:/certs:ro
    ports:
      - "3000:3000"
```

**Client configuration for bearer + HTTPS** — the URL must use `https://`:

`streamable-http` transport:

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-8 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "https://localhost:3000/mcp",
      "headers": { "Authorization": "Bearer my-secret-token" }
    }
  }
}
```

`sse` transport (`FASTMCP_TRANSPORT=sse`):

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-9 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "sse",
      "url": "https://localhost:3000/sse",
      "headers": { "Authorization": "Bearer my-secret-token" }
    }
  }
}
```

See [`docs/TLS.md`](TLS.md) for certificate generation and the HEALTHCHECK requirement when enabling in-server TLS.

### Bearer + mTLS (High-assurance internal)

Combine `MCP_BEARER_TOKEN` with `MCP_TLS_MODE=mtls` for mutual transport identity on top of the shared-secret check. The server requires every client to present a certificate issued by your CA:

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-10 mode=non-executable reason=deployment-or-client-interaction -->
```bash
# Docker — bearer auth with mutual TLS (UNIFI_API_KEY and MCP_BEARER_TOKEN exported)
docker run \
  -e UNIFI_API_KEY \
  -e MCP_AUTH_MODE=bearer \
  -e MCP_BEARER_TOKEN \
  -e MCP_TLS_MODE=mtls \
  -e MCP_TLS_CERTFILE=/certs/server-cert.pem \
  -e MCP_TLS_KEYFILE=/certs/server-key.pem \
  -e MCP_TLS_CA_CERTS=/certs/ca-cert.pem \
  -v /path/to/certs:/certs:ro \
  -p 3000:3000 \
  ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.2
```

Most MCP clients cannot present a client certificate directly. The recommended pattern is a TLS-terminating reverse proxy that presents the client certificate toward the server; downstream MCP clients connect to the proxy over standard HTTPS with the bearer token in the `Authorization` header:

<!-- doc-provenance: source=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 support=0.7.2 citation=file:src/unifi_fabric/transport_security.py@sha256:eae785b891802c23a10c70edf379ede994598d45f54ce0758d7638a302b2cec7 -->
<!-- install-case: docs-auth-tls-11 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "https://proxy.example.com/mcp",
      "headers": { "Authorization": "Bearer my-secret-token" }
    }
  }
}
```

Replace `https://proxy.example.com/mcp` with the proxy's public HTTPS address. See [`docs/TLS.md`](TLS.md) for the mTLS client configuration details and certificate generation.

## Host and Origin validation

The HTTP transports check two request headers before authentication or any MCP handling. This blocks DNS rebinding and cross-site requests from a browser page:

- **Origin.** A request with no `Origin` header passes; desktop, CLI and server-side MCP clients send none. A request with an `Origin` header passes only when the origin is loopback (`localhost` and its subdomains, or any loopback IP literal including `127.0.0.0/8` and `[::1]`, over HTTP or HTTPS on any port), the origin of `MCP_OAUTH_BASE_URL`, or listed in `MCP_ALLOWED_ORIGINS`. Anything else, `Origin: null` included, gets `403` with a body naming `MCP_ALLOWED_ORIGINS` and `MCP_HOST_ORIGIN_PROTECTION`.
- **Host.** With bearer or OAuth authentication and no explicit allowlist, proxy Host values are accepted on every bind address. The required token protects the MCP endpoint against unauthenticated browser access, while the Origin check above still rejects cross-site browser requests. Without authentication, FastMCP's `auto` mode requires a loopback Host on a loopback bind. Setting `MCP_ALLOWED_HOSTS` restricts Host to loopback or listed values on every bind and in every authentication mode. A rejected Host gets `421 Misdirected Request`. An unauthenticated `0.0.0.0` listener with no allowlist accepts any Host; configure authentication and an allowlist when exposing it.

| Env var | Default | Description |
|---|---|---|
| `MCP_ALLOWED_ORIGINS` | _(none)_ | Comma-separated origins (`scheme://host[:port]`, http or https, no path), e.g. `https://app.example.com`. Loopback and the `MCP_OAUTH_BASE_URL` origin are always allowed. |
| `MCP_ALLOWED_HOSTS` | _(none)_ | Comma-separated `Host` values (a host name or IP, optional `:port`), e.g. `mcp.example.com`. Loopback is always allowed. |
| `MCP_HOST_ORIGIN_PROTECTION` | `on` | `off` (or any false value) turns both checks off, for example when a reverse proxy in front already enforces them. |

A malformed entry fails startup with a message naming the variable.

## Startup warnings

The server never refuses to start over these postures, but prints one `WARNING` line to stderr for each. Each warning names the variables and a fix:

| Posture | Fix the warning names |
|---|---|
| HTTP transport on a non-loopback `FASTMCP_HOST` with `MCP_AUTH_MODE=none` | Set `MCP_AUTH_MODE=bearer` and `MCP_BEARER_TOKEN` (`openssl rand -hex 32`), or `oauth`; or bind `FASTMCP_HOST=127.0.0.1`. |
| `MCP_TLS_MODE=mtls` with `MCP_TLS_CERT_REQS=optional` and `MCP_AUTH_MODE=none`: a client without a certificate gets in unauthenticated | Set `MCP_TLS_CERT_REQS=required` (or unset it), or add `bearer` / `oauth`. |
| `MCP_AUTH_MODE=bearer` on an HTTP transport with `MCP_BEARER_TOKEN` shorter than 32 characters | Generate one with `openssl rand -hex 32`. |
| `MCP_OAUTH_JWKS_URI` on plain `http://` to a host that is not loopback: anyone on the path can substitute the signing keys | Use the identity provider's `https://` JWKS URI. |

## Auth × TLS Deployment Matrix

`MCP_BEARER_TOKEN` (above) is one mode of a broader auth/transport/TLS selector
surface. The selectors live in the `MCP_*` namespace and apply to **HTTP
transports only** — auth and TLS are rejected (fail-closed) when
`FASTMCP_TRANSPORT` is `stdio`. Set `FASTMCP_TRANSPORT=streamable-http` (or `sse`)
when enabling any of these.

**Auth × TLS deployment grid**

The table below summarises all supported combinations and where each is appropriate:

| Auth mode | TLS mode | Posture / Use when |
|-----------|----------|--------------------|
| `none` | `none` | Local loopback / single-user dev only — see [SECURITY.md](../.github/SECURITY.md) |
| `none` | `https` | **Not recommended as-is** — only acceptable when a TLS-terminating proxy in front enforces authentication |
| `none` | `mtls` | **Not recommended as-is** — transport-level peer identity but still no application-layer auth; set `MCP_AUTH_MODE` to `bearer` or `oauth` to add application-layer auth |
| `bearer` | `none` | Trusted LAN (token travels in cleartext — secure at the network level) |
| `bearer` | `https` | **Recommended for LAN/VPN** — shared-secret auth + transport encryption |
| `bearer` | `mtls` | High-assurance internal — mutual transport identity + shared secret |
| `oauth` | `none` | **Avoid** — tokens validated per-client but travel in cleartext; only tolerable behind a TLS-terminating proxy |
| `oauth` | `https` | **Recommended for internet-exposed** — per-client JWT + transport encryption |
| `oauth` | `mtls` | Zero-trust / multi-tenant — maximum assurance |

All nine cells are supported. Configuration details are in the tables below and in
[docs/AUTH-OAUTH.md](AUTH-OAUTH.md) / [docs/TLS.md](TLS.md).
See [SECURITY.md](../.github/SECURITY.md) for the full posture decision matrix including
guidance on mTLS as a transport boundary.

With `UNIFI_KEY_MODE=header` every tool call also carries UniFi API keys in its
`X-UniFi-Api-Key` request header, so only the `https` and `mtls` rows (or a
TLS-terminating proxy that does not log request headers) keep those keys off the wire
in cleartext. Header mode does not authenticate the caller, so pair it with `bearer` or
`oauth`. See
[Header key mode](CONFIGURATION.md#header-key-mode-unifi_key_mode) and
[SECURITY.md](../.github/SECURITY.md#header-key-mode).

**Auth selectors**

| Env var | Default | Description |
|---|---|---|
| `MCP_AUTH_MODE` | _(unset)_ | `none`, `bearer`, or `oauth`. Unset resolves to `bearer` when `MCP_BEARER_TOKEN` is set, else `none`. |
| `MCP_BEARER_TOKEN` | `""` | Shared secret for `bearer` mode. Generate it with `openssl rand -hex 32`; under 32 characters prints a startup warning. Compared in constant time. |
| `MCP_OAUTH_ISSUER` | `""` | OAuth issuer URL (absolute `http(s)`). Required for `oauth`. |
| `MCP_OAUTH_JWKS_URI` | `""` | JWKS URI for signature verification. Required for `oauth`. Use `https://`; plain `http://` to a non-loopback host prints a startup warning. A JWKS document over 1 MiB is refused. |
| `MCP_OAUTH_AUDIENCE` | `""` | Expected token audience, preserved exactly including spaces. Required for `oauth`. |
| `MCP_OAUTH_BASE_URL` | `""` | Public base URL of this resource server. Required for `oauth`. |
| `MCP_OAUTH_REQUIRED_SCOPES` | `""` | Comma-separated non-empty scopes a token must carry; an empty setting means no required scopes. |
| `MCP_OAUTH_ALGORITHM` | `RS256` | JWT signing algorithm to accept: `RS256`/`RS384`/`RS512`, `ES256`/`ES384`/`ES512`, `PS256`/`PS384`/`PS512`, `EdDSA`, `Ed25519` or `Ed448` (case-sensitive; HS* needs a shared secret, which a JWKS never holds). |
| `MCP_OAUTH_AUTHORIZATION_SERVERS` | _(issuer)_ | Comma-separated authorization-server URLs. Defaults to `[MCP_OAUTH_ISSUER]`. |
| `MCP_OAUTH_WRITE_SCOPE` | `""` | One scope a token must also carry to call write tools. Unset: every accepted token can call every tool. Set with another auth mode, startup fails. See [AUTH-OAUTH.md](AUTH-OAUTH.md#scopes-and-write-access). |

**TLS selectors**

| Env var | Default | Description |
|---|---|---|
| `MCP_TLS_MODE` | `none` | `none`, `https`, or `mtls`. |
| `MCP_TLS_CERTFILE` | `""` | Server certificate path. Required for `https`/`mtls`. |
| `MCP_TLS_KEYFILE` | `""` | Server private key path. Required for `https`/`mtls`. |
| `MCP_TLS_CA_CERTS` | `""` | Client CA bundle for verifying client certs. Required for `mtls`. |
| `MCP_TLS_KEY_PASSWORD` | `""` | Password for an encrypted private key. Optional. |
| `MCP_TLS_CERT_REQS` | `required` under `mtls` | `required` demands a trusted certificate; `optional` verifies one if supplied but allows clients without one (with `MCP_AUTH_MODE=none` that prints a startup warning). `none` is rejected under `mtls`. Ignored under `https`. |

**Fail-closed validation:** `https`/`mtls` require a cert + key (`mtls` also a CA
bundle); `oauth` requires issuer + JWKS URI + audience + base URL; `bearer` requires
a non-empty `MCP_BEARER_TOKEN`; unknown enum values and `stdio` + auth/TLS are
rejected at startup with a clear message.

All auth modes (`none`, `bearer`, `oauth`) and TLS modes (`none`, `https`, `mtls`)
are active and CI-tested. For OAuth setup see [`docs/AUTH-OAUTH.md`](AUTH-OAUTH.md);
for HTTPS / mTLS see [`docs/TLS.md`](TLS.md).
