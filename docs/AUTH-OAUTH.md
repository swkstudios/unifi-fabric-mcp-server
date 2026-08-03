# OAuth 2.0 Authorization (`MCP_AUTH_MODE=oauth`)

This server can run as an **OAuth 2.0 / MCP protected resource** (an OAuth *resource
server*). In this mode it verifies the bearer JWT on every incoming MCP request against
an **external OIDC identity provider** (IdP) that you already operate.

The server **does not** issue tokens, host a login or consent screen, or implement
dynamic client registration. All of that is the identity provider's job. This server
only:

1. validates the access token's signature against the IdP's published JWKS,
2. checks the `iss` (issuer), `aud` (audience), and `exp` (expiry) claims,
3. enforces any required scopes, and
4. advertises itself via the standard protected-resource discovery document so MCP
   clients can find the authorization server.

## When to use which auth mode

| Mode | Use when |
|---|---|
| `none` | Transport-level access control already exists (loopback, private VPN) and no per-request auth is needed. |
| `bearer` | A single shared secret is acceptable (LAN/VPN); see the bearer section in the README. Not a standalone public-internet boundary. |
| `oauth` | You front the server with a real IdP and want per-client, scoped, expiring access tokens — the recommended posture for shared or internet-exposed deployments. |

## Requirements

- An HTTP transport. OAuth applies to HTTP transports only; set
  `FASTMCP_TRANSPORT=streamable-http` (or `sse`). Selecting an auth mode while the
  transport is `stdio` fails closed at startup.
- TLS is strongly recommended for any non-loopback deployment — see
  [`TLS.md`](TLS.md). Bearer tokens travelling in cleartext can be replayed.
- An OIDC identity provider that publishes a JWKS endpoint and issues RS256 (or your
  configured algorithm) signed JWT access tokens.

## Configuration

Set `MCP_AUTH_MODE=oauth` and the resource-server descriptor:

| Env var | Required | Description |
|---|---|---|
| `MCP_AUTH_MODE` | yes | Set to `oauth`. |
| `MCP_OAUTH_ISSUER` | yes | The IdP issuer URL. Must equal the `iss` claim of issued tokens (e.g. `https://idp.example.com/realms/main` for Keycloak-style IdPs; other providers use different issuer path shapes — derive from `/.well-known/openid-configuration`). |
| `MCP_OAUTH_JWKS_URI` | yes | The IdP's JWKS endpoint used to fetch signing keys (e.g. `https://idp.example.com/realms/main/protocol/openid-connect/certs` for Keycloak; for Auth0/Okta-style IdPs, use the `jwks_uri` from `/.well-known/openid-configuration`). |
| `MCP_OAUTH_AUDIENCE` | yes | The audience this server accepts. `MCP_OAUTH_AUDIENCE` must match the token's `aud` claim. When `aud` is a **JSON array**, the check is membership (`MCP_OAUTH_AUDIENCE` must be one of the values). When `aud` is a **plain string** (single-audience tokens), the check is byte-for-byte equality. **This is the most common point of misconfiguration — see below.** |
| `MCP_OAUTH_BASE_URL` | yes | The public base URL clients use to reach this server (e.g. `https://mcp.example.com`). Published in the discovery document. |
| `MCP_OAUTH_REQUIRED_SCOPES` | no | Comma-separated scopes a token must carry to be accepted (e.g. `fabric:read,fabric:write`). Empty means no scope requirement. |
| `MCP_OAUTH_ALGORITHM` | no | JWT signing algorithm to accept. Default `RS256`. |
| `MCP_OAUTH_AUTHORIZATION_SERVERS` | no | Comma-separated authorization-server URLs to advertise. Defaults to `[MCP_OAUTH_ISSUER]`. |

All four required fields are validated **fail-closed** at startup: if any of issuer,
JWKS URI, audience, or base URL is missing, the server refuses to start with an explicit
error rather than running without verification.

### Example (environment)

`FASTMCP_HOST` and `FASTMCP_PORT` control the **local bind address and port** (the
socket the server listens on). `MCP_OAUTH_BASE_URL` is the **public URL** a
TLS-terminating reverse proxy maps to that local socket — the two are independent.
When running directly (not via Docker), FastMCP defaults to `127.0.0.1:8000`; the
Docker image sets `0.0.0.0:3000`.

```bash
export FASTMCP_TRANSPORT=streamable-http
export FASTMCP_HOST=127.0.0.1   # local bind address
export FASTMCP_PORT=8000         # local bind port (proxy maps this to the public URL)
export MCP_AUTH_MODE=oauth
export MCP_OAUTH_ISSUER="https://idp.example.com/realms/main"          # Keycloak-style
export MCP_OAUTH_JWKS_URI="https://idp.example.com/realms/main/protocol/openid-connect/certs"
export MCP_OAUTH_AUDIENCE="unifi-fabric-mcp"
export MCP_OAUTH_BASE_URL="https://mcp.example.com"   # public URL your proxy fronts
export MCP_OAUTH_REQUIRED_SCOPES="fabric:read"
```

### Example (Docker Compose)

```yaml
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.5.0
    environment:
      UNIFI_API_KEY: "your-api-key"
      FASTMCP_TRANSPORT: streamable-http
      MCP_AUTH_MODE: oauth
      MCP_OAUTH_ISSUER: "https://idp.example.com/realms/main"
      MCP_OAUTH_JWKS_URI: "https://idp.example.com/realms/main/protocol/openid-connect/certs"
      MCP_OAUTH_AUDIENCE: "unifi-fabric-mcp"
      MCP_OAUTH_BASE_URL: "https://mcp.example.com"
      MCP_OAUTH_REQUIRED_SCOPES: "fabric:read"
    ports:
      - "3000:3000"
```

> **Tip:** `:0.5.0` pins to this release. For production deployments, pin by digest instead — see the [Docker Deployment](../README.md#docker-deployment) section in the README.

### Example — OAuth + in-server HTTPS (Recommended for internet-exposed)

The matrix labels `oauth + https` as the recommended public posture. Add the
`MCP_TLS_*` variables to any OAuth config above:

```yaml
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.5.0
    environment:
      UNIFI_API_KEY: "your-api-key"
      FASTMCP_TRANSPORT: streamable-http
      MCP_AUTH_MODE: oauth
      MCP_OAUTH_ISSUER: "https://idp.example.com/realms/main"
      MCP_OAUTH_JWKS_URI: "https://idp.example.com/realms/main/protocol/openid-connect/certs"
      MCP_OAUTH_AUDIENCE: "unifi-fabric-mcp"
      MCP_OAUTH_BASE_URL: "https://mcp.example.com"
      MCP_OAUTH_REQUIRED_SCOPES: "fabric:read"
      MCP_TLS_MODE: https
      MCP_TLS_CERTFILE: /certs/cert.pem
      MCP_TLS_KEYFILE: /certs/key.pem
    volumes:
      - /path/to/certs:/certs:ro
    ports:
      - "3000:3000"
```

`MCP_OAUTH_BASE_URL` reflects what external clients see (e.g. after a proxy); it
is independent of `MCP_TLS_MODE`. Setting `MCP_TLS_MODE=https` means the server
terminates TLS itself on port 3000. If you prefer to terminate TLS at a reverse
proxy and have the proxy forward plain HTTP to the server, omit the `MCP_TLS_*`
variables and set `MCP_OAUTH_BASE_URL` to the proxy's `https://` address.

### Example — OAuth + mTLS (Zero-trust / multi-tenant — maximum assurance)

For the highest-assurance posture, combine OAuth JWT validation with mutual TLS:

```yaml
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.5.0
    environment:
      UNIFI_API_KEY: "your-api-key"
      FASTMCP_TRANSPORT: streamable-http
      MCP_AUTH_MODE: oauth
      MCP_OAUTH_ISSUER: "https://idp.example.com/realms/main"
      MCP_OAUTH_JWKS_URI: "https://idp.example.com/realms/main/protocol/openid-connect/certs"
      MCP_OAUTH_AUDIENCE: "unifi-fabric-mcp"
      MCP_OAUTH_BASE_URL: "https://mcp.example.com"
      MCP_OAUTH_REQUIRED_SCOPES: "fabric:read"
      MCP_TLS_MODE: mtls
      MCP_TLS_CERTFILE: /certs/server-cert.pem
      MCP_TLS_KEYFILE: /certs/server-key.pem
      MCP_TLS_CA_CERTS: /certs/ca-cert.pem
    volumes:
      - /path/to/certs:/certs:ro
    ports:
      - "3000:3000"
```

mTLS gates the transport (client certificate required at handshake); OAuth gates
each request (JWT validated per-call). See [`TLS.md`](TLS.md) for mTLS
certificate generation and the HEALTHCHECK requirement under mTLS.

## Discovery endpoint

When `oauth` mode is active the server automatically serves an
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) **protected-resource metadata**
document. Compliant MCP clients fetch it to learn which authorization server to obtain
a token from.

The metadata is published at a **path-aware** well-known URI derived from the resource
mount path:

| Transport | Mount path | Discovery URI |
|---|---|---|
| `streamable-http` | `/mcp` | `/.well-known/oauth-protected-resource/mcp` |
| `sse` | `/sse` | `/.well-known/oauth-protected-resource/sse` |

The `resource` field in each document names `MCP_OAUTH_BASE_URL + <mount path>` — for
example `https://mcp.example.com/mcp` or `https://mcp.example.com/sse`. A request to
the bare `/.well-known/oauth-protected-resource` (no suffix) returns 404; always derive
the discovery path from the resource mount.

## Worked example (Keycloak-style IdP)

> **Prerequisites:** `curl` and `jq` must be installed. `jq` is used to extract the access token from the token response and to pretty-print discovery documents. Install via your package manager (e.g. `brew install jq`, `apt install jq`).

> **Non-Keycloak IdPs:** The token endpoint path below (`/protocol/openid-connect/token`) is Keycloak-specific. For Auth0, Okta, or other IdPs, derive the correct `TOKEN_ENDPOINT` from your IdP's discovery document before running Step 2: `curl -s "${ISSUER}/.well-known/openid-configuration" | jq -r .token_endpoint`.

This section walks the full token-acquire → connect flow using `curl`. Replace
`$ISSUER`, `$CLIENT_ID`, and `$CLIENT_SECRET` with your IdP's values.

### Step 1 — Configure your IdP

Create an API resource / application in your IdP:

- Set its **identifier** (audience) to `unifi-fabric-mcp`.
- Add a scope named `fabric:read`.
- If your IdP supports explicit audience claims (e.g. an "audience mapper"), configure
  it to stamp `unifi-fabric-mcp` into the `aud` field of every issued access token.
- Create a *client credentials* client (machine-to-machine) and note its `client_id`
  and `client_secret`.

### Step 2 — Acquire a token

```bash
ISSUER="https://idp.example.com/realms/main"   # your IdP's issuer URL — no trailing slash
CLIENT_ID="my-mcp-client"
CLIENT_SECRET="my-client-secret"

TOKEN=$(curl -s -X POST \
  "${ISSUER}/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d scope=fabric:read \
  | jq -r .access_token)

# Verify the token was acquired before proceeding.
# If the request failed, jq outputs "null" and subsequent steps will fail
# with a confusing "invalid token" error rather than a clear "token request
# failed" message.
echo "Token prefix: ${TOKEN:0:20}"   # should start with "ey" for a JWT
```

> **IdP-specific notes:**
>
> - **Trailing slash in ISSUER:** Do not include a trailing slash. `ISSUER="https://idp.example.com/realms/main/"` produces a double-slash URL (`…/main//protocol/…`) that Keycloak resolves as a 404 with no clear error message.
>
> - **Audience claim:** The `audience=` body parameter is an **Auth0-specific extension** and is **silently ignored by Keycloak**. On Keycloak, set the token audience via a **protocol mapper** (Client → Mappers → Add mapper → Audience): configure it to add `unifi-fabric-mcp` to the `aud` claim of every issued access token. Auth0 and similar providers accept the `audience=` body parameter directly. Note: RFC 8707 ("Resource Indicators for OAuth 2.0") defines a separate `resource=` request parameter — this is distinct from the `audience=` extension. If tokens are rejected for audience mismatch, decode the JWT and check the `aud` claim — if it is missing or does not contain `unifi-fabric-mcp`, the audience was not stamped at issuance.

### Step 3 — Verify discovery

`streamable-http` transport:

```bash
curl -s http://127.0.0.1:8000/.well-known/oauth-protected-resource/mcp | jq .
```

Expected `200 OK` response:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://idp.example.com/realms/main"]
}
```

`sse` transport (`FASTMCP_TRANSPORT=sse`):

```bash
curl -s http://127.0.0.1:8000/.well-known/oauth-protected-resource/sse | jq .
```

Expected `200 OK` response:

```json
{
  "resource": "https://mcp.example.com/sse",
  "authorization_servers": ["https://idp.example.com/realms/main"]
}
```

### Step 4 — Authenticated MCP call (`streamable-http`)

POST an `initialize` message to confirm the server is up and the token is accepted.
(A bare GET to `/mcp` returns `400 Bad Request` on FastMCP 3.x — the
streamable-http protocol requires a POST to open a session.)

```bash
curl -s -w "\nHTTP:%{http_code}\n" \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}' \
  http://127.0.0.1:8000/mcp
```

`HTTP:200` on the last line confirms the token is accepted; the `data:` line will
contain `"protocolVersion":"2024-11-05"`. A `401` means the token failed
validation — see [Troubleshooting 401s](#troubleshooting-401s) below.
Set `UNIFI_LOG_LEVEL=DEBUG` to see the per-claim rejection reason in stderr logs.

### Alternative — SSE transport (`FASTMCP_TRANSPORT=sse`)

The SSE transport model is fundamentally different — a client opens a long-lived
GET to `/sse` rather than posting to `/mcp`. The `Authorization: Bearer` header
is identical; only the endpoint changes:

```bash
curl --max-time 3 -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:8000/sse
```

A `200` confirms the token is accepted. (The SSE stream stays open; `--max-time 3`
disconnects after a few seconds — that is expected.) A `401` means the token
failed validation.

## MCP client configuration for OAuth

How you configure your MCP client depends on whether it understands the
[MCP-2025-03-26 OAuth flow](https://spec.modelcontextprotocol.io/specification/basic/authorization/).

### OAuth-aware clients

An OAuth-aware MCP client (one that implements the MCP authorization spec) can
discover the authorization server automatically via the protected-resource metadata
document (see [Discovery endpoint](#discovery-endpoint) above). The client config is
minimal — no token or header injection needed:

```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "https://mcp.example.com/mcp"
    }
  }
}
```

The client fetches `/.well-known/oauth-protected-resource/mcp`, discovers the
authorization server, performs the OAuth flow, and injects the resulting token
automatically. For `sse` transport, point at `/sse` instead.

### Non-OAuth-aware clients (manual token injection)

Most MCP clients today are not OAuth-aware. The operator must obtain a token out-of-band
(e.g. with the `curl` flow in Step 2 above) and inject it via `headers`. Note that
OAuth tokens are **short-lived** — the client cannot refresh them automatically; the
operator must rotate the injected token before it expires.

**`streamable-http` transport:**

```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer <your-access-token>" }
    }
  }
}
```

**`sse` transport:**

```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "sse",
      "url": "https://mcp.example.com/sse",
      "headers": { "Authorization": "Bearer <your-access-token>" }
    }
  }
}
```

Replace `<your-access-token>` with a freshly acquired token from your IdP.

## Most common misconfiguration: audience mismatch

`MCP_OAUTH_AUDIENCE` must match the `aud` claim the IdP stamps into its access
tokens. The `aud` claim may be a **string** or a **JSON array**:

- When `aud` is a **JSON array**: `MCP_OAUTH_AUDIENCE` must be one of the values in
  the array (membership check).
- When `aud` is a **plain string**: `MCP_OAUTH_AUDIENCE` must equal it exactly
  (byte-for-byte equality — not substring matching).

This is the single most frequent cause of "everything is configured but every request
returns 401".

Identity providers vary in how the audience is set:

- Some default the `aud` to the client ID, the token endpoint, or the IdP's own URL.
- Many require you to attach an explicit *audience* / *resource* / *API identifier*
  (often via a scope, an "audience mapper", or a resource-indicator parameter) for the
  token's `aud` to contain your API's identifier.

If valid-looking tokens are rejected, decode the token (e.g. paste the JWT into a local
decoder) and confirm `MCP_OAUTH_AUDIENCE` appears in its `aud` claim. Then confirm `iss`
equals `MCP_OAUTH_ISSUER` and that the required scopes are present in the `scope` claim.

## Troubleshooting 401s

The server returns a generic `401` with a `WWW-Authenticate: Bearer` header; it does
not echo per-claim failure detail in the HTTP response body. Set `UNIFI_LOG_LEVEL=DEBUG`
to see the rejection category in stderr logs.

| Diagnostic category | Likely cause | Fix |
|---|---|---|
| Every request 401 with a valid-looking token | `MCP_OAUTH_AUDIENCE` not found in token `aud` | Configure the IdP to issue the correct audience; align `MCP_OAUTH_AUDIENCE`. |
| Issuer mismatch | Token `iss` ≠ `MCP_OAUTH_ISSUER` | Use the exact issuer string the IdP advertises (watch for trailing slashes / realm paths). |
| Missing required scopes | Token lacks a scope in `MCP_OAUTH_REQUIRED_SCOPES` | Grant the scope to the client, or relax the requirement. |
| Token expired | Clock skew or stale token | Refresh the token; ensure server and IdP clocks are in sync. |
| JWKS endpoint unreachable | `MCP_OAUTH_JWKS_URI` is wrong or outbound egress to the IdP is blocked | Verify the URI and network path from the server to the IdP. |
| `kid` not found after IdP key rotation | IdP rotated signing keys; cached JWKS is stale | Restart the server so the JWKS is re-fetched, or check your IdP's key-rotation policy. |
| Algorithm mismatch | Token `alg` ≠ `MCP_OAUTH_ALGORITHM` (default `RS256`) | Set `MCP_OAUTH_ALGORITHM` to match the algorithm your IdP uses for signing. |
| Server refuses to start | A required descriptor field is unset | Provide issuer + JWKS URI + audience + base URL. |
| Startup error on `stdio` | Auth is HTTP-only — `stdio` + any auth mode fails closed at startup | Set `FASTMCP_TRANSPORT=streamable-http` or `sse`. |

## What this server is *not*

This is a resource server, not an identity provider. It does not:

- issue, refresh, or revoke tokens,
- render login or consent UI,
- implement OAuth dynamic client registration,
- manage client redirect URIs.

Operate those concerns in your OIDC provider; point this server at it via the env vars
above.
