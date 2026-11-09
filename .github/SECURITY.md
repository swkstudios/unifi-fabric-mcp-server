# Security Policy

## Supported Versions

We provide security fixes for the latest release only.

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| older   | No        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's **Private Vulnerability Reporting** to disclose security issues privately:
open <https://github.com/swkstudios/unifi-fabric-mcp-server/security/advisories/new>
(the **Security** tab of the public repository, then **"Report a vulnerability"**). Use this
link wherever you read this policy. We aim to
acknowledge reports within 5 business days and will coordinate a fix and public
disclosure timeline with you.

When reporting, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (if applicable).
- Any suggested mitigations.

We follow responsible disclosure and will credit reporters in the release notes unless you
prefer to remain anonymous.

## Trust store (eMudhra CA incident, October 2026)

The container image ships the Debian CA bundle and the build fails if it trusts a root named in the incident. Other install paths use the host: the HTTPS client for the JWKS download loads the operating system trust store, and the UniFi API client loads certifi (locked at 2026.10.23 or later). Following the FastMCP security notice, "update the CA stores in your operating system, containers, and custom TLS configuration. Rebuild affected images and restart processes after changing their trust stores"; upgrading this server alone is insufficient for a pip, uvx or Homebrew install. Update your operating system CA package (Debian bookworm `ca-certificates` 20250419~deb12u2 or later, Homebrew `ca-certificates` 2026-09-25_1 or later), and update uv to 0.13.4 or later and pip to 26.2.2 or later.

## Transport Authentication Posture

The server selects how it authenticates incoming HTTP requests with the
`MCP_AUTH_MODE` environment variable: one of `none`, `bearer`, or `oauth`.
Authentication applies to the HTTP transports only (streamable-http and SSE). The
stdio transport has no network surface, and setting an auth or TLS mode while using
stdio is rejected at startup rather than silently ignored.

Pick the mode that matches where the server is reachable from:

| Mode     | Use when                                                                 | Boundary it provides                                                              |
|----------|--------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| `none`   | Local loopback / single-user development only.                           | None. Anyone who can reach the port can call every tool.                          |
| `bearer` | A trusted private network (LAN / VPN), or behind a TLS-terminating authenticating reverse proxy. | A single shared secret. No per-client identity, no scopes, no expiry, no rotation. |
| `oauth`  | Internet-exposed or multi-tenant deployments.                            | Per-client identity via signed, audience-scoped, expiring tokens from an issuer.  |

Tool responses include all upstream API fields, including credential fields (WLAN
passphrases, RADIUS secrets, DDNS passwords), GPS coordinates, and Protect recognition data.
The server always replaces its own configured secrets (its API keys, `MCP_BEARER_TOKEN`,
`MCP_TLS_KEY_PASSWORD`), and in header mode the keys a call sends, with `***` wherever a
response, error or log line echoes them;
masking upstream credential fields (with `***REDACTED***`) is off by default and opt-in with `UNIFI_REDACT_SECRETS`. Authentication controls admission, not field visibility. Transport security is therefore load-bearing: an inadequately secured
listener exposes complete network credentials and sensitive data, not just network visibility.

The HTTP transports also check the `Host` and `Origin` headers by default, as a defence against DNS
rebinding and cross-site requests: a browser request from an origin that is not loopback, the origin
of `MCP_OAUTH_BASE_URL` or listed in `MCP_ALLOWED_ORIGINS` is refused. Unauthenticated loopback binds keep FastMCP’s automatic Host protection.
Bearer/OAuth authentication in automatic mode accepts proxy Host values unless an explicit
allowlist is configured; strict FastMCP protection preserves its Host checks.
`MCP_ALLOWED_HOSTS` adds allowed names to FastMCP’s Host policy. Origin checks still apply
to authenticated requests. `MCP_HOST_ORIGIN_PROTECTION=off` disables both checks. See
[`docs/AUTH-TLS.md`](../docs/AUTH-TLS.md#host-and-origin-validation).

Authentication admits a caller to the server; OAuth can additionally restrict writes with
`MCP_OAUTH_WRITE_SCOPE`. To limit what all admitted callers can change, set
`UNIFI_WRITE_POLICY=deny` (every write and action is refused before it reaches UniFi) or deny writes
for single families or tools with `UNIFI_WRITE_EXCEPTIONS` (for example `family:network=deny`); both are listed in
[`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md).

### `none`

No authentication is performed. Only safe when the listener is bound to loopback
(`127.0.0.1` / `::1`) and reachable solely by trusted local processes, e.g. during
development. Never expose a `none`-mode listener beyond the local host.

### `bearer`

Every request must present `Authorization: Bearer <token>`, where `<token>` matches
the single shared secret in `MCP_BEARER_TOKEN`. Requests with a missing, empty, or
non-matching token are rejected with `401 Unauthorized` before any tool is invoked.

Bearer mode is a shared-secret check, not an identity system: there is one secret for
all callers, with no per-client identity, no scopes, no built-in expiry, and no
rotation mechanism. Treat the token as a high-value credential -- inject it from a
secret store, never commit it, and rotate it if it may have been exposed.

> **Bearer auth is not a standalone public-internet boundary.** A single static
> shared secret carried in a header is vulnerable to leakage, replay, and brute force,
> and gives no way to distinguish or revoke individual clients. Do not expose a
> bearer-only server directly to the internet. Use it only on a trusted private
> network, or behind a TLS-terminating authenticating reverse proxy that performs the
> real client authentication. Bearer mode also provides no transport confidentiality
> on its own: without TLS the token travels in cleartext, so always pair it with
> `MCP_TLS_MODE` or a TLS-terminating proxy.

### `oauth`

Requests must present a signed token validated against the configured issuer, audience,
and (optionally) required scopes. This is the mode intended for internet-exposed or
multi-tenant deployments, because it provides per-client identity, scope-checked admission,
and token expiry rather than a single shared secret.

OAuth scopes control admission to the whole server. `MCP_OAUTH_REQUIRED_SCOPES` decides which tokens
get in, and a scope named `fabric:read` does not disable write tools on its own. To restrict writes per token, set `MCP_OAUTH_WRITE_SCOPE`
(opt-in, unset by default): a write tool, or a `fabric_connector_get` call to a known state-changing
GET route, is then refused before it runs unless the caller's token also carries that scope; read
tools need only the admission scopes. All admitted clients share the deployment's tool catalog and
write settings; the request policy headers let a client tighten them for its own calls, never loosen
them. In the default key mode every client also uses the deployment's configured UniFi key(s); with
`UNIFI_KEY_MODE=header` each call brings its own (see [Header key mode](#header-key-mode)). For an
instance with no write path at all, run it with `UNIFI_WRITE_POLICY=deny`; use separate instances and
keys when callers need different UniFi permissions.
See [Scopes and write access](../docs/AUTH-OAUTH.md#scopes-and-write-access).

### Header key mode

With `UNIFI_KEY_MODE=header` the server stores no UniFi key: each tool call carries its keys in the
`X-UniFi-Api-Key` request header, and the server uses whatever key a caller sends
([Header key mode](../docs/CONFIGURATION.md#header-key-mode-unifi_key_mode)). This changes the trust
model:

- **MCP authentication still decides who may call.** Header mode does not authenticate the caller;
  the UniFi key only decides what UniFi lets that call do. Run it with `MCP_AUTH_MODE=bearer` or
  `oauth`.
- **TLS is required.** UniFi keys travel in every request, so without TLS they cross the network in
  cleartext. Use `MCP_TLS_MODE=https` (or `mtls`), or a TLS-terminating reverse proxy on the same
  host or a trusted segment, and make sure that proxy does not log request headers.
- **Keys are held in memory.** The connections opened for a key keep it in process memory, for at
  most 256 key identities at once (the least recently used idle one is dropped first), until its
  identity is dropped or the server stops. Keys are never written to disk or the audit log; responses, errors and logs replace
  them with `***`. A memory dump of the server process can contain them.
- **Request policy headers are not an access control.** `X-UniFi-Write-Policy`,
  `X-UniFi-Family-Allow` and `X-UniFi-Exclude` let a client tighten the operator policy for its own
  calls; they never loosen it, and a client that omits them gets the operator policy
  ([Request policy headers](../docs/CONFIGURATION.md#request-policy-headers)).

### Internet-exposed deployments

If the server is reachable from the public internet, do **not** rely on `none` or a
bare `bearer` secret as the only boundary. Either:

- run in `oauth` mode over HTTPS (`MCP_TLS_MODE=https`), validating signed,
  audience-scoped tokens from your identity provider; or
- front the server with a TLS-terminating reverse proxy that performs authentication
  (for example OAuth/OIDC or mutual TLS) and only forwards already-authenticated
  requests to the server.

In all cases, transport confidentiality (TLS) should terminate at or before the
server so credentials and tool traffic are never carried in cleartext.

### Auth × TLS Deployment Matrix

Choosing a posture means selecting **both** an auth mode and a TLS mode. The
table below covers all nine combinations across the full 3 × 3 grid:

| Auth mode | TLS mode | Posture | Use when |
|-----------|----------|---------|----------|
| `none` | `none` (plain) | Development only | Local loopback (`127.0.0.1`) / single-user dev. **Never expose beyond the local host.** |
| `none` | `https` | Not recommended as-is | Transport encryption without request auth. Only acceptable when a TLS-terminating proxy in front of the server enforces authentication. |
| `none` | `mtls` | Not recommended as-is | mTLS enforces a transport-level peer identity; still no application-layer auth. Pair with `oauth` for per-client identity (`bearer` adds one shared secret, a single identity for every caller). |
| `bearer` | `none` (plain) | Trusted-LAN only | Shared-secret auth but token travels in cleartext. Safe only on a physically-secured private network or loopback. |
| `bearer` | `https` | Trusted LAN / VPN | **Recommended for private deployments**: shared-secret auth plus transport encryption. |
| `bearer` | `mtls` | High-assurance internal | Adds mutual transport identity on top of shared-secret auth. Suitable for zero-trust internal networks. |
| `oauth` | `none` (plain) | Avoid | Per-client JWT validation but tokens travel in cleartext. Only tolerable behind a TLS-terminating proxy. |
| `oauth` | `https` | Internet-exposed | **Recommended public posture**: per-client signed, expiring tokens plus transport encryption. |
| `oauth` | `mtls` | Zero-trust / multi-tenant | Maximum assurance: mutual transport identity plus per-client application identity. For high-security or zero-trust network deployments. |

**Key rules:**

- **mTLS is a transport boundary, not an application identity system.** It verifies
  that a client's certificate was issued by a trusted CA but does not identify
  individual users or API clients. Pair it with an application auth mode: `oauth` for
  per-client identity, or `bearer` for one shared secret (every bearer caller is the
  same identity).
- Bearer auth is not a standalone public-internet boundary (see the warning in the
  `bearer` section above). A single static shared secret gives no way to distinguish
  or revoke individual clients.
- Internet-exposed = `oauth` over HTTPS (`MCP_AUTH_MODE=oauth` +
  `MCP_TLS_MODE=https`), or front the server with a TLS-terminating reverse proxy
  that performs authentication before forwarding requests.

For per-mode configuration see [`docs/AUTH-OAUTH.md`](../docs/AUTH-OAUTH.md) (OAuth)
and [`docs/TLS.md`](../docs/TLS.md) (HTTPS / mTLS).
