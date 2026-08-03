# Security Policy

## Supported Versions

We provide security fixes for the latest release only.

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| older   | No        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's **Private Vulnerability Reporting** feature to disclose security issues
privately: navigate to the **Security** tab of whichever repository you are working
from and click **"Report a vulnerability"**. We aim to acknowledge reports within
5 business days and will coordinate a fix and public disclosure timeline with you.

When reporting, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (if applicable).
- Any suggested mitigations.

We follow responsible disclosure and will credit reporters in the release notes unless you
prefer to remain anonymous.

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

Tool responses include all upstream API fields without filtering, including credential
fields (WLAN passphrases, RADIUS secrets, DDNS passwords), GPS coordinates, and Protect
recognition data. Transport security is therefore load-bearing — an inadequately secured
listener exposes complete network credentials and sensitive data, not just network visibility.

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
multi-tenant deployments, because it provides per-client identity, scoped authorization,
and token expiry rather than a single shared secret.

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
| `none` | `mtls` | Not recommended as-is | mTLS enforces a transport-level peer identity; still no application-layer auth. Pair with `bearer` or `oauth` for per-client identity. |
| `bearer` | `none` (plain) | Trusted-LAN only | Shared-secret auth but token travels in cleartext. Safe only on a physically-secured private network or loopback. |
| `bearer` | `https` | Trusted LAN / VPN | **Recommended for private deployments**: shared-secret auth plus transport encryption. |
| `bearer` | `mtls` | High-assurance internal | Adds mutual transport identity on top of shared-secret auth. Suitable for zero-trust internal networks. |
| `oauth` | `none` (plain) | Avoid | Per-client JWT validation but tokens travel in cleartext. Only tolerable behind a TLS-terminating proxy. |
| `oauth` | `https` | Internet-exposed | **Recommended public posture**: per-client signed, expiring tokens plus transport encryption. |
| `oauth` | `mtls` | Zero-trust / multi-tenant | Maximum assurance: mutual transport identity plus per-client application identity. For high-security or zero-trust network deployments. |

**Key rules:**

- **mTLS is a transport boundary, not an application identity system.** It verifies
  that a client's certificate was issued by a trusted CA but does not identify
  individual users or API clients. Always pair it with `bearer` or `oauth` for
  application-level identity.
- Bearer auth is not a standalone public-internet boundary (see the warning in the
  `bearer` section above). A single static shared secret gives no way to distinguish
  or revoke individual clients.
- Internet-exposed = `oauth` over HTTPS (`MCP_AUTH_MODE=oauth` +
  `MCP_TLS_MODE=https`), or front the server with a TLS-terminating reverse proxy
  that performs authentication before forwarding requests.

For per-mode configuration see [`docs/AUTH-OAUTH.md`](../docs/AUTH-OAUTH.md) (OAuth)
and [`docs/TLS.md`](../docs/TLS.md) (HTTPS / mTLS).
