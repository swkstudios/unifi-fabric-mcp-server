# In-server TLS (HTTPS)

The server can terminate TLS itself when run over an HTTP transport
(`streamable-http` or `sse`). This is selected with the `MCP_TLS_*` environment
variables and is independent of the auth selector (`MCP_AUTH_MODE`).

TLS applies to HTTP transports only. With `FASTMCP_TRANSPORT=stdio`, setting any
`MCP_TLS_MODE` other than `none` is a configuration error and the server refuses
to start (fail-closed) — stdio has no socket to wrap.

> **Production PKI is out of scope for this repository.** The instructions below
> generate a throwaway self-signed certificate for **local development and
> testing only**. For any real deployment, obtain certificates from your own CA
> or ACME provider and mount them into the runtime; never commit key material to
> the repo.

## Modes

`MCP_TLS_MODE` selects the TLS posture:

| Mode     | Server cert | Client cert (mTLS) | Typical use                          |
| -------- | ----------- | ------------------ | ------------------------------------ |
| `none`   | no          | no                 | default; terminate TLS at a proxy    |
| `https`  | yes         | no                 | in-server HTTPS, server-auth only    |
| `mtls`   | yes         | yes (verified)     | mutual TLS — client cert required at handshake |

## Environment variables

| Variable               | Required when            | Purpose                                                   |
| ---------------------- | ------------------------ | --------------------------------------------------------- |
| `MCP_TLS_MODE`         | always (to enable)       | `none` \| `https` \| `mtls`                               |
| `MCP_TLS_CERTFILE`     | `https`, `mtls`          | Path to the server certificate (PEM).                     |
| `MCP_TLS_KEYFILE`      | `https`, `mtls`          | Path to the server private key (PEM).                     |
| `MCP_TLS_KEY_PASSWORD` | optional                 | Password for an encrypted private key.                    |
| `MCP_TLS_CA_CERTS`     | `mtls`                   | Client CA bundle used to verify client certificates.      |
| `MCP_TLS_CERT_REQS`    | optional (`mtls` only)   | `none` \| `optional` \| `required` client-cert checking.  |

### `MCP_TLS_CERT_REQS` (mTLS only)

`MCP_TLS_CERT_REQS` controls how strictly client certificates are verified and
only applies to `mtls`:

- `required` (the default under `mtls`) — every client must present a valid
  certificate that chains to `MCP_TLS_CA_CERTS`.
- `optional` — a client certificate is verified if presented, but not demanded.
- `none` — **rejected under `mtls`.** mTLS exists to verify client certificates,
  so disabling the check while advertising mTLS is a fail-closed error; the
  server refuses to start. Use `MCP_TLS_MODE=https` if you do not want client
  certificates at all.

Under `MCP_TLS_MODE=https` the server never requests a client certificate (the
effective level is `CERT_NONE`); the selector is ignored.

## Generate a self-signed cert/key for dev/testing

A single self-signed certificate (no separate CA) is enough to exercise
`https` locally. Generate one valid for `localhost` / `127.0.0.1`:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout dev-key.pem -out dev-cert.pem \
  -days 7 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"
```

This writes an unencrypted `dev-key.pem` and a matching `dev-cert.pem`. Keep
both out of version control (they are dev throwaways).

> **Python 3.13+:** Python 3.13 enforces CA key-usage extensions when a certificate
> is used as a trust anchor. The `basicConstraints` and `keyUsage` extensions above are
> required — without them, Python 3.13 fails with
> `CA cert does not include key usage extension (_ssl.c:1029)`. Earlier Python versions
> accept certs without these extensions.

## Run with in-server HTTPS

```sh
export FASTMCP_TRANSPORT=streamable-http
export FASTMCP_HOST=127.0.0.1
export FASTMCP_PORT=3000
export MCP_TLS_MODE=https
export MCP_TLS_CERTFILE="$PWD/dev-cert.pem"
export MCP_TLS_KEYFILE="$PWD/dev-key.pem"
export UNIFI_API_KEY=...        # your Site Manager API key

unifi-fabric-mcp
```

The server now listens for HTTPS on the configured host/port. Because the
certificate is self-signed, clients must trust it explicitly — point the client
at the certificate (or its issuing CA) rather than disabling verification:

```sh
# Smoke-test the TLS handshake against the MCP endpoint.
# --max-time 3 disconnects after headers are received; a GET /mcp opens a
# persistent SSE stream so curl would otherwise hang indefinitely.
curl --max-time 3 --cacert dev-cert.pem \
  -H "Accept: application/json, text/event-stream" \
  -s -o /dev/null -w "%{http_code}\n" \
  https://127.0.0.1:3000/mcp
```

The automated proof of this path lives in `tests/test_tls_socket.py`: it stands
up the server over a real ephemeral socket with an in-memory CA, confirms a
client trusting the right CA completes the handshake and a live MCP request,
and confirms a client trusting the wrong CA is rejected.

## Container HEALTHCHECK requirement when HTTPS is enabled

> **Important — read this before enabling in-server HTTPS in a container.**

The published image's default `HEALTHCHECK` is a bare TCP-connect probe, which
keeps working under TLS because it only opens a socket. **However, if you
override the healthcheck with an application-level (HTTP) probe, that probe must
match the actual listener** — both the scheme **and** the port:

- Use `https://` (not `http://`) once `MCP_TLS_MODE=https` is set. An `http://`
  probe against a TLS port fails the handshake and the container is marked
  unhealthy even though the server is fine.
- Target the **bound** port (`FASTMCP_PORT`), not a stale hard-coded one. A
  scheme/port-mismatched healthcheck was a real defect caught in review; do not
  reintroduce it.
- The self-signed dev certificate will not validate against system trust, so an
  HTTP-level probe must point at the cert/CA (e.g. `curl --cacert ...`) or the
  probe itself will fail closed.

Example override (adjust the port to your `FASTMCP_PORT`). An HTTP GET to
`/mcp` opens a persistent SSE stream, so a bare `curl https://.../mcp` hangs
until Docker SIGKILLs it (exit 137 = unhealthy). Use a TLS handshake probe
instead — it verifies the certificate without touching the HTTP layer. In non-dev deployments replace `'127.0.0.1'` with the DNS name your cert was issued for (e.g. `'mcp.example.com'`):

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python3 -c "\
import ssl, socket; \
ctx = ssl.create_default_context(cafile='/certs/cert.pem'); \
s = ctx.wrap_socket(socket.create_connection(('127.0.0.1', 3000), timeout=5), \
    server_hostname='127.0.0.1'); \
s.close()" || exit 1
```

This confirms the TLS handshake succeeds (correct certificate, server is up)
without opening an HTTP stream that would hang.

The default `Dockerfile` is intentionally left on the TCP probe and is not
changed by enabling these variables — switching the healthcheck is the operator's
responsibility when they front the server with in-server HTTPS.

## Mutual TLS (mTLS): require a client certificate

`MCP_TLS_MODE=mtls` builds on `https` and additionally **requires every client to
present a certificate that chains to a CA bundle you control** (`MCP_TLS_CA_CERTS`).
The TLS handshake is rejected for any client that presents no certificate or a
certificate signed by an untrusted CA. By default the client-cert check is
`required` (see [`MCP_TLS_CERT_REQS`](#mcp_tls_cert_reqs-mtls-only) above);
`MCP_TLS_CERT_REQS=none` is rejected fail-closed under `mtls`.

> **mTLS is a network / transport boundary, not an application identity.** A
> verified client certificate proves the connection terminates at a peer holding
> a key your CA signed — it does **not** tell the application *which user* is
> calling, and this server does not map the certificate subject to any app-level
> principal. If you need application identity (per-caller authorization, audit,
> scopes), **pair mTLS with an app-auth mode** (`MCP_AUTH_MODE=bearer` or
> `oauth`). The two compose: mTLS gates the transport, app-auth gates the request.

## Generate a CA + server cert + client cert for dev/testing

Production PKI is out of scope (see the warning at the top of this doc). The
commands below mint a throwaway local CA and issue a server cert (for
`localhost` / `127.0.0.1`) and a client cert from it — enough to exercise `mtls`
locally. Nothing here is committed; keep every `*.pem`, `*.csr`, and `*.srl`
file out of version control.

```bash
# bash required — the <(...) process substitution below is a bash feature and will
# fail with a syntax error or be treated as a literal filename under sh/dash/zsh.
# Run these commands in bash (e.g. `bash` or `#!/usr/bin/env bash`).

# 1. A throwaway local CA (root key + self-signed cert).
#    The basicConstraints and keyUsage extensions are required for Python 3.13+,
#    which enforces these when the cert is used as a trust anchor.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca-key.pem -out ca-cert.pem \
  -days 7 -subj "/CN=Dev Local CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. Server key + CSR, signed by the CA. SAN must cover the address clients use.
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 7 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# 3. Client key + CSR, signed by the SAME CA. The subject is cosmetic — mTLS here
#    is transport admission, not application identity.
openssl req -newkey rsa:2048 -nodes \
  -keyout client-key.pem -out client.csr \
  -subj "/CN=dev-mtls-client"
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out client-cert.pem -days 7
```

`ca-cert.pem` is the bundle the **server** uses to verify client certificates
(`MCP_TLS_CA_CERTS`); it is also what the **client** trusts to verify the server
cert. In a real deployment the server cert and the client-signing CA are often
different CAs — split them as needed.

## Run with in-server mTLS

```sh
export FASTMCP_TRANSPORT=streamable-http
export FASTMCP_HOST=127.0.0.1
export FASTMCP_PORT=3000
export MCP_TLS_MODE=mtls
export MCP_TLS_CERTFILE="$PWD/server-cert.pem"
export MCP_TLS_KEYFILE="$PWD/server-key.pem"
export MCP_TLS_CA_CERTS="$PWD/ca-cert.pem"   # CA that signed the client cert(s)
export UNIFI_API_KEY=...        # your Site Manager API key

unifi-fabric-mcp
```

The server now demands a client certificate during the TLS handshake. A client
must present its cert/key **and** trust the server CA:

```sh
# Succeeds: presents a client cert that chains to MCP_TLS_CA_CERTS.
# --max-time 3 disconnects after headers are received; a GET /mcp opens a
# persistent SSE stream so curl would otherwise hang indefinitely.
curl --max-time 3 --cacert ca-cert.pem \
  --cert client-cert.pem --key client-key.pem \
  -H "Accept: application/json, text/event-stream" \
  -s -o /dev/null -w "%{http_code}\n" \
  https://127.0.0.1:3000/mcp

# Rejected at the handshake: no client certificate presented.
curl --cacert ca-cert.pem \
  -H "Accept: application/json, text/event-stream" \
  https://127.0.0.1:3000/mcp
```

A certificate signed by any other (untrusted) CA is rejected the same way.

The automated proof of this path lives in `tests/test_mtls_socket.py`: it stands
the server up over a real ephemeral socket with an in-memory CA, then asserts
that a **valid** client cert completes the handshake and a live MCP `initialize`,
while a request with **no** client cert and a request with a **foreign-CA** client
cert are both rejected (the two reject cases are the security-load-bearing checks
and run in CI by default — no runtime skip).

## Container HEALTHCHECK requirement under mTLS

The published image's default `HEALTHCHECK` is a bare TCP-connect probe. It keeps
working under `mtls` because it only opens a socket and **never starts the TLS
handshake**, so `CERT_REQUIRED` is never triggered — no client cert is needed.

**If you override the healthcheck with an application-level probe, that probe
must itself present a client certificate**, or the server will reject it and the
container will be marked unhealthy while the server is fine. An HTTP GET to `/mcp`
also opens a persistent SSE stream, so a bare `curl https://.../mcp` under mTLS
would be killed by Docker (exit 137 = unhealthy) even with a valid client cert.
Use a TLS handshake probe that presents the client cert without issuing any HTTP
request. In non-dev deployments replace `'127.0.0.1'` with the DNS name your server cert was issued for (e.g. `'mcp.example.com'`):

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python3 -c "\
import ssl, socket; \
ctx = ssl.create_default_context(cafile='/certs/ca-cert.pem'); \
ctx.load_cert_chain('/certs/client-cert.pem', '/certs/client-key.pem'); \
s = ctx.wrap_socket(socket.create_connection(('127.0.0.1', 3000), timeout=5), \
    server_hostname='127.0.0.1'); \
s.close()" || exit 1
```

This confirms the mTLS handshake succeeds (server cert trusted, client cert
accepted) without opening an HTTP stream.

As with HTTPS, the default `Dockerfile` is left on the TCP probe and is not
changed by enabling `mtls`. Either keep the TCP probe (no client cert needed), or
use an mTLS handshake probe as above — switching the healthcheck is the operator's
responsibility.

## MCP client configuration when TLS is enabled

### HTTPS (`MCP_TLS_MODE=https`)

Once in-server HTTPS is active, the client URL must change from `http://` to `https://`. No `Authorization` header is required when `MCP_AUTH_MODE=none` (the server enforces no application-layer auth; network-level access control is assumed):

`streamable-http` transport:

```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "https://localhost:3000/mcp"
    }
  }
}
```

`sse` transport (`FASTMCP_TRANSPORT=sse`):

```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "sse",
      "url": "https://localhost:3000/sse"
    }
  }
}
```

When adding bearer auth on top (`MCP_AUTH_MODE=bearer`), include `"headers": { "Authorization": "Bearer <token>" }` in either block above.

**Certificate trust:** The client must trust the server certificate.

- **Publicly trusted CA** (e.g. Let's Encrypt, your corporate CA): no extra client-side
  steps; the certificate chains to a root the client already trusts.
- **Self-signed cert** (dev/testing only): most MCP clients have no mechanism to supply a
  custom CA bundle. The connection will fail with a certificate-verification error unless
  you either:
  - import the self-signed certificate (or its issuing CA) into the system trust store
    of the machine running the MCP client, or
  - use a TLS-terminating reverse proxy (e.g. Traefik, Caddy, nginx) that terminates TLS
    with a publicly trusted certificate and proxies plain HTTP to the server.

For any deployment where clients cannot be configured to trust a self-signed cert, use a
publicly trusted certificate or run the server behind a TLS-terminating proxy.

### mTLS (`MCP_TLS_MODE=mtls`)

mTLS requires each *client* to present a certificate during the TLS handshake. Most MCP
clients (including Claude Code, Cline, and similar tools) have no built-in mechanism to
supply a client certificate. In practice this means:

- **Direct mTLS from an MCP client is not supported** by most clients.
- **The recommended path** is a TLS-terminating reverse proxy that presents a client
  certificate on behalf of the downstream MCP clients. The proxy handles mTLS toward the
  server; MCP clients connect to the proxy over plain HTTP or standard HTTPS.

If your MCP client does support custom TLS configuration (e.g. a programmatic client), it
must supply both the client certificate/key and trust the server certificate:

```bash
# curl equivalent of what a properly configured client would do
# --max-time 3 disconnects after receiving headers; a GET /mcp opens a
# persistent SSE stream so curl would otherwise hang indefinitely.
curl --max-time 3 --cacert ca-cert.pem \
  --cert client-cert.pem --key client-key.pem \
  -H "Accept: application/json, text/event-stream" \
  -s -o /dev/null -w "%{http_code}\n" \
  https://localhost:3000/mcp
```

The JSON client config would point at `https://` and rely on the system trust store for
the server CA; client-cert injection is outside the MCP client config spec and must be
handled at the operating-system or proxy level.
