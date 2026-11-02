# Use with ChatGPT (self-hosted)

> **Status: not end-to-end tested with ChatGPT.** The server-side pieces ChatGPT needs (OAuth protected-resource metadata, the `401` challenge, JWT verification) were checked against a local run of this server; the full sign-in flow from ChatGPT has not been run by the maintainers.

ChatGPT can talk to an MCP server you host yourself, as a **custom MCP server**. This is not a listing in the ChatGPT app directory: a directory listing needs a hosted service, and we do not run one. You run your own instance, with your own UniFi API key, on infrastructure you control.

ChatGPT connects only to remote servers over HTTPS and authenticates with **OAuth 2.1 or no authentication**. It cannot send a static bearer token or API key ([OpenAI: Authentication](https://developers.openai.com/apps-sdk/build/auth)). So the only safe setup is this server's OAuth mode (`MCP_AUTH_MODE=oauth`, see [AUTH-OAUTH.md](AUTH-OAUTH.md)) behind an identity provider you operate.

> **Never expose this server without authentication.** It is a write-capable network controller: with `MCP_AUTH_MODE=none` on a public URL, anyone who finds the URL can reconfigure or restart your UniFi network.

## What you need

1. **A public HTTPS URL for the server**, either your own domain behind a TLS-terminating reverse proxy, or OpenAI's [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels), which connects a private server without opening it to the internet.
2. **An OAuth 2.1 identity provider (IdP)** that ChatGPT can use as the authorization server. This server is only the *resource server*: it verifies tokens but does not issue them, host a login page or register clients. Your IdP must:
   - publish discovery metadata (`/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`);
   - support the authorization-code flow with PKCE and list `S256` in `code_challenge_methods_supported`;
   - let ChatGPT register itself, with Client ID Metadata Documents (CIMD) or Dynamic Client Registration (DCR), or accept a client you create for ChatGPT by hand;
   - put the `resource` value ChatGPT sends (your server URL ending in `/mcp`) into the access token's `aud` claim;
   - sign access tokens as JWTs with a published JWKS, using RS256 (the default) or another algorithm you accept with `MCP_OAUTH_ALGORITHM`.

   OpenAI's guide lists providers with MCP support, for example Auth0. Check your provider's MCP documentation for the exact settings.
3. **A ChatGPT account whose plan and workspace allow custom MCP servers.** OpenAI notes that account and workspace policies apply; check what your plan offers before you start.

## Steps

1. **Run the server with OAuth on HTTP.** Use the Docker image or `uvx` with these variables (the `/mcp` path matters: the advertised resource is `MCP_OAUTH_BASE_URL` plus `/mcp`):

<!-- doc-provenance: source=file:src/unifi_fabric/server.py@sha256:7bb79c7ee98ee6627c7533892f7363c5376e37dbea251ea066c906fe7ae723d4 support=0.7.0 citation=file:src/unifi_fabric/server.py@sha256:7bb79c7ee98ee6627c7533892f7363c5376e37dbea251ea066c906fe7ae723d4 -->
<!-- install-case: docs-chatgpt-1 mode=non-executable reason=remote-deployment-requires-user-host -->
   ```bash
   export UNIFI_API_KEY="your-api-key-here"
   export FASTMCP_TRANSPORT=streamable-http
   export MCP_AUTH_MODE=oauth
   export MCP_OAUTH_BASE_URL="https://unifi-mcp.example.com"
   export MCP_OAUTH_AUDIENCE="https://unifi-mcp.example.com/mcp"   # equals the advertised resource
   export MCP_OAUTH_ISSUER="https://idp.example.com/"                # exactly as your IdP's metadata "issuer"
   export MCP_OAUTH_JWKS_URI="https://idp.example.com/.well-known/jwks.json"
export MCP_ALLOWED_HOSTS="unifi-mcp.example.com"                  # the Host header your proxy forwards
   export MCP_OAUTH_REQUIRED_SCOPES="fabric:read"                    # optional; advertised to ChatGPT
   uvx --from unifi-fabric-mcp-server==0.7.0 unifi-fabric-mcp
   ```

   `MCP_ALLOWED_HOSTS` matters when the server listens on loopback behind a reverse proxy: the Host check then refuses any other host name with `421 Misdirected Request`. List your public host name (see [Host and Origin validation](AUTH-TLS.md#host-and-origin-validation)).

   Consider `UNIFI_READ_ONLY=1` until you trust the setup; it hides write-only tools and refuses write and action requests. The generic GET connector remains available for ordinary reads. Writes are on by default.

2. **Check discovery from outside.** Both must work over HTTPS:

<!-- doc-provenance: source=file:src/unifi_fabric/server.py@sha256:7bb79c7ee98ee6627c7533892f7363c5376e37dbea251ea066c906fe7ae723d4 support=0.7.0 citation=file:src/unifi_fabric/server.py@sha256:7bb79c7ee98ee6627c7533892f7363c5376e37dbea251ea066c906fe7ae723d4 -->
<!-- install-case: docs-chatgpt-2 mode=non-executable reason=remote-deployment-requires-user-host -->
   ```bash
   curl -s https://unifi-mcp.example.com/.well-known/oauth-protected-resource/mcp
   curl -s -i -X POST https://unifi-mcp.example.com/mcp | grep -i www-authenticate
   ```

   The first returns `{"resource":"https://unifi-mcp.example.com/mcp","authorization_servers":[...],...}`. The second shows `WWW-Authenticate: Bearer ... resource_metadata="https://unifi-mcp.example.com/.well-known/oauth-protected-resource/mcp"`, which is how ChatGPT finds the metadata (the bare `/.well-known/oauth-protected-resource` path returns 404 by design).

3. **Add it in ChatGPT.** Open [ChatGPT Plugins](https://chatgpt.com/plugins), select **+**, then **Add custom MCP server**. Enter a name, choose your public URL (including `/mcp`) or your tunnel, select OAuth, review the risk warning and continue. ChatGPT then sends you through your IdP's sign-in ([OpenAI: Connect and test](https://developers.openai.com/apps-sdk/deploy/connect-chatgpt)).

4. **Register the redirect URI** that ChatGPT's management page shows for the connection in your IdP's allowlist.

## Exact issuer matching

The server publishes the authorization-server issuer exactly as configured in `MCP_OAUTH_ISSUER`, including whether it has a trailing slash. Use the exact `issuer` string from your IdP's discovery metadata; the same string is used to validate token `iss` claims. Issuers with and without a path are supported.

## Security checklist

- OAuth mode only; never `none`, and never the static `bearer` mode on a public URL (ChatGPT cannot use it anyway).
- Require a scope (`MCP_OAUTH_REQUIRED_SCOPES`) and grant it only to the people who should manage your network.
  OAuth scopes control admission to the whole server. `MCP_OAUTH_REQUIRED_SCOPES` decides which tokens
  get in, and a scope named `fabric:read` does not disable write tools on its own. To restrict writes per token, set `MCP_OAUTH_WRITE_SCOPE`
  (opt-in, unset by default): a write tool, or a `fabric_connector_get` call to a known state-changing
  GET route, is then refused before it runs unless the caller's token also carries that scope; read
  tools need only the admission scopes. All admitted clients use the deployment's configured UniFi
  key(s), tool catalog and write settings. For an instance with no write path at all, run it with
  `UNIFI_READ_ONLY=1`; use separate instances and keys when callers need different UniFi permissions.
  See [Scopes and write access](AUTH-OAUTH.md#scopes-and-write-access).
- Prefer the Secure MCP Tunnel over a public port. With a public URL, you can also restrict the server to [ChatGPT's published egress IP ranges](https://developers.openai.com/api/docs/guides/ip-addresses) or require ChatGPT's mTLS client certificate at your proxy ([OpenAI: Authentication](https://developers.openai.com/apps-sdk/build/auth)).
- Keep your UniFi API key on the server only; it never goes to ChatGPT. Tool results (device lists, Wi-Fi passphrases and other credential fields the API returns) do go to ChatGPT; set `UNIFI_REDACT_SECRETS=1` to mask credential fields.
