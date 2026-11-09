# Client setup

The package commands in this guide install the published 0.7.1 release, and the guide describes 0.7.1 source. Upgrading from 0.7.0? See the [0.7.1 migration guide](MIGRATING-0.7.1.md) before changing settings.

Choose your MCP client below. Local setups run the server on your machine with your own UniFi API key; the ChatGPT option uses a self-hosted remote server. Your AI client may use its own services. Local stdio setups use [uv](https://docs.astral.sh/uv/); Docker deployments need Docker instead.

### Install as a Claude Code plugin

The [`plugins/claude/`](../plugins/claude/) folder is a Claude Code plugin. It runs this server locally through `uvx` with the API key you enter when you enable it (kept in Claude Code's secure credential storage), and it has optional Write policy and Tool mode settings. UniFi requests go from your machine to `api.ui.com`; Claude Code may use its own services. It works in Claude Code (terminal, IDE extensions and the desktop Code tab). Claude Desktop chat runs local servers configured through `claude_desktop_config.json`; see [Use with Claude Desktop](#use-with-claude-desktop). The claude.ai web and mobile chat clients do not run local MCP servers. See the [plugin README](../plugins/claude/README.md) for what it runs, where data goes, and example prompts, and [PRIVACY.md](../PRIVACY.md) for the privacy policy.

Install it from this repository's marketplace (Claude Code 2.1.275 or later installs in one step):

<!-- install-case: readme-install-09 mode=plugin -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-09 -->
```text
/plugin marketplace add swkstudios/unifi-fabric-mcp-server
/plugin install unifi-fabric@unifi-fabric
```

Claude Code asks for your API key, Write policy (`allow` by default; set it to `deny` for read-only) and Tool mode (discovery by default) when you enable it. Or try it for one session from a checkout:

<!-- install-case: readme-install-10 mode=plugin -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-10 -->
```bash
claude --plugin-dir ./plugins/claude
```

Without the plugin, register the server directly with `claude mcp add` as shown in [Connect your assistant](../README.md#2-connect-your-assistant) or [Track A](#track-a--local-stdio).

### Use with Claude Desktop

Claude Desktop chat runs local MCP servers from its config file (macOS and Windows; not claude.ai on the web or mobile). Open it with **Settings > Developer > Edit Config**:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

<!-- install-case: readme-install-11 mode=desktop -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-11 -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "command": "/absolute/path/to/uvx",
      "args": ["--from", "unifi-fabric-mcp-server==0.7.1", "unifi-fabric-mcp"],
      "env": { "UNIFI_API_KEY": "your-api-key-here" }
    }
  }
}
```

Replace `/absolute/path/to/uvx` with the output of `which uvx` (macOS) or `where uvx` (Windows): an app started from the Dock or Start menu may not see `~/.local/bin` or other shell `PATH` entries. Add `"UNIFI_WRITE_POLICY": "deny"` to `env` to hide and refuse every write and action tool. Then quit Claude Desktop completely and start it again. The key sits in this file in plain text, so keep the file private.

On macOS or Windows you can instead install the Claude Desktop extension bundle (`.mcpb`), built from [`plugins/claude-desktop/`](../plugins/claude-desktop/): Claude Desktop asks for the key at install time and keeps it in its secure storage. See the [bundle README](../plugins/claude-desktop/README.md).

### Use with OpenAI Codex

The Codex CLI, the Codex IDE extension and the ChatGPT desktop app share `~/.codex/config.toml`, so one setup serves all three. ChatGPT on the web cannot start local servers; see [Use with ChatGPT (self-hosted)](#use-with-chatgpt-self-hosted).

**Recommended: forward the key from your environment (nothing stored).** Add this to `~/.codex/config.toml`:

<!-- install-case: readme-install-12 mode=codex -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-12 -->
```toml
[mcp_servers.unifi-fabric]
command = "uvx"
args = ["--from", "unifi-fabric-mcp-server==0.7.1", "unifi-fabric-mcp"]
env_vars = ["UNIFI_API_KEY", "UNIFI_WRITE_POLICY"]   # forwarded from the environment Codex starts in
```

Then start Codex from a shell that has the key (the `read` keeps it out of your shell history):

<!-- install-case: readme-install-13 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-13 -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo; export UNIFI_API_KEY
export UNIFI_WRITE_POLICY=deny   # optional: read-only mode
codex
```

**One-liner (stores the key in `config.toml` in plain text):**

<!-- install-case: readme-install-14 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-14 -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo
codex mcp add unifi-fabric --env UNIFI_API_KEY="$UNIFI_API_KEY" -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

Add `--env UNIFI_WRITE_POLICY=deny` for read-only mode. `codex mcp list` shows the server.

**ChatGPT desktop app:** it reads the same `config.toml`, and its servers are listed under **Settings > MCP servers** (**Add server** for a new one, then **Restart**). An app started from the Dock or Finder does not see variables exported in a terminal, so `env_vars` forwarding only works when Codex starts from a shell; for the desktop app, give the key with the one-liner above (or an `env = { UNIFI_API_KEY = "your-api-key-here" }` line in the `[mcp_servers.unifi-fabric]` table).

**Codex plugin:** this repository is also a Codex plugin marketplace ([`plugins/codex/`](../plugins/codex/)). The plugin stores no key; it forwards `UNIFI_API_KEY`, `UNIFI_WRITE_POLICY` and `UNIFI_TOOL_MODE` from the environment Codex starts in:

<!-- install-case: readme-install-15 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-15 -->
```bash
codex plugin marketplace add swkstudios/unifi-fabric-mcp-server
codex plugin add unifi-fabric@unifi-fabric
```

With no key in the environment the server exits at startup and Codex lists no unifi-fabric tools; a wrong key returns the upstream `HTTP 401` on the first tool call.

### Use with Google Antigravity

Antigravity starts local servers with the environment of the shell that started `agy`, and it does not expand `${VAR}` in `env` values. Keep the key out of config files by exporting it before you start `agy`:

<!-- install-case: readme-install-16 mode=antigravity -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-16 -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo; export UNIFI_API_KEY
export UNIFI_WRITE_POLICY=deny   # optional: read-only mode
agy mcp add unifi-fabric -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
agy
```

Or install the plugin from a checkout of this repository; it uses the same exported key:

<!-- install-case: readme-install-17 mode=antigravity -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-17 -->
```bash
agy plugin install ./plugins/antigravity
```

Antigravity 2.0 and the Antigravity IDE read the same `~/.gemini/config`, but when started from the Dock they do not see variables exported in a terminal. For them, store the key in the config instead (in plain text, in `~/.gemini/config/mcp_config.json`):

<!-- install-case: readme-install-18 mode=antigravity -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-18 -->
```bash
agy mcp add --env UNIFI_API_KEY="$UNIFI_API_KEY" unifi-fabric -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

Without a key the server exits at startup and Antigravity lists no unifi-fabric tools; a wrong key returns the upstream `HTTP 401` on the first tool call. See the [plugin README](../plugins/antigravity/README.md).

### Use with Gemini CLI

Google replaced the consumer Gemini CLI with Antigravity; Gemini CLI remains available to Enterprise and API-key users. This repository's root [`gemini-extension.json`](../gemini-extension.json) makes it a Gemini CLI extension that prompts at install time for your API key (stored in the system keychain) and the optional Write policy (enter `allow`, `dry-run` or `deny`; a blank value stops the server from starting) and Tool mode settings:

<!-- install-case: readme-install-19 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-19 -->
```bash
gemini extensions install https://github.com/swkstudios/unifi-fabric-mcp-server
```

We have checked the manifest against the [extension reference](https://geminicli.com/docs/extensions/reference/) but have not run it in Gemini CLI. Antigravity's `agy plugin import` also reads this manifest.

### Use with ChatGPT (self-hosted)

ChatGPT custom connectors use remote MCP servers over HTTPS, signed in with OAuth 2.1; they cannot start a local server or send an API key. You can still use this server with ChatGPT by hosting **your own** instance in OAuth mode behind your own identity provider and adding it as a custom MCP server. Never put this write-capable server on a public URL without authentication. The [self-hosted ChatGPT guide](CHATGPT.md) has the prerequisites, steps, a known limitation and a security checklist; that setup has not been tested end to end with ChatGPT.

A listing in the ChatGPT app directory would need a hosted service run by us. We do not run one, so there is no directory listing.

### Track A — Local (stdio)

Install from PyPI and run the server locally. The MCP client launches it as a subprocess over stdio. **Requires Python 3.12+** (or [uv](https://docs.astral.sh/uv/), which fetches a suitable Python for you).

<!-- install-case: readme-install-20 mode=uvx -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-20 -->
<!-- docs-fact: run -->
```bash
export UNIFI_API_KEY="your-api-key-here"
uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

Or install it once in an isolated environment:

<!-- install-case: readme-install-21 mode=pipx -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-21 -->
<!-- docs-fact: run -->
```bash
pipx install unifi-fabric-mcp-server==0.7.1
unifi-fabric-mcp
```

Or use a virtual environment you manage:

<!-- install-case: readme-install-22 mode=pip -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-22 -->
```bash
python3 -m venv .venv
.venv/bin/python -m pip install unifi-fabric-mcp-server==0.7.1
.venv/bin/unifi-fabric-mcp
```

For Claude Code, put this in `.mcp.json` at your project root (Claude Code asks you to approve it on first use). To register the server for all your projects, use `claude mcp add --scope user unifi-fabric -e UNIFI_API_KEY=… -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp`; Claude Code stores that configuration in `~/.claude.json`. Supported locations are documented by [Claude Code](https://code.claude.com/docs/en/mcp).

<!-- install-case: readme-install-23 mode=desktop -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-23 -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "command": "uvx",
      "args": ["--from", "unifi-fabric-mcp-server==0.7.1", "unifi-fabric-mcp"],
      "env": { "UNIFI_API_KEY": "your-api-key-here" }
    }
  }
}
```

If you installed with `pipx` or `pip` instead, use `"command": "unifi-fabric-mcp"` and omit `args`.

> **PATH note:** A bare `"command": "unifi-fabric-mcp"` only resolves if it is on the MCP client's `PATH`. Many MCP clients do not inherit the shell's virtual environment. Use `uvx` as above, the absolute path to the installed binary (for example `/path/to/.venv/bin/unifi-fabric-mcp`), or install globally with `pipx install unifi-fabric-mcp-server==0.7.1` or `uv tool install unifi-fabric-mcp-server==0.7.1`.

**Homebrew:** a Homebrew formula is planned, but there is no tap yet; follow [issue #24](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/24).

**Verify it works:** When launched by the client the server exits immediately if `UNIFI_API_KEY` is absent or empty; an incorrect key will not prevent startup but will cause tool calls to fail with an authentication error. A successful start produces no output on stdio (the client communicates over stdin/stdout).

### Track B — Docker (HTTP)

See [Docker HTTP setup and verification](DOCKER.md#track-b-docker-http).

<a id="unauthenticated-http-trusted-network-only"></a>

### Track C — From source (development)

<!-- install-case: readme-install-28 mode=source -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-28 -->
```bash
git clone https://github.com/swkstudios/unifi-fabric-mcp-server.git
cd unifi-fabric-mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -e .          # -e is editable/dev mode
export UNIFI_API_KEY="your-api-key-here"
unifi-fabric-mcp
```

See [setup](../AGENTS.md#setup) and [verification](../AGENTS.md#verify-without-committing) for hash-locked installation and targeted tests.

## Troubleshooting

### Common Setup Issues

**"ModuleNotFoundError: No module named 'unifi_fabric'"**
- Ensure the package is installed in the active environment: `pip install unifi-fabric-mcp-server==0.7.1` (or `pip install -e .` in a source checkout)
- Verify your Python version is 3.12+: `python3 --version`
- Try `pip install --upgrade pip` and reinstall if using an older pip version

**"command not found: unifi-fabric-mcp"**
- The entry point is only available after installation: `pipx install unifi-fabric-mcp-server==0.7.1` (or `pip install -e .` in a source checkout), or run it on demand with `uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp`
- For local development, install the source checkout first: `python3 -m pip install -e .`, then run `unifi-fabric-mcp`
- Check that your virtual environment is activated: `source .venv/bin/activate`

**A detached `docker compose up` of a stdio server exits with code 0**
- A stdio server needs a client on stdin/stdout. Configure your MCP client to spawn it instead: see [Override Transport in Docker Compose](CONFIGURATION.md#override-transport-in-docker-compose)

**Startup exits with code 2 and `startup:<NAME>`**
- The named policy setting is invalid. `UNIFI_WRITE_POLICY` accepts `allow`, `dry-run` or `deny`; see [write switches](CONFIGURATION.md#write-switches) for the grammar of `UNIFI_WRITE_EXCEPTIONS`. Correct the setting and restart.

**Docker fails to start with "exit code 1"**
- Exit code 1 at startup means a configuration error: a missing key ("UNIFI_API_KEY is not set") or a malformed setting ("invalid configuration: <reason>"), printed on stderr. Read it with `docker logs <container-id>`
- Startup makes no upstream call, so an unreachable `api.ui.com` or a rejected key does not stop the server; it shows up on the first tool call

### Environment Variable Misconfiguration

**"unrecognized settings: ... Settings were renamed"** at startup, upgrading from 0.7.0
- The server found a `UNIFI_*` variable it does not know (exit status 2, last stderr line `startup:retired:<NAME>`). Upgrading from 0.7.0: rename the settings with [MIGRATING-0.7.1.md](MIGRATING-0.7.1.md) or its one-command migrator; a typo in a current setting name fails the same way

**"401 Unauthorized" or "Invalid API key"**
- Verify your `UNIFI_API_KEY` is correct — copy it directly from [UniFi Site Manager](https://unifi.ui.com) **API Keys** (left sidebar)
- API keys expire or may be regenerated; if recently created, use the new key
- Ensure no trailing whitespace in the env var: `export UNIFI_API_KEY="key-here"` (not `"key-here "`). Startup rejects a key holding whitespace, naming the variable

**"UNIFI_API_KEYS" JSON parse error**
- Use proper JSON formatting: `[{"key": "...", "label": "..."}, ...]`
- Escape quotes correctly in shell: `export UNIFI_API_KEYS='[{"key":"your-key"}]'` (single quotes)
- In a Docker `--env-file`, write the value **without** surrounding quotes: the Docker CLI keeps them literally and they break JSON parsing. Compose `env_file:` removes surrounding quotes, but an unquoted line works with both ([details](CONFIGURATION.md#multi-key-msp-setup))
- Validate locally after setting the variable: `python3 -c 'import json, os; json.loads(os.environ["UNIFI_API_KEYS"]); print("Valid JSON")'`. Keep API keys out of online validators and public issue reports

**"Base URL is incorrect" or "api.ui.com not found"**
- The default base URL is `https://api.ui.com`. Leave `UNIFI_API_BASE_URL` unset for real UniFi data
- Override it only to point the server at a mock or a private endpoint you run, for example `UNIFI_API_BASE_URL="http://127.0.0.1:8765"`. Every request, including your API key, is sent to that URL, so use only a host you trust
- It must be an absolute `http(s)` URL with a host and no credentials, query or fragment; startup rejects anything else, naming the variable. A trailing slash is ignored
- A redirect from the configured URL is not followed: the call fails with an error that names `UNIFI_API_BASE_URL`

### Connection Errors

**"Connection refused" or "Cannot connect to api.ui.com"**
- Check your internet connection: `ping api.ui.com`
- Verify your firewall/proxy allows outbound HTTPS (port 443)
- Behind an outbound proxy, set `HTTPS_PROXY` in the server's environment
- The server makes requests to `https://api.ui.com/v1/` — ensure this endpoint is reachable

**"Certificate verification failed" or "SSL: CERTIFICATE_VERIFY_FAILED"**
- This typically occurs behind corporate proxies with MITM certificate injection
- The UniFi API client trusts the certifi bundle, not the system trust store; keep it current with `pip install --upgrade certifi`
- For a corporate CA, set `SSL_CERT_FILE` to a PEM bundle that contains it (or `SSL_CERT_DIR` to a directory of them); importing it into the system trust store has no effect
- Certificate verification of the UniFi API cannot be turned off

**"Request timeout" or "socket timeout"**
- UniFi requests have no application elapsed-time deadline. The deprecated
  `UNIFI_REQUEST_TIMEOUT_SECONDS` setting has been removed; delete it from deployment configuration before upgrading.
- A timeout reported by a proxy, peer, or transport remains a network failure;
  inspect that source and connection progress rather than increasing a local cap.
- Check if `api.ui.com` is experiencing an outage: [status.ui.com](https://status.ui.com)
- If using Docker, ensure the container has network connectivity: `docker run --network host ...`

**"No hosts found" or "Site not found"**
- Your API key must have access to the sites you're querying. Verify in [UniFi Site Manager](https://unifi.ui.com) by opening **API Keys**, then the key, then **Sites**
- Which sites a key sees is set on the key in Site Manager (its Sites selection). `is_org_key` in `UNIFI_API_KEYS` is only a label the server reports back; it does not change access
- If you just created the key or changed site permissions, wait 1-2 minutes for propagation and retry. The server also caches host and site lists for `UNIFI_CACHE_TTL_SECONDS` (default 900 s), and a not-found lookup does not refresh them: restart the server, or wait up to 15 minutes

### Errors you may see

**"HTTP 403" from a tool call** — The key lacks the scope for that product. Edit the key in UniFi Site Manager (API Keys) and enable Site Manager, Network, and Protect as needed. The error carries a hint naming the key and pointing at [step 1 of the README installation](../README.md#1-join-your-fabric-and-create-an-api-key).

**"refused: the server is in read-only mode"** — `UNIFI_WRITE_POLICY=deny` is set. Unset it or set it to `allow` (or set the plugin's Write policy option to `allow`) in the configuration that starts the server, and restart the server to allow writes. See [Read-only mode](CONFIGURATION.md#read-only-mode).

**`ambiguous site '<name>'` / `ambiguous host '<name>'`** — Several sites or consoles share that name. Pass the id from `list_sites` / `list_hosts` instead.

**`cannot resolve '<name>' unambiguously`** — The site or console list is incomplete, because a page cap (`UNIFI_PAGINATE_MAX_PAGES`) stopped it or the list drain stopped short, so another object with that name may exist. Use the exact id (unsetting the cap helps only in the first case).

**`Classic API error from <METHOD> <path>: HTTP 200 with meta.rc 'error' (meta.msg 'api.err.…')`** — The Network controller rejected the request in its Classic response body although the HTTP status was 200. Every typed tool treats that as an upstream error and quotes the complete body (`meta` and `data`); `meta.msg` names the controller's reason (an invalid value, an unknown object).

**Server starts but no tools appear (Codex, Antigravity)** — Usually the server did not start: the key was not in the environment of the process that launched the client, so it exited with "UNIFI_API_KEY is not set" on stderr. Export `UNIFI_API_KEY` and restart the client. Seeing only five tools is normal: that is [discovery mode](CONFIGURATION.md#tool-catalog-mode-unifi_tool_mode).

### Getting Help

- Check [developer.ui.com](https://developer.ui.com) for API documentation and latest firmware compatibility
- Search existing [GitHub issues](https://github.com/swkstudios/unifi-fabric-mcp-server/issues) for your problem
- Include the following in bug reports:
  - Tool name and parameters you were using
  - Full error message (redact your API key and sensitive IPs)
  - Server version (`unifi-fabric-mcp --version`)
  - Python version (`python3 --version`) and OS
  - Docker image tag (if applicable)
  - Relevant env vars (without secrets)
