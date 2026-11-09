<!-- mcp-name: io.github.swkstudios/unifi-fabric-mcp-server -->

<h1 align="center">UniFi Fabric MCP Server</h1>

<p align="center">Ask your AI assistant to check and manage your UniFi network.</p>

<p align="center">
  <a href="https://github.com/swkstudios/unifi-fabric-mcp-server/actions/workflows/ci.yml"><img src="https://github.com/swkstudios/unifi-fabric-mcp-server/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://pypi.org/project/unifi-fabric-mcp-server/"><img src="https://img.shields.io/pypi/v/unifi-fabric-mcp-server" alt="PyPI" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.12+-blue" alt="Python 3.12+" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://registry.modelcontextprotocol.io/?q=io.github.swkstudios%2Funifi-fabric-mcp-server"><img src="https://img.shields.io/badge/MCP-Registry-blue" alt="MCP Registry" /></a>
</p>

<br/>

<p align="center">
  <b><a href="#installation">📦 Installation</a></b> &nbsp;·&nbsp;
  <b><a href="https://youtu.be/GIzz1bKrtJk">▶️ Watch demo</a></b> &nbsp;·&nbsp;
  <b><a href="#how-it-works">⚙️ How it works</a></b> &nbsp;·&nbsp;
  <b><a href="#security">🛡️ Security</a></b> &nbsp;·&nbsp;
  <b><a href="#more-info">📚 More info</a></b>
</p>

<br/>


UniFi Fabric MCP Server connects your AI assistant to your UniFi network. Find
offline devices, dig into Wi-Fi problems, review cameras, or change settings just
by asking.

It works through UniFi Fabrics, which put your sites and companies under one
organization in [UniFi Site Manager](https://unifi.ui.com). Join your consoles to
a fabric, create a fabric API key, and you're set. One key covers the whole
organization, and the server runs on your own computer or server. Everything goes
through Ubiquiti's cloud, so it never needs to reach a controller on your local
network.

<br/>

## What you can do

Ask your assistant to help with tasks such as:

- “List my UniFi sites and the devices in each one.”
- “Which devices are offline, and what should I investigate?”
- “Show me the recent events from my Protect cameras.”
- “Show me the floor plans in my InnerSpace project.”

You can also manage networks, Wi-Fi and firewall policies. See
[tool usage](docs/TOOL-USAGE.md) and the [tools reference](docs/TOOLS.md) for details.

<br/>

## Features

- **792 tools, loaded on demand.** Discovery mode gives your assistant a small
  search-and-call toolset instead of flooding its context with the whole catalog;
  the full catalog is one setting away.
- **Deep Network and Protect coverage, plus InnerSpace.** Networks, Wi-Fi, VPN,
  firewall, clients, devices, cameras and floor plans; see
  [tool families](#tool-families) for what is and is not covered.
- **Multi-site and multi-organization.** One fabric key covers every site in the
  organization, and you can configure several keys to manage many organizations
  from one server. See the [MSP guide](docs/MSP.md).
- **Ready for shared deployments.** Run it over HTTPS behind a gateway: request
  headers can carry each caller's own API keys (the server stores none) and tighten
  write policy or tool families per request, so one server can safely serve many
  users. See [header key mode](docs/CONFIGURATION.md#header-key-mode-unifi_key_mode).
- **Write controls.** `allow`, `dry-run` or `deny` globally, with per-family and
  per-tool exceptions.
- **Everything is a switch.** Expose only the tool families you want, hide
  individual tools, run discovery mode or advertise the full catalog, and opt into
  redaction and audit logging; all of it is environment settings, no code changes.
  See the [configuration guide](docs/CONFIGURATION.md).
- **Secret redaction and audit logging.** Mask credential fields in responses and
  log every write attempt. See the [configuration guide](docs/CONFIGURATION.md).
- **Any MCP client, any transport.** stdio locally; HTTPS and SSE for servers,
  with bearer-token or OAuth authentication and TLS served by the server itself
  (bring your own certificate), up to mutual TLS. See
  [authentication and TLS](docs/AUTH-TLS.md).

<br/>

## Installation

<p align="center">
  <a href="https://insiders.vscode.dev/redirect/mcp/install?name=unifi-fabric&inputs=%5B%7B%22id%22%3A%22unifi_api_key%22%2C%22type%22%3A%22promptString%22%2C%22description%22%3A%22UniFi%20Fabric%20API%20key%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22--from%22%2C%22unifi-fabric-mcp-server%3D%3D0.7.1%22%2C%22unifi-fabric-mcp%22%5D%2C%22env%22%3A%7B%22UNIFI_API_KEY%22%3A%22%24%7Binput%3Aunifi_api_key%7D%22%7D%7D"><img src="https://img.shields.io/badge/VS_Code-Install-0098FF?style=flat-square&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyBmaWxsPSJ3aGl0ZSIgcm9sZT0iaW1nIiB2aWV3Qm94PSIwIDAgMjQgMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI%2BPHRpdGxlPlZpc3VhbCBTdHVkaW8gQ29kZTwvdGl0bGU%2BPHBhdGggZD0iTTIzLjE1IDIuNTg3TDE4LjIxLjIxYTEuNDk0IDEuNDk0IDAgMCAwLTEuNzA1LjI5bC05LjQ2IDguNjMtNC4xMi0zLjEyOGEuOTk5Ljk5OSAwIDAgMC0xLjI3Ni4wNTdMLjMyNyA3LjI2MUExIDEgMCAwIDAgLjMyNiA4Ljc0TDMuODk5IDEyIC4zMjYgMTUuMjZhMSAxIDAgMCAwIC4wMDEgMS40NzlMMS42NSAxNy45NGEuOTk5Ljk5OSAwIDAgMCAxLjI3Ni4wNTdsNC4xMi0zLjEyOCA5LjQ2IDguNjNhMS40OTIgMS40OTIgMCAwIDAgMS43MDQuMjlsNC45NDItMi4zNzdBMS41IDEuNSAwIDAgMCAyNCAyMC4wNlYzLjkzOWExLjUgMS41IDAgMCAwLS44NS0xLjM1MnptLTUuMTQ2IDE0Ljg2MUwxMC44MjYgMTJsNy4xNzgtNS40NDh2MTAuODk2eiIvPjwvc3ZnPg%3D%3D" alt="Install in VS Code" /></a>&nbsp;
  <a href="https://cursor.com/en/install-mcp?name=unifi-fabric&config=eyJjb21tYW5kIjoidXZ4IC0tZnJvbSB1bmlmaS1mYWJyaWMtbWNwLXNlcnZlcj09MC43LjEgdW5pZmktZmFicmljLW1jcCIsImVudiI6eyJVTklGSV9BUElfS0VZIjoieW91ci1hcGkta2V5LWhlcmUifX0="><img src="https://img.shields.io/badge/Cursor-Install-111111?style=flat-square&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyBmaWxsPSIjZmZmZmZmIiByb2xlPSJpbWciIHZpZXdCb3g9IjAgMCAyNCAyNCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48dGl0bGU%2BQ3Vyc29yPC90aXRsZT48cGF0aCBkPSJNMTEuNTAzLjEzMSAxLjg5MSA1LjY3OGEuODQuODQgMCAwIDAtLjQyLjcyNnYxMS4xODhjMCAuMy4xNjIuNTc1LjQyLjcyNGw5LjYwOSA1LjU1YTEgMSAwIDAgMCAuOTk4IDBsOS42MS01LjU1YS44NC44NCAwIDAgMCAuNDItLjcyNFY2LjQwNGEuODQuODQgMCAwIDAtLjQyLS43MjZMMTIuNDk3LjEzMWExLjAxIDEuMDEgMCAwIDAtLjk5NiAwTTIuNjU3IDYuMzM4aDE4LjU1Yy4yNjMgMCAuNDMuMjg3LjI5Ny41MTVMMTIuMjMgMjIuOTE4Yy0uMDYyLjEwNy0uMjI5LjA2NC0uMjI5LS4wNlYxMi4zMzVhLjU5LjU5IDAgMCAwLS4yOTUtLjUxbC05LjExLTUuMjU3Yy0uMTA5LS4wNjMtLjA2NC0uMjMuMDYxLS4yMyIvPjwvc3ZnPg%3D%3D" alt="Install in Cursor" /></a>&nbsp;
  <a href="https://github.com/swkstudios/unifi-fabric-mcp-server/releases/latest"><img src="https://img.shields.io/badge/Claude_Desktop-Install-d97757?style=flat-square&logo=claude&logoColor=white" alt="Install in Claude Desktop" /></a>
</p>

### 1. Join your fabric and create an API key

1. Sign in to [UniFi Site Manager](https://unifi.ui.com). In the Sites sidebar under
   **Fabrics**, create a fabric (**Create New**) if you don't have one, and make sure
   the sites with your consoles are in it. New to fabrics? See Ubiquiti's
   [video](https://www.youtube.com/watch?v=69g3O3Ltygw) and
   [announcement](https://blog.ui.com/article/introducing-unifi-fabrics).
2. Select your fabric, then open [**API Keys**](https://unifi.ui.com/settings/api-keys)
   and select **Create New API Key**.
3. Enable at least **Site Manager** and **Network** scopes; add **Protect** for
   cameras. Choose the sites the key can access.
4. Copy the key and store it securely. It is shown only once.

Treat the key like a password: each client stores it **in plain text** in its own
configuration file, so keep those files private.

### 2. Connect your assistant


> [!NOTE]
> The package commands below use the currently published 0.7.1 release. This README
> describes 0.7.1 source. Upgrading from 0.7.0? See the [migration guide](docs/MIGRATING-0.7.1.md)
> before changing settings.

The setups below run the server with [`uvx` (from uv)](https://docs.astral.sh/uv/getting-started/installation/),
which fetches everything it needs — no Python setup required. Prefer pip? See the
[client setup guide](docs/CLIENT-SETUP.md).

#### <img src="https://cdn.simpleicons.org/claude" width="16" height="16" /> Claude Code

With Claude Code 2.1.275 or later, run:

<!-- install-case: readme-install-29 mode=plugin -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-29 -->
```text
/plugin marketplace add swkstudios/unifi-fabric-mcp-server
/plugin install unifi-fabric@unifi-fabric
```

Enter your API key when prompted. Or skip the plugin and add the server directly
from a terminal (the first line prompts for your key):

<!-- install-case: readme-install-30 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-30 -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo; export UNIFI_API_KEY
claude mcp add unifi-fabric -e UNIFI_API_KEY="$UNIFI_API_KEY" -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

<details>
<summary><b><img src="https://cdn.simpleicons.org/claude" width="16" height="16" /> Claude Desktop</b></summary>

Open **Settings > Developer > Edit Config** and merge the following into the
configuration:

<!-- install-case: readme-install-31 mode=desktop -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-31 -->
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

Replace the command path with the output of `which uvx` on macOS or `where uvx`
on Windows, and replace the key placeholder. Quit Claude Desktop completely and
reopen it.

Alternatively, [download the Claude Desktop extension (.mcpb)](https://github.com/swkstudios/unifi-fabric-mcp-server/releases/latest)
and open it; Claude Desktop prompts for your API key during installation.

</details>

<details>
<summary><b><img src="https://avatars.githubusercontent.com/u/14957082?s=32" width="16" height="16" /> Codex</b></summary>

From a terminal (the first line prompts for your key):

<!-- install-case: readme-install-32 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-32 -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo
codex mcp add unifi-fabric --env UNIFI_API_KEY="$UNIFI_API_KEY" -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

This stores the key in `~/.codex/config.toml`. Run `codex mcp list` to check the
registration.

</details>

<details>
<summary><b><img src="https://cdn.simpleicons.org/google" width="16" height="16" /> Google Antigravity</b></summary>

Export the key before starting `agy` — that keeps it out of config files
(Antigravity does not expand `${VAR}` in `env` values):

<!-- install-case: readme-install-33 mode=antigravity -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-33 -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo; export UNIFI_API_KEY
agy mcp add unifi-fabric -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
agy
```

When Antigravity is started from the Dock (Antigravity 2.0 and the IDE), it cannot
see exported variables; store the key in the config instead:

<!-- install-case: readme-install-34 mode=antigravity -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-34 -->
```bash
agy mcp add --env UNIFI_API_KEY="$UNIFI_API_KEY" unifi-fabric -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

</details>

<details>
<summary><b><img src="https://cdn.simpleicons.org/googlegemini" width="16" height="16" /> Gemini CLI</b></summary>

Install this repository as a Gemini CLI extension; it prompts for your API key
(stored in the system keychain) and your write-policy choice:

<!-- install-case: readme-install-35 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-35 -->
```bash
gemini extensions install https://github.com/swkstudios/unifi-fabric-mcp-server
```

</details>

<details>
<summary><b><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/vscode/vscode-original.svg" width="16" height="16" /> VS Code</b></summary>

Use the install button above, or add this to `.vscode/mcp.json` in your workspace
(VS Code prompts for the key on first start):

<!-- install-case: readme-install-36 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-36 -->
```json
{
  "inputs": [
    { "id": "unifi_api_key", "type": "promptString", "description": "UniFi Fabric API key", "password": true }
  ],
  "servers": {
    "unifi-fabric": {
      "command": "uvx",
      "args": ["--from", "unifi-fabric-mcp-server==0.7.1", "unifi-fabric-mcp"],
      "env": { "UNIFI_API_KEY": "${input:unifi_api_key}" }
    }
  }
}
```

</details>

<details>
<summary><b><img src="https://cdn.simpleicons.org/cursor/8b949e" width="16" height="16" /> Cursor</b></summary>

Use the install button above, or merge this into `~/.cursor/mcp.json` and replace
the key placeholder:

<!-- install-case: readme-install-37 mode=desktop -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-37 -->
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

</details>

<details>
<summary><b><img src="https://avatars.githubusercontent.com/u/14957082?s=32" width="16" height="16" /> ChatGPT</b></summary>

ChatGPT cannot launch a local MCP server. It connects over the network, signed in
through OAuth — so using it means self-hosting:

1. Run this server in OAuth mode (`MCP_AUTH_MODE=oauth`) behind an identity
   provider you operate.
2. Make it reachable from ChatGPT: a public HTTPS URL behind a TLS proxy, or a
   private connection through
   [OpenAI's Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
   (no public exposure needed).
3. In ChatGPT, open Plugins, select **+**, then **Add custom MCP server**, and
   choose OAuth.

The [ChatGPT guide](docs/CHATGPT.md) walks through each step and has a security
checklist. Never expose the server without authentication: it can reconfigure
your network.

</details>

<details>
<summary><b><img src="https://cdn.simpleicons.org/modelcontextprotocol/8b949e" width="16" height="16" /> Any other MCP client</b></summary>

Run the server locally over stdio (Python 3.12+, or let uv fetch one):

<!-- install-case: readme-install-38 mode=uvx -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-38 -->
```bash
export UNIFI_API_KEY="your-api-key-here"
uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

Or register it with the standard MCP configuration your client reads:

<!-- install-case: readme-install-39 mode=desktop -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-39 -->
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

Prefer a one-time install with `pipx install unifi-fabric-mcp-server==0.7.1` or
`uv tool install unifi-fabric-mcp-server==0.7.1`, then use
`"command": "unifi-fabric-mcp"` with no `args`.

</details>

<details>
<summary><b><img src="https://cdn.simpleicons.org/docker" width="16" height="16" /> Docker (self-hosted HTTP server)</b></summary>

Run the server as a container that your MCP clients reach over HTTP with a bearer
token, so only clients holding the token can use your UniFi key:

<!-- install-case: readme-install-40 mode=docker -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-40 -->
```bash
# Generate a random token once and keep it: the server checks it and your MCP client sends it.
export MCP_BEARER_TOKEN="$(openssl rand -hex 32)"
docker run -e UNIFI_API_KEY="your-api-key-here" -e MCP_AUTH_MODE=bearer -e MCP_BEARER_TOKEN \
  -p 127.0.0.1:3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.1
```

Point your client at it with an HTTP entry (the token stays in your environment):

<!-- install-case: readme-install-41 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-41 -->
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

`-p 127.0.0.1:3000:3000` serves this machine only; to serve other machines, publish
the port and add TLS. The [Docker guide](docs/DOCKER.md) has the smoke test, digest
pinning and TLS options.

</details>

Full walkthroughs for every client are in the [client setup guide](docs/CLIENT-SETUP.md).

### 3. Ask your first question

Ask your assistant: “List my UniFi sites and the devices in each one.”
If it answers with your sites, you are connected — everything in
[What you can do](#what-you-can-do) works from here.

<br/>

## How it works

By default, the server exposes a small set of discovery tools to your assistant rather
than loading the entire 792-tool catalog into context at once. When you ask a question
or request a change, the assistant searches the catalog, inspects the matching tool, and
calls it through the server.

The server sends the request over HTTPS with your UniFi Fabric API key to the UniFi
Fabric API (`api.ui.com`). Ubiquiti's cloud relays the request to the consoles joined
to your fabric,
which reach your network devices and Protect deployment, and returns the response along
the same path. You do not need to open inbound ports, log in directly to a controller,
or install software on your consoles.

### Tool families

<!-- BEGIN GENERATED: tool-families -->
Catalog: **792 registered tools**; **773** are in the product
families listed below. The remaining 19 cover Ubiquiti's ISP and
mobile-routing products (Carrier Fabric and Mobility), which this overview
leaves out. Availability depends on your hardware, permissions and API routes;
see [coverage and limitations](docs/COVERAGE.md).

| Family | Tools | Family | Tools |
|---|---:|---|---:|
| Network | 343 | Protect | 227 |
| VPN | 42 | Devices | 37 |
| Firewall | 33 | InnerSpace | 32 |
| Site Manager | 19 | Statistics | 16 |
| Clients | 15 | Connector relay | 5 |
| Hotspot | 4 |  |  |
<!-- END GENERATED -->

### Verification status

<!-- verification-status:start -->
| Evidence | Result |
|---|---|
| Every tool runs in CI against a simulated upstream | 792 tools |
| Live-tested on a real console | 380 of 786 passed on build `cde04b5c1520`, 2026-10-28 |
| Live write tools passed | 114 on that build and date |
<!-- verification-status:end -->

Full results, failures and untested tools are in
[coverage and limitations](docs/COVERAGE.md).

<br/>

## Security

> [!IMPORTANT]
> **Writes are allowed by default** — the server can change your network. One setting
> controls that:

| Setting | Effect |
|---|---|
| `UNIFI_WRITE_POLICY=allow` | Default: read and write tools are available. |
| `UNIFI_WRITE_POLICY=dry-run` | Writes return a preview of what would be sent; nothing changes. |
| `UNIFI_WRITE_POLICY=deny` | Read-only: write tools are hidden and refused. |

<!-- install-case: readme-install-42 mode=non-executable reason=client-interaction-or-deployment-step-requires-user-setup -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=readme-install-42 -->
```bash
# example: run read-only
export UNIFI_WRITE_POLICY=deny
```

Per-family and per-tool exceptions are available through `UNIFI_WRITE_EXCEPTIONS`;
see the [configuration guide](docs/CONFIGURATION.md).
Upgrading from an older release? The variable names changed; see the [migration guide](docs/MIGRATING-0.7.1.md).

- **Review requests before they run** — use your MCP client's permission prompts.
- **Responses can contain sensitive data** — the server masks its own configured
  secrets; set `UNIFI_REDACT_SECRETS=1` to also mask documented credential fields
  (Wi-Fi PSKs, RADIUS secrets, tokens).
- **Protect your files** — client config files and logs hold your API key; keep
  them private.
- **Remote deployments need authentication and TLS** — see
  [authentication and TLS](docs/AUTH-TLS.md).

<br/>

### Verify the image

Release images are signed with Cosign and carry an SBOM and provenance attestation; see [Verify the image](docs/VERIFY-IMAGE.md).

## More info

| Guide | What it covers |
|---|---|
| [Configuration](docs/CONFIGURATION.md) | Every setting: discovery, write controls, audit logging |
| [Client setup](docs/CLIENT-SETUP.md) | Full walkthroughs for every supported MCP client |
| [Troubleshooting](docs/CLIENT-SETUP.md#troubleshooting) | Fixes for common setup, connection and key errors |
| [Docker deployment](docs/DOCKER.md) | Running as a shared HTTP service with auth and TLS |
| [Migration guide](docs/MIGRATING-0.7.1.md) | Upgrading from an older release |
| [Tool usage](docs/TOOL-USAGE.md) | Workflows and examples for using the tools |
| [Tool reference](docs/TOOLS.md) | Every tool, listed by family |
| [Coverage](docs/COVERAGE.md) | Live-verification results, compatibility and limits |
| [Agent skills](docs/AGENT-SKILLS.md) | Ready-made skills for AI assistants |
| [MSP setup](docs/MSP.md) | Managed-service and multi-organization use |
| [Introducing UniFi Fabrics](https://blog.ui.com/article/introducing-unifi-fabrics) | Ubiquiti's announcement of fabrics, with a [video overview](https://www.youtube.com/watch?v=69g3O3Ltygw) |

**Project:** [Privacy](PRIVACY.md) · [Security policy](.github/SECURITY.md) · [Contributing](CONTRIBUTING.md) · [License](LICENSE)

This project is not affiliated with or endorsed by Ubiquiti. UniFi is a trademark of
Ubiquiti Inc. Licensed under the [MIT License](LICENSE).
