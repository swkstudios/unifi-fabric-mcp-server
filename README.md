![UniFi Fabric MCP Server](docs/banner.png)

# UniFi Fabric MCP Server

[![CI](https://github.com/swkstudios/unifi-fabric-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/swkstudios/unifi-fabric-mcp-server/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Cloud-first UniFi management for AI agents.** This server connects to the official UniFi Site Manager / Fabric cloud API (`api.ui.com`) — no direct controller access, SSH, or local network access required. Manage your entire UniFi fleet from anywhere through natural language.

An MCP (Model Context Protocol) server that exposes the UniFi Site Manager API as tools for AI assistants. Built with [FastMCP](https://github.com/PrefectHQ/fastmcp), it lets Claude Code, Cline, and other MCP clients manage UniFi network infrastructure through natural language.

> **Disclaimer:** This project is not affiliated with, endorsed by, or sponsored by Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.

## Architecture

```mermaid
flowchart LR
    A[AI Assistant<br/>MCP Client] -->|MCP protocol<br/>stdio / HTTP| B[UniFi Fabric<br/>MCP Server]
    B -->|HTTPS<br/>API key auth| C[api.ui.com<br/>UniFi Site Manager]
    C -->|Cloud Connector<br/>Proxy| D[UDM / UDR / UCG<br/>Consoles]
    D --- E[Devices & Clients]
    D --- F[Protect NVRs]
```

## What is MCP?

**Model Context Protocol (MCP)** is an open standard that enables large language models (LLMs) and AI assistants to securely interact with external systems and tools. Instead of asking the AI to make manual API calls or describe steps, MCP allows the AI to:

- Execute commands and operations directly in external systems
- Query data and retrieve real-time information
- Automate complex workflows through natural conversation

This UniFi Fabric MCP server bridges UniFi's network management API with AI assistants, enabling you to control your network infrastructure through conversation.

## Use Cases

- **Network Operations**: Monitor fleet health, manage sites, and troubleshoot devices using natural language
- **Security Management**: Create and update firewall policies, manage ACLs, and configure DNS policies without manual API calls
- **MSP Operations**: Manage multiple UniFi consoles and organizations with a single AI interface
- **Device Management**: Monitor and control cameras, sensors, and other Protect devices across your infrastructure
- **Automation**: Build AI-powered workflows for routine network tasks and compliance audits

## Quick Start

### Get Your API Key

1. Sign in to [UniFi Site Manager](https://unifi.ui.com) with your Ubiquiti account
2. Select your organization from the dropdown (top-left)
3. In the left sidebar, click **API Keys**
4. Click **Create New API Key** and give it a descriptive name
5. Select the **API Scope** — enable **Site Manager** and **Network** at minimum (add **Protect** if managing cameras)
6. Under **Sites**, choose which sites the key can access (or select all)
7. Copy the key immediately — it won't be shown again

> **Note:** These are UniFi Site Manager API keys that authenticate against the cloud API (`api.ui.com`). Your consoles must be adopted to your UI.com account and connected to Ubiquiti's cloud for the key to discover them. See the [API Docs](https://developer.ui.com) for more details.

---

### Track A — Local (stdio)

Install and run the server locally. The MCP client launches it as a subprocess over stdio.

**Requires Python 3.12+**

```bash
git clone https://github.com/swkstudios/unifi-fabric-mcp-server.git
cd unifi-fabric-mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
export UNIFI_API_KEY="your-api-key-here"
unifi-fabric-mcp
```

Add to `~/.claude/settings.json` or project `.mcp.json`:

```json
{
  "mcpServers": {
    "unifi-fabric": {
      "command": "unifi-fabric-mcp",
      "env": { "UNIFI_API_KEY": "your-api-key-here" }
    }
  }
}
```

---

### Track B — Docker (HTTP, Recommended)

Run the server as a container. The MCP client connects over HTTP to the `/mcp` endpoint.

```bash
docker run -e UNIFI_API_KEY="your-api-key-here" -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server
```

Add to `~/.claude/settings.json` or project `.mcp.json`:

```json
{
  "mcpServers": {
    "unifi-fabric": {
      "type": "http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

See [`config/mcp-server.example.json`](config/mcp-server.example.json) for a full example.

> **Network deployments:** The MCP server listens on plain HTTP. For non-localhost deployments, run behind a TLS-terminating reverse proxy (e.g., Traefik, Caddy, nginx).

---

## Example Prompts

Copy-paste these into Claude Code or any MCP client after connecting:

```
Show me a summary of all devices and clients across my sites.
```

```
Are there any offline devices? List them with their site names.
```

```
Create a firewall policy that blocks traffic from the guest VLAN to the server VLAN.
```

```
List all firewall policies and show their current ordering.
```

```
Get the RTSPS stream URLs for cameras in the main office.
```

```
How many clients are connected to each site right now?
```

### Sample Tool Output

When you ask the MCP server a question, it executes tools and returns structured data. Here's an example of a fleet summary:

```json
{
  "total_consoles": 3,
  "total_sites": 7,
  "total_devices": 42,
  "total_clients": 157,
  "device_status": {
    "online": 38,
    "offline": 3,
    "adopting": 1
  },
  "sites": [
    {
      "site_name": "Main Office",
      "device_count": 12,
      "client_count": 65,
      "health": "good"
    },
    {
      "site_name": "Branch 1",
      "device_count": 15,
      "client_count": 52,
      "health": "good"
    },
    {
      "site_name": "Branch 2",
      "device_count": 10,
      "client_count": 40,
      "health": "degraded"
    }
  ]
}
```

## Compatibility

This server integrates with the following UniFi components:

| Component | Minimum Version | Tested Version | Tested OS |
|-----------|-----------------|----------------|-----------|
| Site Manager API | — | v1.0 | N/A |
| Network | v10.0.0 | v10.1.84+ | — |
| Protect | v7.0.0 | v7.0.104+ | — |
| UDM Pro / UDR Hardware | — | — | OS 5.1.7 / Network 10.3.55 / Protect 7.0.107 |

For the latest component versions and hardware compatibility, see [developer.ui.com](https://developer.ui.com).

## Available Tools

The server exposes **168+ tools** organized by domain for managing UniFi infrastructure:

| Domain | Tool Count | Purpose |
|--------|-----------|---------|
| **Fleet & Aggregation** | 6 | Cross-console device search, fleet summary, site comparison |
| **Site Management** | 8 | Site operations, health, inventory, system info |
| **Network & VLAN** | 18 | Networks, VLANs, WiFi broadcasts, WAN interfaces |
| **Device Management** | 16 | Device control, adoption, stats, actions, location |
| **Clients** | 8 | Client listing, stats, blocking, reconnection |
| **Firewall** | 24 | Policies, zones, ACL rules, rule ordering |
| **DNS & Traffic** | 21 | DNS policies, traffic rules, matching lists, routes |
| **Port Forwarding** | 4 | List, create, update, delete port forwards |
| **WLAN** | 6 | WLAN configs, groups, security settings |
| **Protect** | 22 | Cameras, sensors, lights, chimes, liveviews, PTZ, snapshots |
| **VPN** | 12 | VPN servers, site-to-site tunnels, RADIUS profiles |
| **Hotspot** | 4 | Voucher management, operators, billing packages |
| **Settings & Monitoring** | 8 | Controller settings, ISP metrics, WAN health |
| **Utilities** | 7 | Country list, file upload, alarm webhooks |
| **Other** | 4 | Miscellaneous network operations |

For the authoritative tool list, MCP clients can query the server directly or see `src/unifi_fabric/server.py` for all `@mcp.tool()` definitions.

## Configuration

### UniFi API Settings

All UniFi-specific settings are loaded from environment variables with the `UNIFI_` prefix.

| Variable | Required | Default | Description |
|---|---|---|---|
| `UNIFI_API_KEY` | Yes (if `UNIFI_API_KEYS` not set) | — | Single API key shorthand |
| `UNIFI_API_KEYS` | No | — | JSON list of key configs for multi-console MSP setups |
| `UNIFI_API_BASE_URL` | No | `https://api.ui.com` | UniFi Site Manager API base URL |
| `UNIFI_CACHE_TTL_SECONDS` | No | `900` | TTL for host/site registry cache (seconds) |
| `UNIFI_CACHE_MAX_HOSTS` | No | `512` | Max entries in the hosts/sites TTLCache (bounds memory use) |
| `UNIFI_CACHE_MAX_SITES` | No | `2048` | Max entries in the per-console sites TTLCache |
| `UNIFI_MAX_CONCURRENCY` | No | `10` | Max concurrent outbound requests to api.ui.com |
| `UNIFI_REQUEST_TIMEOUT_SECONDS` | No | `30` | HTTP request timeout in seconds |
| `UNIFI_PAGINATE_MAX_PAGES` | No | `None` (unlimited) | Hard cap on pagination page count. Unset by default — stall detection is the primary safeguard. Set to a generous number (e.g. `100000`) if desired. |
| `UNIFI_LOG_LEVEL` | No | `INFO` | Logging verbosity. Accepts standard Python levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Logs go to stderr only — request/response bodies are never logged. |

### Transport Configuration

The MCP server communicates with clients using the FastMCP transport protocol. By default, the Docker image uses `streamable-http`, but you can override this for different deployment scenarios.

**`FASTMCP_TRANSPORT`**: Sets the communication protocol between the MCP server and clients.

| Transport | Use Case | Port | Notes |
|---|---|---|---|
| `streamable-http` | Docker containers, HTTP load balancers, reverse proxies | `3000` | Default; recommended for containerized deployments |
| `sse` | Server-sent events; browser clients, long-polling scenarios | `3000` | Stateful, requires connection persistence |
| `stdio` | Process-to-process communication, local development | — | No network port; requires parent process stdin/stdout |

#### Override Transport via Docker

To use a different transport, override the environment variable at runtime:

```bash
# SSE transport
docker run -e UNIFI_API_KEY="your-api-key-here" -e FASTMCP_TRANSPORT=sse -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server

# Stdio transport
docker run -e UNIFI_API_KEY="your-api-key-here" -e FASTMCP_TRANSPORT=stdio ghcr.io/swkstudios/unifi-fabric-mcp-server
```

#### Override Transport in Docker Compose

```yaml
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server
    environment:
      UNIFI_API_KEY: your-api-key-here
      FASTMCP_TRANSPORT: sse  # or stdio
    ports:
      - "3000:3000"
```

**Note:** The server exposes port 3000 for `streamable-http` and `sse` transports. If using `stdio`, no port is exposed; the server communicates exclusively via stdin/stdout.

### Bearer Token Authentication (Optional)

Set `MCP_BEARER_TOKEN` to require all incoming MCP requests to include an `Authorization: Bearer <token>` header. Requests with a missing or incorrect token receive a 401 response.

When unset (the default), the server runs without transport-layer authentication — the same behavior as previous versions.

```bash
# Docker
docker run -e UNIFI_API_KEY="..." -e MCP_BEARER_TOKEN="my-secret-token" -p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server

# Docker Compose
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server
    environment:
      UNIFI_API_KEY: your-api-key-here
      MCP_BEARER_TOKEN: my-secret-token
    ports:
      - "3000:3000"
```

This uses FastMCP's `StaticTokenVerifier` — a single shared-secret pattern designed for LAN/VPN deployments where network-level access control is already in place. It is not intended as a standalone security boundary for public-internet deployments. See [issue #10](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/10) for design context.

### Single key setup

```bash
export UNIFI_API_KEY="your-api-key-here"
```

### Multi-key MSP setup

```bash
export UNIFI_API_KEYS='[{"key": "key-a", "label": "org-east", "is_org_key": true}, {"key": "key-b", "label": "org-west"}]'
```

Organization keys (`is_org_key: true`) cover all sites under the org. Personal keys only access consoles owned by the key holder.

## Retry & Backoff Behavior

The MCP server automatically retries failed requests to handle transient failures and rate limits gracefully.

### Rate Limit Handling (HTTP 429)

When the UniFi API responds with HTTP 429 (Too Many Requests), the server retries with **exponential backoff + jitter**:

- **Max retries**: 5 (6 total attempts)
- **Backoff formula**: `delay = min(2^attempt, 32) + random_jitter`
  - Attempt 1: immediate
  - Attempt 2: ~1 second (1 + jitter 0-1)
  - Attempt 3: ~2 seconds (2 + jitter 0-2)
  - Attempt 4: ~4 seconds (4 + jitter 0-4)
  - Attempt 5: ~8 seconds (8 + jitter 0-8)
  - Attempt 6: ~16 seconds (16 + jitter 0-16)
  - Attempt 7+: capped at ~32 seconds (32 + jitter 0-32)

- **Jitter**: Uniform random(0, base_delay) added to avoid "thundering herd" — coordinated retries from multiple clients hitting the API at the same moment.

After all retries are exhausted, a `RateLimitError` is raised. This is expected behavior when hitting API quotas; users should back off before retrying.

### Network Errors (No Retry)

The following errors are **not retried** and raise immediately:

- **Timeout**: Request exceeds `UNIFI_REQUEST_TIMEOUT_SECONDS` (default 30)
- **Connection failed**: Network unreachable, DNS failure, refused connection
- **HTTP errors**: 4xx (auth, not found) and 5xx (server error) are raised immediately

These are considered non-transient and retrying would not help. See [Troubleshooting](#troubleshooting) for how to handle them.

### Configuration

- **Timeout**: `UNIFI_REQUEST_TIMEOUT_SECONDS` (default: `30`)
- **Max retries**: Hard-coded to 5 in the client; override by subclassing if needed
- **Max concurrency**: `UNIFI_MAX_CONCURRENCY` (default: `10`) — limits parallel requests to prevent overwhelming the API

## Troubleshooting

### Common Setup Issues

**"ModuleNotFoundError: No module named 'unifi_fabric'"**
- Ensure you've installed the package with `pip install -e .` in the repo directory
- Verify your Python version is 3.12+: `python3 --version`
- Try `pip install --upgrade pip` and reinstall if using an older pip version

**"command not found: unifi-fabric-mcp"**
- The entry point is only available after installation: `pip install -e .`
- For local development without installation, run directly: `python3 -m unifi_fabric.server`
- Check that your virtual environment is activated: `source .venv/bin/activate`

**Docker fails to start with "exit code 1"**
- Verify the `UNIFI_API_KEY` environment variable is set and non-empty
- Check Docker logs: `docker logs <container-id>`
- Ensure you have internet connectivity to reach `api.ui.com`

### Environment Variable Misconfiguration

**"401 Unauthorized" or "Invalid API key"**
- Verify your `UNIFI_API_KEY` is correct — copy it directly from [UniFi Site Manager](https://unifi.ui.com) **Settings > API Keys**
- API keys expire or may be regenerated; if recently created, use the new key
- Ensure no trailing whitespace in the env var: `export UNIFI_API_KEY="key-here"` (not `"key-here "`)

**"UNIFI_API_KEYS" JSON parse error**
- Use proper JSON formatting: `[{"key": "...", "label": "..."}, ...]`
- Escape quotes correctly in shell: `export UNIFI_API_KEYS='[{"key":"your-key"}]'` (single quotes)
- Validate JSON at [jsonlint.com](https://www.jsonlint.com) before setting

**"Base URL is incorrect" or "api.ui.com not found"**
- The default base URL is `https://api.ui.com` — do not change this unless you have a private Ubiquiti API endpoint
- If you must override, set `UNIFI_API_BASE_URL="https://your-custom-endpoint.com"`
- Ensure no trailing slash: `https://api.ui.com` (not `https://api.ui.com/`)

### Connection Errors

**"Connection refused" or "Cannot connect to api.ui.com"**
- Check your internet connection: `ping api.ui.com`
- Verify your firewall/proxy allows outbound HTTPS (port 443)
- If behind a corporate proxy, you may need to configure `httpx` with custom certificates — open an issue if you need guidance
- The server makes requests to `https://api.ui.com/v1/` — ensure this endpoint is reachable

**"Certificate verification failed" or "SSL: CERTIFICATE_VERIFY_FAILED"**
- This typically occurs behind corporate proxies with MITM certificate injection
- Verify your system CA bundle is up-to-date: `pip install --upgrade certifi`
- If using a corporate proxy certificate, import it into your system trust store
- As a last resort (not recommended), you can disable verification: `export UNIFI_API_VERIFY_SSL=false` (add support if needed — open an issue)

**"Request timeout" or "socket timeout"**
- The default timeout is 30 seconds. If your network is slow, increase it:
  ```bash
  export UNIFI_REQUEST_TIMEOUT_SECONDS=60
  ```
- Check if `api.ui.com` is experiencing an outage: [status.ui.com](https://status.ui.com)
- If using Docker, ensure the container has network connectivity: `docker run --network host ...`

**"No hosts found" or "Site not found"**
- Your API key must have access to the sites you're querying. Verify in [UniFi Site Manager](https://unifi.ui.com) **Settings > API Keys > <your-key> > Sites**
- Organization keys (`is_org_key: true`) should see all sites; personal keys only see sites you own
- If you just created the key or changed site permissions, wait 1-2 minutes for propagation and retry

### Getting Help

- Check [developer.ui.com](https://developer.ui.com) for API documentation and latest firmware compatibility
- Search existing [GitHub issues](https://github.com/swkstudios/unifi-fabric-mcp-server/issues) for your problem
- Include the following in bug reports:
  - Tool name and parameters you were using
  - Full error message (redact your API key and sensitive IPs)
  - Python version (`python3 --version`) and OS
  - Docker image tag (if applicable)
  - Relevant env vars (without secrets)

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/
ruff format --check src/ tests/
```

## Docker Deployment

The server ships as a Docker image. When pinning deployments for production use,
reference the image by digest rather than a mutable tag to ensure reproducibility
and guard against tag mutation:

```bash
# Pull by digest instead of :latest or a version tag
docker pull ghcr.io/swkstudios/unifi-fabric-mcp-server@sha256:<digest>
```

You can find the digest for a given release on the package page or via:

```bash
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/swkstudios/unifi-fabric-mcp-server:latest
```

### Stateless Design (No Persistent Volumes)

**By design, this container is stateless and does not require persistent volumes.** The MCP server:

- Makes API calls to the remote UniFi Site Manager cloud API (`api.ui.com`)
- Does not maintain local state between requests
- Does not store credentials, configurations, or cached data on disk
- Uses in-memory caching only (with configurable TTL, default 900 seconds)
- Has no dependencies on local storage, databases, or filesystem persistence

**Why stateless?** The server acts as an ephemeral proxy/bridge between AI assistants and the UniFi cloud API. Each session is independent; all configuration and data live in the cloud. Deployment is simplified by container orchestrators (Docker Compose, Kubernetes) with no persistent volume claims needed.

**Implications:**
- Cache is reset on container restart (this is safe and expected)
- Multiple server instances can run in parallel without coordination
- No data loss risk from container updates or replacements
- Scaling is stateless and simple

## Contributing

Use conventional commits and standard branch naming. See [SECURITY.md](.github/SECURITY.md) for how to report vulnerabilities privately.

## License

MIT. See [LICENSE](LICENSE) for details.


