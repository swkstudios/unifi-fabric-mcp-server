# UniFi Fabric MCP for Claude Desktop (MCPB bundle)

This folder holds the manifest for a Claude Desktop extension bundle (`.mcpb`). The bundle runs the open-source UniFi Fabric MCP server on your own Mac or Windows PC with your own UniFi Site Manager API key, which Claude Desktop asks for when you install it and keeps in its secure storage. Nothing goes through a hosted service: the server talks from your machine to the UniFi Fabric API in Ubiquiti's cloud (`api.ui.com`) only. See [PRIVACY.md](../../PRIVACY.md).

## What it runs

`uvx --from unifi-fabric-mcp-server==0.7.2 unifi-fabric-mcp` over stdio, so [uv](https://docs.astral.sh/uv/) must be installed. The bundle contains the manifest and this README; uv downloads the pinned release from PyPI on first start.

## Build and install

<!-- doc-provenance: source=file:plugins/claude-desktop/manifest.json@sha256:77dafd00e15b4fb34b5095ec8b1e6cc7e102adf5586e39463eba68cb09845e89 support=0.7.2 citation=file:plugins/claude-desktop/manifest.json@sha256:77dafd00e15b4fb34b5095ec8b1e6cc7e102adf5586e39463eba68cb09845e89 -->
<!-- install-case: claude-desktop-readme-1 mode=non-executable reason=deployment-or-client-interaction -->
```bash
npx -y @anthropic-ai/mcpb@2.1.2 pack plugins/claude-desktop unifi-fabric.mcpb
```

Then double-click `unifi-fabric.mcpb`, drag it onto Claude Desktop, or use **Settings > Extensions > Advanced > Install Extension**. Enter your API key when asked. The optional **Write policy** setting is `allow` by default (writes on); `deny` hides every write and action tool and refuses any call to one before anything is sent to UniFi, and `dry-run` previews every write without sending it. The optional **Tool mode** setting defaults to `discovery` (meta-tools that search, describe and call tools; the write dispatcher is hidden under the `deny` write policy); enter `full` to advertise every tool.

Some tools depend on console-internal paths that Ubiquiti can restrict without notice. Set `UNIFI_EXCLUDE=unofficial,source:relay` for a published-API-only profile.

The same bundle supports macOS and Windows. Install uv before opening the bundle, and ensure `uvx` is available to Claude Desktop.

## If something is wrong

- **uvx not found:** install uv, or use the manual config with the absolute path to `uvx` (`which uvx` on macOS or `where uvx` on Windows).
- **Wrong key:** tools return the upstream error, for example `HTTP 401 from GET /v1/hosts: {"code":"unauthorized",...}`. Create a new key at [unifi.ui.com](https://unifi.ui.com) under API Keys and reinstall or reconfigure the extension.

Not affiliated with Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.
