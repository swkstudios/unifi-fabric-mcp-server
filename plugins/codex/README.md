# UniFi Fabric MCP for OpenAI Codex

This folder is an OpenAI Codex plugin. It runs the open-source UniFi Fabric MCP server on your own machine with your own UniFi Site Manager API key. Nothing goes through a hosted service: the server talks from your machine to Ubiquiti's cloud API (`api.ui.com`) only. See [PRIVACY.md](../../PRIVACY.md).

## What it runs

`uvx --from unifi-fabric-mcp-server==0.7.0 unifi-fabric-mcp` over stdio. It needs [uv](https://docs.astral.sh/uv/), which fetches Python 3.12 or later for you.

## Where the key comes from

The plugin stores no key. It forwards `UNIFI_API_KEY` (and the optional `UNIFI_READ_ONLY` and `UNIFI_TOOL_MODE`) from the environment of the process that starts Codex, using Codex's `env_vars` setting. Export the key in the shell before you start `codex`:

<!-- doc-provenance: source=file:plugins/codex/.mcp.json@sha256:1e37bc9872bfcf4f3e469bcb43f3f0511332f22ff489655c7aebd3ce1901659f support=0.7.0 citation=file:plugins/codex/.mcp.json@sha256:1e37bc9872bfcf4f3e469bcb43f3f0511332f22ff489655c7aebd3ce1901659f -->
<!-- install-case: codex-readme-1 mode=non-executable reason=deployment-or-client-interaction -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo; export UNIFI_API_KEY
export UNIFI_READ_ONLY=1   # optional: hide and refuse every write and action tool
export UNIFI_TOOL_MODE=full   # optional: advertise every tool instead of discovery
codex
```

Writes are on by default; `UNIFI_READ_ONLY=1` hides every write and action tool and refuses any call to one before anything is sent to UniFi. Discovery mode is the default (five meta-tools: `search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, `list_tool_families`); `UNIFI_TOOL_MODE=full` advertises every tool instead. A ChatGPT desktop app started from the Dock or Finder does not see variables exported in a terminal; for the desktop app use the [`config.toml` setup in the main README](../../README.md#use-with-openai-codex) instead.

## Install

<!-- doc-provenance: source=file:plugins/codex/.mcp.json@sha256:1e37bc9872bfcf4f3e469bcb43f3f0511332f22ff489655c7aebd3ce1901659f support=0.7.0 citation=file:plugins/codex/.mcp.json@sha256:1e37bc9872bfcf4f3e469bcb43f3f0511332f22ff489655c7aebd3ce1901659f -->
<!-- install-case: codex-readme-2 mode=non-executable reason=deployment-or-client-interaction -->
```bash
codex plugin marketplace add swkstudios/unifi-fabric-mcp-server
codex plugin add unifi-fabric@unifi-fabric
```

Or, from a checkout of this repository: `codex plugin marketplace add ./unifi-fabric-mcp-server`.

## If something is wrong

- **No key in the environment:** the server exits at startup with `UNIFI_API_KEY is not set — get a key at https://unifi.ui.com (Site Manager > API Keys) and set UNIFI_API_KEY or UNIFI_API_KEYS; see README#get-your-api-key`, and Codex shows no unifi-fabric tools. Export the key and restart Codex.
- **Wrong key:** tools return the upstream error, for example `HTTP 401 from GET /v1/hosts: {"code":"unauthorized",...}`. Create a new key at [unifi.ui.com](https://unifi.ui.com) under API Keys.

Example prompts: "List my UniFi sites and the devices in each one.", "Which UniFi devices are offline or need a firmware update?", "Show the firewall policies on my main site."

Not affiliated with Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.
