# UniFi Fabric MCP for Google Antigravity

This folder is a Google Antigravity plugin. It runs the open-source UniFi Fabric MCP server on your own machine with your own UniFi Site Manager API key. Nothing goes through a hosted service: the server talks from your machine to Ubiquiti's cloud API (`api.ui.com`) only. See [PRIVACY.md](../../PRIVACY.md).

## What it runs

`uvx --from unifi-fabric-mcp-server==0.7.2 unifi-fabric-mcp` over stdio. It needs [uv](https://docs.astral.sh/uv/), which fetches Python 3.12 or later for you.

## Where the key comes from

The plugin stores no key. Antigravity starts the server with the environment of the shell that started `agy`, so export the key first:

<!-- doc-provenance: source=file:plugins/antigravity/plugin.json@sha256:0020a5d085941148ac58a545f67ac11f74e8a889a5b5a24d58b1e375d9859bea support=0.7.2 case=antigravity-readme-1 -->
<!-- install-case: antigravity-readme-1 mode=antigravity -->
```bash
printf 'UniFi API key: '; read -rs UNIFI_API_KEY; echo; export UNIFI_API_KEY
export UNIFI_WRITE_POLICY=deny   # optional: hide and refuse every write and action tool
export UNIFI_TOOL_MODE=full   # optional: advertise every tool instead of discovery
agy
```

Antigravity passes `env` values in plugin and MCP configs literally (it does not expand `${VAR}`), which is why this plugin has no `env` block. Writes are on by default; `UNIFI_WRITE_POLICY=deny` hides every write and action tool and refuses any call to one before anything is sent to UniFi. Discovery mode is the default (five meta-tools: `search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, `list_tool_families`); `UNIFI_TOOL_MODE=full` advertises every tool instead.

Some tools depend on console-internal paths that Ubiquiti can restrict without notice. Set `UNIFI_EXCLUDE=unofficial,source:relay` for a published-API-only profile.

## Install

From a checkout of this repository:

<!-- doc-provenance: source=file:plugins/antigravity/plugin.json@sha256:0020a5d085941148ac58a545f67ac11f74e8a889a5b5a24d58b1e375d9859bea support=0.7.2 case=antigravity-readme-2 -->
<!-- install-case: antigravity-readme-2 mode=antigravity -->
```bash
agy plugin install ./plugins/antigravity
```

Check it with `agy plugin list`; remove it with `agy plugin uninstall unifi-fabric`.

## If something is wrong

- **No key in the environment:** the server exits at startup and Antigravity shows no unifi-fabric tools. Export the key and start `agy` again.
- **Wrong key:** tools return the upstream error, for example `HTTP 401 from GET /v1/hosts: {"code":"unauthorized",...}`. Create a new key at [unifi.ui.com](https://unifi.ui.com) under API Keys.

Example prompts: "List my UniFi sites and the devices in each one.", "Which UniFi devices are offline or need a firmware update?", "Show the firewall policies on my main site."

Not affiliated with Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.
