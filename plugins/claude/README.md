# UniFi Fabric MCP — Claude Code plugin

This plugin runs the open-source [UniFi Fabric MCP server](https://github.com/swkstudios/unifi-fabric-mcp-server) on your own computer, using your own UniFi Site Manager API key. Claude Code can then read and manage your UniFi sites, gateways, switches, access points, clients, firewall policies, VPN, Wi-Fi and Protect cameras by talking to Ubiquiti's cloud API. There is no hosted service in between: the server runs locally and talks only to Ubiquiti.

This project is not affiliated with, endorsed by, or sponsored by Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.

## Where it works

- **Claude Code only** (terminal, IDE extensions, and the desktop app's Code tab). Claude Code asks for your API key when you enable the plugin.
- **Claude Desktop chat** runs local MCP servers added via `claude_desktop_config.json`; use the [Desktop configuration](../../docs/CLIENT-SETUP.md#use-with-claude-desktop) rather than this Code plugin.
- **claude.ai web and mobile chat** do not run local MCP servers.
- **Cowork** does not prompt for plugin settings, so it cannot supply the API key and the server does not start there.

## What it runs

When Claude Code starts the plugin, it runs this command:

<!-- doc-provenance: source=file:plugins/claude/.claude-plugin/plugin.json@sha256:22daa18f8f80de9a6dc5f66032db95e19272b5d93bdbba8921fdf4f73762e436 support=0.7.1 case=claude-readme-1 -->
<!-- install-case: claude-readme-1 mode=uvx -->
```
uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

`uvx` (part of [uv](https://docs.astral.sh/uv/)) downloads the pinned `unifi-fabric-mcp-server` 0.7.1 package and its dependencies from PyPI, and runs it as a local MCP server over stdio. You need `uv` installed. The server needs Python 3.12 or newer; `uv` downloads a suitable Python if you do not have one. The package's own dependencies (FastMCP, httpx, pydantic and a few small libraries) resolve from PyPI at install time.

The plugin explicitly sets your API key (`UNIFI_API_KEY`), the write policy option (`UNIFI_WRITE_POLICY`: `allow`, `dry-run` or `deny`), the tool mode option (`UNIFI_TOOL_MODE`), and `FASTMCP_TRANSPORT=stdio`. The tool mode defaults to `discovery` (five meta-tools: `search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`, `list_tool_families`; four with the write policy `deny`, which hides `call_write_tool`); choose `full` to advertise every tool, or `codemode` for the experimental, read-only [Code Mode](../../docs/CONFIGURATION.md#code-mode-experimental). The server also inherits Claude Code's environment and reads the other documented settings. A nonempty `UNIFI_API_KEYS` overrides the single plugin key; unset it before starting Claude Code to use only the plugin's key. Inherited HTTP authentication or TLS settings can also prevent this stdio server from starting.

## Where your data goes

The server sends requests to one host: **`api.ui.com`**, Ubiquiti's UniFi Site Manager / Fabric cloud API, over HTTPS, authenticated with your API key. Requests that reach your consoles (Network, Protect, InnerSpace and the generic connector tools) also go to `api.ui.com`, through Ubiquiti's cloud connector at `https://api.ui.com/v1/connector/consoles/<console id>/...`; the server never connects to a console, controller or device directly.

Nothing else is contacted. The server has no telemetry, analytics, crash reporting or update checks, and it does not send data to SWK Studios or anyone else. (If you set `UNIFI_API_BASE_URL` yourself, requests go to that address instead of `api.ui.com`.) Some tool responses contain links such as Ubiquiti product image URLs on `static.ui.com` or console asset URLs; the server only returns these as text and does not fetch them.

What the server returns becomes part of your Claude Code conversation, like any other tool result, and is handled under your agreement with Anthropic. By default the server returns UniFi's responses unchanged, and those can include Wi-Fi passphrases, RADIUS secrets, VPN keys, client names, IP and MAC addresses, GPS coordinates and Protect recognition data. The one exception: if a response echoes your API key, the server always replaces it with `***`.

See the [privacy policy](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/main/PRIVACY.md) for the full statement.

## Read and write

The server has read tools (list and inspect sites, devices, clients, networks, Wi-Fi, firewall, VPN, statistics, Protect cameras and events) and write and action tools (create, update and delete configuration, restart or locate devices, block clients, Protect actions, and more). The full list is in [TOOLS.md](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/main/docs/TOOLS.md).

**Writes are on by default** (Write policy `allow`). Set the plugin's **Write policy** option to `deny` to hide every write and action tool and refuse any call to one before anything is sent to UniFi; read tools keep working. `dry-run` returns a preview of every write and sends nothing. Claude Code also asks for your approval before it calls a tool, unless you have allowed it.

Some tools depend on console-internal paths that Ubiquiti can restrict without notice. Set `UNIFI_EXCLUDE=unofficial,source:relay` for a published-API-only profile.

## Privacy options

- **Credential masking (opt-in):** start Claude Code with `UNIFI_REDACT_SECRETS=1` in its environment to replace a documented list of credential fields (Wi-Fi passphrases, RADIUS secrets, VPN keys, private keys) with `***REDACTED***` in every response. It is off by default.
- **Audit log (opt-in, local):** start Claude Code with `UNIFI_AUDIT_LOG=/path/to/audit.log` to append one line per write attempt (time, method, path, outcome, status) to a file on your computer. Records are JSON lines by default; set `UNIFI_AUDIT_LOG_FORMAT=text` for key=value lines. The API key is never written; the request body only with `UNIFI_AUDIT_LEVEL=debug` (credential fields masked). It is off by default. Audit logging is best-effort: an I/O failure produces a warning on stderr and the tool call continues, so create a writable parent directory before enabling it.

The plugin's server inherits Claude Code's environment, so these are set in the shell you start Claude Code from. The [configuration reference](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/main/docs/CONFIGURATION.md) lists every option.

## Get an API key

1. Sign in to [UniFi Site Manager](https://unifi.ui.com) with your Ubiquiti account.
2. Choose your organization (top left).
3. Open **API Keys** in the left sidebar and select **Create New API Key**.
4. Enable the **Site Manager** and **Network** scopes, and **Protect** if you want camera tools.
5. Choose the sites the key may access, then copy the key. It is shown only once.

Your consoles must be adopted to your UI.com account and connected to Ubiquiti's cloud. UniFi API keys cannot be limited to read access, so set the plugin's Write policy option to `deny` if you want a read-only setup.

## Install

Update Claude Code before installing this plugin. The manifest was validated with Claude Code 2.1.296; older releases may reject its fields or lack the plugin settings prompt.

In Claude Code, add this repository's marketplace and install the plugin (Claude Code 2.1.275 or later installs in one step):

<!-- doc-provenance: source=file:plugins/claude/.claude-plugin/plugin.json@sha256:22daa18f8f80de9a6dc5f66032db95e19272b5d93bdbba8921fdf4f73762e436 support=0.7.1 citation=file:plugins/claude/.claude-plugin/plugin.json@sha256:22daa18f8f80de9a6dc5f66032db95e19272b5d93bdbba8921fdf4f73762e436 -->
<!-- install-case: claude-readme-2 mode=non-executable reason=deployment-or-client-interaction -->
```
/plugin marketplace add swkstudios/unifi-fabric-mcp-server
/plugin install unifi-fabric@unifi-fabric
```

Or try this folder for one session from a checkout:

<!-- doc-provenance: source=file:plugins/claude/.claude-plugin/plugin.json@sha256:22daa18f8f80de9a6dc5f66032db95e19272b5d93bdbba8921fdf4f73762e436 support=0.7.1 citation=file:plugins/claude/.claude-plugin/plugin.json@sha256:22daa18f8f80de9a6dc5f66032db95e19272b5d93bdbba8921fdf4f73762e436 -->
<!-- install-case: claude-readme-3 mode=non-executable reason=deployment-or-client-interaction -->
```
claude --plugin-dir ./plugins/claude
```

Claude Code asks for your API key, Tool mode and the Write policy option (`allow`, `dry-run` or `deny`; lower case, and a blank or other value stops the server from starting) when the plugin is enabled. Claude Code stores the key in its secure credential storage (the macOS Keychain, or a credentials file in your Claude Code configuration folder where no supported keychain exists), not in a settings file. To change these values later, run `/plugin`, choose **Manage**, and open the plugin to configure it.

## Skills

The plugin also loads six workflow skills from its `skills/` folder: firewall zone and policy audit, network or VLAN change, device and client troubleshooting, Protect camera and event review, Wi-Fi radio change, and site health report. Claude Code offers them as `/unifi-fabric:<skill>` and can load one on its own when a task matches. Each skill reads before it writes, shows you the exact change, and reads back afterwards; it holds no credentials.

## Example prompts

- "List my UniFi sites and the devices in each one."
- "Are any devices offline right now? Show their site and model."
- "How many clients are connected to each site, and which access point has the most?"
- "Show my firewall policies in order and explain what each one allows or blocks."
- "List my Protect cameras and tell me which ones are disconnected."

## Troubleshooting

- **No API key:** Claude Code does not start the server and reports `Plugin option "unifi_api_key" isn't set. Open /plugin manage to configure it`. Run `/plugin`, open UniFi Fabric MCP under **Manage**, and enter your key.
- **Wrong or revoked key:** the server starts, but every tool call that reaches UniFi fails with UniFi's own response, for example `HTTP 401 from GET /v1/hosts: {"code":"unauthorized",...}`. Calls answered locally still work: the discovery tools (`search_tools`, `describe_tool`, `list_tool_families`) and `list_configured_api_keys`. Create a new key as described above and update it in `/plugin`.
- **Server fails to start:** make sure `uv` is installed and on your `PATH` (`uvx --version`). The first start downloads the package, so it needs internet access to PyPI.
- **A console or site is missing:** the key only sees consoles in the organization and sites it was created for, and the console must be online and connected to the cloud.
- **A write tool is missing or was refused:** check whether the Write policy option is `deny`, or whether `UNIFI_WRITE_EXCEPTIONS` in the environment Claude Code passes to the server holds a `deny` entry for the tool or its area (for example `family:network=deny`, `family:protect=deny` or `family:connector=deny`). Both hide the write tools they refuse.

## Support and security

- Questions and bugs: [GitHub issues](https://github.com/swkstudios/unifi-fabric-mcp-server/issues)
- Security problems: follow the [security policy](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/main/.github/SECURITY.md) and report privately; do not open a public issue.

## License

MIT. See [LICENSE](LICENSE).
