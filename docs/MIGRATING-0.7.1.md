# Migrating to 0.7.1

0.7.1 replaces the 0.7.0 write and exposure settings with four settings: `UNIFI_WRITE_POLICY`, `UNIFI_WRITE_EXCEPTIONS`, `UNIFI_FAMILY_ALLOW` and `UNIFI_EXCLUDE`. The old names have no aliases. A 0.7.1 server that finds any `UNIFI_*` variable it does not recognise refuses to start, before it reads any other setting or opens a port. It writes this line to stderr, followed by the line `startup:retired:<first name>`, and exits with status 2:

<!-- doc-provenance: source=file:src/unifi_fabric/policy.py@sha256:edf300de0646b969e678363a5b1069b57cf87c58a60226fb50e37198a96ed7b4 support=0.7.1 citation=file:src/unifi_fabric/policy.py@sha256:edf300de0646b969e678363a5b1069b57cf87c58a60226fb50e37198a96ed7b4 -->
```text
unifi-fabric-mcp 0.7.1: unrecognized settings: <NAMES>. Settings were renamed in 0.7.1 and the old names are not accepted. Migrate: <this guide> (one command: uv run <migrator URL> <config file>)
```

The server keeps no list of the old names. The names in the message come from your environment, and the mapping lives only in this guide and in the one-shot migrator below.

Stay on `unifi-fabric-mcp-server==0.7.0` (or the `0.7.0` image tag) until you have migrated. Configuration that names none of the old settings needs no change.

Family selection changes: `list_vpn_servers`, `list_site_to_site_tunnels`, and `list_radius_profiles` move from `network` to `vpn`; `list_device_tags`, `get_scheduled_task`, and `list_scheduled_tasks` move from `network` to `devices`. Update network-only `UNIFI_FAMILY_ALLOW` settings to include the relevant families. Family exclusions and `family:` write selectors also use the new families.

## Active clients tool split

In 0.7.0, `list_clients` accepted `source="v2"` to select the controller's active-client
route. In 0.7.1, `list_clients` is the official Integration API list only; its default
behavior and `host`, `site`, `offset`, `limit`, `client_type`, and `filter` arguments are unchanged.

Use `list_active_clients(host, site, include_matter_thread_clients=None,
include_traffic_usage=None, include_unifi_devices=None)` for the former `source="v2"`
path. It keeps the GET `network/v2/api/site/{site_slug}/clients/active` route and returns
the upstream body verbatim. Each optional `include_*` flag is omitted by default; when supplied,
`True` and `False` are sent as the lowercase query values `true` and `false`.

| 0.7.0 | 0.7.1 |
| --- | --- |
| `list_clients(host, site, source="v2", include_*)` | `list_active_clients(host, site, include_*)` |
| `list_clients` default or `source="integration"` | `list_clients(host, site, offset, limit, client_type, filter)` |
| one selector changed routes | separate route-explicit tools |

## Migrate with one command

The migrator is a standalone Python script (Python 3.11 or later, standard library only). It is not part of the installed package, and the server never runs it. Run it on each file that configures the server. It prints a diff of setting names and new values and writes nothing:

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
<!-- install-case: docs-migrating-071-1 mode=non-executable reason=deployment-or-client-interaction -->
```bash
uv run https://raw.githubusercontent.com/swkstudios/unifi-fabric-mcp-server/v0.7.1/tools/migrate-0.7.1-env.py ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Without uv, download the script once and run it with `python3`:

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
```bash
curl -fsSLO https://raw.githubusercontent.com/swkstudios/unifi-fabric-mcp-server/v0.7.1/tools/migrate-0.7.1-env.py
python3 migrate-0.7.1-env.py .mcp.json
```

A dry run looks like this. Removed settings are shown by name only. The script never prints an old value or the value of any other setting, such as your API key:

<!-- install-case: docs-migrating-071-6 mode=non-executable reason=deployment-or-client-interaction -->
<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
```text
== claude_desktop_config.json (json)
mcpServers.unifi-fabric.env:
  - UNIFI_READ_ONLY
  - UNIFI_ENABLE_NETWORK_WRITE
  + UNIFI_WRITE_POLICY=deny
  + UNIFI_WRITE_EXCEPTIONS=family:network=deny
Dry run: nothing written. Run again with --write to save (keeps a .bak copy).
```

Add `--write` to save the change. The script first copies the file to `<file>.bak`. Then restart the client or container, and change the package pin or image tag to 0.7.1.

| File | What the script does |
| --- | --- |
| Client JSON (`*.json`): Claude Desktop `claude_desktop_config.json`, Claude Code `.mcp.json` or `~/.claude.json`, Gemini CLI `settings.json`, Antigravity `mcp_config.json` | Rewrites every `env` object and every `-e`/`--env` pair in an `args` list. With `--write` the file is saved with consistent indentation. |
| Docker Compose (`*.yml`, `*.yaml`) | Rewrites `environment:` entries in list or map form. When the service also has an `env_file`, the script reads it (relative to the Compose file) and merges the 0.7.1 values it holds, or will hold once migrated, into each new entry. A service whose environment can also come from somewhere the script does not read is left unchanged and marked `# MANUAL:` (see [Compose env_file](#compose-env_file)). |
| Compose `env_file` or `.env` (`*.env`, `.env`, `.env.*`) | Rewrites `KEY=VALUE` lines. |
| Codex `config.toml` (`*.toml`) | Prints the lines to delete and the lines to add in each `env` table; it does not edit TOML. |
| Shell profile or script (any other file) | Prints replacement `export` lines and `docker run -e` flags; it does not edit the file. |
| The current environment (`--env`, no file) | Prints `unset` and `export` lines for the shell you run it in. |

Use `--format json|env|compose|toml|shell` when the file name does not match. The exit status is 0 when nothing needs a decision, 3 when a `# MANUAL:` item remains (see [Decide manually](#decide-manually)), and 2 when the file cannot be read or parsed.

## Mapping

Each row maps one 0.7.0 setting and value to its 0.7.1 replacement. The migrator applies the same table; a test keeps the two identical.

| 0.7.0 setting | 0.7.0 value | 0.7.1 setting | 0.7.1 value |
| --- | --- | --- | --- |
| `UNIFI_READ_ONLY` | true | `UNIFI_WRITE_POLICY` | `deny` |
| `UNIFI_READ_ONLY` | false or empty | remove the setting | - |
| `UNIFI_DRY_RUN` | true | `UNIFI_WRITE_POLICY` | `dry-run` |
| `UNIFI_DRY_RUN` | false or empty | remove the setting | - |
| `UNIFI_ENABLE_CONNECTOR_WRITE` | false | `UNIFI_WRITE_EXCEPTIONS` | `family:connector=deny` |
| `UNIFI_ENABLE_CONNECTOR_WRITE` | true or empty | remove the setting | - |
| `UNIFI_ENABLE_NETWORK_WRITE` | false | `UNIFI_WRITE_EXCEPTIONS` | `family:network=deny` |
| `UNIFI_ENABLE_NETWORK_WRITE` | true or empty | remove the setting | - |
| `UNIFI_ENABLE_MOBILITY_WRITE` | false | `UNIFI_WRITE_EXCEPTIONS` | `family:mobility=deny` |
| `UNIFI_ENABLE_MOBILITY_WRITE` | true or empty | remove the setting | - |
| `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` | false | `UNIFI_WRITE_EXCEPTIONS` | `family:carrier=deny` |
| `UNIFI_ENABLE_CARRIER_FABRIC_WRITE` | true or empty | remove the setting | - |
| `UNIFI_ENABLE_INNERSPACE_WRITE` | false | `UNIFI_WRITE_EXCEPTIONS` | `family:innerspace=deny` |
| `UNIFI_ENABLE_INNERSPACE_WRITE` | true or empty | remove the setting | - |
| `UNIFI_PROTECT_MUTATIONS_ENABLED` | false | `UNIFI_WRITE_EXCEPTIONS` | `family:protect=deny` |
| `UNIFI_PROTECT_MUTATIONS_ENABLED` | true or empty | remove the setting | - |
| `UNIFI_TOOL_FAMILIES` | family names | `UNIFI_FAMILY_ALLOW` | the names, lower case, comma-separated |
| `UNIFI_TOOL_FAMILIES` | empty | remove the setting | - |
| `UNIFI_DISABLED_TOOL_FAMILIES` | family names | `UNIFI_EXCLUDE` | `family:<name>` for each name |
| `UNIFI_DISABLED_TOOL_FAMILIES` | empty | remove the setting | - |
| `UNIFI_DISABLE_API_SOURCES` | selectors | `UNIFI_EXCLUDE` | `source:<selector>` for each selector |
| `UNIFI_DISABLE_API_SOURCES` | an app/source/access selector | decide manually | - |
| `UNIFI_DISABLE_API_SOURCES` | empty | remove the setting | - |

How the 0.7.0 values are read:

- **True** is `1`, `true`, `yes`, `on`, `t` or `y`, and **false** is `0`, `false`, `no`, `off`, `f` or `n`, in any letter case. An empty value meant "unset" in 0.7.0, so the setting is simply removed. The per-area write settings defaulted to true and `UNIFI_READ_ONLY` and `UNIFI_DRY_RUN` to false, so a configuration that left them unset needs nothing.
- **Family names** were separated by commas or whitespace, in any letter case. 0.7.1 takes lower-case IDs separated by commas only, each named once: `"Network PROTECT"` becomes `network,protect`. The family IDs are unchanged: `carrier`, `clients`, `connector`, `devices`, `firewall`, `hotspot`, `innerspace`, `mobility`, `network`, `protect`, `site_manager`, `statistics` and `vpn`.
- **Selectors** were comma-separated and matched in any letter case. 0.7.1 matches them case-sensitively in lower case, so `Protect/Private` becomes `source:protect/private`.

How several settings combine into one:

- `UNIFI_READ_ONLY` and `UNIFI_DRY_RUN` both set `UNIFI_WRITE_POLICY`. When both are true, the stricter value (`deny`) wins, as it did in 0.7.0. When `UNIFI_WRITE_POLICY` is already set, the strictest of the three applies (`allow` < `dry-run` < `deny`).
- Each per-area write setting that is false adds one entry to `UNIFI_WRITE_EXCEPTIONS`, separated by semicolons, after any entries the setting already has: `family:network=deny;family:protect=deny`.
- `UNIFI_DISABLED_TOOL_FAMILIES` and `UNIFI_DISABLE_API_SOURCES` both add entries to `UNIFI_EXCLUDE`, separated by commas: `family:vpn,source:network/private`.

## Decide manually

The migrator does not guess in these cases. It leaves the old setting in place, so the server keeps refusing to start until you choose, and it marks the setting with a `# MANUAL:` comment (Compose and `.env` files) or prints the `# MANUAL:` line (JSON, TOML and shell, and a Compose service it leaves unchanged because it cannot resolve the service's environment):

- **An app/source/access selector** in `UNIFI_DISABLE_API_SOURCES`, such as `network/private/write`. 0.7.0 disabled the write tools of that one source. 0.7.1 has no selector for that combination: `source:network/private` hides every private Network tool, and `source:network/write` hides every Network write tool. Use the wider of the two, or list the tools you want to hide with `tool:<name>` entries in `UNIFI_EXCLUDE`.
- **A value the script cannot read**, such as a `${VAR}` reference, a Compose interpolation, or a name passed through from the parent environment (`-e UNIFI_READ_ONLY` with no value, or Codex `env_vars`). Migrate the place where the value is set, for example the shell that starts the client (`--env` prints the lines), then rename the variable here.
- **A value 0.7.0 would also have rejected**, such as `UNIFI_READ_ONLY=maybe` or an unknown family name.
- **A 0.7.1 setting that is already set to a value the script cannot read or merge**, such as a `${VAR}` reference on `UNIFI_WRITE_POLICY` or `UNIFI_EXCLUDE`, an `UNIFI_EXCLUDE` value the script cannot parse, or `UNIFI_FAMILY_ALLOW` next to `UNIFI_TOOL_FAMILIES`.
- **A new entry that would replace a value set somewhere the script cannot read**: a Compose service whose environment the script cannot fully resolve (see [Compose env_file](#compose-env_file)); an env_file value the script cannot read, such as a `${VAR}` reference; a `docker run` with `--env-file`, whose `-e` flags replace the file's values; or an env_file `UNIFI_FAMILY_ALLOW` under an `UNIFI_TOOL_FAMILIES` entry. Combine the two values by hand.

### Compose env_file

Compose reads a service's `env_file` first, and an `environment:` entry replaces any value the env_file sets for the same name. So a new `UNIFI_WRITE_EXCEPTIONS`, `UNIFI_EXCLUDE` or `UNIFI_WRITE_POLICY` entry in `environment:` would silently drop the env_file's value, for example a `family:vpn=deny` exception. The script reads the env_file and writes the merged value: the env_file's entries plus the new ones, or the stricter write policy.

The script rewrites a service's `environment:` only when it can resolve every source of that service's environment: the service's own `environment:` in list or map form, directly under the top-level `services:`, and its `env_file` (a path, a list of paths, or `path:` entries with `required:`) made of plain `NAME=value` lines. Otherwise it leaves the service exactly as it is, prints a `# MANUAL:` line that names the service, what it uses and the 0.7.0 settings left in place, and exits with status 3. That happens when:

- the file uses YAML anchors (`&name`), aliases (`*name`), `<<:` merge keys or tags such as `!reset` and `!override` anywhere, or `extends:` or a top-level `include:`, because a service's settings can then come from, or be shared with, another mapping or file; this covers an `environment:` inherited through `<<:` or `extends:` by a service that has its own `env_file`;
- an override file sits next to the Compose file (any of `compose.override.yml`, `compose.override.yaml`, `docker-compose.override.yml`, `docker-compose.override.yaml`, whatever the main file is called, or `<name>.override.yaml` next to `<name>.yaml`), or the file is itself an override file;
- the file has more than one YAML document (a `---` or `...` line after content), uses an explicit `? key`, or a double-quoted key with an escape sequence, because Compose reads keys the script cannot match by their text;
- a service has `build:`, because an `ENV` in the image it builds is the lowest layer of its environment and the script does not read it (the published image sets no `UNIFI_` policy settings; check an `ENV` in any image you build or derive yourself);
- the settings are not in the `environment:` of a service, for example in an `x-` block, or are in a form the script does not rewrite, such as a flow list `environment: [...]` or mapping `environment: {...}`;
- the service's `env_file` is missing or unreadable, uses an interpolated path, sets `format:`, or has a line the script does not parse: a `UNIFI_` setting written as `NAME = value`, `NAME: value` or a bare `NAME`, or a quoted value that runs onto the next line.

The script reads one Compose file. When `COMPOSE_FILE` is set, in your shell or in the `.env` file next to the Compose file (which a plain `docker compose up` reads), or `COMPOSE_ENV_FILES` is set in your shell, it leaves the file unchanged and prints a `# MANUAL:` line. It cannot see other Compose files you pass with `-f`, a `.env` in the directory you run Compose from when the Compose file is in a parent directory, or an `env_file` they add to a service, so check those yourself. Profiles only choose which services start; they do not change a service's environment. The same applies the other way round: when you migrate an env_file, check that the service's `environment:` does not also set the 0.7.1 setting, because that entry wins.

Two client integrations store settings where the script cannot reach them. Change those by hand:

- **Claude Code plugin:** the plugin asks for the Write policy option (`allow`, `dry-run` or `deny`). After the plugin updates, open `/plugin`, choose UniFi Fabric MCP under **Manage**, and set it to `deny` if you used read-only mode.
- **Claude Desktop extension (`.mcpb`) and Gemini CLI extension:** the 0.7.1 extension asks for the Write policy setting instead of the read-only toggle. Reinstall or update the extension and choose the value from the table.

## Examples by client

Each example is the 0.7.1 form of a read-only setup that also turned off Protect writes (0.7.0: `UNIFI_READ_ONLY=1` and `UNIFI_PROTECT_MUTATIONS_ENABLED=0`). Replace `your-api-key-here` with your key.

**Claude Desktop** (`claude_desktop_config.json`), **Claude Code** (`.mcp.json`), **Gemini CLI** (`settings.json`) and **Antigravity** (`mcp_config.json`) all use an `env` object:

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
<!-- install-case: docs-migrating-071-2 mode=non-executable reason=deployment-or-client-interaction -->
```json
{
  "mcpServers": {
    "unifi-fabric": {
      "command": "uvx",
      "args": ["--from", "unifi-fabric-mcp-server==0.7.1", "unifi-fabric-mcp"],
      "env": {
        "UNIFI_API_KEY": "your-api-key-here",
        "UNIFI_WRITE_POLICY": "deny",
        "UNIFI_WRITE_EXCEPTIONS": "family:protect=deny"
      }
    }
  }
}
```

**Claude Code** from the command line:

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
<!-- install-case: docs-migrating-071-3 mode=non-executable reason=deployment-or-client-interaction -->
```bash
claude mcp remove unifi-fabric
claude mcp add unifi-fabric -e UNIFI_API_KEY="$UNIFI_API_KEY" -e UNIFI_WRITE_POLICY=deny -e "UNIFI_WRITE_EXCEPTIONS=family:protect=deny" -- uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

**Codex** (`~/.codex/config.toml`):

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
<!-- install-case: docs-migrating-071-4 mode=non-executable reason=deployment-or-client-interaction -->
```toml
[mcp_servers.unifi-fabric]
command = "uvx"
args = ["--from", "unifi-fabric-mcp-server==0.7.1", "unifi-fabric-mcp"]
env_vars = ["UNIFI_API_KEY"]

[mcp_servers.unifi-fabric.env]
UNIFI_WRITE_POLICY = "deny"
UNIFI_WRITE_EXCEPTIONS = "family:protect=deny"
```

**Shell** (the environment that starts Codex, the Codex plugin, Antigravity or Claude Code). Quote values that contain a semicolon:

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
```bash
unset UNIFI_READ_ONLY UNIFI_PROTECT_MUTATIONS_ENABLED
export UNIFI_WRITE_POLICY=deny
export UNIFI_WRITE_EXCEPTIONS='family:protect=deny'
```

**Docker:**

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
<!-- install-case: docs-migrating-071-5 mode=non-executable reason=deployment-or-client-interaction -->
```bash
docker run --rm -i -e UNIFI_API_KEY -e UNIFI_WRITE_POLICY=deny -e "UNIFI_WRITE_EXCEPTIONS=family:protect=deny" -e FASTMCP_TRANSPORT=stdio ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.1
```

**Docker Compose** (an `env_file` takes the same `KEY=VALUE` lines without the leading dash):

<!-- doc-provenance: source=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c support=0.7.1 citation=file:tools/migrate-0.7.1-env.py@sha256:4dda589fb01d615ba5036143c6881333637947a5e2e3f445b4e767d9559eec5c -->
```yaml
services:
  unifi-fabric-mcp:
    image: ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.1
    environment:
      - UNIFI_API_KEY=${UNIFI_API_KEY}
      - UNIFI_WRITE_POLICY=deny
      - UNIFI_WRITE_EXCEPTIONS=family:protect=deny
```

## Common settings

| Goal | 0.7.0 | 0.7.1 |
| --- | --- | --- |
| Read-only | `UNIFI_READ_ONLY=1` | `UNIFI_WRITE_POLICY=deny` |
| Preview every write | `UNIFI_DRY_RUN=1` | `UNIFI_WRITE_POLICY=dry-run` |
| Writes on except one area | `UNIFI_ENABLE_NETWORK_WRITE=0` | `UNIFI_WRITE_EXCEPTIONS=family:network=deny` |
| Writes on, one area previewed | none | `UNIFI_WRITE_EXCEPTIONS=family:protect=dry-run` |
| Only some families | `UNIFI_TOOL_FAMILIES=network,protect` | `UNIFI_FAMILY_ALLOW=network,protect` |
| One family hidden | `UNIFI_DISABLED_TOOL_FAMILIES=vpn` | `UNIFI_EXCLUDE=family:vpn` |
| One API source hidden | `UNIFI_DISABLE_API_SOURCES=network/private` | `UNIFI_EXCLUDE=source:network/private` |

The full grammar of the four settings is in [CONFIGURATION.md](CONFIGURATION.md).

## When this guide is removed

The migrator and this guide are deleted from the main branch in 0.7.2, and no later than 2026-12-03. The `v0.7.1` tag keeps both, so the links in the 0.7.1 startup message keep working. A later release still refuses unrecognised `UNIFI_*` settings at startup. If you upgrade from 0.7.0 to a later release, install 0.7.1 first, migrate with this guide, then upgrade.

For the 0.7.0 behaviour changes, see [MIGRATING-0.7.md](MIGRATING-0.7.md).
