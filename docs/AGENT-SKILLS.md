# Agent skills

The [`skills/`](../skills/) folder holds six workflow skills for AI clients. Each is a folder
with one `SKILL.md`: a short frontmatter (`name`, and a `description` saying when to load it)
and one workflow that names the tools to call, their arguments and the order.

| Skill | Workflow |
|---|---|
| `firewall-zone-policy-audit` | List zones and policies, flag WAN-to-LAN allows, and change the policy order within one zone pair |
| `network-vlan-read-modify-write` | Read one network, change only the approved fields, update it and read it back |
| `device-client-troubleshooting` | Device, switch port, client link and spanning-tree reads before any restart |
| `protect-camera-event-review` | Cameras, events in a time window and a snapshot, read-only |
| `wifi-radio-change` | Channel plan and AP radios, a previewed radio change, the DFS wait and a read-back |
| `site-health-report` | Site health, inventory, ISP metrics and fleet summary in a fixed outline |

Every write workflow reads first, shows you the exact change, uses the tool's own dry-run
preview where it has one, and reads back afterwards. For anything outside its workflow a skill
tells the agent to find the tool with `search_tools` and read its schema with `describe_tool`.
A skill holds no credentials and calls nothing by itself: the agent still needs this MCP server
configured, and server settings such as read-only mode stay yours to set.

## Install

| Client | How to install the skills |
|---|---|
| Claude Code | Included in the [plugin](../README.md#2-connect-your-assistant) under `plugins/claude/skills/`; they load with the plugin as `/unifi-fabric:<skill>`. Without the plugin, copy a skill folder into `~/.claude/skills/` or a project's `.claude/skills/`. |
| Claude Desktop and claude.ai | Zip one skill folder, with the folder itself at the root of the ZIP, and upload it under **Customize > Skills**. Code execution must be turned on. |
| Codex | The Codex plugin does not include them. Copy a skill folder into `~/.agents/skills/` or a repository's `.agents/skills/`, and restart Codex if it does not appear. |
| Gemini CLI | The extension installs from this repository's root, and Gemini CLI reads an extension's skills from its `skills/` folder, so the extension brings them; we have not run this in Gemini CLI. You can also copy a skill folder into `~/.gemini/skills/` or a project's `.gemini/skills/` and run `/skills reload`. |
| Antigravity | The Antigravity plugin does not include them. Copy a skill folder into a workspace's `.agents/skills/`, or into `~/.gemini/config/skills/` for every workspace; the Antigravity CLI reads `~/.gemini/antigravity-cli/skills/`. |

The skill files in `plugins/claude/skills/` are a byte-identical copy of `skills/`; the test
suite checks that they match.
