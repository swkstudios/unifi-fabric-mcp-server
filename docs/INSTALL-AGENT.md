# Agent install guide

Choose a checked launch path below. The linked README sections explain client setup.
These cases start the server, compare the complete tool catalog, perform a read against
a local mock, and check clean missing-key and wrong-key messages. Client marketplace
installation and account setup remain manual steps; those interactions are not claimed
as executed tests.

A same-repository pull request executes every row except the two Docker rows, on Linux.
The Docker rows run only in the `linux-docker` job, on a published release or a manual
dispatch on a protected ref (see [Verification evidence](#verification-evidence)).

| Path | Executed case | Setup |
|---|---|---|
| uvx | `readme-install-20` | [README](CLIENT-SETUP.md#track-a--local-stdio) |
| pipx | `readme-install-21` | [README](CLIENT-SETUP.md#track-a--local-stdio) |
| pip venv (local sdist) | `readme-install-22` | [README](CLIENT-SETUP.md#track-a--local-stdio) |
| Editable source (local sdist) | `readme-install-28` | [README](CLIENT-SETUP.md#track-c--from-source-development) |
| Claude plugin launcher | `readme-install-09` | [README](CLIENT-SETUP.md#install-as-a-claude-code-plugin) |
| Claude Desktop JSON | `readme-install-11` | [README](CLIENT-SETUP.md#use-with-claude-desktop) |
| Codex TOML | `readme-install-12` | [README](CLIENT-SETUP.md#use-with-openai-codex) |
| Antigravity manifest launcher | `antigravity-plugin-manifest`, `readme-install-16`, `readme-install-17`, `readme-install-18` | [README](CLIENT-SETUP.md#use-with-google-antigravity) |
| Codex plugin JSON | `codex-plugin-manifest` | [README](CLIENT-SETUP.md#use-with-openai-codex) |
| Docker HTTP with bearer client config | `readme-install-24`, `readme-install-25` | [README](CLIENT-SETUP.md#track-b--docker-http) |
| Docker HTTP on loopback without bearer | `readme-install-27` | [README](CLIENT-SETUP.md#track-b--docker-http) |

## Local stdio

Requires Python 3.12+ and uv. Replace the placeholder with your own key for real use.
The smoke job substitutes a synthetic key and repins the package to its local wheel.

<!-- install-case: install-agent-uvx mode=uvx -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=install-agent-uvx -->
<!-- docs-fact: run -->
```bash
export UNIFI_API_KEY="your-api-key-here"
uvx --from unifi-fabric-mcp-server==0.7.1 unifi-fabric-mcp
```

## Desktop configuration

Set the absolute uvx path as described in the linked README, then restart the client.
The smoke job parses this JSON and launches its declared command over stdio.

<!-- install-case: install-agent-desktop mode=desktop -->
<!-- doc-provenance: source=file:scripts/extract_install_cases.py@sha256:28801c0956bd864ce308d568a20859b4ec881331cc627b23ffef6d1b80fc9458 support=0.7.1 case=install-agent-desktop -->
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

## Verification evidence

The install workflow uploads `install-results.json` with each case status and catalog count.
The Linux pull-request job executes non-Docker launch paths with `--skip-docker`.
The separate `linux-docker` job executes Docker built from the local wheel only for a
published release or a manual dispatch on a protected ref. Desktop-platform rehearsals
require a manual dispatch with `release_rehearsal` enabled; inspect the workflow's
configured platforms and uploaded artifacts before claiming platform coverage.
Docker stays on Linux. A skipped or `NOT-TESTED` case is not a passing execution.
Client UI interactions remain outside these launcher probes.
