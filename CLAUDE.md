# CLAUDE.md — UniFi Fabric MCP Server

## What this repo is

A Python MCP (Model Context Protocol) server that wraps the UniFi Site Manager cloud API (`api.ui.com`) as tools for AI assistants. Built with FastMCP. Enables Claude Code and other MCP clients to manage UniFi network infrastructure via natural language.

## Project structure

```
src/unifi_fabric/
  server.py        — FastMCP app, all @mcp.tool() definitions, lifespan setup
  client.py        — UniFiClient: async HTTP client (httpx) for api.ui.com
  config.py        — Settings (pydantic-settings), env var loading
  registry.py      — Lazy-load host/site cache with per-key TTL (MSP support)
  tools/           — Tool implementation modules (one per domain):
    site_manager.py, network.py, device_mgmt.py, clients.py,
    firewall_proxy.py, network_services_proxy.py, hotspot.py,
    protect.py, vpn.py, statistics.py, aggregation.py
tests/             — pytest + respx tests, one test file per tool module
Dockerfile         — Production container (python:3.12-slim-bookworm, digest-pinned)
requirements.lock  — Locked dependencies with hashes for reproducible Docker builds
pyproject.toml     — Hatchling build, deps, ruff + pytest config
```

## Development setup

See `README.md` for development setup instructions.

## Environment variables

See README.md for the full environment variable reference.

## Key conventions

- All tools are registered in `server.py` via `@mcp.tool()` decorators.
- Tool logic that needs HTTP calls uses helper functions from the `tools/` modules, receiving `client` and `registry` from `_require()`.
- The registry resolves host/site names to IDs so tools accept human-readable names.
- Multi-key MSP support: each API key gets independent cache entries in the registry.
- Python 3.12+ required. Ruff for linting (E, F, I, W, B, S, ANN, UP rules). Line length 100.

## Stateless Architecture

See README.md for stateless design rationale. Do not add file-based logging, databases, or persistent volumes to this project.

## What not to touch

- Do not remove or rename existing `@mcp.tool()` functions — external MCP clients depend on stable tool names.
- Do not change the `UNIFI_` env var prefix — it's a public contract.
- Do not change the entry point name `unifi-fabric-mcp` without updating Dockerfile and docs.

## Branch Strategy

- **main** is the primary branch. All PRs target `main`.
- CI triggers on push and PRs to `main`.


## CI requirements

- `ruff check` and `ruff format --check` must pass.
- `pytest tests/ -v` must pass.
- Both run in GitHub Actions (`.github/workflows/ci.yml`).

## Testing

**Running tests locally:**
```bash
pytest tests/ -v                    # Full test suite (unit + mocked integration)
pytest tests/ -v -k "not integration"  # Unit tests only (no live controller needed)
```

**Integration tests** require a live UniFi controller with `UNIFI_API_KEY` set. They are skipped automatically in CI via `pytest.mark.skipif`.

**Test structure:**
- `tests/` — all test files, named `test_<module>.py` matching `src/unifi_fabric/tools/<module>.py`
- `tests/fixtures/` — synthetic JSON response data (no real device data)

**Coverage expectations:**
- Every registered tool must have at least one happy-path test and one error-path test
- Write tools (create/update/delete) must verify input validation rejects empty/invalid payloads
- All test MACs, IPs, and hostnames must be clearly synthetic (never real hardware identifiers)

**Fresh-AI validation:**
- Tools must be usable with zero prior context — descriptions alone must guide correct usage
- The MCP INSTRUCTIONS constant is the primary discovery mechanism; keep it accurate

**Known limitations:** See README.md "Compatibility" section for firmware-specific constraints.

## Priority and workflow rules

**Task priority order:**
- Always prioritize urgent/P0 tasks before medium/low tasks.
- CI failures are always P0 — they block the project and require immediate attention.

**Mandatory local test before push:**
- Run `pytest tests/ -v` locally to completion before pushing any changes.
- Run `ruff check src/ tests/` and `ruff format --check src/ tests/` before pushing.
- Do not push if tests or linting fails locally.

**CI monitoring:**
- After pushing, immediately check CI status with `gh run list`.
- If CI fails, diagnosing and fixing it is your immediate next task — it is P0.
- Once CI is green again, continue with the next planned work.
