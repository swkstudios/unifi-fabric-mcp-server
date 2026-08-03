# CLAUDE.md — UniFi Fabric MCP Server

## What this repo is

A Python MCP (Model Context Protocol) server that wraps the UniFi Site Manager cloud API (`api.ui.com`) as tools for AI assistants. Built with FastMCP. Enables Claude Code and other MCP clients to manage UniFi network infrastructure via natural language.

## Pass-through invariant (do not break this)

**This server is a faithful pass-through. Tools return whatever the upstream
UniFi API returns for a request, unchanged. Do not add runtime filtering,
redaction, sanitisation, or field-stripping to tool *responses* — not for
credentials, not for MAC/IP/hostname identifiers, not for GPS coordinates, not
for asset URLs.**

Why this is a rule and not a preference — the reasoning is the guardrail, because
a bare "don't redact" line does not survive the next contributor who thinks they
are helpfully cleaning something up (which is exactly how such filtering got
written here before and had to be removed):

- **This is a layering decision, and the layer is wrong for policy.** The
  server's one job is faithful access. Whether a given caller is *allowed* to see
  a passphrase or a coordinate is a policy question that belongs to whoever
  deploys the server, and they have somewhere to put it — a proxy or wrapper
  between the consumer and this server.
- **The asymmetry is the whole argument.** A deployment can always ADD
  restriction on top of a faithful response (drop a field, mask a value). It can
  never RECOVER data the tool chose not to return. Withholding by default
  destroys information irreversibly for every downstream consumer, including the
  operator who legitimately owns that data and asked for it.
- **If you think output should be restricted, you are probably right for *your*
  deployment — so restrict it in *your* deployment,** not in this shared access
  layer. A reviewer may argue for narrowing what a tool returns; the data-survival
  tests (see `docs/internal/testing-procedure.md`) are the check on that, and they
  are meant to fail such a change loudly.

Scope note: this invariant is about tool *response bodies*. It is unrelated to
(a) redacting identifiers inside *error-message text* (`client.py`), which stays,
and (b) `.github/scripts/check_fixtures_sanitization.py`, which governs what
synthetic data may be committed into repo fixtures — a separate concern that also
stays. Conflating committed-fixture hygiene with runtime responses is how the
runtime filtering got written; keep them separate.

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
    protect.py, recognition.py, vpn.py, statistics.py, aggregation.py, innerspace.py,
    _history_common.py  — shared epoch-unit / host-error helpers (not a tool module)
    _pagination.py      — shared list-drain helpers for complete result sets across paginated endpoints (not a tool module)
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

All of the following must pass before pushing and are enforced by GitHub Actions
(`.github/workflows/ci.yml`):

- `ruff check src/ tests/` — linting (E, F, I, W, B, S, ANN, UP rules)
- `ruff format --check src/ tests/` — formatting
- "No runtime response redaction" grep step (in the `lint` job) — fails if a removed
  response-filtering helper reappears in `src/`, enforcing the pass-through invariant above

- `mypy src/unifi_fabric --ignore-missing-imports` — type checking
- `pytest tests/ -v --cov=src/unifi_fabric --cov-fail-under=91` — full suite with 91% coverage gate
- `python3 scripts/gen_tools_doc.py --check` — `docs/TOOLS.md` must be current with the runtime
- `gitleaks detect --no-git --source . --redact` — secret scanning (pinned CLI binary, not the action)
- `python3 .github/scripts/check_fixtures_sanitization.py` — synthetic-data assertion on fixtures
- `changelog-check` (`.github/workflows/changelog-check.yml`) — PRs that modify `src/` must also
  update `CHANGELOG.md` under `[Unreleased]`, or carry the `skip-changelog` label if the change
  has no user-visible effect (test-only, CI-only, pure refactor).

## Testing

**Running tests locally:**
```bash
pytest tests/ -v --cov=src/unifi_fabric --cov-report=term-missing  # Full suite + coverage
pytest tests/ -v -k "not integration"  # Unit only (no live API connection needed)
ruff check src/ tests/
ruff format --check src/ tests/
```

**Integration tests** require a live UniFi API connection (`UNIFI_API_KEY` pointing to `api.ui.com`).
They are permanently skipped in public CI. Do not add `@pytest.mark.integration` to unit tests.

**Test structure:**
- `tests/` — all test files, named `test_<module>.py` matching `src/unifi_fabric/tools/<module>.py`
- `tests/fixtures/` — synthetic JSON response data (no real device data)
- `tests/conftest.py` — shared fixtures: `multikey_client`, `multikey_registry`,
  `_hermetic_credentials_env` (autouse), `auth_http_client`

**Coverage gate:** CI enforces `--cov-fail-under=91`. Do not chase 100%; the gate is
a regression tripwire, not a quality target. Measure before raising it.

**Hermetic credential isolation (hard rule):** An autouse fixture `_hermetic_credentials_env`
in `tests/conftest.py` strips `UNIFI_*`, `MCP_*`, and `FASTMCP_*` from the process environment
before every unit test. Do not remove or weaken it. A unit test that reads a real credential
from the environment is an SR-8 violation — it will print it on assertion failure and write it
to the coverage report.

**Multi-key coverage is required, not optional:** Any tool that resolves hosts, sites, or API
keys must have a multi-key test in addition to its single-key tests. Use the shared
`multikey_client` and `multikey_registry` fixtures (two keys, `alpha` personal + `beta` org,
owning disjoint host sets). The multi-key test must assert the correct key is selected for a
`beta`-owned (non-first) host. Never roll a local two-key fixture; use the shared ones.

**Baseline requirements per tool:**
- At least one happy-path test and one error-path test.
- Write tools (create/update/delete): verify input validation rejects empty or invalid payloads.
- All test MACs, IPs, hostnames, site names, and console IDs must be clearly synthetic
  (enforced by `gitleaks` and `check_fixtures_sanitization.py`).
- A multi-key routing test for any tool that calls `client.request()` or uses the registry.

**Known gap (strict-xfail):** Per-host tools in `network`/`clients`/`device_mgmt`/`protect`
are not yet wired to `Registry.resolve_key_for_host`. Strict `xfail` tests in
`tests/test_multikey_routing.py` track this gap and will flip to hard failures once the
wiring lands.

**Fresh-AI validation:**
- Tools must be usable with zero prior context — descriptions alone must guide correct usage.
- The MCP INSTRUCTIONS constant is the primary discovery mechanism; keep it accurate.

**Known limitations:** See README.md "Compatibility" section for firmware-specific constraints.

## Changelog discipline

**Every PR that changes user-visible behavior must include a `CHANGELOG.md` entry.**

Add entries under `## [Unreleased]` following Keep a Changelog conventions:
- `### Added` — new tools, new env vars, new behavior
- `### Changed` — modifications to existing behavior or defaults
- `### Fixed` — bug fixes that affect tool output or correctness
- `### Removed` — removed tools, env vars, or features

**What qualifies:** new or removed tools, parameter behavior changes, new/modified env vars,
bug fixes affecting output, breaking changes.

**What does NOT need an entry:** test-only changes, internal refactors with no behavior
change, CI-only changes, dependency bumps (unless they change runtime behavior).

If a PR does not need a changelog entry, add the **`skip-changelog`** label in GitHub.
The `changelog-check` CI job skips the file check for PRs with that label.

**Public issue references only.** The changelog text is published verbatim in public release
history. Private PR/issue numbers (from this repo or internal trackers) are meaningless on
the public repository and 404 when followed. Use this exact format for public issues:
`([#N](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/N))`

Drop all other parenthetical `(#NNN)` references — let the description stand on its own.

## Known gotchas

- `list_sites` returns `siteId` in ObjectId hex format (from the EA API), which differs from the UUID format used in proxy API paths. Both are valid but for different API subsystems. The registry resolves the correct ID internally — tools accept human-readable site names.

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
