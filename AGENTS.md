# AGENTS.md — UniFi Fabric MCP Server

Instructions for AI coding agents and human contributors working on this repository.
`CLAUDE.md` imports this file, so Claude Code reads the same guide.

## What this repo is

A Python MCP (Model Context Protocol) server that wraps the UniFi Site Manager cloud API (`api.ui.com`) as tools for AI assistants. Built with FastMCP. Enables Claude Code and other MCP clients to manage UniFi network infrastructure via natural language.

## Pass-through invariant (do not break this)

**This server is a faithful pass-through. Tools return whatever the upstream
UniFi API returns for a request, unchanged. Do not add runtime filtering,
redaction, sanitisation, or field-stripping to tool *responses* — not for
credentials, not for MAC/IP/hostname identifiers, not for GPS coordinates, not
for asset URLs.**

There are exactly two built-in transforms. The server always replaces its own configured
secrets (its API keys, `MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`) with `***` wherever a
response, error or log line echoes them, and the operator's opt-in `UNIFI_REDACT_SECRETS`
masks documented credential fields with `***REDACTED***` (`src/unifi_fabric/secret_scrub.py`,
`src/unifi_fabric/redaction.py`). Anything else added to a response is a violation.

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
  tests are the check on that, and they
  are meant to fail such a change loudly.

Scope note: the same rule covers *error messages*. An upstream error is reported with
its real request path and its complete body — identifiers (console ids, UUIDs,
ObjectIds) are not secrets and are never masked, and nothing is truncated; credential
fields in an error body are masked only when the operator opts in with
`UNIFI_REDACT_SECRETS` (redact the secret, never the reason). It is unrelated to
`.github/scripts/check_fixtures_sanitization.py`, which governs what synthetic data
may be committed into repo fixtures — a separate concern that stays. Conflating committed-fixture hygiene with runtime responses is how the
runtime filtering got written; keep them separate.

## Using the server: discovery mode and tool families

The default `UNIFI_TOOL_MODE=discovery` advertises five discovery meta-tools (four with `UNIFI_READ_ONLY=1`, which hides
`call_write_tool`) instead of the full catalog: `search_tools` finds a tool, `describe_tool` returns its input
schema, `call_read_tool` or `call_write_tool` runs it, and `list_tool_families` lists
the families. `UNIFI_TOOL_MODE=full` advertises every tool (for gateways and clients that need
the whole catalog), `UNIFI_TOOL_FAMILIES` limits the catalog to the listed families, `UNIFI_DISABLED_TOOL_FAMILIES`
removes families, and `UNIFI_DISABLE_API_SOURCES` removes tools by API source selector.
Tool modules are grouped by UniFi product and task family under
`src/unifi_fabric/tools/`. Every tool advertises the four MCP annotation hints, derived
from source and never hand-set (`src/unifi_fabric/tool_annotations.py`): read-only when it
can issue no write verb, destructive for every write, idempotent for reads and single
PUT or DELETE writes, open-world when it reaches the UniFi upstream. `docs/TOOLS.md`
lists them per tool.

## Project structure

```
src/unifi_fabric/
  server.py       : FastMCP app, lifespan setup, the core @mcp.tool() definitions and the registration of every tools/ module
  client.py       : UniFiClient: async HTTP client (httpx) for api.ui.com; the single chokepoint for every upstream call (read-only, area opt-outs, dry-run, audit)
  config.py       : Settings (pydantic-settings, UNIFI_*) and MCPTransportSettings (MCP_*), env var loading and validation
  registry.py      — Lazy-load host/site cache with per-key TTL (MSP support)
  discovery.py    : discovery mode: the five meta-tools and the search index
  families.py, api_sources.py: tool families and API-source selectors (UNIFI_TOOL_FAMILIES, UNIFI_DISABLE_API_SOURCES)
  read_only.py, read_only_tools.py, switches.py: UNIFI_READ_ONLY and the per-area write opt-outs
  secret_scrub.py, redaction.py: the server's own secret scrub and the opt-in UNIFI_REDACT_SECRETS masking
  transport_security.py: HTTP auth, Host and Origin checks, OAuth write scope
  tool_annotations.py: the four MCP hints, derived from source
  tools/          : Tool modules, each with a register(mcp, deps_fn) function, grouped by product and task:
    site_manager.py, site_admin.py, aggregation.py, clients.py, client_records.py,
    device_mgmt.py, device_commands.py, device_radios.py, scheduled_tasks.py, system_log.py,
    network.py and the network_*.py modules (clients and guests, controller admin and insights,
    DPI policy, mobile WAN, NAT/QoS/traffic, routing and topology, security diagnostics,
    switching and power, VPN and DNS, Wi-Fi radio, device operations, ProAV sandbox),
    firewall_proxy.py, network_services_proxy.py, hotspot.py, vpn.py, vpn_clients.py,
    radius_profiles.py, statistics.py, matter.py, recognition.py, protect.py and the
    protect_*.py modules (camera recording, device lifecycle, events and cases, PTZ and doorbell,
    recognition search, users and assets, automation and backup, private API),
    innerspace.py, innerspace_internal.py, placement_snapshot.py, carrier_fabric.py, mobility.py,
    connector.py       : helpers of the generic Fabric connector relay (the fabric_connector_* tools are defined in server.py; not a register() module)
    site_config.py      — site configuration CRUD on the controller UI routes (user groups, static routes, RADIUS accounts on v2 radius/users batch routes, AP groups, port profile and Dynamic DNS create/delete)
    _history_common.py  — shared epoch-unit / host-error helpers (not a tool module)
    _pagination.py, _continuation.py, _number_window.py: shared list-drain, paging-window and resume helpers for complete result sets across paginated endpoints (not tool modules)
    _results.py         — shared write-tool result shapes (delete results carry the upstream body; not a tool module)
    _classic_objects.py — shared Classic networkconf / v2 device-tag route and id-resolution helpers for writes the Integration API does not serve (not a tool module)
tests/            : pytest + respx tests, one or more test files per tool module
Dockerfile         — Production container (python:3.12-slim-bookworm, digest-pinned)
requirements-runtime.lock — Runtime-only locked dependencies with hashes (the image, the Homebrew formula)
requirements.lock  — Development lock (runtime plus the `dev` extra): CI, test-locked and the dev venv
pyproject.toml     — Hatchling build, deps, ruff + pytest config
```

## Development setup

See `README.md` for development setup instructions.


## Environment variables

`UNIFI_API_KEY` (or the JSON list `UNIFI_API_KEYS` for several keys) is required.
`MCP_AUTH_MODE`, `MCP_BEARER_TOKEN`, `MCP_TLS_MODE` and the `MCP_OAUTH_*` settings configure HTTP
transport authentication and TLS (setting either on the stdio transport fails at startup).
`UNIFI_READ_ONLY`, the per-area write opt-outs (`UNIFI_ENABLE_NETWORK_WRITE`,
`UNIFI_ENABLE_CONNECTOR_WRITE`, `UNIFI_PROTECT_MUTATIONS_ENABLED` and the Mobility, Carrier Fabric and
InnerSpace flags; writes are on by default), `UNIFI_DRY_RUN`, `UNIFI_TOOL_MODE` and
`UNIFI_TOOL_FAMILIES` control which tools are exposed and which calls are sent;
`UNIFI_REDACT_SECRETS`, `UNIFI_AUDIT_LOG` and `UNIFI_AUDIT_LOG_FORMAT` are the opt-in privacy and audit
options. Boolean switches accept `1/true/yes/on/t/y` and `0/false/no/off/f/n`; any other value fails. See
`docs/CONFIGURATION.md` for the full environment variable reference.

## Key conventions

- Tools are registered with `@mcp.tool()` decorators, in `server.py` or inside a `tools/` module's `register(mcp, deps_fn)`.
- Tool logic that needs HTTP calls uses helper functions from the `tools/` modules, receiving `client` and `registry` from `_require()`.
- The registry resolves host/site names to IDs so tools accept human-readable names.
- Multi-key MSP support: each API key gets independent cache entries in the registry.
- Python 3.12+ required. Ruff for linting (E, F, I, W, B, S, ANN, UP rules). Line length 100.

## Stateless Architecture

See README.md for stateless design rationale. Do not add mandatory file-based logging, databases, or persistent volumes to this project. The opt-in audit log may write to a configured file.

## What not to touch

- Do not remove or rename existing `@mcp.tool()` functions — external MCP clients depend on stable tool names.
- Do not change the `UNIFI_` env var prefix — it's a public contract.
- Do not change the entry point name `unifi-fabric-mcp` without updating Dockerfile and docs.

## Branch Strategy

- **main** is the primary branch. All PRs target `main`.
- CI triggers on push and PRs to `main`.


## CI requirements

All of the following are enforced by GitHub Actions (`.github/workflows/ci.yml`) and must
pass before merge. What to run locally before pushing is in
[Mandatory local test before push](#priority-and-workflow-rules):

- `ruff check src/ tests/ scripts/ .github/scripts/` — linting (E, F, I, W, B, S, ANN, UP rules)
- `ruff format --check src/ tests/ scripts/ .github/scripts/` — formatting
- "No runtime response redaction" grep step (in the `lint` job) — fails if a removed
  response-filtering helper reappears in `src/`, enforcing the pass-through invariant above

- `mypy src/unifi_fabric --ignore-missing-imports` — type checking
- `pytest tests/ -v --cov=src/unifi_fabric --cov-fail-under=97` — full suite with 97% coverage
  gate (CI only, never run locally)
- `python3 scripts/gen_tools_doc.py --check` — `docs/TOOLS.md` must be current with the runtime
- `python3 scripts/gen_catalog_figures.py --check`: the README and CHANGELOG catalog sizes and tool counts must match the runtime
- `python3 scripts/check_markdown.py`, `tests/test_readme_catalog_size.py` and `tests/test_discovery_accuracy.py`: also in the `docs` job
- `gitleaks detect --no-git --source . --redact` — secret scanning (pinned CLI binary, not the action)
- `python3 .github/scripts/check_fixtures_sanitization.py` — synthetic-data assertion on fixtures
- `changelog-check` (the `changelog-check` job in `.github/workflows/ci.yml`) — PRs that modify `src/` must carry
  a valid `changelog.d` fragment, unless they are a release PR folding fragments into `CHANGELOG.md`, or carry the
  `skip-changelog` label for work with no user-visible effect (test-only, CI-only, pure refactor). The lane gate is
  the single source of the lane rule: lanes never edit `CHANGELOG.md`.

## Testing

**Before every push** run the pre-push check (see
[Mandatory local test before push](#priority-and-workflow-rules)):
```bash
PREPUSH_PYTHON=.venv/bin/python scripts/prepush.sh
```

`scripts/prepush.sh` reads the steps of CI's fast jobs from the workflows themselves: from
`.github/workflows/ci.yml` lint, typecheck, docs, the version, fixture and changelog checks,
and the changed-path test selection from `scripts/select_pr_tests.py` with CI's pytest flags;
then the fast jobs of every other workflow that runs for a pull request (the documentation
checks and the changelog size). It runs them for the commit you are about to push, with each
job's CI condition evaluated for a pull request into the base branch (a workflow's
`pull_request` branch filter is not applied). Then it runs the guard test files listed in
`PREPUSH_GUARDS` in `scripts/ci_fast_jobs.py` on every run, whatever the change.
The venv must be installed from `requirements.lock` as CI's is (`python3.12 -m venv .venv`,
`.venv/bin/python -m pip install --require-hashes -r requirements.lock`, then
`.venv/bin/python -m pip install --no-deps -e .`). Set `PREPUSH_BASE_BRANCH` to the pull
request's base branch and `PREPUSH_LABELS` to its labels (for example `full-ci`) when they
differ from the defaults. It stops at the first failing step, refuses uncommitted tracked
changes, and on success prints `Pre-push: scripts/prepush.sh pass (head <sha7>)`.

`scripts/prepush.sh --full` is opt-in: after everything above it also runs CI's full suite,
the `test` job's "Run full suite with coverage" step exactly as read from `ci.yml`, with
CI's worker count unless `PREPUSH_XDIST_WORKERS` names another, and without any `UNIFI_*`,
`MCP_*` or other credential variable in its environment. It prints only
`Pre-push: scripts/prepush.sh --full pass (head <sha7>, workers <n>)`. It is advisory and
never substitutes for CI; cite it only as "local full suite (advisory)". Nothing requires it.

**Running tests while you work** (targeted only; the full suite runs in CI):
```bash
pytest tests/test_network.py -n 4      # the test files for the modules you touched
pytest tests/test_cross_tool_invariants.py tests/test_secret_leak_invariant.py -n 4
```

**Integration tests** require a live UniFi API connection (`UNIFI_API_KEY` pointing to `api.ui.com`).
They are permanently skipped in public CI. Do not add `@pytest.mark.integration` to unit tests.

**Test structure:**
- `tests/`: all test files; a tool module's tests are in `test_<module>.py` (or `test_<module>_*.py` when split) matching `src/unifi_fabric/tools/<module>.py`
- `tests/fixtures/` — synthetic JSON response data (no real device data)
- `tests/conftest.py` — shared fixtures: `multikey_client`, `multikey_registry`,
  `_hermetic_credentials_env` (autouse), `auth_http_client`

**Coverage gate:** CI enforces `--cov-fail-under=97`. Do not chase 100%; the gate is
a regression tripwire, not a quality target. Measure before raising it.

**Hermetic credential isolation (hard rule):** An autouse fixture `_hermetic_credentials_env`
in `tests/conftest.py` strips `UNIFI_*`, `MCP_*`, and `FASTMCP_*` from the process environment
before every unit test. Do not remove or weaken it. A unit test that reads a real credential
from the environment violates hermetic isolation — it will print it on assertion failure and write it
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

**Per-host key routing:** Per-host tools use `Registry.resolve_key_for_host` to select the
owning API key. `tests/test_multikey_routing.py` checks first-key and non-first-key routing;
preserve that coverage.

**Fresh-AI validation:**
- Tools must be usable with zero prior context — descriptions alone must guide correct usage.
- The MCP INSTRUCTIONS constant is the primary discovery mechanism; keep it accurate.

**Known limitations:** See `docs/COVERAGE.md` for firmware-specific constraints.

## Changelog discipline

**Every lane PR that changes user-visible behavior must include one `changelog.d` fragment.**

The lane gate is the single source of this rule: lanes never edit `CHANGELOG.md`. Use a unique sortable filename
ending in `.added.md`, `.changed.md`, `.fixed.md`, or `.security.md`; see `changelog.d/README.md` for the fragment
format. A release PR folds queued fragments into the in-flight version section of `CHANGELOG.md`, then deletes
the folded fragments. Use one block per heading, ordered Added → Changed → Removed → Fixed. When the release ships, the
maintainers date that version heading, and every released section stays verbatim. Follow Keep a Changelog conventions:
- `.added.md` — new tools, new env vars, new behavior
- `.changed.md` — modifications to existing behavior or defaults
- `.fixed.md` — bug fixes that affect tool output or correctness
- `.security.md` — security fixes affecting users

**What qualifies:** new or removed tools, parameter behavior changes, new/modified env vars,
bug fixes affecting output, breaking changes.

**What does NOT need an entry:** test-only changes, internal refactors with no behavior
change, CI-only changes, dependency bumps (unless they change runtime behavior).

If a PR does not need a changelog entry, add the **`skip-changelog`** label in GitHub.
The `changelog-check` CI job skips the file check for PRs with that label. Release PRs may instead update
`CHANGELOG.md` while folding fragments; this is intentionally accepted by the CI check but is not permitted for lanes.

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
- Run `scripts/prepush.sh` (see [Testing](#testing)) on the exact commit before every
  push, and push only when it prints `Pre-push: scripts/prepush.sh pass (head <sha7>)` with
  that commit's short SHA. Cite that line in the pull request body (Self-review section);
  the SHA must equal the head you pushed. A new commit needs a new run.
- `scripts/prepush.sh` runs CI's fast jobs, including the changed-path test selection.
  When the selector escalates a change to the full tier (dependency locks, workflows, test
  configuration or the selector itself), the full suite runs in CI's `test` and
  `test-locked` jobs, not in the default local run.
- The full suite is CI's gate: the `test` check runs all of it with the coverage gate.
  The only local full run is the opt-in `scripts/prepush.sh --full`, which is advisory
  ("local full suite (advisory)") and never replaces the CI check. To measure the suite's
  size, duration or failure count, dispatch the CI workflow (`workflow_dispatch`) on the
  branch and read that run.
- Do not push if `scripts/prepush.sh` fails.
- CI must be green before merge. A local targeted run never substitutes for the full CI
  `test` check.

**CI monitoring:**
- After pushing, immediately check CI status with `gh run list`.
- If CI fails, diagnosing and fixing it is your immediate next task — it is P0.
- Once CI is green again, continue with the next planned work.
