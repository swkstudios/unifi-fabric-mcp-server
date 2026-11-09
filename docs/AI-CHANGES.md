# Changing tools: the recipe for AI agents

This is the one ordered path for adding or changing a tool. It is the same path as the worked example in [CONTRIBUTING.md](../CONTRIBUTING.md#worked-example-add-a-read-tool). Constraints and setup are in [AGENTS.md](../AGENTS.md); the file index is [llms.txt](../llms.txt).

## Recipe

1. **Implement.** Add the tool inside `register(mcp, deps_fn)` of the right module under `src/unifi_fabric/tools/`, decorated with `@mcp.tool(...)`. Return the upstream body unchanged (the pass-through rule in AGENTS.md). Document every argument in the docstring `Args:` section; the schema descriptions are lifted from it.
2. **Register.** A new module is imported and registered in `src/unifi_fabric/server.py` next to the existing `module.register(mcp, _require)` calls. A tool in an existing module is registered by its decorator. Put the tool in a family (`src/unifi_fabric/families.py`) and a README domain row (`DOMAINS` in `scripts/gen_catalog_figures.py`); an unclassified tool fails the generators.
3. **Schema and annotation derivation.** Do not hand-judge annotations or schemas. Pass the shared `READ_ONLY` or `WRITE` constant from `src/unifi_fabric/tool_annotations.py` in the decorator, as sibling tools do; the final four MCP hints are derived from the code at startup. The input schema comes from the signature and docstring. Refresh the committed baseline with `python3 scripts/gen_tool_input_schemas.py --write`.
4. **Focused and invariant tests.** Add `tests/test_<module>.py` cases: a happy path, an error path, and a multi-key routing case for any tool that resolves hosts or keys (use the shared `multikey_client` fixtures). Run the module's tests and the invariant files: `pytest tests/test_<module>.py tests/test_cross_tool_invariants.py tests/test_tool_schema_contract.py tests/test_api_sources.py -n 4`.
5. **Changelog fragment.** Add one `changelog.d/<name>.added.md` file (see `changelog.d/README.md`). Do not edit `CHANGELOG.md`.
6. **Regenerate.** Run the generators in the table below, then each one's `--check`.

## The three invariants

A minimal wrapper that returns upstream JSON is not enough. Every tool must also hold these:

1. **Spec-derived optional arguments, omitted keys absent.** Optional arguments are derived from the pinned upstream specification, not guessed. When the caller leaves an optional argument unset, the key is absent from the request (query string or body); the tool never sends `null`, an empty string or an invented default in its place.
2. **Paging through the shared helpers.** A list tool pages with the shared list-drain and continuation helpers in `src/unifi_fabric/tools/_pagination.py` (`_pagination.collect_cursor`, `_pagination.collect_offset`, `_pagination.collect_links`, `_pagination.collect_batch`) and `src/unifi_fabric/tools/_continuation.py`, never a private loop. By default it drains every page, including a full final page, and marks a capped drain `incomplete`. See [PAGINATION.md](PAGINATION.md). The tests are `tests/test_pagination_contract.py` and `tests/test_pagination_drains.py`.
3. **An `api_source_id` row.** Every tool needs its classification row in `src/unifi_fabric/_api_source_table.py` (the `TOOL_API_SOURCES` entry naming the app and source pairs it calls). An unclassified tool fails catalog validation. The file is generated: run `python -m tests.api_sources_gen --write`, then `ruff format` it; `tests/test_api_sources.py` fails when the committed table differs.

## Generated files: sources, outputs and checks

| Generator | Sources | Outputs | `--check` mode | CI job that runs the check |
| --- | --- | --- | --- | --- |
| `scripts/gen_tools_doc.py` | the registered tools (FastMCP runtime metadata) | `docs/TOOLS.md`; the tool count in `docs/COVERAGE.md` | `python3 scripts/gen_tools_doc.py --check` | `docs` in `.github/workflows/ci.yml` |
| `scripts/gen_catalog_figures.py` | the registered tools, `pyproject.toml`, `docs/COVERAGE.md` | catalog figures in `README.md`, `docs/CATALOG.md`, `docs/DOCKER.md`, `docs/MIGRATING-0.7.md`, `docs/COVERAGE.md`, `docs/CONFIGURATION.md`, `plugins/claude-desktop/README.md`, `docs/site-stats.json`, and the first numbered section of `CHANGELOG.md` (never commit a change to a dated, released section; see [CONTRIBUTING.md](../CONTRIBUTING.md#if-you-add-or-change-tools)) | `python3 scripts/gen_catalog_figures.py --check` | `docs` in `.github/workflows/ci.yml` |
| `scripts/gen_reference_blocks.py` | `unifi_fabric.config.Settings`, `switches`, `families` | the `BEGIN GENERATED` blocks in `README.md`, `docs/CONFIGURATION.md`, `docs/TOOL-USAGE.md` | `python3 scripts/gen_reference_blocks.py --check` | `docs` in `.github/workflows/ci.yml` |
| `scripts/gen_tool_input_schemas.py` | the registered tools' input schemas | `tests/fixtures/tool_input_schemas_baseline.json` | `python3 scripts/gen_tool_input_schemas.py --check` | `test` in `.github/workflows/ci.yml`, through `tests/test_tool_schema_contract.py` |
| `tests/api_sources_gen.py` | the routes each tool calls against the hermetic fake upstream | `src/unifi_fabric/_api_source_table.py` | `python -m tests.api_sources_gen` (no flag compares and exits 1 when stale) | `test` in `.github/workflows/ci.yml`, through `tests/test_api_sources.py` |
| `scripts/gen_discovery_queries.py` | tool purposes and handwritten confusable queries | `tests/fixtures/discovery_queries.json` | none (regenerate only; the fixture is reviewed in the PR) | `docs` in `.github/workflows/ci.yml`, through `tests/test_discovery_accuracy.py` |
| `scripts/gen_workflow_headers.py` | `.github/workflow-headers.toml` | the top-level `concurrency:` block of each workflow listed in its `[pr-concurrency]` table (`own-block` names the workflows that keep a block of their own) | `python3 scripts/gen_workflow_headers.py --check` | `lint` in `.github/workflows/ci.yml` |
| `scripts/gen_homebrew_resources.py` | `requirements-runtime.lock` and the PyPI JSON API | `packaging/homebrew/unifi-fabric-mcp-server.rb` resource stanzas | `python3 scripts/gen_homebrew_resources.py --check` (needs network) | none; `tests/test_homebrew_formula.py` checks the formula offline |

`python3 scripts/check_markdown.py` is not a generator but runs in the same `docs` job: table shape and relative links across every Markdown file.

One more script takes `--check` in a workflow but writes no tracked file. `scripts/refresh_dependencies.py --check` (the `dependency-refresh` workflow) verifies the seven managed pin files against `dependencies/manifest.toml`, and without a flag it re-resolves them.

## Ownership

- **Lock files.** `requirements.lock`, `requirements-runtime.lock` and `requirements-build.lock` are produced from `pyproject.toml` and `requirements-build.in` with hashes. Do not edit them by hand and do not change dependencies in a tool PR; dependency updates are their own change, reviewed by the maintainers.
- **Changelog fragments.** Contributors add a fragment in `changelog.d/`; maintainers fold fragments into the in-flight release section at release time. A released section is never rewritten, and no generator may change one.
- **Maintainer-only release metadata.** The version in `pyproject.toml`, `server.json`, `gemini-extension.json`, the plugin manifests, `packaging/homebrew/unifi-fabric-mcp-server.rb`, `docs/site-stats.json` and the version line of [llms.txt](../llms.txt) move together at release. Contributors leave them alone; `python3 scripts/check_server_json_version.py` guards the pair `pyproject.toml` and `server.json`. `python3 scripts/pypi_readme.py --check README.md` runs in `.github/workflows/publish-pypi.yml` at publish time and is maintainer-only.
