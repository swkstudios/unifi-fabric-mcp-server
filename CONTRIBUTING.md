# Contributing

Thank you for your interest in contributing to the UniFi Fabric MCP Server. This
document covers how to set up a development environment, branch and commit
conventions, CI requirements, testing rules, and the changelog discipline that
keeps public release notes accurate.

## Design invariant: the server is a faithful pass-through

**Tools return whatever the upstream UniFi API returns, unchanged, apart from two
built-in transforms: the server's own configured secrets (its API keys,
`MCP_BEARER_TOKEN`, `MCP_TLS_KEY_PASSWORD`) are always replaced by `***` wherever a
response echoes them, and the operator's opt-in `UNIFI_REDACT_SECRETS` masks
credential fields. Do not add other runtime filtering, redaction, sanitisation, or
field-stripping to tool *responses*** — not for credential fields (passphrases,
passwords, tokens), not for identifiers (MAC/IP/hostname/name), not for GPS
coordinates, not for asset URLs. Responses must carry the complete upstream payload.

Please read this reasoning before "cleaning up" any response, because the rule
only holds if the reasoning does:

- The server's job is faithful *access*. Whether a particular caller should be
  allowed to see a particular field is a *policy* question that belongs to the
  deployment, not to this shared access layer.
- A deployment can always ADD a restriction on top of a faithful response — put
  a proxy or wrapper in front and drop or mask whatever it wants. It can never
  RECOVER a field the tool declined to return. Withholding by default is
  irreversible for every downstream consumer, including the operator who owns the
  data and asked for it.
- So if you believe an output should be restricted, restrict it in *your*
  deployment. A reviewer may reasonably argue for narrowing what a tool returns;
  the **data-survival tests** exist as the
  check on that and are meant to fail such a change loudly.

The same applies to error messages: the real path and the complete upstream error
body are reported (identifiers are not secrets; nothing is truncated), and credential
fields are masked only under the opt-in `UNIFI_REDACT_SECRETS`. The committed-fixture
sanitisation check (`.github/scripts/check_fixtures_sanitization.py`) stays — that is a
separate concern. Do not conflate committed-fixture hygiene with runtime responses.

## Before you start

- Search [existing issues](https://github.com/swkstudios/unifi-fabric-mcp-server/issues)
  before opening a new one — your problem or idea may already be tracked.
- For security vulnerabilities, use the private reporting path in
  [SECURITY.md](.github/SECURITY.md). Do not open a public issue for
  security bugs.
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Questions? Open a
  [GitHub Discussion](https://github.com/swkstudios/unifi-fabric-mcp-server/discussions).

## Development setup

**Requirements:** Python 3.12 or later.

1. Fork the repository on GitHub.
2. Clone your fork:

   ```bash
   git clone https://github.com/<your-username>/unifi-fabric-mcp-server.git
   cd unifi-fabric-mcp-server
   ```

3. Create a virtual environment and install the package with dev dependencies:

   ```bash
   python3.12 -m venv .venv
   .venv/bin/python -m pip install --require-hashes -r requirements.lock
   .venv/bin/python -m pip install --no-deps -e .
   ```

   These are the same hash-locked commands CI and [AGENTS.md](AGENTS.md#setup) use.

4. Verify the setup with a targeted run (the full suite and its coverage gate run in CI):

   ```bash
   pytest tests/test_cross_tool_invariants.py tests/test_secret_leak_invariant.py -n 4
   ```

## Branch naming

Branch off `main`, with a descriptive type prefix:

| Prefix | Use for |
|--------|---------|
| `fix/` | Bug fixes |
| `feat/` | New features or tools |
| `docs/` | Documentation changes only |
| `test/` | Test-only changes |
| `ci/` | CI and workflow changes |
| `chore/` | Dependency updates, housekeeping |

Keep branch names short and lowercase, using hyphens as separators
(e.g. `fix/list-clients-pagination`).

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description in present tense>
```

Examples:

```
feat(protect): add list_protect_recordings tool
fix(network): handle empty site list from API
docs: clarify OAuth audience matching
test(auth): add multi-key coverage for bearer mode
chore(deps): bump httpx to 0.28
```

Types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`, `perf`.

Break individual commits into logical units. A commit that mixes a bug fix
and a refactor is harder to review and revert.

## Changelog requirement

**Every PR that changes user-visible behavior must include one `changelog.d`
fragment.** Do not edit `CHANGELOG.md`: the maintainers fold the fragments into it.

This matters: the changelog text is published verbatim in public release notes.
It has to read well to a stranger, carry no internal vocabulary, and reference
only public issue numbers.

### What qualifies for an entry

- New or removed tools
- New, renamed, or removed environment variables
- Changes to tool parameter behavior or defaults
- Bug fixes that affect tool output or correctness
- Breaking changes (always note these prominently)

### What does NOT need an entry

- Test-only changes (no `src/` modifications)
- Internal refactors with no behavior change
- CI/workflow-only changes
- Dependency bumps (unless they change runtime behavior)

If your PR falls into the no-entry category, add the **`skip-changelog`** label
in GitHub. The `changelog-check` CI job will pass without requiring a
`changelog.d` fragment.

### Format

Add one Markdown file to `changelog.d/` with a unique, sortable filename ending in
`.added.md`, `.changed.md`, `.removed.md`, `.fixed.md`, or `.security.md`, for example
`changelog.d/site-default.fixed.md`. It contains one or more release-note bullets, each
beginning with `- `, and no heading, release-version heading or HTML comment. See
`changelog.d/README.md` for the full fragment format and `changelog.d/TEMPLATE.md` for the
shape of a breaking entry.

```markdown
- `some_tool` no longer returns a 500 when `site` is omitted.
```

While a release is being prepared, its section (`## [X.Y.Z]`, undated
until it ships) is the in-flight version section. When preparing the release, the
maintainers append each fragment's bullets to its
category (`### Added`, `### Changed`, `### Removed`, `### Fixed`, `### Security`) in that section and
deletes the fragment. When the release ships, the maintainers date that version heading,
and every released section stays verbatim.

### Issue references

Use **public issue numbers only**, formatted as a Markdown link:

```
([#19](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19))
```

Private issue or PR numbers from forks or other trackers are meaningless to
other users and will appear as dead links in public release notes. Drop them —
let the description stand on its own.

## CI gates

All of the following checks must pass before a PR can merge. Branch protection marks only
some of them as required, so GitHub can show a PR as mergeable while a check it does not
require is red; maintainers merge only when every check that ran is green. On every pull
request, `test` and `test-locked` run the whole suite with the 97% coverage gate, not a
subset. Before pushing, run lint, types and the tests that cover your change (the local
test rule is in [AGENTS.md](AGENTS.md), "Mandatory local test before push"); the full
suite runs in CI:

```bash
ruff check src/ tests/ scripts/ .github/scripts/
ruff format --check src/ tests/ scripts/ .github/scripts/
mypy src/unifi_fabric --ignore-missing-imports
pytest tests/test_<module>.py tests/test_cross_tool_invariants.py tests/test_secret_leak_invariant.py -n 4
```

Full CI gate matrix:

| Check | What it verifies |
|-------|-----------------|
| `lint` | `ruff check` (rules: E, F, I, W, B, S, ANN, UP) |
| `typecheck` | `mypy` static type analysis |
| `docs` | `gen_tools_doc.py --check`: `TOOLS.md` matches the runtime; `gen_catalog_figures.py --check`: README and CHANGELOG catalog sizes and tool counts match the runtime; `check_markdown.py`; the README catalog-size and discovery-accuracy tests |
| `test` | `pytest` + 97% line-coverage minimum |
| `test-locked` | The full suite again in an environment installed exactly from `requirements.lock` (`pip install --require-hashes`), with the same 97% coverage minimum |
| `scrub-oracle` | The 210,000-case scrubber acceptance corpus (50 chunks, `-m slow -n 4`) and its aggregate coverage-floor step, both of which the full suite skips. Runs in parallel with `test`, whenever `test` runs and on an integration PR that changes the scrubber, the oracle or its generator |
| `gitleaks` | No secrets committed (file scan + PR diff scan) |
| `fixtures-sanitization` | No real MACs, IPs, or API keys in fixtures |
| `version-consistency` | `scripts/check_server_json_version.py` — the `server.json` version and its OCI image identifier tag equal the `pyproject.toml` version (no leading `v`) |
| `docker-build` | The production container image builds from the `Dockerfile` (no push) |
| `changelog-check` | When `src/` changes: a `changelog.d` fragment or a `CHANGELOG.md` change, or the `skip-changelog` label set |
| `lint-public-language` | The pull request title, body, commit messages and author emails use public language (runs on the public repository) |

## Testing requirements

Catalog-size checks in `tests/test_catalog_size_budget.py` use proportional
budgets: 2,400 bytes per tool on average for the full `tools/list` response,
10,000 bytes per input schema, and 10,000 bytes per generated body shape with a
2,000-byte shape average. `tests/test_client_surface_limits.py` enforces the
existing 2,048-character description cap. `tests/test_readme_catalog_size.py`
checks the README table's exact tool counts and sizes within 2%. The discovery-mode
PR owns the separate `DISCOVERY_BUDGET_BYTES = 8_000` ceiling and its test.

Every PR that modifies `src/` must:

**Add tests for the changed behavior.** The 97% coverage gate is enforced in CI.
New code without tests will cause CI to fail.

**Use only synthetic test data.** No real MAC addresses, IP addresses, API keys,
hostnames, or device identifiers in fixtures. The `fixtures-sanitization` check
enforces this; violations block the PR.

**Follow the shared fixture conventions.** Do not roll per-test key or registry
objects when shared fixtures exist:

- `multikey_client` / `multikey_registry` — a pre-configured two-key substrate
  (keys `alpha` and `beta` owning disjoint host sets). Use these for any test
  that touches host or site resolution.

**Include a multi-key test for host/site resolution changes.** If your change
affects how the server selects an API key for a given host or site, add a test
that verifies the correct key is chosen for a *non-first* (beta-owned) host.
A test that only exercises the first/default key cannot catch wrong-key routing.

**Keep unit tests hermetically isolated.** An autouse fixture in `tests/conftest.py`
strips `UNIFI_*`, `MCP_*`, and `FASTMCP_*` environment variables before every unit
test. Do not add code that re-reads credentials from the ambient environment inside
unit tests.

**Minimum per tool:**

1. One happy-path test with a mocked API response.
2. One error-path test verifying the tool surfaces errors clearly.
3. A multi-key routing test if the tool calls `client.request()` or resolves hosts.

## If you add or change tools

If your PR adds, removes, or renames any `@mcp.tool()` function, regenerate the files
that derive from the runtime and commit the result in the same PR. The ordered recipe,
the three invariants and the table of every generator are in
[docs/AI-CHANGES.md](docs/AI-CHANGES.md). The short form:

```bash
.venv/bin/python scripts/gen_tools_doc.py
.venv/bin/python scripts/gen_catalog_figures.py
.venv/bin/python scripts/gen_reference_blocks.py
```

`gen_catalog_figures.py` refreshes the catalog sizes and tool counts in the README and in
the docs listed in its header. It also targets the first numbered section of
`CHANGELOG.md` while that section is undated. Never commit a change to a released section:
a section whose heading carries a date has shipped, and its figures stay verbatim. The
generator leaves a dated first section untouched and the changelog fold refuses to add
fragments to one; as a check, run `git diff --stat CHANGELOG.md` after the generator, and if
it shows a change while the first numbered heading is dated, run `git restore CHANGELOG.md`.
Never edit a generated figure by hand. The `docs`
CI job runs each generator with `--check` and fails if any is out of sync with the runtime.

**Do not remove or rename existing tools without a discussion.** External MCP
clients depend on stable tool names. A rename is a breaking change.

### Worked example: add a read tool

This is the path a first contribution follows. The example adds a paged list read tool,
list_example_widgets, to an existing module; use a real endpoint from the pinned
specification instead.

1. Read an existing paged tool such as `list_sites` in `src/unifi_fabric/tools/site_manager.py`
   and copy its structure. A list tool takes optional `page_token` and `page_size`
   arguments, and a paged read calls `_pagination.collect_cursor` (or `_pagination.collect_offset`) from
   `src/unifi_fabric/tools/_pagination.py` rather than looping itself:

   ```python
   @mcp.tool(annotations=READ_ONLY)  # from ..tool_annotations; the final hints are derived
   async def list_example_widgets(
       page_token: str | None = None, page_size: int | None = None, widget_kind: str | None = None
   ) -> Any:
       """List example widgets.

       Args:
           page_token: Opaque continuation from a previous call.
           page_size: Total records to gather; omit to drain every page.
           widget_kind: Optional filter from the upstream specification; omitted when unset.
       """
       client, _ = deps_fn()
       params = {"kind": widget_kind} if widget_kind is not None else None
       collected = await collect_cursor(
           client, "/v1/example-widgets", params=params, page_token=page_token,
           page_size=page_size, one_page=page_token is not None or page_size is not None,
       )
       return mark_incomplete({"data": collected["items"]}, collected)
   ```

   This is a sketch of the shape, not code to paste: take the exact imports, annotation
   constant and result handling from the sibling tool you copied.
2. Add its row to `src/unifi_fabric/_api_source_table.py` by running
   `.venv/bin/python -m tests.api_sources_gen --write`, then `ruff format` on that file.
3. Write `tests/test_<module>.py` cases: a happy path with a mocked response, an error
   path, a case where `widget_kind` is omitted and the key is absent from the request, and
   a two-page drain that returns every record.
4. Add `changelog.d/example-widgets.added.md` containing one `- ` bullet.
5. Regenerate and check, then run the tests:

   ```bash
   .venv/bin/python scripts/gen_tools_doc.py
   .venv/bin/python scripts/gen_catalog_figures.py
   .venv/bin/python scripts/gen_reference_blocks.py
   .venv/bin/python scripts/gen_tool_input_schemas.py --write
   .venv/bin/python -m pytest tests/test_<module>.py tests/test_api_sources.py tests/test_tool_schema_contract.py -n 4 -q
   ```
6. Commit, then run `PREPUSH_PYTHON=.venv/bin/python scripts/prepush.sh` before pushing.

## Code style

- Python 3.12+.
- `ruff` for linting and formatting. Line length 100.
- Type annotations on all public functions.
- Async for all I/O-touching code.

## Opening a pull request

1. Push your branch to your fork.
2. Open a PR against the `main` branch of this repository.
3. Fill in the PR description: what changed, why, and how to verify it.
4. Confirm all CI checks pass.
5. A maintainer will review your changes and may request revisions.

The `changelog-check` CI job fails a PR that changes `src/` without a `changelog.d`
fragment or a `CHANGELOG.md` change, unless the `skip-changelog` label is set. Add a
fragment; the maintainers fold fragments into `CHANGELOG.md`.

Release maintainers reconcile exact-revision acceptance evidence for every tool.
The evidence checker supplements behavioral and live verification; independent
review must confirm that cited artifacts support their claims.
