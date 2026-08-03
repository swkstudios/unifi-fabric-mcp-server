# Contributing

Thank you for your interest in contributing to the UniFi Fabric MCP Server. This
document covers how to set up a development environment, branch and commit
conventions, CI requirements, testing rules, and the changelog discipline that
keeps public release notes accurate.

## Design invariant: the server is a faithful pass-through

**Tools return whatever the upstream UniFi API returns, unchanged. Do not add
runtime filtering, redaction, sanitisation, or field-stripping to tool
*responses*** — not for credential fields (passphrases, passwords, tokens), not
for identifiers (MAC/IP/hostname/name), not for GPS coordinates, not for asset
URLs. Responses must carry the complete upstream payload.

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
  the **data-survival tests** (`docs/internal/testing-procedure.md`) exist as the
  check on that and are meant to fail such a change loudly.

This is scoped to response *bodies*. Redacting identifiers inside error-message
text stays, and the committed-fixture sanitisation check
(`.github/scripts/check_fixtures_sanitization.py`) stays — those are separate
concerns. Do not conflate committed-fixture hygiene with runtime responses.

## Before you start

- Search [existing issues](https://github.com/swkstudios/unifi-fabric-mcp-server/issues)
  before opening a new one — your problem or idea may already be tracked.
- For security vulnerabilities, use the private reporting path in
  [SECURITY.md](.github/SECURITY.md). Do not open a public issue for
  security bugs.
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
   python3 -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   ```

4. Verify the setup by running the test suite:

   ```bash
   pytest tests/ -v --cov=src/unifi_fabric --cov-fail-under=91
   ```

## Branch naming

This guide is for external contributors working from the public mirror — branch off `main`.
(Internal maintainers work off `dev`; see `CLAUDE.md` for that workflow.)

Create branches off `main` with a descriptive type prefix:

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

**Every PR that changes user-visible behavior must include a `CHANGELOG.md`
entry under `## [Unreleased]`.**

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
`CHANGELOG.md` update.

### Format

Add your entry under the appropriate sub-heading inside `## [Unreleased]`:

```markdown
## [Unreleased]

### Added
- `new_tool` — what it does and when to use it.

### Changed
- `existing_tool` parameter `foo` now accepts a list in addition to a string.

### Fixed
- `some_tool` no longer returns a 500 when `site` is omitted.
```

Sub-headings: `### Added`, `### Changed`, `### Fixed`, `### Removed`.

**Append to the existing sub-heading; do not add a second one.** Each PR adds its
bullet under the matching heading if that heading already exists under
`## [Unreleased]` — never open a second `### Fixed` (or `### Added`, etc.) block.
Because PRs land concurrently, `[Unreleased]` still drifts into duplicate headings
and mixed ordering over time. **Consolidation is a release-time step:** when cutting
a release, merge `[Unreleased]` into exactly one block per heading, ordered
`Added → Changed → Removed → Fixed`, before moving the section under the new version
number. Do not rely on individual PRs to keep the ordering perfect.

### Issue references

Use **public issue numbers only**, formatted as a Markdown link:

```
([#19](https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19))
```

Private issue or PR numbers from forks or other trackers are meaningless to
other users and will appear as dead links in public release notes. Drop them —
let the description stand on its own.

## CI gates

All of the following checks must pass before a PR can merge. Run the first four
locally before pushing to catch failures early:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/unifi_fabric --ignore-missing-imports
pytest tests/ -v --cov=src/unifi_fabric --cov-fail-under=91
```

Full CI gate matrix:

| Check | What it verifies |
|-------|-----------------|
| `lint` | `ruff check` (rules: E, F, I, W, B, S, ANN, UP) |
| `typecheck` | `mypy` static type analysis |
| `docs` | `gen_tools_doc.py --check` — `TOOLS.md` matches the runtime |
| `test` | `pytest` + 91% line-coverage minimum |
| `gitleaks` | No secrets committed (file scan + PR diff scan) |
| `fixtures-sanitization` | No real MACs, IPs, or API keys in fixtures |
| `changelog-check` | `CHANGELOG.md` updated, or `skip-changelog` label set |

## Testing requirements

Every PR that modifies `src/` must:

**Add tests for the changed behavior.** The 91% coverage gate is enforced in CI.
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

If your PR adds, removes, or renames any `@mcp.tool()` function, regenerate
`docs/TOOLS.md` and commit the result in the same PR:

```bash
python3 scripts/gen_tools_doc.py
```

The `docs` CI job runs `gen_tools_doc.py --check` and fails if `TOOLS.md` is out
of sync with the runtime.

**Do not remove or rename existing tools without a discussion.** External MCP
clients depend on stable tool names. A rename is a breaking change.

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

PRs that change `src/` without a `CHANGELOG.md` entry (and without the
`skip-changelog` label) will fail the `changelog-check` CI job.
