# Contributing

## Development Setup

1. Fork the repo and create a feature branch.
2. Install dev dependencies: `pip install -e ".[dev]"`
3. (Optional) Install pre-commit hooks: `pip install pre-commit && pre-commit install`
4. Make your changes — keep commits focused.
5. Run `ruff check src/ tests/` and `ruff format --check src/ tests/` to pass lint.
6. Run `pytest` and ensure all tests pass.
7. Open a pull request against `dev`.

## Developer Certificate of Origin (DCO)

This project uses the Developer Certificate of Origin (DCO). All commits must be signed off with the `-s` flag to certify that you wrote the code or have the right to contribute it:

```bash
git commit -s -m "Your commit message"
```

This adds a `Signed-off-by` trailer to your commit. By signing off, you are certifying that you have the right to contribute the code, either as the original author or with permission from the copyright holder. See [developercertificate.org](https://developercertificate.org/) for details.

## Branch Naming

Use the prefix that matches the change type:

| Prefix | When to use |
|--------|-------------|
| `feat/` | New feature or tool |
| `fix/` | Bug fix |
| `chore/` | Maintenance, deps, CI changes |
| `docs/` | Documentation only |
| `refactor/` | Internal refactor, no behavior change |

Include the ticket ID when one exists: `feat/42-add-list-vpn-tool`.

## Conventional Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short description>

[optional body]
```

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `perf`.

Examples:

```
feat: add list_vpn_servers tool
fix(registry): resolve ObjectId-to-UUID mapping for multi-console setups
chore(ci): pin actions to commit SHAs
```

Breaking changes add `!` after the type: `feat!: rename UNIFI_API_KEY to UNIFI_KEY`.

## PR Requirements

- CI must be green (lint + tests).
- Include a concise description of **what** changed and **why**.
- Reference the ticket ID (e.g. `#42`) in the PR title or description.
- Keep PRs focused — avoid bundling unrelated changes.
- Do not rename or remove existing `@mcp.tool()` functions; external clients rely on stable tool names.

## Merge Strategy & Rollback

This repository uses **merge commit** as the default merge strategy for pull requests. All three strategies (merge commit, squash, rebase) are allowed in GitHub settings, but merges will default to creating a full commit history.

### Rollback Procedure

If you need to roll back a change:

- **Single-commit PR:** Use `git revert <SHA>` for the merge commit SHA.
- **Multi-commit PR:** Revert changes in reverse order of the commits they introduced:
  1. First revert the second commit's changes
  2. Then revert the first commit's changes

  This ensures dependencies are respected and avoids conflicts.

Example: If a PR had two commits (A, B), merged as a single merge commit on dev:
```bash
git revert -m 1 <merge-commit-sha>
```

If you need to revert individual commits from the PR history:
```bash
git revert <commit-B-sha>
git revert <commit-A-sha>
```

## CI/CD

- `ruff check` and `ruff format --check` must pass.
- `pytest tests/ -v` must pass.
- Both run automatically in GitHub Actions on every push/PR to `dev`.

See `.github/workflows/ci.yml` for details.

## Security

Report vulnerabilities privately via GitHub's security advisory system — see [SECURITY.md](.github/SECURITY.md).
