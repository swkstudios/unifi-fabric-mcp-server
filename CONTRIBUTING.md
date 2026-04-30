# Contributing

## Development Setup

1. Fork the repo and create a feature branch.
2. Install dev dependencies: `pip install -e ".[dev]"`
3. (Optional) Install pre-commit hooks: `pip install pre-commit && pre-commit install`
4. Make your changes — keep commits focused.
5. Run `ruff check src/ tests/` and `ruff format --check src/ tests/` to pass lint.
6. Run `pytest` and ensure all tests pass.
7. Open a pull request against `main`.

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

Include the GitHub issue number when one exists: `feat/42-add-list-vpn-tool`.

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
- Reference the GitHub issue number (e.g. `#42`) in the PR title or description.
- Keep PRs focused — avoid bundling unrelated changes.
- Do not rename or remove existing `@mcp.tool()` functions; external clients rely on stable tool names.

## Merge Strategy & Rollback

Pull requests are merged using **merge commits** to preserve full history.

### Rollback Procedure

- **Single-commit PR:** `git revert -m 1 <merge-commit-sha>`
- **Multi-commit PR:** Revert commits in reverse order to avoid conflicts:
  ```bash
  git revert <commit-B-sha>
  git revert <commit-A-sha>
  ```

## CI/CD

- `ruff check` and `ruff format --check` must pass.
- `pytest tests/ -v` must pass.
- Both run automatically in GitHub Actions on every push/PR to `main`.

See `.github/workflows/ci.yml` for details.

## Security

Report vulnerabilities privately via GitHub's security advisory system — see [SECURITY.md](.github/SECURITY.md).

## Filing Issues and Pull Requests

When opening issues or PRs, please use generic phrasing for project rules and constraints. Do not reference internal project documents (e.g., configuration files, governance documents) or internal team and agent names. Describe the rule or requirement in plain terms so the discussion is clear to all external contributors.
