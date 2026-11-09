# Forking and renaming

This server's name appears in a fixed set of places. To publish a fork under a different name, change every row of the identity matrix below, then run the checks in [Rename a fork](#rename-a-fork). Each row names the file and line that owns the value; the tests in `tests/test_docs_ai_files.py` read each cited line and fail when the matrix and the source disagree.

The fork-editable public identity has one source, [`release-identity.json`](../release-identity.json): a fork edits `owner` and `repo`, and the image, registry name, PyPI name and Homebrew tap derive from them unless `overrides` names them. `python3 scripts/prepare_release.py --identity` prints the resolved identity and fails when it disagrees with `server.json`, which stays the authoritative registry identity. The matrix below lists every place the name appears.

## Identity matrix

| Surface | Value | Source |
| --- | --- | --- |
| Package name | `unifi-fabric-mcp-server` | `pyproject.toml:6` |
| Console entry point | `unifi-fabric-mcp` | `pyproject.toml:63` |
| Console entry point (long form) | `unifi-fabric-mcp-server` | `pyproject.toml:64` |
| Registry ID | `io.github.swkstudios/unifi-fabric-mcp-server` | `server.json:3` |
| Registry package identifier (PyPI) | `unifi-fabric-mcp-server` | `server.json:13` |
| Image name (registry OCI identifier) | `swkstudios/unifi-fabric-mcp-server` | `server.json:51` |
| Docker label (registry ownership) | `io.github.swkstudios/unifi-fabric-mcp-server` | `Dockerfile:94` |
| Docker entry point | `unifi-fabric-mcp` | `Dockerfile:126` |
| Client configuration example (Gemini CLI) | `unifi-fabric-mcp-server==` | `gemini-extension.json:10` |
| Client configuration example (Antigravity) | `unifi-fabric-mcp-server==` | `plugins/antigravity/mcp_config.json:7` |
| Client configuration example (Codex) | `unifi-fabric-mcp-server==` | `plugins/codex/.mcp.json:7` |
| Client configuration example (Claude Code plugin) | `unifi-fabric-mcp-server==` | `plugins/claude/.claude-plugin/plugin.json:51` |
| Client configuration example (Claude Desktop) | `unifi-fabric-mcp-server==` | `plugins/claude-desktop/manifest.json:26` |
| Generated install text (package pin) | `unifi-fabric-mcp-server==` | `scripts/gen_catalog_figures.py:852` |
| Generated install text (image tag) | `unifi-fabric-mcp-server:` | `scripts/gen_catalog_figures.py:854` |
| Public URL (package homepage) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `pyproject.toml:67` |
| Public URL (package issues) | `https://github.com/swkstudios/unifi-fabric-mcp-server/issues` | `pyproject.toml:69` |
| Public URL (registry repository) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `server.json:7` |
| Public URL (Claude Code plugin homepage) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `plugins/claude/.claude-plugin/plugin.json:10` |
| Public URL (Claude Desktop homepage) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `plugins/claude-desktop/manifest.json:16` |
| Public URL (Homebrew formula) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `packaging/homebrew/unifi-fabric-mcp-server.rb:26` |

Prose in `README.md` and `docs/DOCKER.md` repeats the package pin and the image name. `scripts/gen_catalog_figures.py` rewrites the version part of those pins from `pyproject.toml`; the names are hand-written, so search for the old name after renaming. The Cursor install badge in `README.md` holds the package name inside a base64 deeplink payload that a text search cannot find: decode it, change the name, and re-encode it.

Things that do not change in a fork: the `UNIFI_` environment variable prefix and the Python import package `unifi_fabric`. Both are public contracts of the code, not of the distribution.

## Rename a fork

1. Pick the new package name, registry ID, image name and repository URLs.
2. Edit every row of the matrix at its cited source. If a line number moves, update the `Source` cell in this file in the same commit.
3. Search for leftovers of the old name: `grep -rn "unifi-fabric-mcp-server" --include="*" . | grep -v "^./.git/"`, and fix prose that still names the old package or image.
4. Run `python3 scripts/gen_catalog_figures.py` so the generated install pins follow `pyproject.toml`, then `python3 scripts/check_server_json_version.py`.
5. Run `python3 scripts/gen_catalog_figures.py --check`, `python3 scripts/check_markdown.py` and `pytest tests/test_docs_ai_files.py tests/test_docs_currency.py -n 4`. The identity tests fail while the matrix and its sources disagree.
6. Run `scripts/prepush.sh` on the committed result before pushing ([AGENTS.md](../AGENTS.md#verify-without-committing)).
