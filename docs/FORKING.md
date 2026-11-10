# Forking and renaming

This server's name appears in a fixed set of places. To publish a fork under a different name, change every row of the identity matrix below, then run the checks in [Rename a fork](#rename-a-fork). Each row names the file and the key or symbol that owns the value, never a line number, so a routine edit that moves code does not break the matrix. The tests in `tests/test_docs_ai_files.py` resolve each cited locator and fail when the value is not there or the matrix and the source disagree.

The fork-editable public identity has one source, [`release-identity.json`](../release-identity.json): a fork edits `owner` and `repo`, and the image, registry name, PyPI name and Homebrew tap derive from them unless `overrides` names them. `python3 scripts/prepare_release.py --identity` prints the resolved identity and fails when it disagrees with `server.json`, which stays the authoritative registry identity. The matrix below lists every place the name appears.

## Identity matrix

| Surface | Value | Source (file and key or symbol) |
| --- | --- | --- |
| Package name | `unifi-fabric-mcp-server` | `pyproject.toml#project.name` |
| Console entry point | `unifi-fabric-mcp` | `pyproject.toml#project.scripts` |
| Console entry point (long form) | `unifi-fabric-mcp-server` | `pyproject.toml#project.scripts` |
| Registry ID | `io.github.swkstudios/unifi-fabric-mcp-server` | `server.json#/name` |
| Registry package identifier (PyPI) | `unifi-fabric-mcp-server` | `server.json#/packages/0/identifier` |
| Image name (registry OCI identifier) | `swkstudios/unifi-fabric-mcp-server` | `server.json#/packages/1/identifier` |
| Docker label (registry ownership) | `io.github.swkstudios/unifi-fabric-mcp-server` | `Dockerfile#LABEL io.modelcontextprotocol.server.name` |
| Docker entry point | `unifi-fabric-mcp` | `Dockerfile#ENTRYPOINT` |
| Client configuration example (Gemini CLI) | `unifi-fabric-mcp-server==` | `gemini-extension.json#/mcpServers/unifi-fabric/args/1` |
| Client configuration example (Antigravity) | `unifi-fabric-mcp-server==` | `plugins/antigravity/mcp_config.json#/mcpServers/unifi-fabric/args/1` |
| Client configuration example (Codex) | `unifi-fabric-mcp-server==` | `plugins/codex/.mcp.json#/mcpServers/unifi-fabric/args/1` |
| Client configuration example (Claude Code plugin) | `unifi-fabric-mcp-server==` | `plugins/claude/.claude-plugin/plugin.json#/mcpServers/unifi-fabric/args/1` |
| Client configuration example (Claude Desktop) | `unifi-fabric-mcp-server==` | `plugins/claude-desktop/manifest.json#/server/mcp_config/args/1` |
| Generated install text (package pin) | `unifi-fabric-mcp-server==` | `scripts/gen_catalog_figures.py::PIN_KINDS` |
| Generated install text (image tag) | `unifi-fabric-mcp-server:` | `scripts/gen_catalog_figures.py::PIN_KINDS` |
| Public URL (package homepage) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `pyproject.toml#project.urls.Homepage` |
| Public URL (package issues) | `https://github.com/swkstudios/unifi-fabric-mcp-server/issues` | `pyproject.toml#project.urls.Issues` |
| Public URL (registry repository) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `server.json#/repository/url` |
| Public URL (Claude Code plugin homepage) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `plugins/claude/.claude-plugin/plugin.json#/homepage` |
| Public URL (Claude Desktop homepage) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `plugins/claude-desktop/manifest.json#/homepage` |
| Public URL (Homebrew formula) | `https://github.com/swkstudios/unifi-fabric-mcp-server` | `packaging/homebrew/unifi-fabric-mcp-server.rb#homepage` |

A `Source` cell is `path#locator` or `path::symbol`:

- `.json` files: a JSON Pointer after `#` (`server.json#/packages/0/identifier`).
- `.toml` files: a dotted key after `#` (`pyproject.toml#project.urls.Homepage`).
- Python files: `::` and the name of the function, class or constant that holds the value (`scripts/gen_catalog_figures.py::render_install_versions`).
- Dockerfile and Ruby formula: the instruction or key that starts the line after `#` (`Dockerfile#ENTRYPOINT`).

Prose in `README.md` and `docs/DOCKER.md` repeats the package pin and the image name. `scripts/gen_catalog_figures.py` rewrites the version part of those pins from `pyproject.toml`; the names are hand-written, so search for the old name after renaming. The Cursor install badge in `README.md` holds the package name inside a base64 deeplink payload that a text search cannot find: decode it, change the name, and re-encode it.

Things that do not change in a fork: the `UNIFI_` environment variable prefix and the Python import package `unifi_fabric`. Both are public contracts of the code, not of the distribution.

## Rename a fork

1. Pick the new package name, registry ID, image name and repository URLs.
2. Edit every row of the matrix at its cited source. If a key or symbol is renamed or moves to another file, update the `Source` cell in this file in the same commit.
3. Search for leftovers of the old name: `grep -rn "unifi-fabric-mcp-server" --include="*" . | grep -v "^./.git/"`, and fix prose that still names the old package or image. The search cannot see the Cursor install badge in `README.md`: its package name sits inside a base64 `config=` payload. Decode that payload, change the name and re-encode it (step 4 re-pins the version in it but does not rename the package).
4. Run `python3 scripts/gen_catalog_figures.py` so the generated install pins follow `pyproject.toml`, then `python3 scripts/check_server_json_version.py`.
5. Run `python3 scripts/gen_catalog_figures.py --check`, `python3 scripts/check_markdown.py` and `pytest tests/test_docs_ai_files.py tests/test_docs_currency.py -n 4`. The identity tests fail while the matrix and its sources disagree.
6. Run `scripts/prepush.sh` on the committed result before pushing ([AGENTS.md](../AGENTS.md#verify-without-committing)).
