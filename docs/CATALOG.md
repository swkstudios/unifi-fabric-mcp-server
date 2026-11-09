# Catalog measurements

## Family sizes

**Catalog size.** With every family registered, full mode advertises 792 tools and its
`tools/list` response is roughly 1466 KB of JSON; default discovery mode advertises five meta-tools. In full mode every tool carries its full description
and parameter docs; the 40 pinned-spec request bodies add their top-level fields and a
compact outline of the nested ones (69,295 bytes of compact JSON in all). A client that loads
the whole catalog into a model's context pays that cost on every session. Trimming to the families you use shrinks it
proportionally. The measurements below use the UTF-8 JSON-RPC response to `tools/list` (1 KB = 1000 bytes):

| `UNIFI_FAMILY_ALLOW` | Tools | `tools/list` size |
|---|---|---|
| unset (all families) | 792 | ~1466 KB |
| `network,firewall,site_manager` | 395 | ~717 KB |
| `protect` | 228 | ~403 KB |
| `network,firewall` | 377 | ~683 KB |
| `site_manager,statistics` | 35 | ~73 KB |

## Mode sizes

**Measured catalog sizes.** UTF-8 bytes of the compact `tools/list` result object
(`{"tools":[...]}`, `ensure_ascii=False`, comma/colon separators), with all families
enabled at the same head. Every catalog size and tool-count figure in the [README](../README.md) and CHANGELOG is written by
`scripts/gen_catalog_figures.py`; the `docs` CI job runs it with `--check`, and
`tests/test_readme_catalog_size.py` re-measures both mode rows independently. Search and describe
responses are loaded on demand; domain results are never truncated to meet a size target. CI measures search as Recall@5 over a committed query set covering every tool and family (`tests/test_discovery_accuracy.py`); the baseline is a floor.

| `UNIFI_TOOL_MODE` | Advertised tools | Domain tools available | `tools/list` bytes | Size (1 KB = 1000 bytes) |
|---|---:|---:|---:|---:|
| `full` | 792 | 792 | 1465730 | ~1466 KB |
| `discovery` (default) | 5 | 792 | 4457 | ~4 KB |
