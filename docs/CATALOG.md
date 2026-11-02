# Catalog measurements

## Family sizes

| `UNIFI_TOOL_FAMILIES` | Tools | `tools/list` size |
|---|---|---|
| unset (all families) | 786 | ~1454 KB |
| `network,firewall,site_manager` | 398 | ~723 KB |
| `protect` | 227 | ~401 KB |
| `network,firewall` | 379 | ~689 KB |
| `site_manager,statistics` | 33 | ~70 KB |

## Mode sizes

**Measured catalog sizes.** UTF-8 bytes of the compact `tools/list` result object
(`{"tools":[...]}`, `ensure_ascii=False`, comma/colon separators), with all families
enabled at the same head. Every catalog size and tool-count figure in the [README](../README.md) and CHANGELOG is written by
`scripts/gen_catalog_figures.py`; the `docs` CI job runs it with `--check`, and
`tests/test_readme_catalog_size.py` re-measures both mode rows independently. Search and describe
responses are loaded on demand; domain results are never truncated to meet a size target. CI measures search as Recall@5 over a committed query set covering every tool and family (`tests/test_discovery_accuracy.py`); the baseline is a floor.

| `UNIFI_TOOL_MODE` | Advertised tools | Domain tools available | `tools/list` bytes | Size (1 KB = 1000 bytes) |
|---|---:|---:|---:|---:|
| `full` | 786 | 786 | 1453538 | ~1454 KB |
| `discovery` (default) | 5 | 786 | 5400 | ~5 KB |
