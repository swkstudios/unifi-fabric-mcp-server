---
name: network-vlan-read-modify-write
description: Load when changing one UniFi network or VLAN (name, VLAN ID, DHCP, isolation and similar) through read, approval, update and read-back.
---

# Network and VLAN change

Change one network at a time and never invent fields the read did not return. In
discovery mode (the default) run each tool below through `call_read_tool` or
`call_write_tool` with `name` and `arguments`; in full mode call it directly. For
anything else, such as finding the network id, use `search_tools` and `describe_tool`.

1. Call `get_network` with
   `{"host":"<console>","site":"<site>","network_id":"<network uuid>"}` and keep the
   returned object as the baseline.
2. Copy the baseline and apply only the requested delta. The update is a full
   replacement (PUT) and omitted fields reset, so keep every unrelated field. The server
   itself drops the top-level `id`, `default`, `metadata` and `index` and the empty
   strings padding lists.
3. Show the operator the changed fields and the complete `network_config`, and wait for
   approval. `update_network` has no per-call preview, so this is the preview.
4. Call `update_network` with `host`, `site`, `network_id` and the approved
   `network_config`. A `status: "dry_run"` result means the server runs in dry-run mode
   and nothing changed.
5. Call `get_network` again. Compare the requested fields and the untouched fields with
   the baseline, and report controller normalization separately.

## Tool contracts checked against code (paths under `src/unifi_fabric/`)

| Tool | Mode | Required arguments (optional) | Return shape and source |
|---|---|---|---|
| `get_network` | read | `host`, `site`, `network_id` | network object verbatim; `families/network/network.py::get_network` → `families/network/network.py::get_network`; `readOnlyHint: true` |
| `update_network` | write | `host`, `site`, `network_id`, `network_config` | upstream body verbatim, or `{status, dryRun, message, preview}`; `families/network/network.py::update_network` → `families/network/network.py::update_network`; `readOnlyHint: false` |

Responses can include secrets such as passphrases; never copy them into a report.
