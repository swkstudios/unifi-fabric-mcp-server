---
name: wifi-radio-change
description: Load when reviewing or changing a UniFi access point radio's channel, width or transmit power, including a move to or from a DFS channel.
---

# Wi-Fi radio change

A radio change can disconnect clients: change one AP and one band at a time. In discovery
mode (the default) run each tool below through `call_read_tool` or `call_write_tool` with
`name` and `arguments`; in full mode call it directly. For anything else use
`search_tools` and `describe_tool`.

1. Call `get_channel_plan` with `{"host":"<console>","site":"<site>"}`; an empty `data`
   means the controller stores no channel plan.
2. Call `get_device_radios` with `host`, `site` and the AP MAC as `device`; keep
   `_radios` (bands `ng`, `na`, `6e`) as the baseline.
3. Propose the channel, width (`ht`) and power change with its DFS exposure and its
   effect on neighbouring APs; show it to the operator and wait for approval.
4. Call `update_device_radio` with `host`, `site`, `device`, `radios` holding only the
   approved fields per band (for example `{"na":{"channel":44,"ht":40}}`) and
   `dry_run: true`; check `preview` and `diff`. Then repeat the call without `dry_run`.
5. After a move to a DFS channel, wait about 60 seconds (DFS_WAIT) before judging it.
6. Re-read `get_device_radios` and compare the band with the approval and with the
   write result's `changed` and `_verified`. Report client disruption or an
   unavailable channel separately from success.

## Tool contracts checked against code (paths under `src/unifi_fabric/`)

| Tool | Mode | Required arguments (optional) | Return shape and source |
|---|---|---|---|
| `get_channel_plan` | read | `host`, `site` | `{meta, data}` verbatim; `tools/network_services_proxy.py::get_channel_plan` → `tools/network_services_proxy.py::get_channel_plan`; `readOnlyHint: true` |
| `get_device_radios` | read | `host`, `site`, `device` | envelope plus `_device`, `_radio_table`, `_radio_table_stats`, `_radios`; `tools/device_radios.py::get_device_radios`; `readOnlyHint: true` |
| `update_device_radio` | write | `host`, `site`, `device`, `radios` (`dry_run`) | `readBefore`, `readAfter`, `changed`, `noOp`, `_verified`, `response`, or `{status, dryRun, message, preview, diff}`; `tools/device_radios.py::update_device_radio`; `readOnlyHint: false` |

The server never retries a radio write; after a timeout, read back before trying again.
