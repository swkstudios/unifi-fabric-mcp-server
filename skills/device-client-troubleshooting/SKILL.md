---
name: device-client-troubleshooting
description: Load when diagnosing a UniFi device, switch port, client link or spanning-tree problem, before any restart is considered.
---

# Device and client troubleshooting

Diagnose with reads before any disruption. Pass MAC addresses: the statistics tools take
a MAC or Classic `_id`, never the Integration id. In discovery mode (the default) run each
tool below through `call_read_tool` or `call_write_tool` with `name` and `arguments`; in
full mode call it directly. For anything else use `search_tools` and `describe_tool`.

1. Call `get_device` with `host`, `site` and the device MAC as `device_id`.
2. Call `get_device_port_state` with `host`, `site`, the MAC as `device_id` and optional
   1-based `port_idx`; check link, error and drop counters, and PoE.
3. Call `get_client` with `host`, `site` and the client MAC as `client_id`, then
   `get_client_link_diagnostics` with `host`, `site` and the same `client_id` (or
   `client_ids` for several clients, never both).
4. When a loop or blocked forwarding is plausible, call `get_device_stp_state` with
   `host`, `site` and the MAC as `device_id`.
5. Correlate timestamps, link state, diagnostics and STP; prefer a non-disruptive fix.
6. `restart_device` is the last resort, never before steps 1-4. Show the operator the
   device and the impact and wait for approval; there is no per-call preview, and a
   `status: "dry_run"` result means dry-run mode and no restart. Restart one device,
   never retry automatically (read back after a timeout), then repeat steps 1-4.

## Tool contracts checked against code (paths under `src/unifi_fabric/`)

| Tool | Mode | Required arguments (optional) | Return shape and source |
|---|---|---|---|
| `get_device` | read | `host`, `site`, `device_id` | device object verbatim; `tools/device_mgmt.py::get_device`; `readOnlyHint: true` |
| `get_device_port_state` | read | `host`, `site`, `device_id` (`port_idx`) | `_device_record`, `port_table`, `lldp_table` (or `_port`) verbatim; `tools/statistics.py::get_device_port_state`; `readOnlyHint: true` |
| `get_client` | read | `host`, `site`, `client_id` | client object verbatim; `tools/clients.py::get_client`; `readOnlyHint: true` |
| `get_client_link_diagnostics` | read | `host`, `site` (`client_id` or `client_ids`) | `{meta, data}` narrowed to the clients; `tools/statistics.py::get_client_link_diagnostics`; `readOnlyHint: true` |
| `get_device_stp_state` | read | `host`, `site`, `device_id` | `{meta, _device, _source, _stp, _ports, _device_record}`; `tools/statistics.py::get_device_stp_state`; `readOnlyHint: true` |
| `restart_device` | write | `host`, `site`, `device_id` (`reboot_type`) | upstream body verbatim, or `{status, dryRun, message, preview, _consequence}`; `tools/device_mgmt.py::restart_device`; `readOnlyHint: false` |
