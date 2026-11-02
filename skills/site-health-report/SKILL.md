---
name: site-health-report
description: Load when writing a UniFi site health report from site health, inventory, ISP metrics and fleet summary data.
---

# Site health report

This workflow is read-only. Keep each query's scope and time; a missing metric is not
proof of an outage. In discovery mode (the default) run each tool below through
`call_read_tool` with `name` and `arguments`; in full mode call it directly. For
anything else use `search_tools` and `describe_tool`.

1. Call `get_site_health_summary` with `{"site":"<site name or siteId>"}`; read
   `_healthSummary` (`allOk`, `notOk`) and the per-subsystem `data` records.
2. Call `get_site_inventory` with `site`; optional `device_filter` and `client_filter`
   narrow the lists. Use `_devices`, `_clients` and their counts.
3. Call `query_isp_metrics` with `interval` (`"5m"` or `"1h"`) and either `host` with
   `site` or `sites`, not both; `start_time` and `end_time` are ISO 8601 strings.
   Record the window and any partial result in `data.status` or `data.message`.
4. Call `get_fleet_summary` with no arguments, or `key_label` for one configured key.
5. Use this outline: **Scope and timestamp**; **Overall health**; **Inventory and device
   state**; **ISP metrics and time window**; **Fleet context**; **Risks and anomalies**;
   **Recommended next checks**. Separate source facts from interpretation, and report
   any `incomplete` or `errors` field.

## Tool contracts checked against code (paths under `src/unifi_fabric/`)

| Tool | Mode | Required arguments (optional) | Return shape and source |
|---|---|---|---|
| `get_site_health_summary` | read | `site` | `{meta, data}` verbatim plus `_healthSummary`; `server.py::get_site_health_summary` → `tools/site_manager.py::get_site_health_summary`; `readOnlyHint: true` |
| `get_site_inventory` | read | `site` (`device_filter`, `client_filter`) | `{_siteId, _devices, _deviceCount, _clients, _clientCount}`; `server.py::get_site_inventory` → `tools/site_manager.py::get_site_inventory`; `readOnlyHint: true` |
| `query_isp_metrics` | read | `interval` (`host`, `site`, `sites`, `start_time`, `end_time`) | `{data: {metrics}, httpStatusCode, traceId}` verbatim; `server.py::query_isp_metrics` → `tools/site_manager.py::query_isp_metrics`; `readOnlyHint: true` |
| `get_fleet_summary` | read | none (`key_label`) | `{hosts, sites, devices: {total, byStatus, byType}, _key_label}`; `tools/aggregation.py::get_fleet_summary`; `readOnlyHint: true` |
