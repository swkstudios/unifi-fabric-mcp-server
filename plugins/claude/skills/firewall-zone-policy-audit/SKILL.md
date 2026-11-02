---
name: firewall-zone-policy-audit
description: Load when auditing UniFi firewall zones and zone-based policies, looking for WAN-to-LAN allows, or changing the policy order within one zone pair.
---

# Firewall and zone-based policy audit

Read first; write only the change the operator approved. In discovery mode (the default)
run each tool below through `call_read_tool` or `call_write_tool` with `name` and
`arguments`; in full mode call it directly. For anything else use `search_tools` and
`describe_tool`.

1. Call `list_firewall_zones_proxy` with `{"host":"<console>","site":"<site>"}` and map
   zone names (case-insensitive: Internal, External, ...) to `data[].id`.
2. Call `list_firewall_policies` with the same scope; omit `offset` and `limit` to get
   every page. Check source and destination zones, action, enabled state and origin.
   Flag every External-to-Internal allow; never infer safety from a policy name.
3. For each zone pair with policies, call `get_firewall_policy_ordering` with `host`,
   `site`, `source_zone_id` and `destination_zone_id`; keep the body as returned.
4. Report zones, policies, effective order and suspected WAN-to-LAN allows; missing data
   is unknown, not safe. For a change, show the exact before and after ordering.
5. After approval, call `set_firewall_policy_ordering` with the same zone pair and the
   whole read-back object, reordered, as `ordering` (both arrays, `[]` for an empty side,
   no `index` field). It has no per-call preview, so the ordering shown in step 4 is the
   preview; a `status: "dry_run"` result means the server runs in dry-run mode and
   nothing changed.
6. Re-read `get_firewall_policy_ordering` and compare it with the approval. On a
   mismatch stop and report; never retry by guessing.

## Tool contracts checked against code (paths under `src/unifi_fabric/`)

| Tool | Mode | Required arguments (optional) | Return shape and source |
|---|---|---|---|
| `list_firewall_zones_proxy` | read | `host`, `site` (`offset`, `limit`, `filter`) | `{data, totalCount}`, all pages; `server.py::list_firewall_zones_proxy` → `tools/firewall_proxy.py::list_firewall_zones`; `readOnlyHint: true` |
| `list_firewall_policies` | read | `host`, `site` (`offset`, `limit`, `filter`) | `{data, totalCount}`, all pages; `server.py::list_firewall_policies` → `tools/firewall_proxy.py::list_firewall_policies`; `readOnlyHint: true` |
| `get_firewall_policy_ordering` | read | `host`, `site`, `source_zone_id`, `destination_zone_id` | `{orderedFirewallPolicyIds: {beforeSystemDefined, afterSystemDefined}}` verbatim; `server.py::get_firewall_policy_ordering` → `tools/firewall_proxy.py::get_firewall_policy_ordering`; `readOnlyHint: true` |
| `set_firewall_policy_ordering` | write | `host`, `site`, `source_zone_id`, `destination_zone_id`, `ordering` | upstream body verbatim, or `{status, dryRun, message, preview}`; `server.py::set_firewall_policy_ordering` → `tools/firewall_proxy.py::set_firewall_policy_ordering`; `readOnlyHint: false` |
