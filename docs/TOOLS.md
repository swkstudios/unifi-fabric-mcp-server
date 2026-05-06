# UniFi Fabric MCP Server — Tools Reference

**Auto-generated reference manual for all `@mcp.tool()` exports.**

This document lists all available tools organized by category. Each tool represents
a discrete operation or query you can perform against UniFi consoles via the MCP protocol.

## Tool Categories

- [Configuration](#configuration)
- [Create](#create)
- [Delete](#delete)
- [Device Control](#device-control)
- [Listing & Discovery](#listing-discovery)
- [Other](#other)
- [Reading & Inspection](#reading-inspection)
- [Search](#search)
- [Update](#update)

---

## Configuration

**3 tools**

### `patch_firewall_policy`

Partially update a firewall policy by ID.

### `set_acl_rule_ordering`

Set the ordering of ACL rules for a site.

### `set_firewall_policy_ordering`

Set the ordering of firewall policies for a site.

## Create

**12 tools**

### `create_acl_rule`

Create a new ACL rule on a site.

### `create_dns_policy`

Create a new DNS policy on a site.

### `create_firewall_policy`

Create a new firewall policy on a site.

### `create_firewall_zone_proxy`

Create a new firewall zone on a site via connector proxy.

### `create_hotspot_vouchers`

Generate hotspot vouchers for a site.

### `create_liveview`

Create a liveview on a Protect console.

### `create_network`

Create a new network/VLAN on a site.

### `create_rtsps_stream`

Create an RTSPS stream for a Protect camera.

### `create_traffic_matching_list`

Create a new traffic matching list on a site.

### `create_traffic_route`

Create a traffic route on a site (policy-based routing / WAN load-balancing).

### `create_traffic_rule`

Create a traffic matching rule (QoS, block, or route by application/IP group).

### `create_wifi_broadcast`

Create a new WiFi broadcast SSID on a site.

## Delete

**12 tools**

### `delete_acl_rule`

Delete an ACL rule.

### `delete_dns_policy`

Delete a DNS policy.

### `delete_firewall_policy`

Delete a firewall policy.

### `delete_firewall_zone_proxy`

Delete a firewall zone via connector proxy.

### `delete_hotspot_voucher`

Delete a single hotspot voucher.

### `delete_network`

Delete a network/VLAN.

### `delete_port_forward`

Delete a port forwarding rule by ID.

### `delete_rtsps_stream`

Delete an RTSPS stream for a Protect camera.

### `delete_traffic_matching_list`

Delete a traffic matching list.

### `delete_traffic_route`

Delete a traffic route by ID.

### `delete_traffic_rule`

Delete a traffic rule by ID.

### `delete_wifi_broadcast`

Delete a WiFi broadcast SSID.

## Device Control

**3 tools**

### `ptz_goto_preset`

Move a PTZ camera to a preset position slot.

### `ptz_patrol_start`

Start a PTZ patrol on a preset slot.

### `ptz_patrol_stop`

Stop the current PTZ patrol on a camera.

## Listing & Discovery

**44 tools**

### `list_accounts`

List local RADIUS user accounts for a site.

### `list_acl_rules`

List all ACL rules for a site.

### `list_all_sites_aggregated`

List all sites with aggregated health stats from the /v1/sites/ API.

### `list_cameras`

List all cameras on a Protect console.

### `list_chimes`

List all chimes on a Protect console.

### `list_countries`

List all countries with ISO codes available on a console.

### `list_device_tags`

List all device tags defined in a site.

### `list_devices`

List all devices across the fleet with status, firmware, and model.

### `list_dns_policies`

List all DNS policies for a site.

### `list_dpi_applications`

List DPI applications available for traffic rules.

### `list_dpi_categories`

List DPI (Deep Packet Inspection) app categories available for traffic rules.

### `list_dynamic_dns`

List Dynamic DNS provider configurations for a site.

### `list_firewall_groups`

List firewall groups (IP/port sets referenced by firewall rules) for a site.

### `list_firewall_policies`

List firewall policies for a site with pagination.

### `list_firewall_rules`

List classic L3/L4 firewall rules for a site (distinct from Integration API policies).

### `list_firewall_zones_proxy`

List all firewall zones for a site via connector proxy.

### `list_hosts`

List all UniFi consoles (hosts) with firmware, WAN IP, and status.

### `list_hotspot_packages`

List guest portal billing packages for a site.

### `list_hotspot_vouchers`

List all hotspot vouchers for a site.

### `list_lights`

List all lights on a Protect console.

### `list_liveviews`

List all liveviews on a Protect console.

### `list_networks`

List all networks/VLANs for a site.

### `list_port_forwards`

List all port forwarding rules for a site.

### `list_port_profiles`

List switch port profiles (speed, VLAN, PoE config) for a site.

### `list_protect_files`

List Protect device asset files of a given type.

### `list_radius_profiles`

List RADIUS profiles for a site.

### `list_rogue_aps`

List neighboring APs detected by the site's radios.

### `list_routing_entries`

List static routing table entries for a site.

### `list_scheduled_tasks`

List scheduled tasks (firmware upgrade schedules, speed tests) for a site.

### `list_sdwan_configs`

List Site Magic (SD-WAN) VPN mesh configurations.

### `list_sensors`

List all sensors on a Protect console.

### `list_settings`

List all controller setting groups for a site.

### `list_site_to_site_tunnels`

List site-to-site VPN tunnels for a site.

### `list_sites`

List all sites with device/client counts and ISP info.

### `list_traffic_matching_lists`

List all traffic matching lists for a site.

### `list_traffic_routes`

List static/policy traffic routes for a site.

### `list_traffic_rules`

List traffic matching rules (QoS, application, IP group matching).

### `list_users`

List DHCP fixed-IP reservations and client aliases for a site.

### `list_viewers`

List all viewers on a Protect console.

### `list_vpn_servers`

List VPN servers for a site.

### `list_wan_interfaces`

List WAN interfaces for a site.

### `list_wifi_broadcasts`

List all WiFi broadcast SSIDs for a site.

### `list_wlan_configs`

List per-SSID WLAN configurations (security, band steering, rate limits) for a site.

### `list_wlan_groups`

List WLAN groups for a site.

## Other

**7 tools**

### `bulk_delete_hotspot_vouchers`

Bulk delete hotspot vouchers matching filter criteria.

### `compare_site_performance`

Compare health and performance metrics across multiple sites side-by-side.

### `disable_camera_mic_permanently`

Permanently disable the microphone on a Protect camera. This cannot be undone.

### `query_isp_metrics`

Query filtered ISP metrics with optional site/time range filters.

### `start_talkback_session`

Start a talkback audio session on a Protect camera.

### `trigger_alarm_webhook`

Trigger an alarm manager webhook by ID. WARNING: triggers physical alarm hardware.

### `upload_protect_file`

Upload a Protect device asset file. WARNING: Uploads asset file to NVR storage.

## Reading & Inspection

**39 tools**

### `get_account`

Get a single RADIUS account by ID.

### `get_acl_rule`

Get a single ACL rule by ID.

### `get_acl_rule_ordering`

Get the ordering of ACL rules for a site.

### `get_camera`

Get details for a single Protect camera by ID.

### `get_camera_snapshot`

Get a snapshot from a Protect camera. Returns base64-encoded JPEG image data.

### `get_channel_plan`

Get RF channel assignments and DFS status for a site.

### `get_chime`

Get details for a single Protect chime by ID.

### `get_dns_policy`

Get a single DNS policy by ID.

### `get_dynamic_dns`

Get a single Dynamic DNS configuration by ID.

### `get_firewall_group`

Get a single firewall group by ID.

### `get_firewall_policy`

Get a single firewall policy by ID.

### `get_firewall_policy_ordering`

Get the ordering of firewall policies for a site filtered by source and destination zone.

### `get_firewall_rule`

Get a single classic firewall rule by ID.

### `get_firewall_zone_proxy`

Get a single firewall zone by ID via connector proxy.

### `get_host`

Get details for a single UniFi console by name or ID.

### `get_hotspot_package`

Get a single hotspot billing package by ID.

### `get_hotspot_voucher`

Get a single hotspot voucher by ID.

### `get_isp_metrics`

Get WAN health metrics (speed, latency, packet loss, uptime).

### `get_light`

Get details for a single Protect light by ID.

### `get_liveview`

Get details for a single Protect liveview by ID.

### `get_network`

Get a single network/VLAN by ID.

### `get_network_references`

Get all resources referencing a network — useful before deleting to check dependencies.

### `get_nvr`

Get NVR details from a Protect console.

### `get_port_profile`

Get a single switch port profile by ID.

### `get_rtsps_stream`

Get existing RTSPS stream URLs for a Protect camera.

### `get_scheduled_task`

Get a single scheduled task by ID.

### `get_sdwan_config`

Get a single SD-WAN configuration by ID.

### `get_sdwan_config_status`

Get the status of an SD-WAN configuration by ID.

### `get_sensor`

Get details for a single Protect sensor by ID.

### `get_setting`

Get a controller setting group by key.

### `get_site_health_summary`

Get health summary for a single site: uptime, alerts, and device counts.

### `get_site_inventory`

Get full inventory for a site: all devices and connected clients.

### `get_traffic_matching_list`

Get a single traffic matching list by ID.

### `get_traffic_route`

Get a single traffic route by ID.

### `get_user`

Get a single DHCP/client-alias entry by ID.

### `get_viewer`

Get details for a single Protect viewer by ID.

### `get_wifi_broadcast`

Get a single WiFi broadcast SSID by ID.

### `get_wlan_config`

Get a single WLAN (SSID) configuration by ID.

### `get_wlan_group`

Get a single WLAN group by ID.

## Search

**1 tools**

### `search_across_sites`

Search for devices or clients matching a query across all sites.

## Update

**22 tools**

### `update_acl_rule`

Update an existing ACL rule by ID.

### `update_camera`

Update settings for a Protect camera (name, recording mode, etc.).

### `update_chime`

Update settings for a Protect chime (volume, ringtone, etc.).

### `update_dns_policy`

Update a DNS policy by ID.

### `update_dynamic_dns`

Update a Dynamic DNS configuration by ID.

### `update_firewall_policy`

Full-replace a firewall policy by ID.

### `update_firewall_zone_proxy`

Update a firewall zone by ID via connector proxy.

### `update_light`

Update settings for a Protect light (brightness, sensitivity, etc.).

### `update_liveview`

Update a liveview on a Protect console.

### `update_network`

Update an existing network/VLAN.

### `update_port_forward`

Update a port forwarding rule by ID.

### `update_port_profile`

Update a switch port profile by ID.

### `update_sensor`

Update settings for a Protect sensor.

### `update_setting`

Update a controller setting group by key.

### `update_traffic_matching_list`

Update a traffic matching list by ID.

### `update_traffic_route`

Update a traffic route by ID.

### `update_traffic_rule`

Update a traffic rule by ID.

### `update_user`

Update a DHCP/client-alias entry by ID.

### `update_viewer`

Update settings for a Protect viewer (liveview assignment, etc.).

### `update_wan_interface`

Update a WAN interface configuration.

### `update_wifi_broadcast`

Update an existing WiFi broadcast SSID.

### `update_wlan_config`

Update a WLAN (SSID) configuration by ID.

---

## Usage Notes

- All tools are registered in `src/unifi_fabric/server.py` via `@mcp.tool()` decorators.
- Tool parameters accept human-readable names (hosts, sites, SSIDs) or IDs where applicable.
- Refer to the [README](../README.md) for setup, authentication, and configuration details.
- For detailed parameter descriptions and return values, inspect tool docstrings in
  the source code or ask your MCP client for help (e.g., Claude Code's built-in help).

---

*Generated from `src/unifi_fabric/server.py` on 2026-05-03.*
