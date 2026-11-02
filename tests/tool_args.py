"""Argument recipes for invoking every registered tool against the fake upstream.

Generated from each tool's input schema (host / site / ids / typed scalars), with explicit
per-tool overrides where a tool validates a value's format. A tool missing from the
registry-wide sweep is a test failure, never a silent skip.
"""

from __future__ import annotations

from typing import Any

from tests.upstream_harness import (
    ARG_HEX,
    ARG_ID,
    ARG_MAC,
    ARG_NAME,
    ARG_SLOT,
    HOST,
    NOW,
    SITE,
)
from unifi_fabric import server

BY_NAME: dict[str, Any] = {
    "host": HOST,
    "site": SITE,
    "interval": "5m",
    # Native cursor strings remain valid alongside additive continuation objects.
    # Prefer these over a generic object when sampling the union's optional form.
    "cursor": "c1",
    "page_token": "p1",
    "type": "face",
    "scope": "site",
    "start": NOW - 3600,
    "end": NOW,
    "query": ARG_NAME,
    "setting_key": ARG_NAME,
    "name": ARG_NAME,
    "password": "probe-password-1",
    "setup_code": "34970112332",
    "ssid": "probe-ssid",
    "mac": ARG_MAC,
    "filename": "probe.png",
    "file_type": "animations",
    "path": "network/integration/v1/sites/{site_id}/clients",
    "sites": [SITE],
    "qualities": ["high"],
    "slot": ARG_SLOT,
    "port_idx": 1,
    "auth_server_ip": "192.0.2.10",
    "auth_server_port": 1812,
    "auth_server_secret": "probe-radius-secret",
    "vpn_type": "WIREGUARD",
    "subscriber_number": "probe-subscriber",
    "file_content_base64": "iVBORw0KGgo=",
    "content_base64": "SUQz",
    "host_id": ARG_ID,
    "client": ARG_ID,
    "client_ref": ARG_ID,
    "target_id": ARG_ID,
    "target": ARG_MAC,
    "ap_mac": ARG_MAC,
    "guest": ARG_ID,
    "view": "24hr-activity",
    "reason": "POOR_LATENCY",
    "target_type": "client",
    "access_point": ARG_MAC,
    "gateway_mac": ARG_MAC,
    "client_mac": ARG_MAC,
    "radios": [{"mac": ARG_MAC}],
    "radio_band": "na",
    "method": "balanced",
    # relay / alarm-hub output channel: the spec's integer 0 or 1, taken as a string
    "output_id": "0",
}

# differs from the fake upstream's current values, so read-before/no-op writes still write
OBJECT_DEFAULT: dict[str, Any] = {"name": "probe-renamed"}

# Per-tool overrides (merged over the generated arguments).
_SITE_SCOPED = {"host": HOST, "site": SITE}
OVERRIDES: dict[str, dict[str, Any]] = {
    "get_poe_info": {"params": {"mac": ARG_MAC}},
    # Private Protect routes use native 24hex object ids, unlike Integration UUIDs.
    "get_camera_private": {"camera_id": ARG_HEX},
    "update_camera_private": {"camera_id": ARG_HEX},
    "list_ptz_presets": {"camera_id": ARG_HEX},
    "list_ptz_patrols": {"camera_id": ARG_HEX},
    "get_sensor_private": {"sensor_id": ARG_HEX},
    "update_sensor_private": {"sensor_id": ARG_HEX},
    "clear_sensor_tamper": {"sensor_id": ARG_HEX},
    "export_camera_video": {"camera_id": ARG_HEX},
    "reboot_protect_device": {"device_type": "camera", "device_id": ARG_HEX},
    # adopt checks device_id against the camera list (an unknown id answers 200 upstream);
    # the generated list records carry ARG_ID as their id.
    "adopt_protect_device": {"device_type": "camera", "device_id": ARG_ID},
    "unadopt_protect_device": {"device_type": "camera", "device_id": ARG_HEX},
    "get_client_observability": {
        "view": "logs-all",
        "client": ARG_MAC,
        "start": NOW - 3600,
        "end": NOW,
    },
    "get_local_client": {"client": ARG_MAC},
    "get_client_insights": {"client": ARG_MAC},
    "update_dhcp_option": {"option_id": ARG_HEX},
    "delete_dhcp_option": {"option_id": ARG_HEX},
    "update_hotspot_package": {"package_id": ARG_HEX},
    "delete_hotspot_package": {"package_id": ARG_HEX},
    "delete_guest_portal_file": {"file_id": ARG_HEX},
    "get_network_config_defaults": {"kind": "lan", **_SITE_SCOPED},
    "get_controller_stats": {"view": "source"},
    "list_site_warnings": {"source": "all", **_SITE_SCOPED},
    "set_ups_pairing": {"action": "unpair", "console_mac": ARG_MAC},
    "get_radio_history": {"view": "timeline", "start": NOW - 3600, "end": NOW},
    "get_wifi_stats": {"view": "details", "start": NOW - 3600, "end": NOW},
    "control_wifi_doctor_optimization": {"action": "start"},
    "list_ssl_inspection_catalog": {"catalog": "categories"},
    "create_ssl_inspection_certificate": {"mode": "generate"},
    "control_packet_capture": {"action": "start"},
    "control_ping_test": {"action": "start"},
    # GS3 NC: topology history takes epoch-millisecond start/end; QoS batch bodies are
    # free-form arrays (an id array resolves each id first)
    "get_topology_snapshot": {
        "view": "timeline",
        "start": (NOW - 3600) * 1000,
        "end": NOW * 1000,
    },
    "delete_qos_rule": {"body": [ARG_HEX]},
    # NL-5: the scoped system-log read routes by scope (BY_NAME scope=site is not one)
    "get_scoped_system_log": {"scope": "device", "identifier": ARG_MAC, "query": {"limit": 1}},
    "reorder_qos_rules": {"body": [ARG_HEX]},
    "get_camera_analytics": {"kind": "detections"},
    "export_edge_recording": {"action": "prepare"},
    "control_site_vpn": {"action": "enable"},
    "get_openvpn_client_config": {"server_id": "00000000-0000-4000-9000-000000000038"},
    "restart_vpn_server": {"server_id": "00000000-0000-4000-9000-000000000038"},
    "list_wireguard_users": {"server_id": "00000000-0000-4000-9000-000000000038"},
    "create_wireguard_users": {
        "server_id": "00000000-0000-4000-9000-000000000038",
        "users": [{"name": ARG_NAME}],
    },
    "update_wireguard_users": {
        "server_id": "00000000-0000-4000-9000-000000000038",
        "users": [{"_id": ARG_HEX, "name": "probe-renamed"}],
    },
    "delete_wireguard_users": {
        "server_id": "00000000-0000-4000-9000-000000000038",
        "users": [ARG_HEX],
    },
    "update_static_dns_record": {"record_id": ARG_HEX},
    "delete_static_dns_record": {"record_id": ARG_HEX},
    "get_proav_matrix": {"kind": "video"},
    "create_proav_group": {"kind": "video"},
    "update_proav_group": {"kind": "video"},
    "delete_proav_group": {"kind": "video"},
    "set_tv_wall_calibration": {"action": "set"},
    "get_shadow_mode_status": {"view": "info"},
    "control_shadow_mode_adoption": {"action": "begin"},
    "apply_test_config": {"action": "apply", "test_config_id": ARG_HEX},
    "delete_test_config": {"test_config_id": ARG_HEX},
    "get_multicast_insights": {"view": "history"},
    # N01 controller administration: the action picks the Classic command
    "set_cloud_access_registration": {"action": "register"},
    "manage_firmware_cache": {"action": "download"},
    "enroll_doorbell_credential": {"credential_type": "fingerprint"},
    "delete_doorbell_credential": {"credential_type": "nfc"},
    # InnerSpace internal routes: array-of-object bodies, UUID path tokens and base64 uploads
    "import_innerspace_captures": {
        "captures": [{"title": ARG_NAME, "files": {"topView": "probe.png"}, "devices": []}]
    },
    "reorder_innerspace_plans": {"plans": [{"id": ARG_ID, "ordering": 0}]},
    "import_innerspace_shared_project": {"token": ARG_ID},
    "upload_innerspace_plan_asset": {"content_base64": "iVBORw0KGgo="},
    # read-merge-write: a plan id present in the recorded integration project fixture
    "update_innerspace_plan": {"plan_id": "00000000-0000-4000-8000-000000fa01d6"},
    # list-first delete: resolves the plan id in the same recorded project fixture
    "delete_innerspace_plan": {"plan_id": "00000000-0000-4000-8000-000000fa01d6"},
    # list-first map update: resolves the plan id in the same recorded project fixture
    "update_innerspace_plan_map": {"plan_id": "00000000-0000-4000-8000-000000fa01d6"},
    # N08 routing / topology: route-selecting enums and ids the harness records carry
    "get_bgp_status": {"view": "config"},
    "get_ospf_status": {"view": "config"},
    "migrate_network_to_layer3": {"network_id": ARG_HEX},
    "detach_from_orchestration": {"target": "network", "object_id": ARG_HEX},
    "manage_virtual_network": {"action": "update", "virtual_network_id": ARG_ID},
    "manage_mclag_group": {
        "action": "update",
        "group_id": ARG_ID,
        "group": {"name": "probe-renamed"},
    },
    # network_mobile_wan (N04): device MACs and the tools' own enum values
    "get_lte_subscription_status": {"macs": [ARG_MAC]},
    "manage_esim_profile": {"action": "delete"},  # "add" reads as a hex id to the br sweep
    "verify_sim_pin": {"manager": "lte"},
    "get_wan_load_balancing": {"view": "status"},
    "get_wan_insights": {"view": "speed_tests"},
    "get_enriched_configuration": {"kind": "lan"},
    # Exercise the write path of this mixed GET / unallowlisted-POST tool.
    "list_guests": {"within_hours": 24},
    "update_scheduled_task": {"task_id": ARG_HEX},
    "delete_scheduled_task": {"task_id": ARG_HEX},
    "get_device_radios": {"device": ARG_MAC},
    "get_rolling_upgrade_plan": {"time_estimate": True},
    "get_device_replacement_options": {"device": ARG_MAC},
    "update_device_radio": {"device": ARG_MAC, "radios": {"na": {"ht": 40}}},
    "update_protect_case": {"name": "probe-renamed"},
    "update_protect_case_asset": {"note": "probe-renamed"},
    "export_protect_case": {"action": "prepare", "case_id": ARG_ID},
    "set_firewall_app_blocks": {"blocks": [{"enabled": False, "app_ids": []}]},
    # every device type but the nvr singleton needs its device id (GS3 P01)
    "update_protect_device_settings": {"device_id": ARG_ID},
    # the shortcut to update is located by the body id (the camera's shortcuts[].id)
    "update_camera_shortcut": {"body": {"id": ARG_ID, "name": "probe-renamed"}},
    # a complete linked-camera shortcut, so validate_schema=true accepts the generated call
    "create_camera_shortcut": {
        "shortcut": {
            "placement": {"x": 0, "y": 0},
            "shortcut": {"type": "linkedCamera", "linkedCameraId": ARG_ID},
        }
    },
    "query_isp_metrics": {"interval": "1h", **_SITE_SCOPED},
    "collect_protect_events": {"poll_count": 2, "poll_interval_seconds": 0.1},
    "collect_protect_device_changes": {"poll_count": 2, "poll_interval_seconds": 0.1},
    "get_historical_stats": {"interval": "hourly"},
    "get_client_link_diagnostics": {"client_id": ARG_MAC},
    "get_traffic_route": {"route_id": ARG_HEX},
    "get_wlan_group": {"group_id": ARG_HEX},
    # Synthetic-record mode (SYNTHETIC_RECORD_TOOLS): the generated portconf and networkconf
    # lists hold the ARG_* ids, in Classic (hex _id) and Integration (UUID) spaces.
    "allow_network_on_port_profile": {"profile_id": ARG_HEX, "network_id": ARG_ID},
    "exclude_network_on_port_profile": {"profile_id": ARG_HEX, "network_id": ARG_HEX},
    # pending devices are identified by MAC (the spec's pending-device schema has no id)
    "approve_pending_device": {"device_id": ARG_MAC, "ignore_device_limit": False},
    # the spec accepts only the two guest-access actions; anything else fails fast
    "execute_client_action": {"action": {"action": "AUTHORIZE_GUEST_ACCESS"}},
    # the spec marks the DELETE filter query parameter required
    "bulk_delete_hotspot_vouchers": {"filter_params": {"filter": "name.eq('probe')"}},
    "update_carrier_subscriber": {"name": "probe-renamed"},
    "attach_carrier_subscriber_host": {"host_id": "00000000-0000-4000-8000-0000000000bb"},
    "update_mobility_device_name": {"name": "probe-renamed"},
    "create_arm_profile": {"settings": {"armMode": "custom"}},
    "update_mobility_device_network": {"host_address": "192.0.2.1"},
    "query_power_supervisor_logs": {"query": {"limit": 1}},
    "query_switch_mac_tables": {
        "query": {"mac": "02:00:5e:00:53:01", "ports": [1]},
        "queries": [{"mac": "02:00:5e:00:53:01", "ports": [1]}],
    },
    # the web app's body shapes: ports/{mac}/reset takes [{port_idx, unit_id?}] and
    # merge-group takes {fromGroupIds, toGroupId} (a group never merges into itself)
    "reset_switch_port": {"device": ARG_MAC, "ports": [{"port_idx": 1}]},
    "assign_detections_to_recognition_group": {"detection_ids": [ARG_ID], "group_id": "face_1"},
    "merge_recognition_groups": {"to_group_id": "face_1", "from_group_ids": ["face_2"]},
    "query_port_system_logs": {"query": {"limit": 1}},
    "pos_ingest_transaction": {
        "transaction": {"type": "sale", "externalId": ARG_ID, "amount": 1.0}
    },
    "fabric_connector_get": {"site": SITE},
    "fabric_connector_post": {"site": SITE, "body": {"name": ARG_NAME}},
    "fabric_connector_put": {"site": SITE, "body": {"name": ARG_NAME}},
    "fabric_connector_patch": {"site": SITE, "body": {"name": ARG_NAME}},
    "fabric_connector_delete": {"site": SITE},
    "create_network": {
        "network_config": {"name": ARG_NAME, "management": "GATEWAY", "enabled": True, "vlanId": 42}
    },
    "create_wifi_broadcast": {"broadcast": {"name": ARG_NAME, "type": "STANDARD"}},
    "create_firewall_policy": {
        "policy": {
            "name": ARG_NAME,
            "action": {"type": "ALLOW"},
            "destination": {"zoneId": ARG_ID},
            "enabled": True,
            "ipProtocolScope": {"ipVersion": "IPV4"},
            "loggingEnabled": False,
            "source": {"zoneId": ARG_ID},
        }
    },
    "create_firewall_zone_proxy": {"zone": {"name": ARG_NAME, "networkIds": [ARG_ID]}},
    "create_acl_rule": {
        "rule": {"name": ARG_NAME, "type": "IPV4", "enabled": True, "action": "ALLOW"}
    },
    "create_dns_policy": {
        "policy": {
            "type": "A_RECORD",
            "domain": "probe.example",
            "enabled": True,
            "ipv4Address": "192.0.2.5",
        }
    },
    "create_traffic_matching_list": {
        "traffic_list": {"name": ARG_NAME, "type": "PORTS", "items": []}
    },
    "create_hotspot_vouchers": {
        "voucher_config": {"name": ARG_NAME, "count": 1, "timeLimitMinutes": 60}
    },
    "create_port_forward": {
        "payload": {
            "name": ARG_NAME,
            "dst_port": "8080",
            "fwd": "192.0.2.20",
            "fwd_port": "80",
            "proto": "tcp",
            "enabled": True,
        }
    },
    "create_traffic_rule": {
        "payload": {
            "action": "BLOCK",
            "matching_target": "INTERNET",
            "target_devices": [{"type": "ALL_CLIENTS"}],
        }
    },
    # v2 device tags: the controller answers HTTP 500 without the member lists; tags are
    # addressed by their v2 _id (the harness's generic record 0 carries ARG_HEX as _id).
    "create_device_tag": {"tag": {"name": ARG_NAME, "member_device_macs": []}},
    "update_device_tag": {
        "tag_id": ARG_HEX,
        "tag": {"name": "probe-renamed", "device_mac_additions": [], "device_mac_removals": []},
    },
    "delete_device_tag": {"tag_id": ARG_HEX},
    # Classic REST / v2 collection writes resolve the id in the collection's list first
    # (the controller answers a DELETE on an unknown id with HTTP 200); the harness's
    # generic record 0 carries ARG_HEX as its _id.
    "update_port_forward": {"forward_id": ARG_HEX},
    "delete_port_forward": {"forward_id": ARG_HEX},
    "update_traffic_rule": {"rule_id": ARG_HEX},
    "delete_traffic_rule": {"rule_id": ARG_HEX},
    "update_traffic_route": {"route_id": ARG_HEX},
    "delete_traffic_route": {"route_id": ARG_HEX},
    "update_user": {"user_id": ARG_HEX},
    "update_dynamic_dns": {"ddns_id": ARG_HEX},
    "update_wlan_config": {"wlan_id": ARG_HEX},
    "update_port_profile": {"profile_id": ARG_HEX},
    "update_hotspot_operator": {"operator_id": ARG_HEX},
    "delete_hotspot_operator": {"operator_id": ARG_HEX},
    # site configuration CRUD (site_config / radius_profiles): same list-first resolution
    "update_user_group": {"group_id": ARG_HEX},
    "delete_user_group": {"group_id": ARG_HEX},
    "update_static_route": {"route_id": ARG_HEX},
    "delete_static_route": {"route_id": ARG_HEX},
    "update_radius_account": {"account_id": ARG_HEX},
    "delete_radius_account": {"account_id": ARG_HEX},
    "update_radius_profile": {"profile_id": ARG_HEX},
    "delete_radius_profile": {"profile_id": ARG_HEX},
    "get_ap_group": {"group_id": ARG_HEX},
    "update_ap_group": {"group_id": ARG_HEX},
    "delete_ap_group": {"group_id": ARG_HEX},
    "delete_port_profile": {"profile_id": ARG_HEX},
    "delete_dynamic_dns": {"ddns_id": ARG_HEX},
    # a known client by MAC (record 0 carries ARG_MAC), the group by its _id
    "set_client_user_group": {"client": ARG_MAC, "group": ARG_HEX},
    # Classic networkconf writes resolve the Integration id through external_id within one
    # purpose. Recorded network_classic networkconf fixture: remote-user-vpn record
    # external_id ...9000-...0038, wan record external_id ...b000-...fa0040. Tunnels resolve
    # the harness record 0 (purpose site-vpn, external_id ARG_ID).
    "update_vpn_server": {"server_id": "00000000-0000-4000-9000-000000000038"},
    "delete_vpn_server": {"server_id": "00000000-0000-4000-9000-000000000038"},
    "update_wan_interface": {"wan_id": "00000000-0000-4000-b000-000000fa0040"},
    "configure_wifi_wan": {
        "wan_id": "00000000-0000-4000-b000-000000fa0040",
        "is_wifi_tethering": True,
        "enabled": True,
        "port": 9,
        "uplink_ssid": "example-uplink",
        "uplink_security": "OPEN",
        "uplink_band": "RADIO_NA",
    },
    "create_site_to_site_tunnel": {"tunnel": {"name": ARG_NAME, "vpn_type": "openvpn-vpn"}},
    # Known-client records (rest/user) and guests (stat/guest) resolve by _id or MAC; the
    # harness record 0 carries ARG_HEX / ARG_MAC.
    "extend_guest": {"guest": ARG_HEX},
    "set_client_name": {"client": ARG_HEX},
    "set_client_note": {"client": ARG_HEX},
    "set_client_fixed_ip": {"client": ARG_HEX, "fixed_ip": "192.0.2.50"},
    "remove_client_fixed_ip": {"client": ARG_HEX},
    # a network named in the recorded networkconf fixture, so the reservation's network
    # lookup (a Classic read) is exercised by the catalog sweeps
    "create_client_reservation": {"network": ARG_HEX},
    # Recorded networkconf fixture: the vpn-client record's external_id (captured live from a
    # disabled synthetic client, sanitized).
    "update_vpn_client": {"vpn_client_id": "00000000-0000-4000-9000-0000000000c1"},
    "delete_vpn_client": {"vpn_client_id": "00000000-0000-4000-9000-0000000000c1"},
    # The console's site list (api/self/sites) answers the harness record 0 (_id ARG_HEX).
    "delete_site": {"site_to_delete": ARG_HEX},
    # full-replace orderings: the spec requires the ordered id list (its absence is
    # refused before any request)
    "set_acl_rule_ordering": {"ordering": {"orderedAclRuleIds": [ARG_ID]}},
    "set_firewall_policy_ordering": {"ordering": {"orderedFirewallPolicyIds": [ARG_ID]}},
    "create_traffic_route": {
        "payload": {
            "matching_target": "INTERNET",
            "network_id": ARG_ID,
            "target_devices": [{"type": "ALL_CLIENTS"}],
        }
    },
}

# Environment a tool needs to be served at all (documented capability flags).
TOOL_ENV: dict[str, dict[str, str]] = {
    "get_unifi_placement_snapshot": {"UNIFI_ENABLE_CONNECTOR_WRITE": "0"},
}


# Per-family selectors come from captures, never from an appended universal object.
# Synthetic property modes retain ARG_* so their generated pages remain addressable.
_RECORDED_FAMILIES = {
    "client_reservation": ("network_api_s_SITE_rest_networkconf", ("network",)),
    "client": ("network_integration_v1_sites_ID_clients", ("client_id",)),
    "device": ("network_integration_v1_sites_ID_devices", ("device_id",)),
    "network": ("network_integration_v1_sites_ID_networks", ("network_id",)),
    "wifi_broadcast": ("network_integration_v1_sites_ID_wifi_broadcasts", ("broadcast_id",)),
    "firewall_policy": ("network_integration_v1_sites_ID_firewall_policies", ("policy_id",)),
    "firewall_zone_proxy": ("network_integration_v1_sites_ID_firewall_zones", ("zone_id",)),
    "acl_rule": ("network_integration_v1_sites_ID_acl_rules", ("rule_id",)),
    "dns_policy": ("network_integration_v1_sites_ID_dns_policies", ("policy_id",)),
    "traffic_matching_list": (
        "network_integration_v1_sites_ID_traffic_matching_lists",
        ("list_id",),
    ),
    "radius_profile": ("network_integration_v1_sites_ID_radius_profiles", ("profile_id",)),
    "hotspot_voucher": ("network_integration_v1_sites_ID_hotspot_vouchers", ("voucher_id",)),
    "port_profile": ("network_api_s_SITE_rest_portconf", ("profile_id",)),
    "wlan_config": ("network_api_s_SITE_rest_wlanconf", ("wlan_id",)),
    "wlan_group": ("network_api_s_SITE_rest_wlangroup", ("group_id",)),
    "port_forward": ("network_api_s_SITE_rest_portforward", ("forward_id",)),
    "traffic_route": ("network_v2_api_site_SITE_trafficroutes", ("route_id",)),
    "traffic_rule": ("network_v2_api_site_SITE_trafficrules", ("rule_id",)),
    "device_tag": ("network_v2_api_site_SITE_device_tags", ("tag_id",)),
    "dynamic_dns": ("network_api_s_SITE_rest_dynamicdns", ("ddns_id",)),
    "user": ("network_api_s_SITE_rest_user", ("user_id",)),
    "scheduled_task": ("network_api_s_default_rest_scheduletask", ("task_id",)),
    "camera": ("protect_integration_v1_cameras", ("camera_id",)),
    "chime": ("protect_integration_v1_chimes", ("chime_id",)),
    "light": ("protect_integration_v1_lights", ("light_id",)),
    "sensor": ("protect_integration_v1_sensors", ("sensor_id",)),
    "siren": ("protect_integration_v1_sirens", ("siren_id",)),
    "viewer": ("protect_integration_v1_viewers", ("viewer_id",)),
    "liveview": ("protect_integration_v1_liveviews", ("liveview_id",)),
}


#: Tools that run on the harness's generated records (``replay_recordings=False``), named
#: explicitly. Each one either resolves its target against a native list that holds none of
#: the generated ARG_* ids (validate-first resolution: an unknown id fails before any write),
#: or reads a route that has no native capture, or only one for a different query. A native
#: capture is never supplemented, so these tools opt out by name; the harness replay tests
#: fail when a name here no longer needs the opt-out (remove it then) or is not a tool.
SYNTHETIC_RECORD_TOOLS: frozenset[str] = frozenset(
    {
        "adopt_protect_device",
        "allow_network_on_port_profile",
        "approve_pending_device",
        "authorize_guest",
        "clear_switch_counters",
        "clone_device_config",
        "control_device_battery",
        "create_port_profile",
        "delete_port_profile",
        "delete_protect_device_tag",
        "delete_radius_profile",
        "delete_recognition_group",
        "delete_site",
        "delete_site_to_site_tunnel",
        "delete_static_route",
        "delete_traffic_rule",
        "detach_from_orchestration",
        "exclude_network_on_port_profile",
        "extend_guest",
        "fabric_connector_get",
        "get_cybersecure_summary",
        "get_device_radios",
        "get_device_replacement_options",
        "get_latest_firmware_versions",
        "get_network_references",
        "get_observability_site_health",
        "get_protect_stream_url",
        "get_sites_overview",
        "list_carrier_subscribers",
        "list_mobility_workspaces",
        "list_protect_cases",
        "list_protect_events",
        "list_sdwan_configs",
        "list_site_features",
        "locate_switch_port",
        "migrate_network_to_layer3",
        "reboot_protect_device",
        "recover_switch_port",
        "remove_client_fixed_ip",
        # the Matter node capture is an empty list (no node on the recorded controller)
        "remove_matter_node",
        "rename_matter_node",
        "replace_device",
        "report_incorrect_wifi_experience",
        "revoke_guest_access",
        "run_device_self_test",
        "set_client_fingerprint_override",
        "set_client_fixed_ip",
        "set_client_icon",
        "set_client_name",
        "set_client_note",
        "set_client_user_group",
        "set_device_alignment_mode",
        "set_device_rearrange_mode",
        "set_outlet_power",
        "set_priority_uplink",
        "set_recognition_group_image",
        "unadopt_protect_device",
        "unpair_building_bridge",
        "update_device_battery_settings",
        "update_device_radio",
        "update_port_profile",
        "update_protect_case",
        "update_protect_device_tag",
        "update_protect_user",
        "update_radius_profile",
        "update_recognition_group",
        "update_site_to_site_tunnel",
        "update_static_route",
        "update_traffic_rule",
    }
)


def prepare_upstream(name: str, upstream: Any) -> None:
    """Make the harness serve ``name``: the named opt-outs and synthetic routes, explicitly.

    Called when the tool is called (``upstream_harness.install`` wraps ``call_tool``) and
    when its arguments are generated, so a test that builds the arguments before it installs
    the harness is served the same way.
    """
    if getattr(upstream, "mode", None) != "normal":
        return
    if name in SYNTHETIC_RECORD_TOOLS:
        upstream.replay_recordings = False
    if name == "get_unifi_placement_snapshot":
        # The tool filters /v1/devices by hostIds[]; no capture holds that query.
        upstream.synthetic_routes[("GET", "/v1/devices")] = "site_manager_devices_host_filter.json"


def resolve_placeholders(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """``args`` with each ARG_* placeholder replaced by the identifier the captures hold.

    A test that generated its arguments before it installed the harness holds placeholders
    that no native capture contains; they are resolved when the tool is called. Any other
    value (an unknown id a test passes on purpose) is left exactly as given.
    """
    resolved = _recorded_args(name, args)
    placeholders = {ARG_ID, ARG_HEX, ARG_MAC, ARG_NAME}
    return {
        key: resolved[key]
        if isinstance(value, str) and value in placeholders and key in resolved
        else value
        for key, value in args.items()
    }


def _recorded_args(name: str, args: dict[str, Any]) -> dict[str, Any]:
    from tests import upstream_harness as uh

    upstream = getattr(server, "_harness_upstream", None)
    prepare_upstream(name, upstream)
    if name in SYNTHETIC_RECORD_TOOLS and getattr(upstream, "mode", None) == "normal":
        return args
    if (
        upstream is None
        or getattr(upstream, "mode", None) != "normal"
        or not upstream.replay_recordings
        or upstream.hosts_by_key is not None
        or upstream.site_count != 1
        or upstream.page_resolution
        or upstream.scalar_body
        or upstream.get_body != "json"
        or upstream.write_body != "json"
    ):
        return args
    entries = list(upstream.recorded_routes.values())
    if name == "collect_protect_events":
        for entry in entries:
            path = entry["request"]["path"]
            if path.endswith("/proxy/protect/api/events"):
                upstream.synthetic_routes[("GET", path)] = "relative_time_protect_events.json"
    if name in {"get_traffic_route", "update_traffic_route", "delete_traffic_route"}:
        for entry in entries:
            path = entry["request"]["path"]
            if path.endswith("/trafficroutes") and entry.get("body") == []:
                upstream.synthetic_routes[("GET", path)] = "empty_traffic_routes_lookup.json"
    out = dict(args)
    # Captured detail paths preserve the exact identifier that the transport can replay.
    own = next(
        (e for e in entries if e.get("recorded_by_tool") == name and 200 <= e["status"] < 300), None
    )
    if own:
        path = own["request"]["path"]
        for collection, parameter in (
            ("clients", "client_id"),
            ("devices", "device_id"),
            ("networks", "network_id"),
            ("wifi/broadcasts", "broadcast_id"),
            ("firewall/policies", "policy_id"),
            ("firewall/zones", "zone_id"),
            ("cameras", "camera_id"),
            ("rest/portconf", "profile_id"),
            ("rest/wlanconf", "wlan_id"),
            ("hosts", "host_id"),
            ("assets", "asset_id"),
        ):
            marker = "/" + collection + "/"
            if marker in path and parameter in out:
                out[parameter] = path.split(marker, 1)[1].split("/", 1)[0]
        if name == "get_setting":
            out["setting_key"] = path.rsplit("/", 1)[-1]
    for family_name, (fixture, parameters) in _RECORDED_FAMILIES.items():
        if not any(parameter in out for parameter in parameters):
            continue
        # Match whole tool noun: a device-tag operation is not an Integration device.
        if not (
            name.endswith("_" + family_name)
            or name.startswith("get_" + family_name + "_")
            or name == "get_" + family_name
        ):
            continue
        capture = next(
            (
                e
                for e in entries
                if e.get("_file", "").endswith(fixture + "_ID.json") and 200 <= e["status"] < 300
            ),
            None,
        )
        if capture is None:
            capture = next(
                (
                    e
                    for e in entries
                    if e.get("_file", "").endswith(fixture + ".json") and 200 <= e["status"] < 300
                ),
                None,
            )
        if capture is None:
            continue
        records = uh.upstream_records(capture.get("body"))
        record = next((row for row in records if isinstance(row, dict)), None)
        if record is None:
            continue
        selector = (
            record.get("_id")
            if "/rest/" in capture["request"]["path"] or "/v2/" in capture["request"]["path"]
            else record.get("id")
        )
        if selector:
            for parameter in parameters:
                if parameter in out and (
                    own is None or out[parameter] in {ARG_ID, ARG_HEX, ARG_MAC}
                ):
                    out[parameter] = selector

    def first_record(fixture: str) -> dict[str, Any]:
        capture = next(
            (
                e
                for e in entries
                if e.get("_file", "").endswith(fixture + ".json") and 200 <= e["status"] < 300
            ),
            None,
        )
        if capture is None:
            return {}
        return next(
            (row for row in uh.upstream_records(capture.get("body")) if isinstance(row, dict)), {}
        )

    if name == "get_client_link_diagnostics":
        row = first_record("network_api_s_SITE_stat_sta")
        if row.get("mac"):
            out["client_id"] = row["mac"]
    if name in {"get_device_port_state", "get_device_stp_state", "get_device_link_diagnostics"}:
        row = first_record("network_api_s_SITE_stat_device")
        if row.get("mac"):
            out["device_id"] = row["mac"]
    if name in {"get_vpn_server", "update_vpn_server", "delete_vpn_server"}:
        row = first_record("network_integration_v1_sites_ID_vpn_servers")
        if row.get("id"):
            out["server_id"] = row["id"]
    # A search query names a record the captures hold (ARG_NAME is a synthetic name).
    if name == "search_device_fleet" and out.get("query") == ARG_NAME:
        wrapper = first_record("site_manager/v1_devices")
        devices = wrapper.get("devices") if isinstance(wrapper.get("devices"), list) else []
        device = next((d for d in devices if isinstance(d, dict) and d.get("name")), {})
        if device:
            out["query"] = device["name"]
    if name == "search_across_sites" and out.get("query") == ARG_NAME:
        row = first_record("network_integration_v1_sites_ID_devices")
        if row.get("name"):
            out["query"] = row["name"]
    if own:
        query = own["request"].get("query", {})
        for upstream_key, argument in (
            ("sourceFirewallZoneId", "source_zone_id"),
            ("destinationFirewallZoneId", "destination_zone_id"),
        ):
            if upstream_key in query and argument in out:
                out[argument] = query[upstream_key]
        if name == "list_protect_events":
            for key in ("start", "end"):
                if key in query:
                    out[key] = float(query[key]) / 1000
    return out


def generated_args(tool: Any) -> dict[str, Any]:
    schema = tool.parameters or {}
    props: dict[str, Any] = schema.get("properties", {})
    args: dict[str, Any] = {}
    for name in schema.get("required", []):
        spec = props.get(name, {})
        types = {spec.get("type")} | {s.get("type") for s in spec.get("anyOf", [])}
        enums = [
            value
            for fragment in [spec, *spec.get("anyOf", [])]
            for value in fragment.get("enum", [])
        ]
        if enums:
            args[name] = enums[0]
        elif name in BY_NAME:
            args[name] = BY_NAME[name]
        elif "object" in types:
            args[name] = dict(OBJECT_DEFAULT)
        elif "array" in types:
            args[name] = [ARG_ID]
        elif "integer" in types:
            args[name] = 1
        elif "number" in types:
            args[name] = 1.0
        elif "boolean" in types:
            args[name] = True
        elif name.endswith("_id") or name.endswith("id"):
            args[name] = ARG_ID
        else:
            args[name] = ARG_NAME
    if "confirm" in props:
        args["confirm"] = True
    args.update(OVERRIDES.get(tool.name, {}))
    return _recorded_args(tool.name, args)


__all__ = ["ARG_HEX", "generated_args", "OVERRIDES"]
