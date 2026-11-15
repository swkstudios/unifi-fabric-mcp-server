"""The explicit tool inventory (public #42 steps 6 and 7): what each family contains.

Every public tool, in registration (``tools/list``) order, with its family and the step of
the explicit loader map (:data:`unifi_fabric.catalog.loaders.LOADERS`) that registers it.
This file is the source of truth for catalog membership: the selection family index
(``UNIFI_FAMILY_ALLOW``, ``family:`` exclusions and write exceptions, the ``tool_id`` of the
policy records), the sub-area module index (``module:`` exclusions and the discovery search
vocabulary) and the family of each ``catalog.json`` row are read from it. Nothing scans
source or imports modules to decide membership (public #42: "Do not use import-time
scanning or AST inference as the source of truth for catalog membership").

It is authored. Adding a tool is one line in :data:`MEMBERS`: its name, its family, and
the step that registers it (``<module key>:<function>``, :func:`step_id`). The family is a
decision, never inferred: a tool registered by a ``network`` step that serves firewall
routes is filed under ``firewall``, and every tool whose family differs from its step's
directory says so on its own line. ``scripts/gen_membership.py --check`` (CI and the
fastgate) fails on a missing, duplicate or unknown entry, and the server refuses to start
when its registration and this inventory disagree (:func:`verify`), naming the tool. After
a family move only steps change: ``scripts/gen_membership.py --generate`` rewrites the steps
and the order from the registration, keeps every family as written here, and refuses a
tool this file does not name.

``list_configured_api_keys`` is in the reserved ``meta`` family and keeps its baseline
selection family (:data:`SELECTION_FAMILY_OVERRIDES`). The five discovery meta tools are
registered by the tool mode at startup, not by a loader step, and are not members.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import Any, NamedTuple

from .loaders import LOADERS, Loader

#: The reserved family of the meta tools (:data:`unifi_fabric.catalog.META_FAMILY`).
META = "meta"
#: The family split out by route (:data:`unifi_fabric.families.FIREWALL`): it has no
#: directory of its own, so no loader step names it.
FIREWALL = "firewall"
#: The module that defines the discovery meta tools' functions.
_DISCOVERY_MODULE = "unifi_fabric.discovery"
#: The meta tools the tool mode registers at startup (``catalog.DISCOVERY_META_TOOLS``).
_DISCOVERY = frozenset(
    {"search_tools", "describe_tool", "call_read_tool", "call_write_tool", "list_tool_families"}
)


class Member(NamedTuple):
    """One public tool: its name, its family, and the loader step that registers it."""

    name: str
    family: str
    step: str


#: Meta tools that keep their baseline selection family until the meta-tool selection rule.
SELECTION_FAMILY_OVERRIDES: Mapping[str, str] = MappingProxyType(
    {"list_configured_api_keys": "site_manager"}
)


def step_id(entry: Loader) -> str:
    """A loader step's id in this inventory: ``<module key>:<function>``."""
    return f"{entry.key}:{entry.function}"


# The registered tools, in registration order. Authored; see the module docstring.
# BEGIN MEMBERS
MEMBERS: tuple[Member, ...] = (
    Member("list_hosts", "site_manager", "site_manager/registrar:register"),
    Member("get_host", "site_manager", "site_manager/registrar:register"),
    Member("list_sites", "site_manager", "site_manager/registrar:register"),
    Member("list_devices", "site_manager", "site_manager/registrar:register"),
    Member("get_isp_metrics", "site_manager", "site_manager/registrar:register"),
    Member("query_isp_metrics", "site_manager", "site_manager/registrar:register"),
    Member("list_sdwan_configs", "site_manager", "site_manager/registrar:register"),
    Member("get_sdwan_config", "site_manager", "site_manager/registrar:register"),
    Member("get_sdwan_config_status", "site_manager", "site_manager/registrar:register"),
    Member("list_all_sites_aggregated", "site_manager", "site_manager/registrar:register"),
    Member("get_site_health_summary", "site_manager", "site_manager/registrar:register"),
    Member("compare_site_performance", "site_manager", "site_manager/registrar:register"),
    Member("search_across_sites", "site_manager", "site_manager/registrar:register"),
    Member("get_site_inventory", "site_manager", "site_manager/registrar:register"),
    Member("get_network_application_info", "network", "network/registrar:register"),
    Member("list_local_sites", "network", "network/registrar:register"),
    Member("list_networks", "network", "network/registrar:register"),
    Member("create_network", "network", "network/registrar:register"),
    Member("get_network", "network", "network/registrar:register"),
    Member("update_network", "network", "network/registrar:register"),
    Member("delete_network", "network", "network/registrar:register"),
    Member("get_network_references", "network", "network/registrar:register"),
    Member("list_lags", "network", "network/registrar:register"),
    Member("get_lag", "network", "network/registrar:register"),
    Member("list_mc_lag_domains", "network", "network/registrar:register"),
    Member("get_mc_lag_domain", "network", "network/registrar:register"),
    Member("list_switch_stacks", "network", "network/registrar:register"),
    Member("get_switch_stack", "network", "network/registrar:register"),
    Member("list_integration_device_tags", "network", "network/registrar:register"),
    Member("list_wifi_broadcasts", "network", "network/registrar:register"),
    Member("create_wifi_broadcast", "network", "network/registrar:register"),
    Member("get_wifi_broadcast", "network", "network/registrar:register"),
    Member("update_wifi_broadcast", "network", "network/registrar:register"),
    Member("delete_wifi_broadcast", "network", "network/registrar:register"),
    Member("list_wan_interfaces", "network", "network/registrar:register"),
    Member("update_wan_interface", "network", "network/registrar:register"),
    Member("get_camera_private", "protect", "protect/registrar:register"),
    Member("list_ptz_presets", "protect", "protect/registrar:register"),
    Member("list_ptz_patrols", "protect", "protect/registrar:register"),
    Member("get_sensor_private", "protect", "protect/registrar:register"),
    Member("get_nvr_private", "protect", "protect/registrar:register"),
    Member("get_protect_alarm_manager_mode", "protect", "protect/registrar:register"),
    Member("update_camera_private", "protect", "protect/registrar:register"),
    Member("update_nvr", "protect", "protect/registrar:register"),
    Member("update_sensor_private", "protect", "protect/registrar:register"),
    Member("export_camera_video", "protect", "protect/registrar:register"),
    Member("reboot_protect_device", "protect", "protect/registrar:register"),
    Member("adopt_protect_device", "protect", "protect/registrar:register"),
    Member("unadopt_protect_device", "protect", "protect/registrar:register"),
    Member("clear_sensor_tamper", "protect", "protect/registrar:register"),
    Member("list_site_devices", "devices", "devices/registrar:register"),
    Member("adopt_device", "devices", "devices/registrar:register"),
    Member("get_device", "devices", "devices/registrar:register"),
    Member("unadopt_device", "devices", "devices/registrar:register"),
    Member("execute_device_action", "devices", "devices/registrar:register"),
    Member("get_device_statistics", "devices", "devices/registrar:register"),
    Member("execute_port_action", "devices", "devices/registrar:register"),
    Member("restart_device", "devices", "devices/registrar:register"),
    Member("locate_device", "devices", "devices/registrar:register"),
    Member("upgrade_device", "devices", "devices/registrar:register"),
    Member("list_pending_devices", "devices", "devices/registrar:register"),
    Member("create_device_tag", "devices", "devices/registrar:register"),
    Member("update_device_tag", "devices", "devices/registrar:register"),
    Member("delete_device_tag", "devices", "devices/registrar:register"),
    Member("approve_pending_device", "devices", "devices/registrar:register"),
    Member("forget_device", "devices", "devices/registrar:register"),
    Member("provision_device", "devices", "devices/registrar:register_2"),
    Member("cancel_rolling_upgrade", "devices", "devices/registrar:register_2"),
    Member("list_device_firmware", "devices", "devices/registrar:register_2"),
    Member("migrate_device", "devices", "devices/registrar:register_2"),
    Member("advanced_adopt_device", "devices", "devices/registrar:register_2"),
    Member("run_speedtest", "devices", "devices/registrar:register_2"),
    Member("get_speedtest_status", "devices", "devices/registrar:register_2"),
    Member("upgrade_all_devices", "devices", "devices/registrar:register_2"),
    Member("start_rolling_upgrade", "devices", "devices/registrar:register_2"),
    Member("move_device_to_site", "devices", "devices/registrar:register_2"),
    Member("list_backups", "devices", "devices/registrar:register_2"),
    Member("create_backup", "devices", "devices/registrar:register_2"),
    Member("export_site", "devices", "devices/registrar:register_2"),
    Member("create_scheduled_task", "devices", "devices/registrar:register_3"),
    Member("update_scheduled_task", "devices", "devices/registrar:register_3"),
    Member("delete_scheduled_task", "devices", "devices/registrar:register_3"),
    Member("get_device_radios", "devices", "devices/registrar:register_4"),
    Member("update_device_radio", "devices", "devices/registrar:register_4"),
    Member("get_switch_port_overrides", "devices", "devices/registrar:register_5"),
    Member("update_switch_port_overrides", "devices", "devices/registrar:register_5"),
    Member("diagnose_wifi", "devices", "devices/registrar:register_6"),
    Member("get_radio_ai_isolation_matrix", "network", "network/registrar:register_2"),
    Member("preview_radio_ai_optimization", "network", "network/registrar:register_2"),
    Member("apply_radio_ai_optimization", "network", "network/registrar:register_2"),
    Member("get_radio_history", "network", "network/registrar:register_2"),
    Member("get_wifi_connectivity", "network", "network/registrar:register_2"),
    Member("control_wifi_doctor_optimization", "network", "network/registrar:register_2"),
    Member("get_wifi_stats", "network", "network/registrar:register_2"),
    Member("get_wifi_tethering_scan", "network", "network/registrar:register_2"),
    Member("get_wifiman_settings", "network", "network/registrar:register_2"),
    Member("get_wlan_capabilities", "network", "network/registrar:register_2"),
    Member("list_available_wifi_channels", "network", "network/registrar:register_2"),
    Member("get_access_point_neighbors", "network", "network/registrar:register_2"),
    Member("start_spectrum_scan", "network", "network/registrar:register_2"),
    Member("get_spectrum_scan_results", "network", "network/registrar:register_2"),
    Member("start_wifi_quick_scan", "network", "network/registrar:register_2"),
    Member("get_wifi_quick_scan_status", "network", "network/registrar:register_2"),
    Member("get_wifi_uplink_scan_status", "network", "network/registrar:register_2"),
    Member("configure_wifi_wan", "network", "network/registrar:register_2"),
    Member("list_nat_rules", "network", "network/registrar:register_3"),
    Member("create_nat_rule", "network", "network/registrar:register_3"),
    Member("update_nat_rule", "network", "network/registrar:register_3"),
    Member("delete_nat_rule", "network", "network/registrar:register_3"),
    Member("list_qos_rules", "network", "network/registrar:register_3"),
    Member("create_qos_rule", "network", "network/registrar:register_3"),
    Member("update_qos_rule", "network", "network/registrar:register_3"),
    Member("delete_qos_rule", "network", "network/registrar:register_3"),
    Member("reorder_qos_rules", "network", "network/registrar:register_3"),
    Member("list_content_filters", "network", "network/registrar:register_3"),
    Member("create_content_filter", "network", "network/registrar:register_3"),
    Member("update_content_filter", "network", "network/registrar:register_3"),
    Member("delete_content_filter", "network", "network/registrar:register_3"),
    Member("list_content_filter_categories", "network", "network/registrar:register_3"),
    Member("get_traffic_stats", "network", "network/registrar:register_3"),
    Member("get_latest_traffic_flow_stats", "network", "network/registrar:register_3"),
    Member("query_traffic_flows", "network", "network/registrar:register_3"),
    Member("export_traffic_flows", "network", "network/registrar:register_3"),
    Member("query_app_traffic_rates", "network", "network/registrar:register_3"),
    Member("get_poe_info", "network", "network/registrar:register_3"),
    Member("get_topology_snapshot", "network", "network/registrar:register_3"),
    Member("list_clients", "clients", "clients/registrar:register"),
    Member("list_active_clients", "clients", "clients/registrar:register"),
    Member("get_client", "clients", "clients/registrar:register"),
    Member("execute_client_action", "clients", "clients/registrar:register"),
    Member("block_client", "clients", "clients/registrar:register"),
    Member("unblock_client", "clients", "clients/registrar:register"),
    Member("reconnect_client", "clients", "clients/registrar:register"),
    Member("wake_client", "clients", "clients/registrar:register"),
    Member("authorize_guest", "network", "network/registrar:register_4"),
    Member("revoke_guest_access", "network", "network/registrar:register_4"),
    Member("get_local_client", "network", "network/registrar:register_4"),
    Member("list_client_traffic_controls", "network", "network/registrar:register_4"),
    Member("get_client_insights", "network", "network/registrar:register_4"),
    Member("get_client_observability", "network", "network/registrar:register_4"),
    Member("set_client_icon", "network", "network/registrar:register_4"),
    Member("set_client_fingerprint_override", "network", "network/registrar:register_4"),
    Member("report_incorrect_wifi_experience", "network", "network/registrar:register_4"),
    Member("list_dhcp_leases", "network", "network/registrar:register_4"),
    Member("list_dhcp_excluded_ips", "network", "network/registrar:register_4"),
    Member("list_dhcp_options", "network", "network/registrar:register_4"),
    Member("create_dhcp_option", "network", "network/registrar:register_4"),
    Member("update_dhcp_option", "network", "network/registrar:register_4"),
    Member("delete_dhcp_option", "network", "network/registrar:register_4"),
    Member("get_hotspot_settings", "network", "network/registrar:register_4"),
    Member("list_hotspot_payments", "network", "network/registrar:register_4"),
    Member("list_hotspot_authorizations", "network", "network/registrar:register_4"),
    Member("get_hotspot_guest_webhook_delivery", "network", "network/registrar:register_4"),
    Member("create_hotspot_package", "network", "network/registrar:register_4"),
    Member("update_hotspot_package", "network", "network/registrar:register_4"),
    Member("delete_hotspot_package", "network", "network/registrar:register_4"),
    Member("delete_guest_portal_file", "network", "network/registrar:register_4"),
    Member("reset_guest_access_settings", "network", "network/registrar:register_4"),
    Member("list_energy_saving_policies", "network", "network/registrar:register_5"),
    Member("create_energy_saving_policy", "network", "network/registrar:register_5"),
    Member("update_energy_saving_policy", "network", "network/registrar:register_5"),
    Member("delete_energy_saving_policy", "network", "network/registrar:register_5"),
    Member("list_port_automations", "network", "network/registrar:register_5"),
    Member("get_port_automation", "network", "network/registrar:register_5"),
    Member("create_port_automation", "network", "network/registrar:register_5"),
    Member("update_port_automation", "network", "network/registrar:register_5"),
    Member("delete_port_automation", "network", "network/registrar:register_5"),
    Member("list_power_supervisors", "network", "network/registrar:register_5"),
    Member("create_power_supervisor", "network", "network/registrar:register_5"),
    Member("update_power_supervisor", "network", "network/registrar:register_5"),
    Member("delete_power_supervisor", "network", "network/registrar:register_5"),
    Member("create_power_supervisor_link", "network", "network/registrar:register_5"),
    Member("update_power_supervisor_link", "network", "network/registrar:register_5"),
    Member("delete_power_supervisor_link", "network", "network/registrar:register_5"),
    Member("query_power_supervisor_logs", "network", "network/registrar:register_5"),
    Member("get_port_history", "network", "network/registrar:register_5"),
    Member("query_switch_mac_tables", "network", "network/registrar:register_5"),
    Member("list_port_anomalies", "network", "network/registrar:register_5"),
    Member("query_port_system_logs", "network", "network/registrar:register_5"),
    Member("list_wireless_links", "network", "network/registrar:register_5"),
    Member("get_device_tx_retries", "network", "network/registrar:register_5"),
    Member("get_infrastructure_history", "network", "network/registrar:register_5"),
    Member("get_camera_analytics", "protect", "protect/registrar:register_2"),
    Member("set_camera_control_enabled", "protect", "protect/registrar:register_2"),
    Member("set_camera_door_lock", "protect", "protect/registrar:register_2"),
    Member("get_camera_lux", "protect", "protect/registrar:register_2"),
    Member("get_camera_playback_history", "protect", "protect/registrar:register_2"),
    Member("reset_camera_image_settings", "protect", "protect/registrar:register_2"),
    Member("set_camera_resolution_scale", "protect", "protect/registrar:register_2"),
    Member("transfer_camera_management", "protect", "protect/registrar:register_2"),
    Member("turn_on_camera_flashlight", "protect", "protect/registrar:register_2"),
    Member("get_camera_wifi_networks", "protect", "protect/registrar:register_2"),
    Member("configure_camera_wifi", "protect", "protect/registrar:register_2"),
    Member("set_camera_video_codec", "protect", "protect/registrar:register_2"),
    Member("export_edge_recording", "protect", "protect/registrar:register_2"),
    Member("set_edge_storage_mount_state", "protect", "protect/registrar:register_2"),
    Member("reformat_edge_storage", "protect", "protect/registrar:register_2"),
    Member("update_edge_recording_settings", "protect", "protect/registrar:register_2"),
    Member("delete_recordings", "protect", "protect/registrar:register_2"),
    Member("reboot_unifi_os_console", "network", "network/registrar:register_6"),
    Member("cancel_controller_backup", "network", "network/registrar:register_6"),
    Member("delete_controller_backup", "network", "network/registrar:register_6"),
    Member("restore_controller_backup", "network", "network/registrar:register_6"),
    Member("import_site_configuration", "network", "network/registrar:register_6"),
    Member("send_test_email", "network", "network/registrar:register_6"),
    Member("get_remote_access_turn_credentials", "network", "network/registrar:register_6"),
    Member("set_cloud_access_registration", "network", "network/registrar:register_6"),
    Member("refresh_sso_session", "network", "network/registrar:register_6"),
    Member("link_ubiquiti_sso_account", "network", "network/registrar:register_6"),
    Member("update_my_admin_profile", "network", "network/registrar:register_6"),
    Member("resend_mfa_code", "network", "network/registrar:register_6"),
    Member("set_controller_system_parameter", "network", "network/registrar:register_6"),
    Member("generate_support_file", "network", "network/registrar:register_6"),
    Member("get_support_file", "network", "network/registrar:register_6"),
    Member("check_controller_firmware_update", "network", "network/registrar:register_6"),
    Member("manage_firmware_cache", "network", "network/registrar:register_6"),
    Member("get_latest_firmware_versions", "network", "network/registrar:register_6"),
    Member("get_bgp_status", "network", "network/registrar:register_7"),
    Member("create_bgp_config", "network", "network/registrar:register_7"),
    Member("update_bgp_config", "network", "network/registrar:register_7"),
    Member("delete_bgp_config", "network", "network/registrar:register_7"),
    Member("get_ospf_status", "network", "network/registrar:register_7"),
    Member("create_ospf_router", "network", "network/registrar:register_7"),
    Member("update_ospf_router", "network", "network/registrar:register_7"),
    Member("delete_ospf_router", "network", "network/registrar:register_7"),
    Member("get_global_network_config", "network", "network/registrar:register_7"),
    Member("update_global_network_config", "network", "network/registrar:register_7"),
    Member("get_mdns_settings", "network", "network/registrar:register_7"),
    Member("migrate_network_to_layer3", "network", "network/registrar:register_7"),
    Member("suggest_network_settings", "network", "network/registrar:register_7"),
    Member("generate_vlan_plan", "network", "network/registrar:register_7"),
    Member("import_dhcp_reservations", "network", "network/registrar:register_7"),
    Member("detach_from_orchestration", "network", "network/registrar:register_7"),
    Member("manage_virtual_network", "network", "network/registrar:register_7"),
    Member("get_loop_detection_status", "network", "network/registrar:register_7"),
    Member("recover_loop_blocked_ports", "network", "network/registrar:register_7"),
    Member("manage_mclag_group", "network", "network/registrar:register_7"),
    Member("update_switch_stack", "network", "network/registrar:register_7"),
    Member("list_thread_networks", "network", "network/registrar:register_8"),
    Member("list_matter_nodes", "network", "network/registrar:register_8"),
    Member("commission_matter_node", "network", "network/registrar:register_8"),
    Member("rename_matter_node", "network", "network/registrar:register_8"),
    Member("remove_matter_node", "network", "network/registrar:register_8"),
    Member("list_firewall_policies", "firewall", "firewall/registrar:register"),
    Member("create_firewall_policy", "firewall", "firewall/registrar:register"),
    Member("get_firewall_policy", "firewall", "firewall/registrar:register"),
    Member("update_firewall_policy", "firewall", "firewall/registrar:register"),
    Member("patch_firewall_policy", "firewall", "firewall/registrar:register"),
    Member("delete_firewall_policy", "firewall", "firewall/registrar:register"),
    Member("get_firewall_policy_ordering", "firewall", "firewall/registrar:register"),
    Member("set_firewall_policy_ordering", "firewall", "firewall/registrar:register"),
    Member("list_firewall_zones_proxy", "firewall", "firewall/registrar:register"),
    Member("create_firewall_zone_proxy", "firewall", "firewall/registrar:register"),
    Member("get_firewall_zone_proxy", "firewall", "firewall/registrar:register"),
    Member("update_firewall_zone_proxy", "firewall", "firewall/registrar:register"),
    Member("delete_firewall_zone_proxy", "firewall", "firewall/registrar:register"),
    Member("list_acl_rules", "firewall", "firewall/registrar:register"),
    Member("create_acl_rule", "firewall", "firewall/registrar:register"),
    Member("get_acl_rule", "firewall", "firewall/registrar:register"),
    Member("update_acl_rule", "firewall", "firewall/registrar:register"),
    Member("delete_acl_rule", "firewall", "firewall/registrar:register"),
    Member("get_acl_rule_ordering", "firewall", "firewall/registrar:register"),
    Member("set_acl_rule_ordering", "firewall", "firewall/registrar:register"),
    Member("list_dns_policies", "network", "network/registrar:register_9"),
    Member("create_dns_policy", "network", "network/registrar:register_9"),
    Member("get_dns_policy", "network", "network/registrar:register_9"),
    Member("update_dns_policy", "network", "network/registrar:register_9"),
    Member("delete_dns_policy", "network", "network/registrar:register_9"),
    Member("list_traffic_matching_lists", "network", "network/registrar:register_9"),
    Member("create_traffic_matching_list", "network", "network/registrar:register_9"),
    Member("get_traffic_matching_list", "network", "network/registrar:register_9"),
    Member("update_traffic_matching_list", "network", "network/registrar:register_9"),
    Member("delete_traffic_matching_list", "network", "network/registrar:register_9"),
    Member("list_vpn_servers", "vpn", "network/registrar:register_9"),
    Member("list_site_to_site_tunnels", "vpn", "network/registrar:register_9"),
    Member("list_radius_profiles", "vpn", "network/registrar:register_9"),
    Member("list_hotspot_vouchers", "network", "network/registrar:register_9"),
    Member("create_hotspot_vouchers", "network", "network/registrar:register_9"),
    Member("get_hotspot_voucher", "network", "network/registrar:register_9"),
    Member("delete_hotspot_voucher", "network", "network/registrar:register_9"),
    Member("bulk_delete_hotspot_vouchers", "network", "network/registrar:register_9"),
    Member("list_device_tags", "devices", "network/registrar:register_9"),
    Member("list_countries", "network", "network/registrar:register_9"),
    Member("list_cameras", "protect", "protect/registrar:register_3"),
    Member("get_camera", "protect", "protect/registrar:register_3"),
    Member("update_camera", "protect", "protect/registrar:register_3"),
    Member("enable_camera_share_link", "protect", "protect/registrar:register_3"),
    Member("get_camera_share_link", "protect", "protect/registrar:register_3"),
    Member("disable_camera_share_link", "protect", "protect/registrar:register_3"),
    Member("get_camera_snapshot", "protect", "protect/registrar:register_3"),
    Member("get_rtsps_stream", "protect", "protect/registrar:register_3"),
    Member("create_rtsps_stream", "protect", "protect/registrar:register_3"),
    Member("delete_rtsps_stream", "protect", "protect/registrar:register_3"),
    Member("start_talkback_session", "protect", "protect/registrar:register_3"),
    Member("disable_camera_mic_permanently", "protect", "protect/registrar:register_3"),
    Member("ptz_goto_preset", "protect", "protect/registrar:register_3"),
    Member("ptz_patrol_start", "protect", "protect/registrar:register_3"),
    Member("ptz_patrol_stop", "protect", "protect/registrar:register_3"),
    Member("list_sensors", "protect", "protect/registrar:register_3"),
    Member("get_sensor", "protect", "protect/registrar:register_3"),
    Member("update_sensor", "protect", "protect/registrar:register_3"),
    Member("list_protect_events", "protect", "protect/registrar:register_3"),
    Member("collect_protect_events", "protect", "protect/registrar:register_3"),
    Member("collect_protect_device_changes", "protect", "protect/registrar:register_3"),
    Member("list_recognition_groups", "protect", "protect/registrar:register_4"),
    Member("get_recognition_group_counts", "protect", "protect/registrar:register_4"),
    Member("get_recognition_group_image", "protect", "protect/registrar:register_4"),
    Member("list_recognition_detections", "protect", "protect/registrar:register_4"),
    Member("get_thumbnail", "protect", "protect/registrar:register_4"),
    Member("list_lights", "protect", "protect/registrar:register_5"),
    Member("get_light", "protect", "protect/registrar:register_5"),
    Member("update_light", "protect", "protect/registrar:register_5"),
    Member("list_chimes", "protect", "protect/registrar:register_5"),
    Member("get_chime", "protect", "protect/registrar:register_5"),
    Member("update_chime", "protect", "protect/registrar:register_5"),
    Member("list_viewers", "protect", "protect/registrar:register_5"),
    Member("get_viewer", "protect", "protect/registrar:register_5"),
    Member("update_viewer", "protect", "protect/registrar:register_5"),
    Member("list_liveviews", "protect", "protect/registrar:register_5"),
    Member("get_liveview", "protect", "protect/registrar:register_5"),
    Member("create_liveview", "protect", "protect/registrar:register_5"),
    Member("update_liveview", "protect", "protect/registrar:register_5"),
    Member("get_nvr", "protect", "protect/registrar:register_5"),
    Member("list_protect_files", "protect", "protect/registrar:register_5"),
    Member("upload_protect_file", "protect", "protect/registrar:register_5"),
    Member("trigger_alarm_webhook", "protect", "protect/registrar:register_5"),
    Member("list_arm_profiles", "protect", "protect/registrar:register_5"),
    Member("get_arm_profile", "protect", "protect/registrar:register_5"),
    Member("create_arm_profile", "protect", "protect/registrar:register_5"),
    Member("update_arm_profile", "protect", "protect/registrar:register_5"),
    Member("delete_arm_profile", "protect", "protect/registrar:register_5"),
    Member("update_arm_profile_settings", "protect", "protect/registrar:register_5"),
    Member("enable_arm", "protect", "protect/registrar:register_5"),
    Member("disable_arm", "protect", "protect/registrar:register_5"),
    Member("list_external_arm_profiles", "protect", "protect/registrar:register_5"),
    Member("get_external_arm_profile", "protect", "protect/registrar:register_5"),
    Member("create_external_arm_profile", "protect", "protect/registrar:register_5"),
    Member("update_external_arm_profile", "protect", "protect/registrar:register_5"),
    Member("delete_external_arm_profile", "protect", "protect/registrar:register_5"),
    Member("arm_external_arm_profile", "protect", "protect/registrar:register_5"),
    Member("disarm_external_arm_profile", "protect", "protect/registrar:register_5"),
    Member("stop_speaker_siren", "protect", "protect/registrar:register_5"),
    Member("list_sirens", "protect", "protect/registrar:register_5"),
    Member("get_siren", "protect", "protect/registrar:register_5"),
    Member("update_siren", "protect", "protect/registrar:register_5"),
    Member("siren_play", "protect", "protect/registrar:register_5"),
    Member("siren_stop", "protect", "protect/registrar:register_5"),
    Member("siren_test_sound", "protect", "protect/registrar:register_5"),
    Member("list_fobs", "protect", "protect/registrar:register_5"),
    Member("get_fob", "protect", "protect/registrar:register_5"),
    Member("update_fob", "protect", "protect/registrar:register_5"),
    Member("list_relays", "protect", "protect/registrar:register_5"),
    Member("get_relay", "protect", "protect/registrar:register_5"),
    Member("update_relay", "protect", "protect/registrar:register_5"),
    Member("relay_activate_output", "protect", "protect/registrar:register_5"),
    Member("list_speakers", "protect", "protect/registrar:register_5"),
    Member("get_speaker", "protect", "protect/registrar:register_5"),
    Member("update_speaker", "protect", "protect/registrar:register_5"),
    Member("speaker_test_sound", "protect", "protect/registrar:register_5"),
    Member("list_bridges", "protect", "protect/registrar:register_5"),
    Member("get_bridge", "protect", "protect/registrar:register_5"),
    Member("update_bridge", "protect", "protect/registrar:register_5"),
    Member("list_link_stations", "protect", "protect/registrar:register_5"),
    Member("get_link_station", "protect", "protect/registrar:register_5"),
    Member("update_link_station", "protect", "protect/registrar:register_5"),
    Member("list_alarm_hubs", "protect", "protect/registrar:register_5"),
    Member("get_alarm_hub", "protect", "protect/registrar:register_5"),
    Member("update_alarm_hub", "protect", "protect/registrar:register_5"),
    Member("alarm_hub_trigger_output", "protect", "protect/registrar:register_5"),
    Member("list_protect_users", "protect", "protect/registrar:register_5"),
    Member("get_protect_user", "protect", "protect/registrar:register_5"),
    Member("get_protect_application_info", "protect", "protect/registrar:register_5"),
    Member("list_ulp_users", "protect", "protect/registrar:register_5"),
    Member("get_ulp_user", "protect", "protect/registrar:register_5"),
    Member("pos_ingest_transaction", "protect", "protect/registrar:register_5"),
    Member("list_port_forwards", "network", "network/registrar:register_10"),
    Member("create_port_forward", "network", "network/registrar:register_10"),
    Member("update_port_forward", "network", "network/registrar:register_10"),
    Member("delete_port_forward", "network", "network/registrar:register_10"),
    Member("list_traffic_rules", "network", "network/registrar:register_10"),
    Member("create_site_to_site_tunnel", "vpn", "vpn/registrar:register"),
    Member("update_site_to_site_tunnel", "vpn", "vpn/registrar:register"),
    Member("delete_site_to_site_tunnel", "vpn", "vpn/registrar:register"),
    Member("get_vpn_server", "vpn", "vpn/registrar:register"),
    Member("create_vpn_server", "vpn", "vpn/registrar:register"),
    Member("update_vpn_server", "vpn", "vpn/registrar:register"),
    Member("delete_vpn_server", "vpn", "vpn/registrar:register"),
    Member("get_radius_profile", "vpn", "vpn/registrar:register"),
    Member("create_radius_profile", "vpn", "vpn/registrar:register"),
    Member("list_static_dns_records", "vpn", "vpn/registrar:register_2"),
    Member("create_static_dns_record", "vpn", "vpn/registrar:register_2"),
    Member("update_static_dns_record", "vpn", "vpn/registrar:register_2"),
    Member("delete_static_dns_record", "vpn", "vpn/registrar:register_2"),
    Member("list_doh_servers", "vpn", "vpn/registrar:register_2"),
    Member("get_ipsec_settings", "vpn", "vpn/registrar:register_3"),
    Member("update_ipsec_settings", "vpn", "vpn/registrar:register_3"),
    Member("list_vpn_users", "vpn", "vpn/registrar:register_3"),
    Member("list_vpn_connections", "vpn", "vpn/registrar:register_3"),
    Member("get_openvpn_client_config", "vpn", "vpn/registrar:register_3"),
    Member("restart_vpn_server", "vpn", "vpn/registrar:register_3"),
    Member("list_wireguard_users", "vpn", "vpn/registrar:register_3"),
    Member("list_wireguard_used_subnets", "vpn", "vpn/registrar:register_3"),
    Member("create_wireguard_users", "vpn", "vpn/registrar:register_3"),
    Member("update_wireguard_users", "vpn", "vpn/registrar:register_3"),
    Member("delete_wireguard_users", "vpn", "vpn/registrar:register_3"),
    Member("create_teleport_invitation", "vpn", "vpn/registrar:register_3"),
    Member("revoke_teleport_invitation", "vpn", "vpn/registrar:register_3"),
    Member("query_teleport_invitations", "vpn", "vpn/registrar:register_3"),
    Member("remove_teleport_client", "vpn", "vpn/registrar:register_3"),
    Member("list_magic_site_vpn", "vpn", "vpn/registrar:register_3"),
    Member("create_site_vpn", "vpn", "vpn/registrar:register_3"),
    Member("delete_site_vpn", "vpn", "vpn/registrar:register_3"),
    Member("control_site_vpn", "vpn", "vpn/registrar:register_3"),
    Member("list_user_groups", "network", "network/registrar:register_11"),
    Member("get_user_group", "network", "network/registrar:register_11"),
    Member("create_user_group", "network", "network/registrar:register_11"),
    Member("update_user_group", "network", "network/registrar:register_11"),
    Member("delete_user_group", "network", "network/registrar:register_11"),
    Member("set_client_user_group", "network", "network/registrar:register_11"),
    Member("get_static_route", "network", "network/registrar:register_11"),
    Member("create_static_route", "network", "network/registrar:register_11"),
    Member("update_static_route", "network", "network/registrar:register_11"),
    Member("delete_static_route", "network", "network/registrar:register_11"),
    Member("create_radius_account", "network", "network/registrar:register_11"),
    Member("update_radius_account", "network", "network/registrar:register_11"),
    Member("delete_radius_account", "network", "network/registrar:register_11"),
    Member("list_ap_groups", "network", "network/registrar:register_11"),
    Member("get_ap_group", "network", "network/registrar:register_11"),
    Member("create_ap_group", "network", "network/registrar:register_11"),
    Member("update_ap_group", "network", "network/registrar:register_11"),
    Member("delete_ap_group", "network", "network/registrar:register_11"),
    Member("create_port_profile", "network", "network/registrar:register_11"),
    Member("delete_port_profile", "network", "network/registrar:register_11"),
    Member("create_dynamic_dns", "network", "network/registrar:register_11"),
    Member("delete_dynamic_dns", "network", "network/registrar:register_11"),
    Member("update_radius_profile", "vpn", "vpn/registrar:register_4"),
    Member("delete_radius_profile", "vpn", "vpn/registrar:register_4"),
    Member("list_hotspot_operators", "hotspot", "hotspot/registrar:register"),
    Member("create_hotspot_operator", "hotspot", "hotspot/registrar:register"),
    Member("update_hotspot_operator", "hotspot", "hotspot/registrar:register"),
    Member("delete_hotspot_operator", "hotspot", "hotspot/registrar:register"),
    Member("list_configured_api_keys", "meta", "site_manager/registrar:register_2"),
    Member("get_server_diagnostic_bundle", "site_manager", "site_manager/registrar:register_2"),
    Member("list_all_devices", "site_manager", "site_manager/registrar:register_2"),
    Member("list_all_clients", "site_manager", "site_manager/registrar:register_2"),
    Member("get_fleet_summary", "site_manager", "site_manager/registrar:register_2"),
    Member("search_device_fleet", "site_manager", "site_manager/registrar:register_2"),
    Member("list_controller_stat_schemas", "statistics", "statistics/registrar:register"),
    Member("get_site_statistics", "statistics", "statistics/registrar:register"),
    Member("get_system_info", "statistics", "statistics/registrar:register"),
    Member("list_active_clients_stats", "statistics", "statistics/registrar:register"),
    Member("list_device_stats", "statistics", "statistics/registrar:register"),
    Member("get_client_link_diagnostics", "statistics", "statistics/registrar:register"),
    Member("get_device_port_state", "statistics", "statistics/registrar:register"),
    Member("get_device_stp_state", "statistics", "statistics/registrar:register"),
    Member("list_client_sessions", "statistics", "statistics/registrar:register"),
    Member("get_historical_stats", "statistics", "statistics/registrar:register"),
    Member("list_speedtest_results", "statistics", "statistics/registrar:register"),
    Member("list_known_clients", "statistics", "statistics/registrar:register"),
    Member("get_protect_event", "protect", "protect/registrar:register_6"),
    Member("get_protect_event_media", "protect", "protect/registrar:register_6"),
    Member("set_protect_event_favorite", "protect", "protect/registrar:register_6"),
    Member("list_protect_cases", "protect", "protect/registrar:register_6"),
    Member("create_protect_case", "protect", "protect/registrar:register_6"),
    Member("update_protect_case", "protect", "protect/registrar:register_6"),
    Member("delete_protect_case", "protect", "protect/registrar:register_6"),
    Member("get_protect_case_activity", "protect", "protect/registrar:register_6"),
    Member("list_protect_case_assets", "protect", "protect/registrar:register_6"),
    Member("add_protect_case_asset", "protect", "protect/registrar:register_6"),
    Member("update_protect_case_asset", "protect", "protect/registrar:register_6"),
    Member("remove_protect_case_asset", "protect", "protect/registrar:register_6"),
    Member("export_protect_case", "protect", "protect/registrar:register_6"),
    Member("get_protect_stream_url", "protect", "protect/registrar:register_6"),
    Member("collect_protect_incident_evidence", "protect", "protect/registrar:register_6"),
    Member("get_network_config_defaults", "network", "network/registrar:register_12"),
    Member("get_controller_stats", "network", "network/registrar:register_12"),
    Member("get_sites_overview", "network", "network/registrar:register_12"),
    Member("get_network_ui_data", "network", "network/registrar:register_12"),
    Member("get_sdn_status", "network", "network/registrar:register_12"),
    Member("list_installed_applications", "network", "network/registrar:register_12"),
    Member("get_console_general_info", "network", "network/registrar:register_12"),
    Member("get_first_system_event", "network", "network/registrar:register_12"),
    Member("list_timezones", "network", "network/registrar:register_12"),
    Member("list_ups_devices", "network", "network/registrar:register_12"),
    Member("set_ups_pairing", "network", "network/registrar:register_12"),
    Member("list_vendor_ids", "network", "network/registrar:register_12"),
    Member("list_device_models", "network", "network/registrar:register_12"),
    Member("get_device_fingerprint", "network", "network/registrar:register_12"),
    Member("list_site_features", "network", "network/registrar:register_12"),
    Member("get_site_dashboard", "network", "network/registrar:register_12"),
    Member("list_site_warnings", "network", "network/registrar:register_12"),
    Member("get_cybersecure_summary", "network", "network/registrar:register_12"),
    Member("get_site_degradation_status", "network", "network/registrar:register_12"),
    Member("get_observability_site_health", "network", "network/registrar:register_12"),
    Member("get_observability_people", "network", "network/registrar:register_12"),
    Member("list_ulp_user_groups", "network", "network/registrar:register_12"),
    Member("list_network_anomalies", "network", "network/registrar:register_12"),
    Member("get_site_dpi_usage", "network", "network/registrar:register_12"),
    Member("get_client_dpi_usage", "network", "network/registrar:register_12"),
    Member("get_client_wifi_experience", "network", "network/registrar:register_12"),
    Member("suggest_service_port", "network", "network/registrar:register_12"),
    Member("reset_dpi_counters", "network", "network/registrar:register_13"),
    Member("list_policy_engine_rules", "network", "network/registrar:register_13"),
    Member("create_policy_engine_rule", "network", "network/registrar:register_13"),
    Member("update_policy_engine_rule", "network", "network/registrar:register_13"),
    Member("delete_policy_engine_rule", "network", "network/registrar:register_13"),
    Member("preview_policy_engine_rule", "network", "network/registrar:register_13"),
    Member("list_network_members_groups", "network", "network/registrar:register_13"),
    Member("create_network_members_group", "network", "network/registrar:register_13"),
    Member("update_network_members_group", "network", "network/registrar:register_13"),
    Member("delete_network_members_group", "network", "network/registrar:register_13"),
    Member("list_firewall_app_blocks", "firewall", "firewall/registrar:register_2"),
    Member("set_firewall_app_blocks", "firewall", "firewall/registrar:register_2"),
    Member("preview_firewall_group", "firewall", "firewall/registrar:register_2"),
    Member("update_predefined_firewall_policy", "firewall", "firewall/registrar:register_2"),
    Member("get_firewall_zone_matrix", "firewall", "firewall/registrar:register_2"),
    Member("batch_delete_acl_rules", "firewall", "firewall/registrar:register_2"),
    Member("batch_delete_firewall_policies", "firewall", "firewall/registrar:register_2"),
    Member("batch_delete_firewall_zones", "firewall", "firewall/registrar:register_2"),
    Member("list_protect_device_tags", "protect", "protect/registrar:register_7"),
    Member("create_protect_device_tag", "protect", "protect/registrar:register_7"),
    Member("update_protect_device_tag", "protect", "protect/registrar:register_7"),
    Member("delete_protect_device_tag", "protect", "protect/registrar:register_7"),
    Member("create_protect_user_group", "protect", "protect/registrar:register_7"),
    Member("update_protect_user_group", "protect", "protect/registrar:register_7"),
    Member("delete_protect_user_group", "protect", "protect/registrar:register_7"),
    Member("update_protect_user", "protect", "protect/registrar:register_7"),
    Member("set_protect_notifications_muted", "protect", "protect/registrar:register_7"),
    Member("get_protect_device_password", "protect", "protect/registrar:register_7"),
    Member("update_protect_device_password", "protect", "protect/registrar:register_7"),
    Member("get_protect_file", "protect", "protect/registrar:register_7"),
    Member("delete_protect_file", "protect", "protect/registrar:register_7"),
    Member("upload_ringtone", "protect", "protect/registrar:register_7"),
    Member("delete_ringtone", "protect", "protect/registrar:register_7"),
    Member("get_ringtone", "protect", "protect/registrar:register_7"),
    Member("delete_liveview", "protect", "protect/registrar:register_7"),
    Member("list_protect_automations", "protect", "protect/registrar:register_8"),
    Member("create_protect_automation", "protect", "protect/registrar:register_8"),
    Member("update_protect_automation", "protect", "protect/registrar:register_8"),
    Member("delete_protect_automation", "protect", "protect/registrar:register_8"),
    Member("get_protect_automation_history", "protect", "protect/registrar:register_8"),
    Member("reset_protect_automations", "protect", "protect/registrar:register_8"),
    Member("set_protect_notification_receivers", "protect", "protect/registrar:register_8"),
    Member("list_protect_backups", "protect", "protect/registrar:register_8"),
    Member("create_protect_backup", "protect", "protect/registrar:register_8"),
    Member("delete_protect_backup", "protect", "protect/registrar:register_8"),
    Member("import_protect_backup", "protect", "protect/registrar:register_8"),
    Member("restore_protect_backup", "protect", "protect/registrar:register_8"),
    Member("restore_protect_database", "protect", "protect/registrar:register_8"),
    Member("get_cloud_archive_status", "protect", "protect/registrar:register_8"),
    Member("start_cloud_video_archive", "protect", "protect/registrar:register_8"),
    Member("connect_cloud_archive_provider", "protect", "protect/registrar:register_8"),
    Member("cancel_cloud_archive_task", "protect", "protect/registrar:register_8"),
    Member("disconnect_cloud_archive_provider", "protect", "protect/registrar:register_8"),
    Member("connect_unifi_video_server", "protect", "protect/registrar:register_8"),
    Member("import_unifi_video_cameras", "protect", "protect/registrar:register_8"),
    Member("accept_ironclad_terms", "protect", "protect/registrar:register_8"),
    Member("list_ssl_inspection_catalog", "network", "network/registrar:register_14"),
    Member("list_ssl_inspection_certificates", "network", "network/registrar:register_14"),
    Member("create_ssl_inspection_certificate", "network", "network/registrar:register_14"),
    Member("delete_ssl_inspection_certificate", "network", "network/registrar:register_14"),
    Member("activate_ssl_inspection_certificate", "network", "network/registrar:register_14"),
    Member("list_ssl_inspection_profiles", "network", "network/registrar:register_14"),
    Member("create_ssl_inspection_profile", "network", "network/registrar:register_14"),
    Member("update_ssl_inspection_profile", "network", "network/registrar:register_14"),
    Member("delete_ssl_inspection_profile", "network", "network/registrar:register_14"),
    Member("get_ssl_inspection_settings", "network", "network/registrar:register_14"),
    Member("update_ssl_inspection_settings", "network", "network/registrar:register_14"),
    Member("list_ips_categories", "network", "network/registrar:register_14"),
    Member("get_ips_signature_status", "network", "network/registrar:register_14"),
    Member("update_ips_signatures", "network", "network/registrar:register_14"),
    Member("get_system_log_settings", "network", "network/registrar:register_14"),
    Member("update_system_log_settings", "network", "network/registrar:register_14"),
    Member("mark_critical_logs_read", "network", "network/registrar:register_14"),
    Member("acknowledge_critical_alert", "network", "network/registrar:register_14"),
    Member("control_packet_capture", "network", "network/registrar:register_14"),
    Member("get_packet_capture_status", "network", "network/registrar:register_14"),
    Member("control_ping_test", "network", "network/registrar:register_14"),
    Member("get_ping_test_results", "network", "network/registrar:register_14"),
    Member("get_unified_ip_thread_topology", "network", "network/registrar:register_14"),
    Member("get_proav_matrix", "network", "network/registrar:register_15"),
    Member("get_proav_snapshot", "network", "network/registrar:register_15"),
    Member("create_proav_group", "network", "network/registrar:register_15"),
    Member("update_proav_group", "network", "network/registrar:register_15"),
    Member("delete_proav_group", "network", "network/registrar:register_15"),
    Member("set_tv_wall_calibration", "network", "network/registrar:register_15"),
    Member("get_shadow_mode_status", "network", "network/registrar:register_15"),
    Member("control_shadow_mode_adoption", "network", "network/registrar:register_15"),
    Member("list_test_configs", "network", "network/registrar:register_15"),
    Member("create_test_config", "network", "network/registrar:register_15"),
    Member("delete_test_config", "network", "network/registrar:register_15"),
    Member("apply_test_config", "network", "network/registrar:register_15"),
    Member("get_port_forward_statistics", "network", "network/registrar:register_15"),
    Member("get_digital_twin_layout", "network", "network/registrar:register_15"),
    Member("update_digital_twin_layout", "network", "network/registrar:register_15"),
    Member("delete_digital_twin_layout", "network", "network/registrar:register_15"),
    Member("get_5g_topology", "network", "network/registrar:register_15"),
    Member("get_multicast_insights", "network", "network/registrar:register_15"),
    Member("move_ptz_camera", "protect", "protect/registrar:register_9"),
    Member("ptz_home", "protect", "protect/registrar:register_9"),
    Member("set_ptz_event_control_window", "protect", "protect/registrar:register_9"),
    Member("create_ptz_patrol", "protect", "protect/registrar:register_9"),
    Member("update_ptz_patrol", "protect", "protect/registrar:register_9"),
    Member("delete_ptz_patrol", "protect", "protect/registrar:register_9"),
    Member("create_ptz_preset", "protect", "protect/registrar:register_9"),
    Member("update_ptz_preset", "protect", "protect/registrar:register_9"),
    Member("delete_ptz_preset", "protect", "protect/registrar:register_9"),
    Member("create_camera_shortcut", "protect", "protect/registrar:register_9"),
    Member("update_camera_shortcut", "protect", "protect/registrar:register_9"),
    Member("delete_camera_shortcut", "protect", "protect/registrar:register_9"),
    Member("trigger_camera_shortcut", "protect", "protect/registrar:register_9"),
    Member("calibrate_camera", "protect", "protect/registrar:register_9"),
    Member("test_doorbell_ringtone", "protect", "protect/registrar:register_9"),
    Member("enroll_doorbell_credential", "protect", "protect/registrar:register_9"),
    Member("delete_doorbell_credential", "protect", "protect/registrar:register_9"),
    Member("create_recognition_group", "protect", "protect/registrar:register_10"),
    Member("update_recognition_group", "protect", "protect/registrar:register_10"),
    Member("delete_recognition_group", "protect", "protect/registrar:register_10"),
    Member("assign_detections_to_recognition_group", "protect", "protect/registrar:register_10"),
    Member("enhance_face_detection_image", "protect", "protect/registrar:register_10"),
    Member("search_recognition_group_candidates", "protect", "protect/registrar:register_10"),
    Member("set_recognition_group_image", "protect", "protect/registrar:register_10"),
    Member("merge_recognition_groups", "protect", "protect/registrar:register_10"),
    Member("recognize_image", "protect", "protect/registrar:register_10"),
    Member("bulk_upload_vehicle_groups", "protect", "protect/registrar:register_10"),
    Member("get_vehicle_group_upload_template", "protect", "protect/registrar:register_10"),
    Member("search_detections", "protect", "protect/registrar:register_10"),
    Member("get_detection_search_metadata", "protect", "protect/registrar:register_10"),
    Member("get_detection_statistics", "protect", "protect/registrar:register_10"),
    Member("report_ai_false_positive", "protect", "protect/registrar:register_10"),
    Member("hide_face_detection_enhanced_image", "protect", "protect/registrar:register_10"),
    Member("apply_recognized_image", "protect", "protect/registrar:register_10"),
    Member("create_recognition_object_group", "protect", "protect/registrar:register_10"),
    Member("readopt_protect_device", "protect", "protect/registrar:register_11"),
    Member("upgrade_protect_device_firmware", "protect", "protect/registrar:register_11"),
    Member("locate_protect_device", "protect", "protect/registrar:register_11"),
    Member("update_protect_device_settings", "protect", "protect/registrar:register_11"),
    Member("set_ai_port_pairing", "protect", "protect/registrar:register_11"),
    Member("control_retroactive_ai_processing", "protect", "protect/registrar:register_11"),
    Member("analyze_footage_with_ai", "protect", "protect/registrar:register_11"),
    Member("check_protect_firmware_updates", "protect", "protect/registrar:register_11"),
    Member("upgrade_all_protect_devices", "protect", "protect/registrar:register_11"),
    Member("get_protect_device_metrics", "protect", "protect/registrar:register_11"),
    Member("assign_sensor_to_bridge", "protect", "protect/registrar:register_11"),
    Member("get_sensor_readings", "protect", "protect/registrar:register_11"),
    Member("stop_speaker_stream", "protect", "protect/registrar:register_11"),
    Member("play_chime_sound", "protect", "protect/registrar:register_11"),
    Member("list_door_locks", "protect", "protect/registrar:register_11"),
    Member("set_door_lock_state", "protect", "protect/registrar:register_11"),
    Member("adopt_third_party_camera", "protect", "protect/registrar:register_11"),
    Member("set_nvr_stack_membership", "protect", "protect/registrar:register_11"),
    Member("get_protect_bootstrap", "protect", "protect/registrar:register_11"),
    Member("list_protect_keyrings", "protect", "protect/registrar:register_11"),
    Member("get_door_lock", "protect", "protect/registrar:register_12"),
    Member("list_door_lock_unlock_events", "protect", "protect/registrar:register_12"),
    Member("get_lte_subscription_status", "network", "network/registrar:register_16"),
    Member("activate_lte_trial", "network", "network/registrar:register_16"),
    Member("authorize_lte_device", "network", "network/registrar:register_16"),
    Member("set_lte_apn_profile", "network", "network/registrar:register_16"),
    Member("verify_sim_pin", "network", "network/registrar:register_16"),
    Member("update_lte_device", "network", "network/registrar:register_16"),
    Member("manage_esim_profile", "network", "network/registrar:register_16"),
    Member("get_inactive_sim_slot", "network", "network/registrar:register_16"),
    Member("reset_mobile_data_usage", "network", "network/registrar:register_16"),
    Member("set_lte_failover", "network", "network/registrar:register_16"),
    Member("get_wan_load_balancing", "network", "network/registrar:register_16"),
    Member("update_wan_load_balancing", "network", "network/registrar:register_16"),
    Member("list_wan_network_groups", "network", "network/registrar:register_16"),
    Member("get_wan_insights", "network", "network/registrar:register_16"),
    Member("list_wan_slas", "network", "network/registrar:register_16"),
    Member("create_wan_sla", "network", "network/registrar:register_16"),
    Member("update_wan_sla", "network", "network/registrar:register_16"),
    Member("delete_wan_sla", "network", "network/registrar:register_16"),
    Member("get_enriched_configuration", "network", "network/registrar:register_16"),
    Member("list_gateway_routes", "network", "network/registrar:register_16"),
    Member("manage_device_ssh_session", "network", "network/registrar:register_17"),
    Member("clear_switch_counters", "network", "network/registrar:register_17"),
    Member("clone_device_config", "network", "network/registrar:register_17"),
    Member("set_outlet_power", "network", "network/registrar:register_17"),
    Member("recover_switch_port", "network", "network/registrar:register_17"),
    Member("run_device_self_test", "network", "network/registrar:register_17"),
    Member("set_device_alignment_mode", "network", "network/registrar:register_17"),
    Member("set_priority_uplink", "network", "network/registrar:register_17"),
    Member("set_device_rearrange_mode", "network", "network/registrar:register_17"),
    Member("disconnect_remote_vpn_user", "network", "network/registrar:register_17"),
    Member("locate_switch_port", "network", "network/registrar:register_17"),
    Member("unpair_building_bridge", "network", "network/registrar:register_17"),
    Member("reset_switch_port", "network", "network/registrar:register_17"),
    Member("get_device_adoption_info", "network", "network/registrar:register_17"),
    Member("get_rolling_upgrade_plan", "network", "network/registrar:register_17"),
    Member("get_device_replacement_options", "network", "network/registrar:register_17"),
    Member("replace_device", "network", "network/registrar:register_17"),
    Member("control_device_battery", "network", "network/registrar:register_17"),
    Member("update_device_battery_settings", "network", "network/registrar:register_17"),
    Member("set_device_tag_assignments", "network", "network/registrar:register_17"),
    Member("bulk_update_objects", "network", "network/registrar:register_17"),
    Member("forget_client", "clients", "clients/registrar:register_2"),
    Member("list_guests", "clients", "clients/registrar:register_2"),
    Member("extend_guest", "clients", "clients/registrar:register_2"),
    Member("set_client_name", "clients", "clients/registrar:register_2"),
    Member("set_client_note", "clients", "clients/registrar:register_2"),
    Member("set_client_fixed_ip", "clients", "clients/registrar:register_2"),
    Member("remove_client_fixed_ip", "clients", "clients/registrar:register_2"),
    Member("create_client_reservation", "clients", "clients/registrar:register_2"),
    Member("get_system_log", "statistics", "statistics/registrar:register_2"),
    Member("list_network_events", "statistics", "statistics/registrar:register_2"),
    Member("list_ips_events", "statistics", "statistics/registrar:register_2"),
    Member("get_scoped_system_log", "statistics", "statistics/registrar:register_2"),
    Member("collect_network_incident_evidence", "statistics", "statistics/registrar:register_2"),
    Member("get_event_stream_status", "statistics", "statistics/registrar:register_3"),
    Member("read_recent_events", "statistics", "statistics/registrar:register_3"),
    Member("list_vpn_clients", "vpn", "vpn/registrar:register_5"),
    Member("create_vpn_client", "vpn", "vpn/registrar:register_5"),
    Member("update_vpn_client", "vpn", "vpn/registrar:register_5"),
    Member("delete_vpn_client", "vpn", "vpn/registrar:register_5"),
    Member("create_site", "network", "network/registrar:register_18"),
    Member("rename_site", "network", "network/registrar:register_18"),
    Member("delete_site", "network", "network/registrar:register_18"),
    Member("list_users", "network", "network/registrar:register_19"),
    Member("get_user", "network", "network/registrar:register_19"),
    Member("update_user", "network", "network/registrar:register_19"),
    Member("list_traffic_routes", "network", "network/registrar:register_19"),
    Member("create_traffic_route", "network", "network/registrar:register_19"),
    Member("get_traffic_route", "network", "network/registrar:register_19"),
    Member("update_traffic_route", "network", "network/registrar:register_19"),
    Member("delete_traffic_route", "network", "network/registrar:register_19"),
    Member("list_settings", "network", "network/registrar:register_19"),
    Member("get_setting", "network", "network/registrar:register_19"),
    Member("update_setting", "network", "network/registrar:register_19"),
    Member("list_dynamic_dns", "network", "network/registrar:register_19"),
    Member("get_dynamic_dns", "network", "network/registrar:register_19"),
    Member("update_dynamic_dns", "network", "network/registrar:register_19"),
    Member("list_port_profiles", "network", "network/registrar:register_19"),
    Member("get_port_profile", "network", "network/registrar:register_19"),
    Member("update_port_profile", "network", "network/registrar:register_19"),
    Member("allow_network_on_port_profile", "network", "network/registrar:register_19"),
    Member("exclude_network_on_port_profile", "network", "network/registrar:register_19"),
    Member("list_routing_entries", "network", "network/registrar:register_19"),
    Member("list_wlan_configs", "network", "network/registrar:register_19"),
    Member("get_wlan_config", "network", "network/registrar:register_19"),
    Member("update_wlan_config", "network", "network/registrar:register_19"),
    Member("list_wlan_groups", "network", "network/registrar:register_19"),
    Member("get_wlan_group", "network", "network/registrar:register_19"),
    Member("get_channel_plan", "network", "network/registrar:register_19"),
    Member("list_rogue_aps", "network", "network/registrar:register_19"),
    Member("list_firewall_rules", "firewall", "firewall/registrar:register_3"),
    Member("create_firewall_rule", "firewall", "firewall/registrar:register_3"),
    Member("get_firewall_rule", "firewall", "firewall/registrar:register_3"),
    Member("list_firewall_groups", "firewall", "firewall/registrar:register_3"),
    Member("get_firewall_group", "firewall", "firewall/registrar:register_3"),
    Member("list_accounts", "network", "network/registrar:register_20"),
    Member("get_account", "network", "network/registrar:register_20"),
    Member("list_hotspot_packages", "network", "network/registrar:register_20"),
    Member("get_hotspot_package", "network", "network/registrar:register_20"),
    Member("list_scheduled_tasks", "devices", "network/registrar:register_20"),
    Member("get_scheduled_task", "devices", "network/registrar:register_20"),
    Member("list_dpi_categories", "network", "network/registrar:register_20"),
    Member("list_dpi_applications", "network", "network/registrar:register_20"),
    Member("get_unifi_placement_snapshot", "innerspace", "innerspace/registrar:register"),
    Member("get_innerspace_summary", "innerspace", "innerspace/registrar:register_2"),
    Member("get_innerspace_project", "innerspace", "innerspace/registrar:register_2"),
    Member("list_innerspace_devices", "innerspace", "innerspace/registrar:register_2"),
    Member("list_innerspace_floor_plans", "innerspace", "innerspace/registrar:register_2"),
    Member("list_innerspace_access_points", "innerspace", "innerspace/registrar:register_2"),
    Member("list_innerspace_switches", "innerspace", "innerspace/registrar:register_2"),
    Member("list_innerspace_inventory", "innerspace", "innerspace/registrar:register_2"),
    Member("get_innerspace_asset", "innerspace", "innerspace/registrar:register_2"),
    Member("list_innerspace_doors", "innerspace", "innerspace/registrar:register_3"),
    Member("get_innerspace_stats", "innerspace", "innerspace/registrar:register_3"),
    Member("get_innerspace_ucore_manifest", "innerspace", "innerspace/registrar:register_3"),
    Member("get_innerspace_ucore_status", "innerspace", "innerspace/registrar:register_3"),
    Member("get_innerspace_health", "innerspace", "innerspace/registrar:register_3"),
    Member("import_innerspace_captures", "innerspace", "innerspace/registrar:register_3"),
    Member("create_innerspace_plan", "innerspace", "innerspace/registrar:register_3"),
    Member("delete_innerspace_plan", "innerspace", "innerspace/registrar:register_3"),
    Member("reorder_innerspace_plans", "innerspace", "innerspace/registrar:register_3"),
    Member("update_innerspace_plan_map", "innerspace", "innerspace/registrar:register_3"),
    Member("update_innerspace_plan", "innerspace", "innerspace/registrar:register_3"),
    Member("update_innerspace_project", "innerspace", "innerspace/registrar:register_3"),
    Member("upload_innerspace_plan_asset", "innerspace", "innerspace/registrar:register_3"),
    Member("update_innerspace_wall_type", "innerspace", "innerspace/registrar:register_3"),
    Member("update_innerspace_attenuation_type", "innerspace", "innerspace/registrar:register_3"),
    Member("import_innerspace_dc_shapes", "innerspace", "innerspace/registrar:register_3"),
    Member("retry_innerspace_plan_maps", "innerspace", "innerspace/registrar:register_3"),
    Member("import_innerspace_shared_project", "innerspace", "innerspace/registrar:register_3"),
    Member("transform_innerspace_shapes", "innerspace", "innerspace/registrar:register_3"),
    Member("export_innerspace_backup", "innerspace", "innerspace/registrar:register_3"),
    Member("import_innerspace_backup", "innerspace", "innerspace/registrar:register_3"),
    Member("create_innerspace_support_dump", "innerspace", "innerspace/registrar:register_3"),
    Member("clean_innerspace_storage", "innerspace", "innerspace/registrar:register_3"),
    Member("list_carrier_subscribers", "carrier", "carrier/registrar:register"),
    Member("get_carrier_subscriber", "carrier", "carrier/registrar:register"),
    Member("list_carrier_service_plans", "carrier", "carrier/registrar:register"),
    Member("get_carrier_service_plan", "carrier", "carrier/registrar:register"),
    Member("create_carrier_subscriber", "carrier", "carrier/registrar:register"),
    Member("update_carrier_subscriber", "carrier", "carrier/registrar:register"),
    Member("attach_carrier_subscriber_host", "carrier", "carrier/registrar:register"),
    Member("detach_carrier_subscriber_host", "carrier", "carrier/registrar:register"),
    Member("assign_carrier_subscriber_plan", "carrier", "carrier/registrar:register"),
    Member("suspend_carrier_subscriber", "carrier", "carrier/registrar:register"),
    Member("resume_carrier_subscriber", "carrier", "carrier/registrar:register"),
    Member("fabric_connector_get", "connector", "connector/registrar:register"),
    Member("fabric_connector_post", "connector", "connector/registrar:register"),
    Member("fabric_connector_put", "connector", "connector/registrar:register"),
    Member("fabric_connector_patch", "connector", "connector/registrar:register"),
    Member("fabric_connector_delete", "connector", "connector/registrar:register"),
    Member("list_mobility_workspaces", "mobility", "mobility/registrar:register"),
    Member("list_mobility_admins", "mobility", "mobility/registrar:register"),
    Member("list_mobility_devices", "mobility", "mobility/registrar:register"),
    Member("get_mobility_device", "mobility", "mobility/registrar:register"),
    Member("list_mobility_clients", "mobility", "mobility/registrar:register"),
    Member("update_mobility_device_name", "mobility", "mobility/registrar:register"),
    Member("update_mobility_device_network", "mobility", "mobility/registrar:register"),
    Member("update_mobility_device_wireless", "mobility", "mobility/registrar:register"),
)
# END MEMBERS


def families() -> tuple[str, ...]:
    """Every family a member may name: the loader map's directories, ``firewall`` and
    ``meta``, sorted."""
    return tuple(sorted({entry.family for entry in LOADERS} | {FIREWALL, META}))


_cache: tuple[Any, dict[str, str], dict[str, str]] | None = None


def _indexes() -> tuple[dict[str, str], dict[str, str]]:
    """The family and module indexes of the current :data:`MEMBERS`, built once."""
    global _cache
    members = MEMBERS
    if _cache is None or _cache[0] is not members:
        origin = {step_id(entry): entry.origin for entry in LOADERS}
        family = {m.name: m.family for m in members if m.family != META}
        family.update(SELECTION_FAMILY_OVERRIDES)
        module = {m.name: origin[m.step] for m in members if m.step in origin}
        _cache = (members, dict(sorted(family.items())), dict(sorted(module.items())))
    return _cache[1], _cache[2]


def family_index() -> dict[str, str]:
    """``tool -> selection family`` for every member (the shared table: do not mutate).

    The member's family; the meta tool takes its :data:`SELECTION_FAMILY_OVERRIDES` entry.
    """
    return _indexes()[0]


def module_index() -> dict[str, str]:
    """``tool -> sub-area module`` for every member (the shared table: do not mutate).

    The ``origin`` of the member's loader step: the tools module stem the step was
    registered from, kept across family moves.
    """
    return _indexes()[1]


def modules() -> frozenset[str]:
    """Every sub-area module: the ``origin`` of each loader step."""
    return frozenset(entry.origin for entry in LOADERS)


def problems(members: Sequence[Member] | None = None) -> list[str]:
    """What is wrong with the inventory on its own: a duplicate tool, an unknown family or
    step, a meta tool without a selection family, or a loader step with no member."""
    members = MEMBERS if members is None else members
    out: list[str] = []
    counts = Counter(member.name for member in members)
    out += [f"duplicate tool: {name} is listed {n} times" for name, n in counts.items() if n > 1]
    known_families = set(families())
    steps = {step_id(entry) for entry in LOADERS}
    for member in members:
        if member.family not in known_families:
            out.append(f"unknown family: {member.name} names {member.family!r}")
        elif member.family == META and member.name not in SELECTION_FAMILY_OVERRIDES:
            out.append(f"meta tool without a selection family: {member.name}")
        if member.step not in steps:
            out.append(
                f"unknown step: {member.name} names {member.step!r}, which is not in the loader map"
            )
    used = {member.step for member in members}
    out += [
        f"empty step: {step} is in the loader map but registers no tool of the inventory"
        for step in sorted(steps - used)
    ]
    return out


def registered_steps(mcp: Any) -> list[tuple[str, str]]:
    """``(tool name, step id)`` of every tool registered on ``mcp``, in registration order.

    A tool's step is read from its function: the loader step whose ``register`` function
    defines it (``<module>:<function>``). A not-yet-loaded tool without a function (a
    deferred stub, public #41) names its step by its index in the loader map
    (``deferred_step``). A tool no step defines gets the step ``""``. The discovery meta
    tools that the tool mode adds at startup (their function is defined in
    :mod:`unifi_fabric.discovery`) are left out; any other tool, whatever its name, is
    listed, so a family tool named like a meta tool is an unknown tool.
    """
    from fastmcp.tools import Tool

    steps = {entry.ref: step_id(entry) for entry in LOADERS}
    out: list[tuple[str, str]] = []
    for component in mcp.local_provider._components.values():  # noqa: SLF001
        if not isinstance(component, Tool):
            continue
        fn = getattr(component, "fn", None)
        if component.name in _DISCOVERY and getattr(fn, "__module__", "") == _DISCOVERY_MODULE:
            continue
        index = getattr(component, "deferred_step", None)
        if fn is None and isinstance(index, int) and 0 <= index < len(LOADERS):
            out.append((component.name, step_id(LOADERS[index])))
            continue
        qualname = str(getattr(fn, "__qualname__", "")).split(".<locals>", 1)[0]
        out.append((component.name, steps.get(f"{getattr(fn, '__module__', '')}:{qualname}", "")))
    return out


def registration_problems(
    registered: Iterable[tuple[str, str]], members: Sequence[Member] | None = None
) -> list[str]:
    """Where a registration and the inventory disagree, each named: a tool registered twice,
    a registered tool the inventory does not name (unknown), a tool registered by another
    step than the inventory says, an inventory tool no step registered (missing); then, if
    none of those, a different order."""
    members = MEMBERS if members is None else members
    registered = list(registered)
    out: list[str] = []
    counts = Counter(name for name, _step in registered)
    out += [
        f"duplicate tool: {name} is registered {n} times" for name, n in counts.items() if n > 1
    ]
    declared = {member.name: member for member in members}
    seen: dict[str, str] = {}
    for name, step in registered:
        seen.setdefault(name, step)
    for name, step in seen.items():
        member = declared.get(name)
        where = step or "no loader step"
        if member is None:
            out.append(
                f"unknown tool: {name} is registered by {where} but is not in the "
                "explicit inventory"
            )
        elif member.step != step:
            out.append(
                f"wrong step: {name} is registered by {where}, the explicit inventory "
                f"says {member.step}"
            )
    out += [
        f"missing tool: {member.name} is in the explicit inventory but no step registered it"
        for member in members
        if member.name not in seen
    ]
    if not out and [name for name, _step in registered] != [m.name for m in members]:
        out.append("order: the registration order differs from the explicit inventory")
    return out


def verify(mcp: Any) -> None:
    """Refuse to start when ``mcp``'s registration and the inventory disagree.

    Run once, right after the loader map registered every step and before any install
    pass. Raises :class:`RuntimeError` naming the first problems.
    """
    found = problems() + registration_problems(registered_steps(mcp))
    if found:
        more = f" (and {len(found) - 5} more)" if len(found) > 5 else ""
        raise RuntimeError(
            "explicit inventory: "
            + "; ".join(found[:5])
            + more
            + ". Edit src/unifi_fabric/catalog/membership.py "
            "(scripts/gen_membership.py --check names every difference)."
        )
