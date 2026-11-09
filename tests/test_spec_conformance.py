"""Spec conformance: every outgoing request a tool sends matches the published API contract.

Each registered tool is invoked through the shape-faithful fake upstream
(``tests/upstream_harness.py``) with valid arguments, every request it sends is captured,
and each request whose API family has a published OpenAPI spec is checked against that
spec (vendored, pinned, under ``tests/fixtures/openapi/``):

1. the path matches a spec path template and the method is allowed on it;
2. every required path, query and body parameter is present;
3. path and query values validate against their parameter schemas (type, enum);
4. the JSON body validates against the operation's requestBody schema (types, enums,
   required fields, ``additionalProperties``); a body sent to an operation that defines
   no requestBody is a violation;
5. no query parameter the operation does not define.

Why: ``restart_device`` once sent ``{"action": "restart"}`` while the spec allows only
``RESTART``. Every test passed, because nothing compared outgoing requests with the
published contract.

API families without a published spec (Classic REST ``/proxy/network/api/...``, the
Network ``/proxy/network/v2/api/...`` endpoints, and the Protect private
``/proxy/protect/api/...`` endpoints) cannot be checked. Tools that only reach those
families are listed in ``UNSPECCED_EXEMPT`` with a reason, and the set is asserted to be
exactly the tools whose requests reach no specced family: a new specced tool can never be
silently exempt, and a tool that moves onto a specced API loses its exemption.

A violation that is really a spec defect (the live controller provably needs something
else) is waived per tool in ``WAIVERS`` with evidence; an unused waiver fails the run.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

import httpx
import jsonschema
import pytest
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches
from unifi_fabric import server

ROOT = Path(__file__).resolve().parents[1]
OPENAPI_DIR = Path(__file__).parent / "fixtures" / "openapi"
BASELINE = Path(__file__).parent / "fixtures" / "spec_drift" / "baseline_snapshot.json"

# --------------------------------------------------------------------------- routing
# Console-proxied families: prefix after /v1/connector/consoles/{id} -> spec service.
PROXIED_SPECS = {
    "/proxy/network/integration": "network",
    "/proxy/protect/integration": "protect",
    "/proxy/innerspace/integration": "innerspace",
}
# Console-proxied families with no published spec.
UNSPECCED_PREFIXES = {
    "/proxy/network/api/": "classic",
    "/proxy/network/v2/api/": "v2",
    "/proxy/protect/api/": "protect_private",
    "/proxy/innerspace/api/": "innerspace_private",
    "/proxy/innerspace/health": "innerspace_private",
}
# Families served at api.ui.com directly (no connector prefix).
DIRECT_SPECS = ("site-manager", "mobility", "carrier-fabric")
_CONNECTOR = re.compile(r"^/v1/connector/consoles/[^/]+(?P<rest>/.*)\Z")

# --------------------------------------------------------------------------- policy
_CLASSIC = "Classic REST (/proxy/network/api/...) has no published OpenAPI spec"
_V2 = "Network v2 API (/proxy/network/v2/api/...) has no published OpenAPI spec"
_PROTECT_PRIVATE = (
    "Protect private API (/proxy/protect/api/...) has no published OpenAPI spec; the "
    "published Protect spec covers /proxy/protect/integration only"
)

_EA_FIREWALL = (
    "The Site Manager EA classic firewall-rule creation route has no published OpenAPI "
    "path or request schema; the published Network API covers zone-based policies"
)

_INNERSPACE_PRIVATE = (
    "InnerSpace application routes (/proxy/innerspace/api/..., /proxy/innerspace/health) have "
    "no published OpenAPI spec; the published InnerSpace spec is the GET-only Integration API "
    "(/proxy/innerspace/integration), which serves none of these routes"
)

# Writes the published Integration spec serves GET-only. Evidence, Network 11.0.81 via the
# cloud connector, 2026-10-10: the Integration route answers HTTP 405 on POST and 404 "No
# endpoint" on PUT/DELETE; the controller UI's own bundle (11.0.81) writes these records
# through the Classic or v2 route the tool now uses, and non-mutating probes there answer
# api.err.IdInvalid / InvalidPayload (route served) where a made-up object answers
# api.err.InvalidObject (Classic) or 404 (v2). Device-tag and RADIUS-profile writes were
# also round-tripped on synthetic zz-uf-acceptance-* objects, deleted afterwards.
_CLASSIC_UI_WRITE = (
    _CLASSIC + "; the Integration spec serves this collection GET-only and the live "
    "controller rejects the Integration write (405 / 404 No endpoint), so the tool writes "
    "the Classic record the controller UI writes"
)
_V2_UI_READ = (
    _V2 + "; the Integration device-tag list is a separate collection that answers empty "
    "on Network 11.0.81 while the controller has tags, and its ids are not the v2 _id the "
    "device-tag writes take, so the tool reads the v2 list the controller UI reads"
)
_V2_UI_WRITE = (
    _V2 + "; the Integration spec serves device tags GET-only and the live controller "
    "rejects the Integration write (405 / 404 No endpoint), so the tool writes the v2 "
    "device-tags route the controller UI writes"
)

_V2_AND_CLASSIC = (
    _V2 + " and " + _CLASSIC + ": the tool reads or writes both families (neither is specced)"
)

# N08 Layer 3 migration / orchestration detach: the v2 write addresses a network whose
# Classic _id the tool first resolves in the Classic networkconf list (both unspecced).
_V2_CLASSIC_LOOKUP = (
    _V2 + "; the network id is resolved in the Classic networkconf list (no published "
    "spec either) before the v2 write"
)

# Tools whose every request goes to a family without a published spec. Asserted to be
# exactly that set (test_exemptions_are_exactly_the_unspecced_tools).
UNSPECCED_EXEMPT: dict[str, str] = {
    "list_controller_stat_schemas": _V2,  # GET /v2/api/stats/schemas
    "list_speedtest_results": _CLASSIC,  # POST /api/s/{site}/stat/report/archive.speedtest
    "reboot_unifi_os_console": _CLASSIC,  # POST /api/system/reboot
    "get_camera_private": _PROTECT_PRIVATE,
    "update_camera_private": _PROTECT_PRIVATE,
    "list_ptz_presets": _PROTECT_PRIVATE,
    "list_ptz_patrols": _PROTECT_PRIVATE,
    "get_nvr_private": _PROTECT_PRIVATE,
    "update_nvr": _PROTECT_PRIVATE,
    "get_sensor_private": _PROTECT_PRIVATE,
    "update_sensor_private": _PROTECT_PRIVATE,
    "export_camera_video": _PROTECT_PRIVATE,
    "reboot_protect_device": _PROTECT_PRIVATE,
    "create_firewall_rule": _EA_FIREWALL,
    "adopt_protect_device": _PROTECT_PRIVATE,
    "unadopt_protect_device": _PROTECT_PRIVATE,
    "reboot_nvr": _PROTECT_PRIVATE,
    "clear_sensor_tamper": _PROTECT_PRIVATE,
    "clean_innerspace_storage": _INNERSPACE_PRIVATE,
    "create_innerspace_plan": _INNERSPACE_PRIVATE,
    "create_innerspace_support_dump": _INNERSPACE_PRIVATE,
    "export_innerspace_backup": _INNERSPACE_PRIVATE,
    "get_innerspace_health": _INNERSPACE_PRIVATE,
    "get_innerspace_stats": _INNERSPACE_PRIVATE,
    "get_innerspace_ucore_manifest": _INNERSPACE_PRIVATE,
    "get_innerspace_ucore_status": _INNERSPACE_PRIVATE,
    "import_innerspace_backup": _INNERSPACE_PRIVATE,
    "import_innerspace_captures": _INNERSPACE_PRIVATE,
    "import_innerspace_dc_shapes": _INNERSPACE_PRIVATE,
    "import_innerspace_shared_project": _INNERSPACE_PRIVATE,
    "list_innerspace_doors": _INNERSPACE_PRIVATE,
    "reorder_innerspace_plans": _INNERSPACE_PRIVATE,
    "retry_innerspace_plan_maps": _INNERSPACE_PRIVATE,
    "transform_innerspace_shapes": _INNERSPACE_PRIVATE,
    "update_innerspace_attenuation_type": _INNERSPACE_PRIVATE,
    "update_innerspace_project": _INNERSPACE_PRIVATE,
    "update_innerspace_wall_type": _INNERSPACE_PRIVATE,
    "upload_innerspace_plan_asset": _INNERSPACE_PRIVATE,
    # The NET-B (0.7.0) tools here: client records (Classic rest/user, cmd/stamgr,
    # stat/guest, cmd/hotspot), VPN clients (Classic rest/networkconf purpose vpn-client: no
    # Integration resource) and site administration (Classic cmd/sitemgr, self/sites) are
    # Classic REST; the system-log readers are Network v2 system-log read-POSTs. Neither
    # family has a published spec.
    "allow_network_on_port_profile": _CLASSIC,
    "collect_protect_events": _PROTECT_PRIVATE,
    "compare_site_performance": _CLASSIC,
    "create_client_reservation": _CLASSIC,
    "create_device_tag": _V2_UI_WRITE,
    "create_hotspot_operator": _CLASSIC,
    "create_port_forward": _CLASSIC,
    "create_radius_profile": _CLASSIC_UI_WRITE,
    "create_site": _CLASSIC,
    "create_site_to_site_tunnel": _CLASSIC_UI_WRITE,
    "create_traffic_route": _V2,
    "create_traffic_rule": _V2,
    "create_vpn_client": _CLASSIC,
    "create_vpn_server": _CLASSIC_UI_WRITE,
    "delete_device_tag": _V2_UI_WRITE,
    "delete_hotspot_operator": _CLASSIC,
    "delete_port_forward": _CLASSIC,
    "delete_site": _CLASSIC,
    "delete_site_to_site_tunnel": _CLASSIC_UI_WRITE,
    "delete_traffic_route": _V2,
    "delete_traffic_rule": _V2,
    "delete_vpn_client": _CLASSIC,
    "delete_vpn_server": _CLASSIC_UI_WRITE,
    "exclude_network_on_port_profile": _CLASSIC,
    "extend_guest": _CLASSIC,
    "forget_client": _CLASSIC,
    # forget_device: the Classic site manager cmd/sitemgr delete-device by MAC, which is what
    # the controller UI's Forget device sends. No Integration route forgets or rejects a
    # device (the device-action enum is RESTART-only). Live 2026-10-10, Network 11.0.81: an
    # unknown MAC answers HTTP 400 api.err.UnknownDevice.
    "forget_device": _CLASSIC,
    "get_account": _CLASSIC,
    "get_channel_plan": _CLASSIC,
    "get_client_link_diagnostics": _CLASSIC,
    "get_device_port_state": _CLASSIC,
    "get_device_radios": _CLASSIC,
    "get_device_stp_state": _CLASSIC,
    "get_dynamic_dns": _CLASSIC,
    "get_firewall_group": _CLASSIC,
    "get_firewall_rule": _CLASSIC,
    "get_historical_stats": _CLASSIC,
    "get_hotspot_package": _CLASSIC,
    "get_port_profile": _CLASSIC,
    "get_recognition_group_counts": _PROTECT_PRIVATE,
    "get_recognition_group_image": _PROTECT_PRIVATE,
    "get_scheduled_task": _CLASSIC,
    "get_setting": _CLASSIC,
    "get_site_health_summary": _CLASSIC,
    "get_site_statistics": _CLASSIC,
    "get_system_info": _CLASSIC,
    "get_system_log": _V2,
    "get_thumbnail": _PROTECT_PRIVATE,
    "get_traffic_route": _V2,
    "get_user": _CLASSIC,
    "get_wlan_config": _CLASSIC,
    "get_wlan_group": _CLASSIC,
    "list_accounts": _CLASSIC,
    "list_active_clients": _V2,
    "list_active_clients_stats": _CLASSIC,
    "list_client_sessions": _CLASSIC,
    "list_device_stats": _CLASSIC,
    "list_dynamic_dns": _CLASSIC,
    "list_firewall_groups": _CLASSIC,
    "list_firewall_rules": _CLASSIC,
    "list_guests": _CLASSIC,
    "list_hotspot_operators": _CLASSIC,
    "list_hotspot_packages": _CLASSIC,
    "list_ips_events": _V2,
    "list_known_clients": _CLASSIC,
    "list_network_events": _V2,
    "list_port_forwards": _CLASSIC,
    "list_port_profiles": _CLASSIC,
    "list_protect_events": _PROTECT_PRIVATE,
    "list_recognition_detections": _PROTECT_PRIVATE,
    "list_recognition_groups": _PROTECT_PRIVATE,
    "list_rogue_aps": _CLASSIC,
    "list_routing_entries": _CLASSIC,
    "list_scheduled_tasks": _CLASSIC,
    "list_settings": _CLASSIC,
    "list_device_tags": _V2_UI_READ,
    "list_traffic_routes": _V2,
    "list_traffic_rules": _V2,
    "list_users": _CLASSIC,
    "list_vpn_clients": _CLASSIC,
    "list_wlan_configs": _CLASSIC,
    "list_wlan_groups": _CLASSIC,
    "remove_client_fixed_ip": _CLASSIC,
    "rename_site": _CLASSIC,
    "set_client_fixed_ip": _CLASSIC,
    "set_client_name": _CLASSIC,
    "set_client_note": _CLASSIC,
    "update_device_tag": _V2_UI_WRITE,
    "update_device_radio": _CLASSIC,
    "update_dynamic_dns": _CLASSIC,
    "update_hotspot_operator": _CLASSIC,
    "update_port_forward": _CLASSIC,
    "update_port_profile": _CLASSIC,
    "update_setting": _CLASSIC,
    "update_site_to_site_tunnel": _CLASSIC_UI_WRITE,
    "update_traffic_route": _V2,
    "update_traffic_rule": _V2,
    "update_user": _CLASSIC,
    "update_vpn_client": _CLASSIC,
    "update_vpn_server": _CLASSIC_UI_WRITE,
    "update_wan_interface": _CLASSIC_UI_WRITE,
    "update_wlan_config": _CLASSIC,
    # GS3 P03 (protect_camera_recording): the Protect 7.3.74 spec has none of these routes.
    "configure_camera_wifi": _PROTECT_PRIVATE,
    "delete_recordings": _PROTECT_PRIVATE,
    "export_edge_recording": _PROTECT_PRIVATE,
    "get_camera_adoption_qr": _PROTECT_PRIVATE,
    "get_camera_analytics": _PROTECT_PRIVATE,
    "get_camera_lux": _PROTECT_PRIVATE,
    "get_camera_playback_history": _PROTECT_PRIVATE,
    "get_camera_wifi_networks": _PROTECT_PRIVATE,
    "reformat_edge_storage": _PROTECT_PRIVATE,
    "reset_camera_image_settings": _PROTECT_PRIVATE,
    "set_camera_control_enabled": _PROTECT_PRIVATE,
    "set_camera_door_lock": _PROTECT_PRIVATE,
    "set_camera_resolution_scale": _PROTECT_PRIVATE,
    "set_camera_video_codec": _PROTECT_PRIVATE,
    "set_edge_storage_mount_state": _PROTECT_PRIVATE,
    "transfer_camera_management": _PROTECT_PRIVATE,
    "turn_on_camera_flashlight": _PROTECT_PRIVATE,
    "update_edge_recording_settings": _PROTECT_PRIVATE,
    # GS3 P02 (protect_ptz_doorbell): Protect UI 5.3.18 private routes; ptz_home is specced.
    "move_ptz_camera": _PROTECT_PRIVATE,
    "set_ptz_event_control_window": _PROTECT_PRIVATE,
    "create_ptz_patrol": _PROTECT_PRIVATE,
    "update_ptz_patrol": _PROTECT_PRIVATE,
    "delete_ptz_patrol": _PROTECT_PRIVATE,
    "create_ptz_preset": _PROTECT_PRIVATE,
    "update_ptz_preset": _PROTECT_PRIVATE,
    "delete_ptz_preset": _PROTECT_PRIVATE,
    "create_camera_shortcut": _PROTECT_PRIVATE,
    "update_camera_shortcut": _PROTECT_PRIVATE,
    "delete_camera_shortcut": _PROTECT_PRIVATE,
    "trigger_camera_shortcut": _PROTECT_PRIVATE,
    "calibrate_camera": _PROTECT_PRIVATE,
    "test_doorbell_ringtone": _PROTECT_PRIVATE,
    "enroll_doorbell_credential": _PROTECT_PRIVATE,
    "delete_doorbell_credential": _PROTECT_PRIVATE,
    # N08 routing / topology: Network v2 web-UI routes (inventory_network_11.0.81)
    "create_bgp_config": _V2,
    "create_ospf_router": _V2,
    "delete_bgp_config": _V2,
    "delete_ospf_router": _V2,
    "detach_from_orchestration": _V2_CLASSIC_LOOKUP,
    "generate_vlan_plan": _V2,
    "get_bgp_status": _V2,
    "get_global_network_config": _V2,
    "get_loop_detection_status": _V2,
    "get_mdns_settings": _V2,
    "get_ospf_status": _V2,
    "import_dhcp_reservations": _V2,
    "manage_mclag_group": _V2,
    "manage_virtual_network": _V2,
    "migrate_network_to_layer3": _V2_CLASSIC_LOOKUP,
    "recover_loop_blocked_ports": _V2,
    "suggest_network_settings": _V2,
    "update_bgp_config": _V2,
    "update_global_network_config": _V2,
    "update_ospf_router": _V2,
    "update_switch_stack": _V2,
    # Classic cmd / rest routes of the device-command and scheduled-task tools.
    "advanced_adopt_device": _CLASSIC,
    "cancel_rolling_upgrade": _CLASSIC,
    "create_backup": _CLASSIC,
    "create_scheduled_task": _CLASSIC,
    "delete_scheduled_task": _CLASSIC,
    "export_site": _CLASSIC,
    "get_speedtest_status": _CLASSIC,
    "list_backups": _CLASSIC,
    "list_device_firmware": _CLASSIC,
    "run_speedtest": _CLASSIC,
    "start_rolling_upgrade": _CLASSIC,
    "update_scheduled_task": _CLASSIC,
    "upgrade_all_devices": _CLASSIC,
    # site configuration CRUD on the routes the controller UI uses (site_config.py,
    # radius_profiles.py; live-probed on Network 11.0.81, L16-NET-A)
    "list_user_groups": _CLASSIC,
    "get_user_group": _CLASSIC,
    "create_user_group": _CLASSIC,
    "update_user_group": _CLASSIC,
    "delete_user_group": _CLASSIC,
    "set_client_user_group": _CLASSIC,
    "get_static_route": _CLASSIC,
    "create_static_route": _CLASSIC,
    "update_static_route": _CLASSIC,
    "delete_static_route": _CLASSIC,
    "create_radius_account": _V2,
    "update_radius_account": _V2,
    "delete_radius_account": _V2,
    "create_port_profile": _CLASSIC,
    "delete_port_profile": _CLASSIC,
    "create_dynamic_dns": _CLASSIC,
    "delete_dynamic_dns": _CLASSIC,
    "update_radius_profile": _CLASSIC_UI_WRITE,
    "delete_radius_profile": _CLASSIC_UI_WRITE,
    "list_ap_groups": _V2,
    "get_ap_group": _V2,
    "create_ap_group": _V2,
    "update_ap_group": _V2,
    "delete_ap_group": _V2,
    # Tools added by the 0.7.0 lanes whose every request reaches a family without a published
    # spec. Registered from the harness classification (the route family each tool's recorded
    # requests reach); a tool that later reaches a specced route fails the exact-set test.
    "accept_ironclad_terms": _PROTECT_PRIVATE,
    "activate_lte_trial": _CLASSIC,
    "activate_ssl_inspection_certificate": _V2,
    "add_protect_case_asset": _PROTECT_PRIVATE,
    "adopt_third_party_camera": _PROTECT_PRIVATE,
    "analyze_footage_with_ai": _PROTECT_PRIVATE,
    "apply_radio_ai_optimization": _V2,
    "apply_recognized_image": _PROTECT_PRIVATE,
    "apply_test_config": _V2,
    "assign_detections_to_recognition_group": _PROTECT_PRIVATE,
    "assign_sensor_to_bridge": _PROTECT_PRIVATE,
    "authorize_lte_device": _CLASSIC,
    "batch_delete_acl_rules": _V2,
    "batch_delete_firewall_zones": _V2,
    "bulk_update_objects": _CLASSIC,
    "bulk_upload_vehicle_groups": _PROTECT_PRIVATE,
    "calibrate_door_lock": _PROTECT_PRIVATE,
    "cancel_cloud_archive_task": _PROTECT_PRIVATE,
    "cancel_controller_backup": _CLASSIC,
    "check_controller_firmware_update": _CLASSIC,
    "check_protect_firmware_updates": _PROTECT_PRIVATE,
    "clear_switch_counters": _CLASSIC,
    "clone_device_config": _CLASSIC,
    "commission_matter_node": _V2,
    "configure_wifi_wan": _CLASSIC,
    "connect_cloud_archive_provider": _PROTECT_PRIVATE,
    "connect_unifi_video_server": _PROTECT_PRIVATE,
    "control_device_battery": _V2_AND_CLASSIC,
    "control_packet_capture": _V2,
    "control_ping_test": _V2,
    "control_retroactive_ai_processing": _PROTECT_PRIVATE,
    "control_shadow_mode_adoption": _V2,
    "control_site_vpn": _CLASSIC,
    "control_wifi_doctor_optimization": _V2,
    "create_content_filter": _V2,
    "create_dhcp_option": _CLASSIC,
    "create_energy_saving_policy": _V2,
    "create_hotspot_package": _CLASSIC,
    "create_nat_rule": _V2,
    "create_network_members_group": _V2,
    "create_policy_engine_rule": _V2,
    "create_power_supervisor": _V2,
    "create_power_supervisor_link": _V2,
    "create_proav_group": _V2,
    "create_protect_automation": _PROTECT_PRIVATE,
    "create_protect_backup": _PROTECT_PRIVATE,
    "create_protect_case": _PROTECT_PRIVATE,
    "create_protect_device_tag": _PROTECT_PRIVATE,
    "create_protect_user_group": _PROTECT_PRIVATE,
    "create_qos_rule": _V2,
    "create_recognition_group": _PROTECT_PRIVATE,
    "create_recognition_object_group": _PROTECT_PRIVATE,
    "create_site_vpn": _CLASSIC,
    "create_ssl_inspection_certificate": _V2,
    "create_ssl_inspection_profile": _V2,
    "create_static_dns_record": _V2,
    "create_teleport_invitation": _V2,
    "create_test_config": _V2,
    "create_wan_sla": _V2,
    "create_wireguard_users": _V2_AND_CLASSIC,
    "delete_content_filter": _V2,
    "delete_controller_backup": _CLASSIC,
    "delete_dhcp_option": _CLASSIC,
    "delete_digital_twin_layout": _V2,
    "delete_energy_saving_policy": _V2,
    "delete_guest_portal_file": _CLASSIC,
    "delete_hotspot_package": _CLASSIC,
    "delete_liveview": _PROTECT_PRIVATE,
    "delete_nat_rule": _V2,
    "delete_network_members_group": _V2,
    "delete_policy_engine_rule": _V2,
    "delete_power_supervisor": _V2,
    "delete_power_supervisor_link": _V2,
    "delete_proav_group": _V2,
    "delete_protect_automation": _PROTECT_PRIVATE,
    "delete_protect_backup": _PROTECT_PRIVATE,
    "delete_protect_case": _PROTECT_PRIVATE,
    "delete_protect_device_tag": _PROTECT_PRIVATE,
    "delete_protect_file": _PROTECT_PRIVATE,
    "delete_protect_user_group": _PROTECT_PRIVATE,
    "delete_qos_rule": _V2,
    "delete_recognition_group": _PROTECT_PRIVATE,
    "delete_ringtone": _PROTECT_PRIVATE,
    "delete_site_vpn": _CLASSIC,
    "delete_ssl_inspection_certificate": _V2,
    "delete_ssl_inspection_profile": _V2,
    "delete_static_dns_record": _V2,
    "delete_test_config": _V2,
    "delete_wan_sla": _V2,
    "delete_wireguard_users": _V2_AND_CLASSIC,
    "disable_camera_share_link": _PROTECT_PRIVATE,
    "disconnect_cloud_archive_provider": _PROTECT_PRIVATE,
    "disconnect_remote_vpn_user": _CLASSIC,
    "enable_camera_share_link": _PROTECT_PRIVATE,
    "enhance_face_detection_image": _PROTECT_PRIVATE,
    "export_protect_case": _PROTECT_PRIVATE,
    "export_traffic_flows": _V2,
    "generate_support_file": _V2_AND_CLASSIC,
    "get_5g_topology": _V2,
    "get_access_point_neighbors": _V2,
    "get_camera_share_link": _PROTECT_PRIVATE,
    "get_client_insights": _V2,
    "get_client_observability": _V2,
    "get_cloud_archive_status": _PROTECT_PRIVATE,
    "get_console_general_info": _V2,
    "get_controller_stats": _V2,
    "get_cybersecure_summary": _V2,
    "get_detection_search_metadata": _PROTECT_PRIVATE,
    "get_detection_statistics": _PROTECT_PRIVATE,
    "get_device_adoption_info": _V2,
    "get_device_fingerprint": _V2,
    "get_device_replacement_options": _V2_AND_CLASSIC,
    "get_device_tx_retries": _V2,
    "get_digital_twin_layout": _V2,
    "get_enriched_configuration": _V2,
    "get_firewall_zone_matrix": _V2,
    "get_first_system_event": _V2,
    "get_hotspot_settings": _CLASSIC,
    "get_inactive_sim_slot": _CLASSIC,
    "get_infrastructure_history": _V2,
    "get_ips_signature_status": _V2,
    "get_ipsec_settings": _V2,
    "get_latest_traffic_flow_stats": _V2,
    "get_local_client": _V2,
    "get_lte_subscription_status": _CLASSIC,
    "get_multicast_insights": _V2,
    "get_network_config_defaults": _V2,
    "get_network_ui_data": _CLASSIC,
    "get_observability_people": _V2,
    "get_observability_site_health": _V2,
    "get_openvpn_client_config": _V2_AND_CLASSIC,
    "get_packet_capture_status": _V2,
    "get_ping_test_results": _V2,
    "get_poe_info": _V2,
    "get_port_forward_statistics": _CLASSIC,
    "get_port_history": _V2,
    "get_proav_matrix": _V2,
    "get_proav_snapshot": _V2,
    "get_protect_automation_history": _PROTECT_PRIVATE,
    "get_protect_bootstrap": _PROTECT_PRIVATE,
    "get_protect_case_activity": _PROTECT_PRIVATE,
    "get_protect_case_asset_snapshot": _PROTECT_PRIVATE,
    "get_protect_device_metrics": _PROTECT_PRIVATE,
    "get_protect_device_password": _PROTECT_PRIVATE,
    "get_protect_event": _PROTECT_PRIVATE,
    "get_protect_event_media": _PROTECT_PRIVATE,
    "get_protect_file": _PROTECT_PRIVATE,
    "get_protect_stream_url": _PROTECT_PRIVATE,
    "get_radio_ai_isolation_matrix": _V2,
    "get_radio_history": _V2,
    "get_remote_access_turn_credentials": _CLASSIC,
    "get_ringtone": _PROTECT_PRIVATE,
    "get_rolling_upgrade_plan": _V2,
    "get_scoped_system_log": _V2,
    "get_sdn_status": _CLASSIC,
    "get_sensor_readings": _PROTECT_PRIVATE,
    "get_shadow_mode_status": _V2,
    "get_site_dashboard": _V2,
    "get_site_degradation_status": _V2,
    "get_sites_overview": _V2,
    "get_spectrum_scan_results": _CLASSIC,
    "get_ssl_inspection_settings": _V2,
    "get_support_file": _V2,
    "get_system_log_settings": _V2,
    "get_topology_snapshot": _V2,
    "get_traffic_stats": _V2,
    "get_unified_ip_thread_topology": _V2,
    "get_vehicle_group_upload_template": _PROTECT_PRIVATE,
    "get_wan_insights": _V2,
    "get_wan_load_balancing": _V2,
    "get_wifi_connectivity": _V2,
    "get_wifi_quick_scan_status": _V2,
    "get_wifi_stats": _V2,
    "get_wifi_tethering_scan": _V2,
    "get_wifi_uplink_scan_status": _V2,
    "get_wifiman_settings": _V2,
    "get_wlan_capabilities": _V2,
    "hide_face_detection_enhanced_image": _PROTECT_PRIVATE,
    "import_protect_backup": _PROTECT_PRIVATE,
    "import_site_configuration": _CLASSIC,
    "import_unifi_video_cameras": _PROTECT_PRIVATE,
    "link_ubiquiti_sso_account": _CLASSIC,
    "list_available_wifi_channels": _CLASSIC,
    "list_client_traffic_controls": _V2,
    "list_content_filter_categories": _V2,
    "list_content_filters": _V2,
    "list_device_models": _V2,
    "list_dhcp_excluded_ips": _V2,
    "list_dhcp_leases": _V2,
    "list_dhcp_options": _CLASSIC,
    "list_doh_servers": _V2,
    "list_door_locks": _PROTECT_PRIVATE,
    "list_energy_saving_policies": _V2,
    "list_firewall_app_blocks": _V2,
    "list_gateway_routes": _V2,
    "list_hotspot_authorizations": _CLASSIC,
    "list_hotspot_payments": _CLASSIC,
    "list_installed_applications": _V2,
    "list_ips_categories": _V2,
    "list_magic_site_vpn": _V2,
    "list_matter_nodes": _V2,
    "list_nat_rules": _V2,
    "list_network_anomalies": _CLASSIC,
    "list_network_members_groups": _V2,
    "list_policy_engine_rules": _V2,
    "list_port_anomalies": _V2,
    "list_power_supervisors": _V2,
    "list_protect_automations": _PROTECT_PRIVATE,
    "list_protect_backups": _PROTECT_PRIVATE,
    "list_protect_case_assets": _PROTECT_PRIVATE,
    "list_protect_cases": _PROTECT_PRIVATE,
    "list_protect_device_tags": _PROTECT_PRIVATE,
    "list_protect_keyrings": _PROTECT_PRIVATE,
    "list_qos_rules": _V2,
    "list_site_features": _V2,
    "list_site_warnings": _V2_AND_CLASSIC,
    "list_ssl_inspection_catalog": _V2,
    "list_ssl_inspection_certificates": _V2,
    "list_ssl_inspection_profiles": _V2,
    "list_static_dns_records": _V2,
    "list_test_configs": _V2,
    "list_thread_networks": _V2,
    "list_timezones": _V2,
    "list_ulp_user_groups": _V2,
    "list_ups_devices": _V2,
    "list_vendor_ids": _V2,
    "list_vpn_connections": _V2,
    "list_vpn_users": _V2,
    "list_wan_network_groups": _V2,
    "list_wan_slas": _V2,
    "list_wireguard_used_subnets": _V2,
    "list_wireguard_users": _V2_AND_CLASSIC,
    "list_wireless_links": _V2,
    "locate_protect_device": _PROTECT_PRIVATE,
    "locate_switch_port": _CLASSIC,
    "manage_device_ssh_session": _CLASSIC,
    "manage_esim_profile": _CLASSIC,
    "manage_firmware_cache": _CLASSIC,
    "mark_critical_logs_read": _V2,
    "merge_recognition_groups": _PROTECT_PRIVATE,
    "play_chime_sound": _PROTECT_PRIVATE,
    "preview_firewall_group": _V2,
    "preview_policy_engine_rule": _V2,
    "preview_radio_ai_optimization": _V2,
    "query_app_traffic_rates": _V2,
    "query_port_system_logs": _V2,
    "query_power_supervisor_logs": _V2,
    "query_switch_mac_tables": _V2,
    "query_teleport_invitations": _V2,
    "query_traffic_flows": _V2,
    "readopt_protect_device": _PROTECT_PRIVATE,
    "recognize_image": _PROTECT_PRIVATE,
    "recover_switch_port": _CLASSIC,
    "refresh_sso_session": _CLASSIC,
    "remove_matter_node": _V2,
    "remove_protect_case_asset": _PROTECT_PRIVATE,
    "remove_teleport_client": _V2,
    "rename_matter_node": _V2,
    "reorder_qos_rules": _V2,
    "replace_device": _V2_AND_CLASSIC,
    "report_ai_false_positive": _PROTECT_PRIVATE,
    "resend_mfa_code": _V2,
    "reset_dpi_counters": _V2,
    "reset_guest_access_settings": _V2,
    "reset_mobile_data_usage": _CLASSIC,
    "reset_protect_automations": _PROTECT_PRIVATE,
    "reset_switch_port": _V2,
    "restart_vpn_server": _V2_AND_CLASSIC,
    "restore_controller_backup": _CLASSIC,
    "restore_protect_backup": _PROTECT_PRIVATE,
    "restore_protect_database": _PROTECT_PRIVATE,
    "revoke_teleport_invitation": _V2,
    "run_device_self_test": _CLASSIC,
    "search_detections": _PROTECT_PRIVATE,
    "search_recognition_group_candidates": _PROTECT_PRIVATE,
    "send_test_email": _CLASSIC,
    "set_ai_port_pairing": _PROTECT_PRIVATE,
    "set_cloud_access_registration": _CLASSIC,
    "set_controller_system_parameter": _CLASSIC,
    "set_device_alignment_mode": _CLASSIC,
    "set_device_rearrange_mode": _CLASSIC,
    "set_device_tag_assignments": _V2,
    "set_door_lock_auto_close": _PROTECT_PRIVATE,
    "set_door_lock_state": _PROTECT_PRIVATE,
    "set_firewall_app_blocks": _V2,
    "set_lte_apn_profile": _CLASSIC,
    "set_lte_failover": _V2,
    "set_nvr_stack_membership": _PROTECT_PRIVATE,
    "set_outlet_power": _CLASSIC,
    "set_priority_uplink": _CLASSIC,
    "set_protect_event_favorite": _PROTECT_PRIVATE,
    "set_protect_notification_receivers": _PROTECT_PRIVATE,
    "set_protect_notifications_muted": _PROTECT_PRIVATE,
    "set_recognition_group_image": _PROTECT_PRIVATE,
    "set_tv_wall_calibration": _V2,
    "set_ups_pairing": _V2,
    "start_cloud_video_archive": _PROTECT_PRIVATE,
    "start_spectrum_scan": _CLASSIC,
    "start_wifi_quick_scan": _V2,
    "stop_speaker_stream": _PROTECT_PRIVATE,
    "unpair_building_bridge": _CLASSIC,
    "update_content_filter": _V2,
    "update_device_battery_settings": _V2_AND_CLASSIC,
    "update_dhcp_option": _CLASSIC,
    "update_digital_twin_layout": _V2,
    "update_energy_saving_policy": _V2,
    "update_hotspot_package": _CLASSIC,
    "update_ips_signatures": _V2,
    "update_ipsec_settings": _V2,
    "update_lte_device": _CLASSIC,
    "update_my_admin_profile": _CLASSIC,
    "update_nat_rule": _V2,
    "update_network_members_group": _V2,
    "update_policy_engine_rule": _V2,
    "update_power_supervisor": _V2,
    "update_power_supervisor_link": _V2,
    "update_proav_group": _V2,
    "update_protect_automation": _PROTECT_PRIVATE,
    "update_protect_case": _PROTECT_PRIVATE,
    "update_protect_case_asset": _PROTECT_PRIVATE,
    "update_protect_device_password": _PROTECT_PRIVATE,
    "update_protect_device_settings": _PROTECT_PRIVATE,
    "update_protect_device_tag": _PROTECT_PRIVATE,
    "update_protect_user": _PROTECT_PRIVATE,
    "update_protect_user_group": _PROTECT_PRIVATE,
    "update_protect_user_notifications": _PROTECT_PRIVATE,
    "update_qos_rule": _V2,
    "update_recognition_group": _PROTECT_PRIVATE,
    "update_ssl_inspection_profile": _V2,
    "update_ssl_inspection_settings": _V2,
    "update_static_dns_record": _V2,
    "update_system_log_settings": _V2,
    "update_wan_load_balancing": _V2,
    "update_wan_sla": _V2,
    "update_wireguard_users": _V2_AND_CLASSIC,
    "upgrade_all_protect_devices": _PROTECT_PRIVATE,
    "upgrade_protect_device_firmware": _PROTECT_PRIVATE,
    "upload_ringtone": _PROTECT_PRIVATE,
    "verify_sim_pin": _CLASSIC,
}

# Tools that send no upstream request at all.
NO_REQUEST: dict[str, str] = {
    "list_configured_api_keys": "reports the server's own key configuration",
}

# Per-tool waivers for violations that are spec defects: {tool: {substring: evidence}}.
WAIVERS: dict[str, dict[str, str]] = {}

# Tools whose request targets an operation the published spec does not define AND the
# live controller does not serve either: spec and controller agree, so these are not spec
# defects, and the tools cannot succeed. Each entry is checked like a waiver (it must still
# match a violation). Empty: every such tool was either removed (reject_pending_device,
# 2026-10-10; forget_device replaces it) or moved onto the route the controller's own UI
# uses (the device-tag, VPN-server, site-to-site-tunnel, RADIUS-profile-create and
# WAN-update writes, now exempt above as unspecced Classic / v2 tools).
UNSERVED_PENDING_DECISION: dict[str, dict[str, str]] = {}

# Arguments that make a tool send a spec-valid request where the shared recipes in
# tests/tool_args.py pick a value that is valid for the tool but not for the API (the
# generic connector relays forward a caller-chosen path and body verbatim).
_RELAY_ID = uh.ARG_ID
CONFORMANCE_ARGS: dict[str, dict[str, Any]] = {
    # The documented body names its native network by an id the harness networkconf list
    # does not hold (an unknown network id fails before the POST); this body names the
    # harness network by its Integration id, which the tool converts to the Classic _id.
    "create_port_profile": {
        "profile": {
            "name": "Cameras",
            "forward": "native",
            "tagged_vlan_mgmt": "block_all",
            "native_networkconf_id": tool_args.ARG_ID,
            "poe_mode": "auto",
        }
    },
    # Output channel ids are integers 0 or 1 in the spec (the tools take them as strings
    # and document that); the shared recipe passes a UUID for every *_id argument.
    "alarm_hub_trigger_output": {"output_id": "0"},
    "relay_activate_output": {"output_id": "0"},
    "fabric_connector_post": {
        "path": "network/integration/v1/sites/{site_id}/clients/" + _RELAY_ID + "/actions",
        "body": {"action": "AUTHORIZE_GUEST_ACCESS"},
    },
    "fabric_connector_put": {
        "path": "network/integration/v1/sites/{site_id}/acl-rules/ordering",
        "body": {"orderedAclRuleIds": [_RELAY_ID]},
    },
    "fabric_connector_patch": {
        "path": "network/integration/v1/sites/{site_id}/firewall/policies/" + _RELAY_ID,
        "body": {"loggingEnabled": True},
    },
    "fabric_connector_delete": {
        "path": "network/integration/v1/sites/{site_id}/networks/" + _RELAY_ID,
    },
}


# --------------------------------------------------------------------------- specs
def _nullable_to_jsonschema(node: Any) -> Any:
    """OpenAPI 3.0 ``nullable: true`` -> JSON Schema null admission (3.1 docs pass through)."""
    if isinstance(node, list):
        return [_nullable_to_jsonschema(v) for v in node]
    if not isinstance(node, dict):
        return node
    out = {k: _nullable_to_jsonschema(v) for k, v in node.items()}
    if out.pop("nullable", False) is True:
        if "type" in out:
            types = out["type"] if isinstance(out["type"], list) else [out["type"]]
            out["type"] = [*types, "null"]
            if "enum" in out:
                out["enum"] = [*out["enum"], None]
        else:
            out = {"anyOf": [out, {"type": "null"}]}
    return out


def _closed_allof_to_unevaluated(node: Any) -> Any:
    """``{"allOf": [...], "additionalProperties": false}`` with no own ``properties``
    means "only the properties the allOf branches declare" (Protect liveview bodies).
    Under JSON Schema 2020-12 ``additionalProperties`` cannot see properties declared in
    ``allOf`` branches, so read literally it rejects every key and no body could ever
    conform. ``unevaluatedProperties: false`` is the 2020-12 keyword for the intent and
    still rejects a key no branch declares."""
    if isinstance(node, list):
        return [_closed_allof_to_unevaluated(v) for v in node]
    if not isinstance(node, dict):
        return node
    out = {k: _closed_allof_to_unevaluated(v) for k, v in node.items()}
    if out.get("additionalProperties") is False and "allOf" in out and "properties" not in out:
        del out["additionalProperties"]
        out["unevaluatedProperties"] = False
    return out


@dataclass
class Spec:
    service: str
    doc: dict[str, Any]
    uri: str
    templates: list[tuple[re.Pattern[str], str, int]] = field(default_factory=list)


@cache
def specs() -> dict[str, Spec]:
    manifest = json.loads((OPENAPI_DIR / "manifest.json").read_text())
    out: dict[str, Spec] = {}
    for service, entry in manifest.items():
        doc = json.loads((OPENAPI_DIR / entry["file"]).read_text())
        if str(doc.get("openapi", "")).startswith("3.0"):
            doc = _nullable_to_jsonschema(doc)
        doc = _closed_allof_to_unevaluated(doc)
        spec = Spec(service, doc, f"urn:unifi-openapi:{service}")
        for template in doc["paths"]:
            if "*" in template:
                continue  # Site Manager's connector wildcard: routed to the inner spec
            regex = "^" + re.sub(r"\\\{([^}]+)\\\}", r"(?P<\1>[^/]+)", re.escape(template)) + r"\Z"
            literal = sum(1 for seg in template.split("/") if seg and not seg.startswith("{"))
            spec.templates.append((re.compile(regex), template, literal))
        out[service] = spec
    return out


@cache
def _registry() -> Registry:
    return Registry().with_resources(
        (s.uri, Resource.from_contents(s.doc, default_specification=DRAFT202012))
        for s in specs().values()
    )


def _pointer(*parts: str) -> str:
    return "#/" + "/".join(p.replace("~", "~0").replace("/", "~1") for p in parts)


def _resolve(spec: Spec, node: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Follow a local ``$ref`` (components/parameters, requestBodies); return the target
    and its JSON pointer (None when ``node`` was inline)."""
    ref = node.get("$ref")
    if not ref:
        return node, None
    target: Any = spec.doc
    for part in ref.lstrip("#/").split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    return target, ref


_ACTIVE_DISCRIMINATIONS: set[tuple[int, str]] = set()


def _discriminator(validator: Any, disc: Any, instance: Any, schema: dict[str, Any]) -> Any:
    """OpenAPI ``discriminator``: the property value must be a ``mapping`` key, and the
    instance must also satisfy the mapped subtype. The specs express many closed value
    sets this way only (Network: device ``action`` is ``RESTART`` via the mapping of
    ``Device action request``), so ignoring the keyword would accept any value.

    Subtypes ``allOf`` their base, which carries the same discriminator again; the guard
    stops that re-entry for the same instance."""
    if not isinstance(instance, dict) or not isinstance(disc, dict):
        return
    prop, mapping = disc.get("propertyName"), disc.get("mapping") or {}
    if not mapping or prop not in instance:
        return
    value = instance[prop]
    if value not in mapping:
        yield jsonschema.ValidationError(
            f"{value!r} is not one of {sorted(mapping)} (discriminator {prop!r})",
            path=[prop],
        )
        return
    guard = (id(instance), mapping[value])
    if guard in _ACTIVE_DISCRIMINATIONS:
        return
    _ACTIVE_DISCRIMINATIONS.add(guard)
    try:
        yield from validator.descend(instance, {"$ref": mapping[value]})
    finally:
        _ACTIVE_DISCRIMINATIONS.discard(guard)


_OpenAPIValidator = jsonschema.validators.extend(
    jsonschema.Draft202012Validator, {"discriminator": _discriminator}
)


def _schema_errors(spec: Spec, pointer: str, instance: Any) -> list[str]:
    validator = _OpenAPIValidator(
        {"$ref": spec.uri + pointer},
        registry=_registry(),
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
    )
    errs = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message[:200]}" for e in errs]


def _coerce(value: str, schema: dict[str, Any]) -> Any:
    """A query/path string as the JSON value its parameter schema describes."""
    types = schema.get("type")
    types = set(types) if isinstance(types, list) else {types}
    if "integer" in types and re.fullmatch(r"-?\d+", value):
        return int(value)
    if "number" in types:
        try:
            return float(value)
        except ValueError:
            return value
    if "boolean" in types and value in ("true", "false"):
        return value == "true"
    return value


def _param_schema(spec: Spec, param: dict[str, Any], ptr: str) -> tuple[dict[str, Any], str]:
    schema = param.get("schema") or {}
    sub, ref = _resolve(spec, schema)
    return sub, (ref or ptr + "/schema")


# --------------------------------------------------------------------------- matching
@dataclass
class Request:
    method: str
    path: str
    query: str
    content: bytes
    content_type: str
    resolution: bool


def route(path: str) -> tuple[str, str]:
    """(service-or-family, path within that API). Family names for unspecced APIs are
    prefixed ``unspecced:``; an unrecognised proxied family is ``unknown``."""
    if re.fullmatch(r"/ea/sites/[^/]+/rest/firewallrule", path):
        return "unspecced:ea-firewall", path
    m = _CONNECTOR.match(path)
    if m:
        rest = m.group("rest")
        for prefix, service in PROXIED_SPECS.items():
            if rest.startswith(prefix + "/"):
                return service, rest[len(prefix) :]
        for prefix, fam in UNSPECCED_PREFIXES.items():
            if rest.startswith(prefix):
                return f"unspecced:{fam}", rest
        return "unknown", rest
    return "direct", path


def _match(spec: Spec, path: str) -> tuple[str, dict[str, str]] | None:
    best: tuple[int, str, dict[str, str]] | None = None
    for regex, template, literal in spec.templates:
        m = regex.match(path)
        if m and (best is None or literal > best[0]):
            best = (literal, template, m.groupdict())
    return None if best is None else (best[1], best[2])


def violations(req: Request) -> tuple[str, list[str]]:
    """(family, problems) for one outgoing request."""
    fam, inner = route(req.path)
    if fam == "unspecced:ea-firewall" and req.method != "POST":
        return fam, [
            f"{req.method} {req.path}: private EA firewall route is classified for POST only"
        ]
    if fam.startswith("unspecced:"):
        return fam, []
    if fam == "unknown":
        return fam, [f"{req.method} {req.path}: proxied API family with no routing rule"]
    if fam == "direct":
        candidates = [specs()[s] for s in DIRECT_SPECS]
    else:
        candidates = [specs()[fam]]
    for spec in candidates:
        hit = _match(spec, inner)
        if hit:
            return spec.service, _operation_problems(spec, hit[0], hit[1], req)
    return fam, [f"{req.method} {req.path}: no path template in {[s.service for s in candidates]}"]


def _operation_problems(
    spec: Spec, template: str, path_values: dict[str, str], req: Request
) -> list[str]:
    where = f"{req.method} {template} [{spec.service}]"
    item = spec.doc["paths"][template]
    method = req.method.lower()
    if method not in item:
        allowed = sorted(m.upper() for m in item if m in {"get", "put", "post", "patch", "delete"})
        return [f"{where}: method not allowed (spec allows {allowed})"]
    op = item[method]
    op_ptr = _pointer("paths", template, method)
    params: dict[tuple[str, str], tuple[dict[str, Any], str]] = {}
    for base_ptr, plist in (
        (_pointer("paths", template), item.get("parameters", [])),
        (op_ptr, op.get("parameters", [])),
    ):
        for i, raw in enumerate(plist):
            p, ref = _resolve(spec, raw)
            params[(p["name"], p["in"])] = (p, ref or f"{base_ptr}/parameters/{i}")
    problems: list[str] = []

    # path parameters
    for (name, loc), (p, ptr) in params.items():
        if loc != "path":
            continue
        if name not in path_values:
            problems.append(f"{where}: path parameter {name} missing")
            continue
        schema, sptr = _param_schema(spec, p, ptr)
        for err in _schema_errors(spec, sptr, _coerce(path_values[name], schema)):
            problems.append(f"{where}: path parameter {name}={path_values[name]!r}: {err}")

    # query parameters
    sent: dict[str, list[str]] = {}
    for k, v in parse_qsl(req.query, keep_blank_values=True):
        sent.setdefault(k, []).append(v)
    defined = {name: pp for (name, loc), pp in params.items() if loc == "query"}
    for name in sorted(set(sent) - set(defined)):
        problems.append(
            f"{where}: unknown query parameter {name!r} (spec defines {sorted(defined)})"
        )
    for name, (p, ptr) in sorted(defined.items()):
        if name not in sent:
            if p.get("required"):
                problems.append(f"{where}: required query parameter {name!r} missing")
            continue
        schema, sptr = _param_schema(spec, p, ptr)
        if schema.get("type") == "array":
            items = schema.get("items") or {}
            value: Any = [_coerce(v, _resolve(spec, items)[0]) for v in sent[name]]
        else:
            if len(sent[name]) > 1:
                problems.append(f"{where}: query parameter {name!r} repeated but not an array")
            value = _coerce(sent[name][0], schema)
        for err in _schema_errors(spec, sptr, value):
            problems.append(f"{where}: query parameter {name}={sent[name]!r}: {err}")

    # body
    body_spec = op.get("requestBody")
    if body_spec is None:
        if req.content:
            problems.append(f"{where}: request body sent but the operation defines none")
        return problems
    body_spec, rb_ref = _resolve(spec, body_spec)
    rb_ptr = rb_ref or f"{op_ptr}/requestBody"
    if not req.content:
        if body_spec.get("required"):
            problems.append(f"{where}: required request body missing")
        return problems
    content = body_spec.get("content", {})
    sent_type = req.content_type.split(";", 1)[0].strip()
    if sent_type not in content:
        problems.append(
            f"{where}: body sent as {sent_type!r}; spec content types {sorted(content)}"
        )
        return problems
    if sent_type == "multipart/form-data":
        if b'Content-Disposition: form-data; name="file"' not in req.content:
            problems.append(f"{where}: multipart body carries no file part")
        return problems
    if sent_type != "application/json":
        return problems
    try:
        body = json.loads(req.content)
    except ValueError:
        return [*problems, f"{where}: body is not valid JSON"]
    schema_ptr = f"{rb_ptr}/content/{_pointer('application/json')[2:]}/schema"
    for err in _schema_errors(spec, schema_ptr, body):
        problems.append(f"{where}: body {err}")
    return problems


# --------------------------------------------------------------------------- capture
class CapturingUpstream(uh.FakeUpstream):
    """The shared fake upstream, also keeping each request's raw body and Content-Type."""

    def __init__(self) -> None:
        super().__init__()
        self.requests: list[Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(
            Request(
                req.method,
                req.url.path,
                req.url.query.decode(),
                req.content,
                req.headers.get("content-type", ""),
                uh.is_resolution(req.url.path) and req.method == "GET",
            )
        )
        return super().__call__(req)


def _tool_names() -> list[str]:
    res = server.mcp.list_tools()
    if asyncio.iscoroutine(res):
        res = asyncio.run(res)
    return sorted(t.name for t in res)


@functools.cache
def _lz_TOOL_NAMES():
    return _tool_names()


@cache
def _tools() -> dict[str, Any]:
    # The shared once-per-process catalog (safe inside a running event loop: built at
    # collection by the lazy parametrization, or here on first use outside a loop).
    from tests import _tool_catalog

    return _tool_catalog.tools_by_name()


_EXAMPLE_CALL = re.compile(r"Example call \((?P<name>\w+)\):\s*\n\s*(?=\{)")


def usage_section(name: str) -> str:
    """The tool's ``## <name>`` section of docs/TOOL-USAGE.md ("" when it has none)."""
    text = (Path(__file__).resolve().parents[1] / "docs/TOOL-USAGE.md").read_text()
    marker = f"\n## {name}\n"
    return text.split(marker, 1)[1].split("\n## ", 1)[0] if marker in text else ""


def documented_example(tool: Any) -> dict[str, Any] | None:
    """The JSON arguments of the tool's ``Example call (<name>):`` block, if it has one.

    A description shortened for client limits points at its docs/TOOL-USAGE.md section,
    where the example moved; that example is the documented one and is checked too.
    """
    text = tool.description or ""
    if f"docs/TOOL-USAGE.md#{tool.name}" in text:
        text += "\n" + usage_section(tool.name)
    m = _EXAMPLE_CALL.search(text)
    if m is None or m.group("name") != tool.name:
        return None
    value, _ = json.JSONDecoder().raw_decode(text[m.end() :])
    return value if isinstance(value, dict) else None


def _is_object_param(schema: dict[str, Any]) -> bool:
    branches = [schema, *schema.get("anyOf", [])]
    return any(b.get("type") == "object" for b in branches)


def conformance_args(name: str) -> dict[str, Any]:
    """Valid arguments: the shared recipe (harness host/site/ids), with every request-body
    (object) argument taken from the tool's own documented example, so a documented body
    that contradicts the spec fails here too; then explicit ``CONFORMANCE_ARGS``."""
    tool = _tools()[name]
    args = tool_args.generated_args(tool)
    example = documented_example(tool) or {}
    props = (tool.parameters or {}).get("properties", {})
    for key, value in example.items():
        if key in props and _is_object_param(props[key]):
            args[key] = value
    args.update(CONFORMANCE_ARGS.get(name, {}))
    return args


def capture(name: str, overrides: dict[str, Any] | None = None) -> list[Request]:
    """Every request ``name`` sends with valid arguments and default flags."""
    upstream = CapturingUpstream()
    logging.disable(logging.CRITICAL)
    try:
        with pytest.MonkeyPatch.context() as mp:
            for k, v in tool_args.TOOL_ENV.get(name, {}).items():
                mp.setenv(k, v)
            uh.install(mp, upstream)
            args = conformance_args(name)
            args.update(overrides or {})
            asyncio.run(server.mcp.call_tool(name, args))
    finally:
        logging.disable(logging.NOTSET)
    return upstream.requests


@cache
def captured(name: str) -> list[Request]:
    """``capture(name)``, once per process (shared with ``captured_all``)."""
    return capture(name)


@cache
def captured_all() -> dict[str, list[Request]]:
    return {name: captured(name) for name in _lz_TOOL_NAMES()}


def tool_problems(name: str, requests: list[Request]) -> list[str]:
    seen: list[str] = []
    for req in requests:
        for problem in violations(req)[1]:
            if problem not in seen:
                seen.append(problem)
    return seen


def classify(requests: list[Request]) -> str:
    """``specced`` (some request reaches a published spec), ``unspecced`` (every
    request reaches an unspecced family) or ``none`` (no request)."""
    if not requests:
        return "none"
    fams = {route(r.path)[0] for r in requests if not r.resolution}
    if not fams:
        return "specced"  # only console/site resolution requests, all Site Manager/Network
    return "unspecced" if all(f.startswith("unspecced:") for f in fams) else "specced"


# =========================================================================== tests
def test_private_ea_firewall_route_classification_is_narrow():
    assert route("/ea/sites/example/rest/firewallrule")[0] == "unspecced:ea-firewall"
    assert route("/ea/sites/example/rest/other")[0] == "direct"
    assert route("/ea/sites/example/rest/firewallrule/extra")[0] == "direct"

    def request(method: str, path: str) -> Request:
        return Request(method, path, "", b"", "", False)

    assert violations(request("GET", "/ea/sites/example/rest/firewallrule"))[1]
    assert violations(request("POST", "/ea/sites/example/rest/other"))[1]


def test_vendored_specs_match_the_spec_drift_pins():
    """The vendored contracts are exactly the versions the spec-drift baseline pins."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "vendor_openapi_specs", ROOT / "scripts" / "vendor_openapi_specs.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.check() == []
    pinned = set(json.loads(BASELINE.read_text())["services"])
    assert set(specs()) == pinned == {*PROXIED_SPECS.values(), *DIRECT_SPECS}


@tool_batches("name", lambda: _lz_TOOL_NAMES())
def test_outgoing_requests_conform_to_the_published_spec(name):
    requests = captured_all()[name]
    problems = tool_problems(name, requests)
    waived = {**WAIVERS.get(name, {}), **UNSERVED_PENDING_DECISION.get(name, {})}
    unwaived = [p for p in problems if not any(w in p for w in waived)]
    assert unwaived == [], f"{name}:\n  " + "\n  ".join(unwaived)
    stale = [w for w in waived if not any(w in p for p in problems)]
    assert stale == [], f"{name}: waiver(s) no longer match a violation: {stale}"


def test_exemptions_are_exactly_the_unspecced_tools():
    by_class: dict[str, set[str]] = {"specced": set(), "unspecced": set(), "none": set()}
    for name, requests in captured_all().items():
        by_class[classify(requests)].add(name)
    assert by_class["unspecced"] == set(UNSPECCED_EXEMPT), (
        f"exempt but specced: {sorted(set(UNSPECCED_EXEMPT) - by_class['unspecced'])}; "
        f"unspecced but not exempt: {sorted(by_class['unspecced'] - set(UNSPECCED_EXEMPT))}"
    )
    assert by_class["none"] == set(NO_REQUEST)
    reasons = {
        _EA_FIREWALL: "ea-firewall",
        _CLASSIC: "classic",
        _CLASSIC_UI_WRITE: "classic",
        _V2: "v2",
        _V2_UI_WRITE: "v2",
        _V2_UI_READ: "v2",
        _PROTECT_PRIVATE: "protect_private",
        _INNERSPACE_PRIVATE: "innerspace_private",
        _V2_CLASSIC_LOOKUP: "v2+classic",
        _V2_AND_CLASSIC: "v2+classic",
    }
    for name in UNSPECCED_EXEMPT:
        fams = {route(r.path)[0] for r in captured_all()[name] if not r.resolution}
        wanted = reasons[UNSPECCED_EXEMPT[name]].split("+")
        assert fams == {f"unspecced:{family}" for family in wanted}, (name, fams)
    validated = by_class["specced"]
    assert len(validated) + len(UNSPECCED_EXEMPT) + len(NO_REQUEST) == len(_lz_TOOL_NAMES())
    assert all(n in validated for n in WAIVERS)
    assert all(n in validated for n in UNSERVED_PENDING_DECISION)


def test_every_specced_request_is_validated():
    """Each specced tool's requests resolve to a spec operation (not merely 'no error')."""
    checked = 0
    for name, requests in captured_all().items():
        if classify(requests) != "specced":
            continue
        checked += 1
        services = {violations(r)[0] for r in requests}
        assert services & {*PROXIED_SPECS.values(), *DIRECT_SPECS}, (name, services)
    assert checked >= 100, f"only {checked} specced tools were checked (vacuous)"


# A request the checker must reject, per rule: the checker itself is under test.
_DEV = (
    "/v1/connector/consoles/C:1/proxy/network/integration/v1/sites/"
    "00000000-0000-4000-8000-000000000001/devices/00000000-0000-4000-8000-000000000002/actions"
)


@pytest.mark.parametrize(
    ("req", "needle"),
    [
        (
            Request("POST", _DEV, "", b'{"action": "restart"}', "application/json", False),
            "'restart' is not one of ['RESTART']",
        ),
        (
            Request("POST", _DEV, "", b"{}", "application/json", False),
            "'action' is a required property",
        ),
        (Request("POST", _DEV, "", b"", "", False), "required request body missing"),
        (Request("GET", _DEV, "", b"", "", False), "method not allowed"),
        (Request("POST", _DEV + "/x", "", b"", "", False), "no path template"),
        (
            Request("GET", "/v1/hosts", "limit=5", b"", "", False),
            "unknown query parameter 'limit'",
        ),
        (
            Request("GET", "/v1/connector/consoles/C:1/proxy/other/x", "", b"", "", False),
            "no routing rule",
        ),
    ],
)
def test_checker_rejects_nonconforming_requests(req, needle):
    problems = violations(req)[1]
    assert any(needle in p for p in problems), problems
