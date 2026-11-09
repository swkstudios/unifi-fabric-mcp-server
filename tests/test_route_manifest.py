"""The checked-in route manifest must match the current tool capture."""

from scripts.gen_route_manifest import generate
from unifi_fabric.route_manifest import MANIFEST


def test_route_manifest_reproduces_current_request_capture():
    assert generate() == MANIFEST


def test_protect_settings_captures_official_and_private_routes():
    routes = MANIFEST["tools"]["update_protect_device_settings"]
    prefix = "/v1/connector/consoles/{console_id}/proxy/protect"
    for method in ("GET", "PATCH"):
        assert {
            "method": method,
            "path": prefix + "/integration/v1/cameras/{id}",
            "route_class": "integration",
        } in routes
        assert {
            "method": method,
            "path": prefix + "/api/doorlocks/{id}",
            "route_class": "internal",
        } in routes


def test_manifest_classifies_early_access_site_manager_routes():
    assert {
        "method": "POST",
        "path": "/ea/sites/{id}/rest/firewallrule",
        "route_class": "site-manager",
    } in MANIFEST["tools"]["create_firewall_rule"]


def test_manifest_includes_alternate_actions_and_device_types():
    network = "/v1/connector/consoles/{console_id}/proxy/network/v2/api/site/{site}"
    protect = "/v1/connector/consoles/{console_id}/proxy/protect/api"
    expected = {
        "control_packet_capture": [
            ("POST", network + "/pcap-start"),
            ("POST", network + "/pcap-stop/{id}"),
        ],
        "manage_mclag_group": [
            ("POST", network + "/mclag-groups"),
            ("PUT", network + "/mclag-groups/{id}"),
            ("DELETE", network + "/mclag-groups/{id}"),
        ],
        "upgrade_protect_device_firmware": [
            ("POST", protect + "/cameras/{id}/update"),
            ("POST", protect + "/sensors/{id}/update"),
        ],
        "readopt_protect_device": [
            ("POST", protect + "/cameras/{id}/readopt"),
            ("POST", protect + "/doorlocks/{id}/readopt"),
        ],
        "control_retroactive_ai_processing": [
            ("POST", protect + "/aiprocessors/retroactive-processing/start"),
            ("POST", protect + "/aiprocessors/retroactive-processing/cancel"),
        ],
    }
    for name, routes in expected.items():
        for method, path in routes:
            assert {"method": method, "path": path, "route_class": "internal"} in MANIFEST["tools"][
                name
            ]
