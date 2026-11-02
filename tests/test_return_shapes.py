"""Read tools describe their return shape and which write tool consumes it.

Every "pass ... as `param` to tool" instruction must name a registered tool and one of its
real parameters, so the read-modify-write guidance can never drift from the schema.
"""

from __future__ import annotations

import re

import pytest

from unifi_fabric import server

_HANDOFF = re.compile(r"as\s+`(?P<param>[a-z_]+)`\s+to\s+(?P<tool>[a-z_]+)")

# read tool -> the write tool its "Returns:" line must hand off to
READ_TO_WRITE = {
    "get_setting": "update_setting",
    "get_wlan_config": "update_wlan_config",
    "get_port_profile": "update_port_profile",
    "get_user": "update_user",
    "get_dynamic_dns": "update_dynamic_dns",
    "get_network": "update_network",
    "get_acl_rule": "update_acl_rule",
    "get_dns_policy": "update_dns_policy",
    "get_firewall_zone_proxy": "update_firewall_zone_proxy",
    "get_traffic_matching_list": "update_traffic_matching_list",
    "get_wifi_broadcast": "update_wifi_broadcast",
    "get_vpn_server": "update_vpn_server",
    "get_traffic_route": "update_traffic_route",
    "get_firewall_policy": "update_firewall_policy",
    "list_port_forwards": "update_port_forward",
    "list_hotspot_operators": "update_hotspot_operator",
    "list_traffic_rules": "update_traffic_rule",
    "list_device_tags": "update_device_tag",
    "list_site_to_site_tunnels": "update_site_to_site_tunnel",
    "list_wan_interfaces": "update_wan_interface",
    "get_firewall_policy_ordering": "set_firewall_policy_ordering",
    "get_acl_rule_ordering": "set_acl_rule_ordering",
    "get_user_group": "update_user_group",
    "list_user_groups": "update_user_group",
    "get_static_route": "update_static_route",
    "get_ap_group": "update_ap_group",
    **{
        f"get_{p}": f"update_{p}"
        for p in (
            "camera",
            "chime",
            "light",
            "sensor",
            "viewer",
            "liveview",
            "alarm_hub",
            "arm_profile",
            "bridge",
            "fob",
            "link_station",
            "relay",
            "siren",
            "speaker",
        )
    },
}


async def _tools():
    return {t.name: t for t in await server.mcp.list_tools()}


async def test_every_handoff_names_a_real_tool_and_parameter():
    tools = await _tools()
    seen = 0
    for name, tool in tools.items():
        for m in _HANDOFF.finditer(" ".join((tool.description or "").split())):
            target = tools.get(m.group("tool"))
            assert target is not None, f"{name} hands off to unknown tool {m.group('tool')}"
            assert m.group("param") in target.parameters["properties"], (name, m.groups())
            seen += 1
    assert seen >= len(READ_TO_WRITE)


@pytest.mark.parametrize("read_tool,write_tool", sorted(READ_TO_WRITE.items()))
async def test_read_tool_states_return_shape_and_consumer(read_tool, write_tool):
    tools = await _tools()
    desc = " ".join((tools[read_tool].description or "").split())
    assert "Returns:" in desc
    handoffs = {m.group("tool") for m in _HANDOFF.finditer(desc)}
    assert write_tool in handoffs


@pytest.mark.parametrize("tool", ["set_firewall_policy_ordering", "set_acl_rule_ordering"])
async def test_ordering_setters_state_what_they_return(tool):
    desc = " ".join(((await _tools())[tool].description or "").split())
    assert "Returns: the controller's response, verbatim" in desc


async def test_every_host_parameter_names_the_short_console_name():
    tools = await _tools()
    assert "list_hosts" in tools
    assert "host" in tools["get_camera"].parameters["properties"]
    for name, tool in tools.items():
        props = tool.parameters.get("properties", {})
        if "host" not in props:
            continue
        desc = " ".join(props["host"].get("description", "").split())
        assert "reportedState.hostname" in desc, name
        assert "data[].id" in desc, name


async def test_list_hosts_documents_shape_and_short_name():
    desc = " ".join(((await _tools())["list_hosts"].description or "").split())
    assert "{data: [host…], _count}" in desc
    for field in ("_key_labels", "errors", "_keyLabel"):
        assert field in desc
    assert "reportedState.hostname" in desc


async def test_firewall_zone_list_documents_names_and_id_matching():
    desc = " ".join(((await _tools())["list_firewall_zones_proxy"].description or "").split())
    assert "the _proxy suffix is historical" in desc
    for zone in ("Internal", "External", "Gateway", "Vpn", "Hotspot", "Dmz"):
        assert zone in desc
    assert "case-insensitively" in desc
    assert "by its id" in desc
