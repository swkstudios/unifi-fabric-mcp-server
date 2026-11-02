#!/usr/bin/env python3
"""Generate catalog-wide natural language queries independently of search rankings.

The two deterministic prompts per tool use its documented purpose. Handwritten
confusable-operation queries supplement them.
Changing this fixture is reviewable; generating it never changes the accuracy baseline.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from unifi_fabric import server
from unifi_fabric.families import build_family_index

TARGET = Path(__file__).resolve().parents[1] / "tests/fixtures/discovery_queries.json"
CONFUSABLE = [
    (
        "get_firewall_policy_ordering",
        "Read the current sequence of firewall policies without changing it",
    ),
    ("set_firewall_policy_ordering", "Change the order in which firewall policies are evaluated"),
    ("get_acl_rule_ordering", "Read the ordered access control rules"),
    ("set_acl_rule_ordering", "Change the sequence of access control rules"),
    ("list_networks", "Show all network configurations for a site"),
    ("get_network", "Retrieve one network configuration using its identifier"),
    ("create_network", "Add a new network configuration to a site"),
    ("update_network", "Modify an existing network configuration"),
    ("delete_network", "Remove an existing network configuration"),
    ("list_cameras", "Show the Protect surveillance cameras"),
    ("list_devices", "Show the Network switches and access points"),
    # One or more handwritten confusable pairs per family, so every family (including
    # the GS3 families) is measured on near-miss intents, not only generated phrasing.
    ("list_all_devices", "Show every device across all consoles and sites"),
    ("get_fleet_summary", "Give me a rollup of device and client counts for the whole fleet"),
    ("suspend_carrier_subscriber", "Pause service for a carrier subscriber"),
    ("resume_carrier_subscriber", "Restore service for a suspended carrier subscriber"),
    ("block_client", "Stop a client device from connecting to the network"),
    ("unblock_client", "Allow a previously blocked client to connect again"),
    ("fabric_connector_get", "Send a raw GET request through the connector relay"),
    ("fabric_connector_post", "Send a raw POST request through the connector relay"),
    ("restart_device", "Reboot a switch or access point"),
    ("upgrade_device", "Install new firmware on one device"),
    ("list_hotspot_operators", "Show the hotspot operator accounts"),
    ("create_hotspot_operator", "Add a hotspot operator account"),
    ("list_innerspace_floor_plans", "Show the floor plans of the InnerSpace project"),
    ("get_innerspace_summary", "Summarize the InnerSpace project contents"),
    ("list_mobility_devices", "Show the cellular mobility devices"),
    ("update_mobility_device_name", "Rename a mobility device"),
    ("list_dns_policies", "Show the DNS policies for a site"),
    ("list_port_forwards", "Show the port forwarding rules"),
    ("get_unifi_placement_snapshot", "Export where each device is placed on the floor plans"),
    ("list_protect_events", "Show recent motion and smart detection events from Protect"),
    ("list_recognition_groups", "Show the face recognition groups"),
    ("list_recognition_detections", "Show recent license plate and face detections"),
    ("list_hosts", "Show every UniFi console I own"),
    ("list_sites", "Show the sites on my consoles"),
    ("get_host", "Look up one console by its id"),
    ("get_site_statistics", "Show traffic statistics for a site"),
    ("list_client_sessions", "Show the connection history of clients"),
    ("list_vpn_servers", "Show the VPN servers configured on the gateway"),
    ("create_site_to_site_tunnel", "Connect two sites with a site-to-site VPN tunnel"),
]


def _purpose(tool_name: str, description: str | None) -> str:
    """Return a human-facing purpose without leaking the registered identifier."""
    first = (description or "").splitlines()[0].strip().rstrip(".")
    first = re.sub(r"`([^`]+)`", lambda match: match[1].replace("_", " "), first)
    words = [re.escape(word) for word in tool_name.split("_")]
    identifier = r"[_\s-]+".join(words)
    # Do not require a trailing word boundary: a purpose such as "delete QoS rules"
    # would otherwise retain the normalized singular identifier as a substring.
    first = re.sub(identifier, "this task", first, flags=re.IGNORECASE)
    first = " ".join(first.split())
    if not first:
        raise ValueError(f"{tool_name} has no usable description for discovery queries")
    normalized = " ".join(tool_name.split("_")).casefold()
    if normalized in first.casefold():
        raise ValueError(f"{tool_name} description still leaks its normalized identifier")
    return first


def _as_request(purpose: str) -> str:
    return purpose[0].lower() + purpose[1:]


async def generate():
    tools = await server.mcp.list_tools()
    families = build_family_index()
    queries = []
    for tool in sorted(tools, key=lambda item: item.name):
        purpose = _purpose(tool.name, tool.description)
        queries.extend(
            [
                {
                    "query": f"I need to {_as_request(purpose)}",
                    "expected": tool.name,
                    "kind": "purpose",
                },
                {
                    "query": f"Help me {_as_request(purpose)}",
                    "expected": tool.name,
                    "kind": "operation",
                },
            ]
        )
    names = {tool.name for tool in tools}
    # A confusable naming a tool that no longer exists would silently drop out of the
    # measured set (two did after the ordering tools were renamed set_*_ordering).
    stale = sorted(expected for expected, _ in CONFUSABLE if expected not in names)
    if stale:
        raise SystemExit(f"CONFUSABLE names unregistered tools: {stale}")
    uncovered = sorted(
        {families.get(n, "other") for n in names}
        - {families.get(expected, "other") for expected, _ in CONFUSABLE}
    )
    if uncovered:
        raise SystemExit(f"families without a confusable query: {uncovered}")
    for expected, query in CONFUSABLE:
        queries.append({"query": query, "expected": expected, "kind": "confusable"})
    return {
        "generator": "scripts/gen_discovery_queries.py",
        "tools": sorted(names),
        "queries": queries,
    }


if __name__ == "__main__":
    TARGET.write_text(json.dumps(asyncio.run(generate()), indent=2) + "\n")
