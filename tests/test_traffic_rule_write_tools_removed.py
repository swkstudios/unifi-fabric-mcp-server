"""Network v2 traffic rules: the write tools are gone, the legacy list stays.

Evidence: the Network application answers ``api.err.NotImplemented`` (HTTP 501) to POST on
``v2/api/site/{site}/trafficrules`` and to PUT and DELETE on
``v2/api/site/{site}/trafficrules/{id}``, while GET on the collection still answers 200.
The Network 11.0.81 web app only reads the route, and the 11.0.99 web app no longer
contains it. ``list_traffic_rules`` keeps reading rules carried over from earlier Network
versions and says so.
"""

from __future__ import annotations

import pytest

from tests.test_tool_schema_contract import _tools
from unifi_fabric import server
from unifi_fabric.families.network import network_services_proxy
from unifi_fabric.generated_api_facts import _api_source_table

REMOVED = ("create_traffic_rule", "update_traffic_rule", "delete_traffic_rule")


@pytest.mark.parametrize("name", REMOVED)
def test_removed_tool_is_not_registered_or_importable_or_classified(name):
    assert name not in {tool.name for tool in _tools()}
    assert not hasattr(network_services_proxy, name)
    assert not hasattr(server, name)
    assert name not in _api_source_table.TOOL_API_SOURCES


def test_list_traffic_rules_stays_and_is_labelled_legacy():
    tool = {t.name: t for t in _tools()}["list_traffic_rules"]
    description = " ".join(tool.description.split())
    assert "Legacy" in description
    assert "carried over from earlier Network versions" in description
    assert "Network 11.0.99 web app no longer shows them" in description
    assert "does not implement creating, changing or deleting" in description
    assert not any(name in description for name in REMOVED)
    assert tool.annotations.readOnlyHint is True


def test_the_supported_families_remain():
    names = {tool.name for tool in _tools()}
    assert {
        "list_traffic_rules",
        "create_firewall_policy",
        "create_qos_rule",
        "create_traffic_route",
        "create_traffic_matching_list",
    } <= names
