"""Regression checks for advertised tool descriptions."""

import asyncio
import re

import pytest

from unifi_fabric import server


@pytest.fixture(scope="module")
def tools():
    return {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}


def test_carrier_subscriber_description_fits_client_budget(tools):
    assert len(tools["update_carrier_subscriber"].description) <= 2048


@pytest.mark.parametrize("name", ["create_wifi_broadcast", "update_wifi_broadcast"])
def test_open_wifi_guidance_supplies_explicit_network(tools, name):
    description = tools[name].description
    assert "OPEN" in description
    assert "explicit network" in description
    assert "SPECIFIC" in description
    assert "networkId" in description
    assert "list_networks" in description
    body = tools[name].parameters["properties"]["broadcast"]["description"]
    assert "OPEN" in body
    assert "explicit network" in body


def test_protect_event_description_explicitly_states_returns(tools):
    description = tools["list_protect_events"].description
    assert re.search(r"\bReturns?\b", description)
    for key in ("result", "data", "_count", "_warnings", "incomplete", "incompleteReason"):
        assert key in description


def test_device_tag_description_has_no_markup(tools):
    for name in ("create_device_tag", "list_device_tags", "update_device_tag", "delete_device_tag"):
        assert re.search(r"<[A-Za-z][^>]*>", tools[name].description) is None, name


@pytest.mark.parametrize("name", ["get_isp_metrics", "query_isp_metrics"])
def test_isp_interval_values_are_discoverable(tools, name):
    interval = tools[name].parameters["properties"]["interval"]
    assert interval["enum"] == ["5m", "1h"]
    assert "5m" in interval["description"]
    assert "1h" in interval["description"]


@pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete"])
def test_connector_relay_description_fits_client_budget(tools, method):
    assert len(tools["fabric_connector_" + method].description) <= 2048
