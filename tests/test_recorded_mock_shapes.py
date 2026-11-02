"""Refreshed mocks must retain the structure of their native recorded siblings."""

import json
from pathlib import Path

import pytest

from tests.test_network import _network_body, _wifi_body
from tests.test_network_services_proxy import _scheduled_tasks_body
from tests.test_protect_cameras import _rtsps_body

RECORDED = Path(__file__).parent / "fixtures" / "recorded"


def _record(family, name):
    return json.loads((RECORDED / family / name).read_text())["body"]


def _type_tree(value):
    if isinstance(value, dict):
        return {key: _type_tree(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_type_tree(item) for item in value]
    return type(value).__name__


@pytest.mark.parametrize(
    "factory,name",
    [
        (_network_body, "network_integration_v1_sites_ID_networks_ID.json"),
        (_wifi_body, "network_integration_v1_sites_ID_wifi_broadcasts_ID.json"),
    ],
)
def test_network_mock_structure_matches_native_detail(factory, name):
    native = _record("network_integration", name)
    assert _type_tree(factory()) == _type_tree(native)


def test_scheduled_task_mock_structure_matches_native_rows():
    native = _record("network_classic", "network_api_s_default_rest_scheduletask.json")
    assert _type_tree(_scheduled_tasks_body()) == _type_tree(native)


def test_rtsps_mock_structure_matches_native_channels():
    native = _record("protect", "protect_integration_v1_cameras_ID_rtsps_stream.json")
    assert _type_tree(_rtsps_body()) == _type_tree(native)
