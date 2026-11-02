"""Shared selector text and the required-arguments line applied at registration."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from unifi_fabric.catalog_descriptions import (
    _ORIGINAL_HOST,
    HOST_DESCRIPTION,
    _host_description,
    install_compact_selector_descriptions,
)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (_ORIGINAL_HOST, HOST_DESCRIPTION),
        (
            'Console name or id from list_hosts, e.g. "my-console".',
            "Console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(e.g. "my-console") or data[].id.',
        ),
        (
            'Protect console name or composite id from list_hosts; for example "Home NVR".',
            "Protect console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(for example "Home NVR") or data[].id.',
        ),
        (
            "Console name or id from list_hosts.",
            "Console name, MAC or id from list_hosts: reportedState.hostname/name or data[].id.",
        ),
        (
            'Required console selector from list_hosts, for example "Home NVR".',
            "Console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(for example "Home NVR") or data[].id.',
        ),
        (
            'Console name or id from list_hosts, e.g. "my-console"; resolved to its owning '
            "Fabric API key.",
            "Console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(e.g. "my-console") or data[].id. Resolved to its owning Fabric API key.',
        ),
    ],
)
def test_generic_host_hints_gain_both_console_forms(given: str, expected: str) -> None:
    assert _host_description(given) == expected
    assert "reportedState.hostname" in expected and "data[].id" in expected


@pytest.mark.parametrize(
    "kept",
    [
        HOST_DESCRIPTION,
        "Optional filter. Console name or id: the short name from list_hosts "
        "(data[].reportedState.hostname or reportedState.name) or the long data[].id.",
        "Console that owns the camera; must match the camera's NVR.",
    ],
)
def test_specific_or_complete_host_hints_are_kept(kept: str) -> None:
    assert _host_description(kept) is None


def _app(**tools: dict[str, Any]) -> SimpleNamespace:
    components = {
        name: SimpleNamespace(description=spec["description"], parameters=spec["parameters"])
        for name, spec in tools.items()
    }
    return SimpleNamespace(_local_provider=SimpleNamespace(_components=components))


def test_unnamed_required_parameter_gets_the_required_arguments_line() -> None:
    app = _app(
        restart={
            "description": "Restart an adopted device.",
            "parameters": {
                "properties": {"host": {}, "site": {}, "device_id": {}},
                "required": ["host", "site", "device_id"],
            },
        },
        named={
            "description": "Read one host's site summary.",
            "parameters": {"properties": {"host": {}, "site": {}}, "required": ["host", "site"]},
        },
    )
    install_compact_selector_descriptions(app)
    components = app._local_provider._components
    assert components["restart"].description == (
        "Restart an adopted device.\n\nRequired arguments: host, site, device_id."
    )
    assert components["named"].description == "Read one host's site summary."
