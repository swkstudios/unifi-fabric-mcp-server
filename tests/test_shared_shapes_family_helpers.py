"""The common helper modules the family moves create in shared_shapes (public #42 step 5).

A helper two or more families use goes to a shared_shapes/_<family>_shared.py module (the
move tool, scripts/move_family.py). Each must import on its own, define what it holds, and keep
every function it defines under its own module name, so a family module that re-exports a name
points at the one definition.
"""

from __future__ import annotations

import inspect

import pytest

from unifi_fabric.shared_shapes import (
    _clients_shared,
    _network_services_proxy_shared,
    _network_shared,
    _protect_shared,
    _site_config_shared,
    _site_manager_shared,
    _statistics_shared,
)

MODULES = [
    _clients_shared,
    _network_services_proxy_shared,
    _network_shared,
    _protect_shared,
    _site_config_shared,
    _site_manager_shared,
    _statistics_shared,
]


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.__name__.rsplit(".", 1)[-1])
def test_a_common_helper_module_owns_what_it_defines(module) -> None:
    assert module.__doc__
    functions = [
        member
        for _, member in inspect.getmembers(module, inspect.isfunction)
        if member.__module__ == module.__name__
    ]
    assert functions, f"{module.__name__} defines no function"
    for function in functions:
        assert getattr(module, function.__name__) is function
