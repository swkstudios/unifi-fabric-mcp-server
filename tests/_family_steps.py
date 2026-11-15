"""Register a family module's tools wherever its register steps live (the loader map).

A family move (``scripts/move_family.py``) takes a module's ``register`` functions into the
family's ``registrar.py``; the loader map keeps each step's ``origin``, the module its tools
are indexed under. Tests that register one module's tools themselves go through
:func:`register_module`, so they hold before and after any move.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from types import ModuleType
from typing import Any

from unifi_fabric.catalog.loaders import LOADERS


def module_steps(module: ModuleType) -> list[Callable[..., Any]]:
    """The register functions of the loader steps indexed under ``module``, in order."""
    family, stem = module.__name__.split(".")[-2:]
    steps = [e for e in LOADERS if e.family == family and e.origin == stem]
    if not steps:
        raise LookupError(f"no loader step has origin {stem!r} in family {family!r}")
    return [getattr(importlib.import_module(e.module_path), e.function) for e in steps]


def register_module(mcp: Any, module: ModuleType, deps_fn: Callable[..., Any]) -> None:
    """Run every loader step indexed under ``module`` against ``mcp``."""
    for register in module_steps(module):
        register(mcp, deps_fn)
