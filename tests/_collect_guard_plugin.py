"""Pytest plugin used only by tests/test_collect_guard.py (``-p tests._collect_guard_plugin``).

Records, per collected test module, how many times the tool catalog was built or read
(``tests._tool_catalog.tools()`` / ``tools_by_name()`` / ``LazyCatalog`` use, or a direct
``FastMCP.list_tools()``) while that module was being IMPORTED. Builds inside
``pytest_generate_tests`` (lazy parametrization) are not counted: they are the intended,
deferred path. Writes ``{module path: count}`` as JSON to ``$COLLECT_GUARD_OUT``.
"""

from __future__ import annotations

import collections
import json
import os
import sys

import pytest

_counts: collections.Counter[str] = collections.Counter()
_current: list[str | None] = [None]
_sites: dict[str, str] = {}


def _record(kind: str) -> None:
    """Count one catalog build/read against the test module whose top-level code ran it.

    The innermost ``<module>`` frame is that module (a catalog-derived name read through
    ``test_cross_tool_invariants.__getattr__`` is blamed on the reader, not on that module).
    Calls made while pytest is not importing a test module are ignored.
    """
    if _current[0] is None:
        return
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_name == "<module>":
            mod = frame.f_globals.get("__name__", "")
            if mod.startswith("tests."):
                key = mod.rsplit(".", 1)[-1] + ".py"
                _counts[key] += 1
                _sites.setdefault(key, f"{frame.f_code.co_filename}:{frame.f_lineno} ({kind})")
            return
        frame = frame.f_back


def pytest_configure(config):
    from tests import _tool_catalog
    from unifi_fabric import server

    _tool_catalog._RECORDER = _record
    # Direct ``server.mcp.list_tools()`` callers (modules not yet converted). The catalog's
    # own build goes through ``_build`` and is counted by ``tools()``, so it is excluded here.
    cls = type(server.mcp)
    original = cls.list_tools

    def counting_list_tools(self, *args, **kwargs):
        if not _tool_catalog._IN_BUILD and not _tool_catalog.GENERATING:
            _record("list_tools")
        return original(self, *args, **kwargs)

    cls.list_tools = counting_list_tools


@pytest.hookimpl(wrapper=True)
def pytest_make_collect_report(collector):
    is_module = isinstance(collector, pytest.Module)
    if is_module:
        _current[0] = str(collector.path.name)
    try:
        return (yield)
    finally:
        if is_module:
            _current[0] = None


def pytest_unconfigure(config):
    path = os.environ.get("COLLECT_GUARD_OUT")
    if path:
        with open(path, "w") as fh:
            json.dump(dict(_counts), fh)
        with open(path + ".sites", "w") as fh:
            json.dump(_sites, fh, indent=1)
