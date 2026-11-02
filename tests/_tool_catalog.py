"""The registered tool catalog, built lazily and once per process.

Test modules must NOT build the catalog (``server.mcp.list_tools()``) while they are
imported: under pytest-xdist every worker imports every test module, so a module-level
``TOOLS = _tools()`` (plus every list derived from it) is paid by every worker during
collection. Build it here, on first use, inside a function, a fixture or a
``lazy_parametrize`` thunk.

``tools()`` imports ``unifi_fabric.server`` lazily inside the function, never at import
of this module.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable, Iterator, Mapping
from typing import Any

import pytest

# Collection-guard recorder (tests/_collect_guard_plugin.py). ``None`` outside the guard.
_RECORDER: Callable[[str], None] | None = None
# True while conftest's ``pytest_generate_tests`` resolves lazy parametrization: building
# the catalog there is intended (parametrization needs the names), not an import-time build.
GENERATING = False
# True while ``_build`` itself calls ``list_tools`` (not an extra build site).
_IN_BUILD = False


def _record(kind: str) -> None:
    if _RECORDER is not None and not GENERATING:
        _RECORDER(kind)


@functools.cache
def _build() -> tuple[Any, ...]:
    global _IN_BUILD
    from unifi_fabric import server  # lazy: never at module import

    _IN_BUILD = True
    try:
        res = server.mcp.list_tools()
        if inspect.isawaitable(res):
            res = asyncio.run(res)
    finally:
        _IN_BUILD = False
    return tuple(res)


def tools() -> tuple[Any, ...]:
    """Every registered tool, in registry order (built once per process)."""
    _record("tools")
    return _build()


def tools_by_name() -> dict[str, Any]:
    """Name -> tool for the whole catalog."""
    _record("tools_by_name")
    return dict(_by_name())


@functools.cache
def _by_name() -> dict[str, Any]:
    return {t.name: t for t in _build()}


class LazyCatalog(Mapping):
    """Read-only name -> tool mapping that builds the catalog on first *use*.

    ``TOOLS = cti.TOOLS`` at the top of a test module only binds this object; the catalog
    is built when something iterates or indexes it.
    """

    def __getitem__(self, name: str) -> Any:
        _record("LazyCatalog")
        return _by_name()[name]

    def __iter__(self) -> Iterator[str]:
        _record("LazyCatalog")
        return iter(_by_name())

    def __len__(self) -> int:
        _record("LazyCatalog")
        return len(_by_name())


class LazyIds:
    """``ids=`` computed at generate time: ``lazy_parametrize(..., ids=LazyIds(lambda: [...]))``."""

    def __init__(self, thunk: Callable[[], Any]) -> None:
        self.thunk = thunk


def lazy_parametrize(argnames: Any, thunk: Callable[[], Any], **kwargs: Any) -> Any:
    """``pytest.mark.parametrize`` whose values are computed at generate time.

    ``thunk()`` runs inside ``pytest_generate_tests`` (see ``tests/conftest.py``), never at
    module import, so values derived from the tool catalog cost nothing for a module that
    is merely imported. Ids, order and keyword arguments are those of ``parametrize``.
    """
    return pytest.mark.lazy_parametrize(argnames, thunk, **kwargs)


def is_read(tool: Any) -> bool:
    ann = tool.annotations
    return bool(ann and getattr(ann, "read_only_hint", None))


__all__ = [
    "LazyCatalog",
    "LazyIds",
    "is_read",
    "lazy_parametrize",
    "tools",
    "tools_by_name",
]
