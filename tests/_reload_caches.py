"""Release the function-keyed caches a server reload leaves behind.

Each ``importlib.reload(server)`` registers a fresh set of tool functions. Caches keyed on
function identity (``_read_only_audit._source_facts`` and FastMCP's own ``lru_cache``
helpers) keep every earlier registration alive, about 3.5 MiB per reload. The autouse
server-reset fixture clears them at teardown; production code is untouched.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from typing import Any


def function_keyed_caches() -> Iterator[Any]:
    """Yield every ``functools.lru_cache`` wrapper in this package and in FastMCP."""
    for name, module in tuple(sys.modules.items()):
        if module is None or name.split(".", 1)[0] not in {"fastmcp", "unifi_fabric"}:
            continue
        for value in tuple(vars(module).values()):
            if hasattr(value, "cache_clear") and hasattr(value, "cache_info"):
                yield value


def clear_function_keyed_caches() -> int:
    """Clear them all; return how many held entries (used by the regression test)."""
    held = 0
    for cached in function_keyed_caches():
        if cached.cache_info().currsize:
            held += 1
        cached.cache_clear()
    return held
