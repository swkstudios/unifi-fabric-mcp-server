"""Registered paging inputs reach one batch policy, including free-form body inputs."""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

from tests._tool_catalog import tools_by_name
from unifi_fabric._read_only_audit import _called_package_functions

_PAGE_FIELDS = frozenset({"page_size", "pageSize", "limit"})

# Protect's pinned upstream inventory exposes only limit on this history route,
# with no offset/page/cursor selector: protect_automation_history_upstream.json, operation
# GET /proxy/protect/api/automations/{}/history. It is an upstream selection count,
# not a managed paging collection. The test below verifies that source evidence.
_UNPAGED = frozenset({"get_protect_automation_history"})


def _schema_exposes_page_size(value: Any) -> bool:
    if isinstance(value, dict):
        if _PAGE_FIELDS.intersection(value.get("properties", {})):
            return True
        description = value.get("description")
        if isinstance(description, str) and re.search(r"\bpageSize\b", description):
            return True
        return any(_schema_exposes_page_size(child) for child in value.values())
    return isinstance(value, list) and any(_schema_exposes_page_size(child) for child in value)


def paging_tool_names() -> list[str]:
    """Derive caller-visible paging tools from the current registered public surface."""
    return sorted(
        name
        for name, tool in tools_by_name().items()
        if _schema_exposes_page_size(tool.parameters)
        # Free-form bodies have no nested JSON schema. Their registered description
        # is the caller's paging contract (traffic query/export both advertise it).
        or re.search(r"\bpageSize\b", tool.description or "")
    )


@cache
def _reachable(fn: Callable[..., Any]) -> frozenset[Callable[..., Any]]:
    seen = set()
    pending = [inspect.unwrap(fn)]
    while pending:
        current = inspect.unwrap(pending.pop())
        if current in seen:
            continue
        seen.add(current)
        # Existing source-inspection utility resolves imported aliases and module
        # delegates by identity; equal function names in other modules do not count.
        pending.extend(_called_package_functions(current))
    return frozenset(seen)


def test_every_registered_paging_tool_reaches_shared_batch_policy():
    from unifi_fabric.tools import _pagination

    helpers = {
        helper
        for name in ("collect_batch", "PageSizeBatch")
        if (helper := getattr(_pagination, name, None)) is not None
    }
    assert helpers, "The shared batching policy must exist"
    names = paging_tool_names()
    assert names, "The runtime registry must expose paging tools"
    assert _UNPAGED <= set(names)
    catalog = tools_by_name()
    missing = [
        name
        for name in names
        if name not in _UNPAGED and not (_reachable(catalog[name].fn) & helpers)
    ]
    assert not missing, f"Paging tools bypassing the shared batch policy: {missing}"


def test_unpaged_history_exception_matches_pinned_upstream_and_registered_source():
    from unifi_fabric.tools.protect_automation_backup import _get_protect_automation_history

    path = Path(__file__).parent / "fixtures/protect_automation_history_upstream.json"
    inventory = json.loads(path.read_text())
    operation = next(
        row
        for row in inventory["operations"]
        if row["id"] == "GET /proxy/protect/api/automations/{}/history"
    )
    assert operation["query_keys"] == ["limit"]
    assert operation["evidence"], "The exception must retain pinned upstream call-site evidence"
    assert _get_protect_automation_history in _reachable(
        tools_by_name()["get_protect_automation_history"].fn
    )
    signature = inspect.signature(_get_protect_automation_history)
    assert "limit" in signature.parameters
    assert not {"offset", "page", "page_token", "cursor"}.intersection(signature.parameters)
