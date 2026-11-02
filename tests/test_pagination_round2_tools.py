"""Pagination round-two T27/T28: validate before I/O and advertise logical windows."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.protect_events_cases import get_protect_case_activity
from unifi_fabric.tools.recognition import list_recognition_detections, list_recognition_groups


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        (list_recognition_groups, ("synthetic-host", "face")),
        (list_recognition_detections, ("synthetic-host", "face", "synthetic-group")),
        (get_protect_case_activity, ("synthetic-host", "synthetic-case")),
    ],
)
@pytest.mark.parametrize("field", ["page", "page_size"])
@pytest.mark.parametrize("value", [0, -1, -5, True, False, 1.5, "1"])
async def test_t27_links_tools_reject_invalid_paging_before_resolution(tool, args, field, value):
    client = AsyncMock()
    registry = AsyncMock()
    if field == "page_size":
        message = (
            f"page_size must be a positive integer (1 or more); got {value}. "
            "Omit page_size to read the whole collection."
        )
    else:
        message = f"page is 1-based and must be 1 or more; got {value}."
    with pytest.raises(ValueError) as caught:
        await tool(client, registry, *args, **{field: value})
    assert str(caught.value) == message
    assert client.mock_calls == []
    assert registry.mock_calls == []


@pytest.mark.parametrize(
    "name",
    ["list_recognition_groups", "list_recognition_detections", "get_protect_case_activity"],
)
async def test_t28_runtime_links_descriptions_define_logical_windows(name):
    from unifi_fabric import server

    tool = next(tool for tool in await server.mcp.list_tools() if tool.name == name)
    description = " ".join((tool.description or "").split())
    assert "[(page-1)*N, page*N)" in description
    assert "exactly N when that many exist, fewer only at the end, never more" in description
    assert "1-based window number counted in units of page_size (default 1)" in description
    assert "without page_size, returns one native console page" in description
    assert "resume from _nextPage with the same page_size" in description
    for banned in ("native pages until", "can exceed", "full final page", "Starting page"):
        assert banned not in description
