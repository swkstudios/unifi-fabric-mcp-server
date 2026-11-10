"""Every tool that takes both offset and limit: the description matches the requests.

- With offset, a limit over 200 is sent as one GET carrying that limit unchanged exactly
  when the description says the call fetches one page; a description that says the limit
  is gathered across pages of at most 200 starting at offset gets that drain instead.
  The tool function is called directly so a spec maximum of 200 does not hide the
  request pattern (SpecLimitMiddleware is pinned in its own tests).
- PAGING-VALIDATION-A1: a limit below 1 is refused with or without offset, and no
  request is sent (without offset is pinned in test_pagination_int_paging).
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any
from urllib.parse import parse_qsl

import pytest

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_catalog import tools as catalog_tools
from unifi_fabric import refusals, server
from unifi_fabric.generated_api_facts._spec_limits_table import SPEC_LIMITS

PAGING_NAMES = {"limit", "page_size", "offset", "page", "page_number"}
#: Wording that tells a caller offset plus limit fetches one page.
ONE_PAGE = (
    "With offset, limit is sent unchanged as one page.",
    "one page manually",
    "a single page manually",
    "one explicit page",
)
#: Wording that tells a caller offset plus limit is gathered (mobility._drain).
GATHERED = "With offset, limit is gathered across pages of at most 200 starting at offset."
LIMIT = 300
OFFSET = 5


@functools.cache
def _offset_limit_tools() -> tuple[str, ...]:
    # Built on first use, never at module import (test_collect_guard).
    return tuple(
        sorted(
            tool.name
            for tool in catalog_tools()
            if {"offset", "limit"} <= set(tool.parameters.get("properties", {}))
        )
    )


def _tool(name: str) -> Any:
    return next(tool for tool in catalog_tools() if tool.name == name)


def _limit_text(tool: Any) -> str:
    return " ".join(str(tool.parameters["properties"]["limit"].get("description", "")).split())


def _claim(tool: Any) -> str:
    text = _limit_text(tool)
    one_page = any(phrase in text for phrase in ONE_PAGE)
    gathered = GATHERED in text
    assert one_page != gathered, (tool.name, text)
    return "one-page" if one_page else "gathered"


def _base(tool: Any) -> dict[str, Any]:
    return {k: v for k, v in tool_args.generated_args(tool).items() if k not in PAGING_NAMES}


def _paging_requests(up: uh.FakeUpstream) -> list[dict[str, str]]:
    # A console or site listing tool's own route is a resolution route, so the paging
    # controls (not the resolution flag) pick out the tool's own list reads; they start
    # at the first request for the caller's offset (site resolution drains from 0 first).
    queries = [dict(parse_qsl(served.query)) for served in up.served]
    paged = [query for query in queries if "offset" in query or "limit" in query]
    starts = [i for i, query in enumerate(paged) if query.get("offset") == str(OFFSET)]
    return paged[starts[0] :] if starts else paged


def test_offset_limit_inventory_covers_both_claims():
    names = _offset_limit_tools()
    assert {"list_networks", "list_mobility_devices", "list_mobility_clients"} <= set(names)
    assert len(names) >= 25
    claims = {name: _claim(_tool(name)) for name in names}
    assert {name for name, claim in claims.items() if claim == "gathered"} == {
        "list_mobility_devices",
        "list_mobility_clients",
    }


@lazy_parametrize("name", _offset_limit_tools)
async def test_offset_limit_description_matches_the_requests(name):
    tool = _tool(name)
    claim = _claim(tool)
    fn = tool.fn
    args = {k: v for k, v in _base(tool).items() if k in inspect.signature(fn).parameters}
    up = uh.FakeUpstream(mode="paged", replay_recordings=False)
    logging.disable(logging.CRITICAL)
    try:
        with pytest.MonkeyPatch.context() as mp:
            for key, value in tool_args.TOOL_ENV.get(name, {}).items():
                mp.setenv(key, value)
            uh.install(mp, up)
            await fn(**args, offset=OFFSET, limit=LIMIT)
    finally:
        logging.disable(logging.NOTSET)
    requests = _paging_requests(up)
    assert requests, name
    first = requests[0]
    assert first.get("offset") == str(OFFSET), (name, requests)
    if claim == "one-page":
        assert len(requests) == 1, (name, requests)
        assert first.get("limit") == str(LIMIT), (name, requests)
    else:
        # Gathered from offset in pages of at most 200: never one GET with limit 300.
        assert first.get("limit") == "200", (name, requests)
        assert all(int(query["limit"]) <= 200 for query in requests), (name, requests)


def _refusal_cases() -> list[Any]:
    return [
        pytest.param(name, offset, value, id=f"{name}-offset={offset}-limit={value}")
        for name in _offset_limit_tools()
        for offset in (0, OFFSET)
        for value in (0, -1, -5)
    ]


@lazy_parametrize(("name", "offset", "value"), _refusal_cases)
async def test_limit_below_one_is_refused_with_offset_before_any_request(name, offset, value):
    up = uh.FakeUpstream(replay_recordings=False)
    message = None
    logging.disable(logging.CRITICAL)
    try:
        with pytest.MonkeyPatch.context() as mp:
            for key, env in tool_args.TOOL_ENV.get(name, {}).items():
                mp.setenv(key, env)
            uh.install(mp, up)
            try:
                await server.mcp.call_tool(
                    name, {**_base(_tool(name)), "offset": offset, "limit": value}
                )
            except Exception as exc:  # noqa: BLE001 - the message is the assertion
                message = str(exc)
    finally:
        logging.disable(logging.NOTSET)
    assert message is not None, f"{name}(offset={offset}, limit={value}) was not refused"
    message = message.removeprefix(f"Error calling tool '{name}': ")
    registered = refusals.classify(message)
    assert registered is not None, message
    minimum = SPEC_LIMITS.get(name, {}).get("limit", {}).get("minimum")
    if isinstance(minimum, int) and value < minimum:
        assert registered.id == "spec-limits", message
        assert f"'limit' is {value}:" in message
    else:
        assert registered.id == "logical-pagination-integer", message
        assert message == (
            f"limit must be a positive integer (1 or more); got {value}. "
            "Omit limit to read the whole collection."
        )
    # No request at all: no host or site resolution and no target request.
    assert up.served == []
