"""Paging and reference descriptions say what the code does.

- Every tool whose ``limit`` is sent unchanged as one page with ``offset`` scopes its
  "gathered" clause to the call without offset, and says how many records the console
  returns at most in that one page (or that no clamp is measured), so a short page with
  offset is not read as the end of the collection.
- The three number-family tools say what ``_pageSize.sent`` holds and when ``_nextPage``
  is absent.
- get_network_references states the keys it returns as result claims, which
  tests/test_result_shape_claims.py checks against the tool's real result.

Every description stays inside the 2,048-character client budget.
"""

from __future__ import annotations

import re

import pytest

from tests._tool_catalog import lazy_parametrize
from tests._tool_catalog import tools as catalog_tools
from tests.test_offset_limit_contract import ONE_PAGE
from tests.test_result_shape_claims import result_claims

NUMBER_FAMILY = ("get_system_log", "get_sites_overview", "query_teleport_invitations")
SENT = re.compile(r"sent \((?:each|every) pageSize sent, in (?:request )?order\)")
NEXT_PAGE_ABSENT = re.compile(
    r"(?:No _nextPage: nothing follows the window|_nextPage is absent when no \w+ follows "
    r"the window),? or the call stopped (?:incomplete|short)"
)


def _tools() -> dict[str, object]:
    return {tool.name: tool for tool in catalog_tools()}


def _flat(text: str | None) -> str:
    return " ".join((text or "").split())


def _one_page_limit_tools() -> list[tuple[str, str]]:
    out = []
    for name, tool in sorted(_tools().items()):
        props = tool.parameters.get("properties", {})
        if not {"offset", "limit"} <= set(props):
            continue
        text = _flat(props["limit"].get("description"))
        if "With offset, limit is sent unchanged as one page." in text:
            out.append((name, text))
    return out


def test_one_page_limit_inventory():
    names = {name for name, _ in _one_page_limit_tools()}
    assert {"list_networks", "list_hotspot_vouchers", "list_protect_events"} <= names
    assert len(names) >= 20


@lazy_parametrize(("name", "text"), _one_page_limit_tools)
def test_one_page_limit_text_scopes_gathered_and_names_the_clamp(name, text):
    gathered, _, with_offset = text.partition("With offset, limit is sent unchanged as one page.")
    # The gathered clause applies only without offset; nothing after it claims gathering.
    assert gathered.startswith("Without offset,"), (name, text)
    assert "gathered" not in with_offset, (name, text)
    # The route maximum: hotspot vouchers 1000, Protect 7.x door-lock unlock events 100.
    maximum = {"list_hotspot_vouchers": "1000", "list_door_lock_unlock_events": "100"}.get(
        name, "200"
    )
    if name == "list_protect_events":
        assert "No size clamp is measured on this feed." in with_offset, text
    else:
        assert f"The console clamps that page to {maximum}, so fewer can return" in (with_offset), (
            name,
            text,
        )
        assert f"in pages of at most {maximum};" in gathered, (name, text)


def test_one_page_wording_is_still_the_contract_phrase():
    assert "With offset, limit is sent unchanged as one page." in ONE_PAGE


@pytest.mark.parametrize("name", NUMBER_FAMILY)
def test_number_family_explains_page_size_sent_and_next_page_absence(name):
    text = _flat(_tools()[name].description)
    assert SENT.search(text), text
    assert NEXT_PAGE_ABSENT.search(text), text
    assert len(_tools()[name].description or "") <= 2048


def test_network_references_states_its_result_keys_as_claims():
    tool = _tools()["get_network_references"]
    claims = result_claims(tool.description or "")
    keys = [set(claim) for _lead, _brace, claim in claims]
    assert {"referenceResources"} in keys
    assert {"resourceType", "referenceCount", "references"} in keys
    assert {"referenceId"} in keys
    text = _flat(tool.description)
    for value in ("CLIENT", "DEVICE", "STATIC_ROUTE", "OSPF_ROUTE", "NEXT_AI", "WIFI"):
        assert value in text
    assert "NAT_RULE or SD_WAN" in text
    assert len(tool.description or "") <= 2048
