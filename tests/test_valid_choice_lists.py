"""A "valid:" list in an unknown-site or unknown-console error names each choice once.

Site and console names match case-insensitively (``matching.name_keys``), so two labels
that differ only in case are one choice: listing both ("Default, default") reads as two
sites. The refusal itself still fails fast before any further request.
"""

from __future__ import annotations

import re

import pytest

from unifi_fabric import registry
from unifi_fabric.registry import _valid_site_choices, match_ea_site, valid_host_choices

SITE_ID = "a" * 24
PROXY_SITE_ID = "00000000-0000-3000-a000-000000000016"


def test_distinct_labels_keeps_the_first_spelling_of_each_case_folded_name():
    assert registry.distinct_labels(["Default", "default", " DEFAULT ", "", None, "Branch"]) == [
        "Default",
        "Branch",
    ]


def test_site_manager_unknown_site_lists_a_case_variant_once():
    sites = [{"siteId": SITE_ID, "hostId": "AA:1", "meta": {"name": "default", "desc": "Default"}}]
    with pytest.raises(ValueError) as exc:
        match_ea_site(sites, "Nowhere", partial=[], max_pages=None)
    valid = re.search(r"valid: (.*)$", str(exc.value)).group(1)
    assert valid.split(", ") == ["Default"], str(exc.value)


def test_site_manager_unknown_site_keeps_distinct_names():
    sites = [
        {"siteId": SITE_ID, "hostId": "AA:1", "meta": {"name": "default", "desc": "Default"}},
        {"siteId": "b" * 24, "hostId": "AA:1", "meta": {"name": "branch", "desc": "Branch"}},
    ]
    with pytest.raises(ValueError) as exc:
        match_ea_site(sites, "Nowhere", partial=[], max_pages=None)
    valid = re.search(r"valid: (.*)$", str(exc.value)).group(1)
    assert valid.split(", ") == ["Branch", "Default"], str(exc.value)


def test_console_site_choice_lists_a_case_variant_once():
    sites = [{"id": PROXY_SITE_ID, "name": "default", "description": "Default"}]
    assert _valid_site_choices(sites) == f"Default ({PROXY_SITE_ID})"


def test_console_site_choice_keeps_two_different_labels():
    sites = [{"id": PROXY_SITE_ID, "name": "office-lan", "description": "Office"}]
    assert _valid_site_choices(sites) == f"Office / office-lan ({PROXY_SITE_ID})"


def test_unknown_host_lists_a_case_variant_once():
    host = {"id": "AA:1", "reportedState": {"hostname": "udm", "name": "UDM"}}
    assert valid_host_choices([host]) == "udm (AA:1)"
    other = {"id": "AA:2", "reportedState": {"hostname": "udm", "name": "Home UDM"}}
    assert valid_host_choices([other]) == "udm (Home UDM, AA:2)"
