"""Every public description of UNIFI_PAGINATE_MAX_PAGES names the tools it does not cap.

``query_traffic_flows`` and ``export_traffic_flows`` drain every page the console reports
even when the cap is configured (released contract, MIGRATING-0.7 change-097; behaviour
pinned by ``test_traffic_flows_drains_every_page_even_with_global_cap``). An operator
reading only the settings table or the pagination guide must not be told the cap bounds
every drain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from unifi_fabric.config import Settings

ROOT = Path(__file__).resolve().parents[1]
EXEMPT = ("query_traffic_flows", "export_traffic_flows")


def _row(path: str, prefix: str) -> str:
    rows = [ln for ln in (ROOT / path).read_text().splitlines() if ln.startswith(prefix)]
    assert len(rows) == 1, f"{path}: expected one row starting {prefix!r}, got {len(rows)}"
    return rows[0]


def _section(path: str, heading: str) -> str:
    text = (ROOT / path).read_text()
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start : end if end != -1 else None]


SURFACES = {
    "CONFIGURATION.md settings table": lambda: _row(
        "docs/CONFIGURATION.md", "| `UNIFI_PAGINATE_MAX_PAGES` | No |"
    ),
    "CONFIGURATION.md generated settings reference": lambda: _row(
        "docs/CONFIGURATION.md", "| `UNIFI_PAGINATE_MAX_PAGES` | unset |"
    ),
    "Settings.paginate_max_pages description": lambda: (
        Settings.model_fields["paginate_max_pages"].description or ""
    ),
    "PAGINATION.md partial-results section": lambda: _section(
        "docs/PAGINATION.md", "## Partial results when a page cap is set"
    ),
}


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_page_cap_description_names_the_exempt_tools(surface: str) -> None:
    text = SURFACES[surface]()
    missing = [tool for tool in EXEMPT if tool not in text]
    assert not missing, f"{surface} describes the page cap without naming {missing}"
    assert "defense-in-depth backstop" not in text, f"{surface} still calls the cap a backstop"
