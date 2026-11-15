"""check_spec_drift reports what it can and cannot check."""

from __future__ import annotations

from pathlib import Path

import pytest

from unifi_fabric.api_sources import is_private
from unifi_fabric.generated_api_facts._api_source_table import TOOL_API_SOURCES


@pytest.fixture
def script(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import check_spec_drift

    return check_spec_drift


def test_counts_are_derived_from_the_generated_table_and_add_up(script):
    lines = script.spec_coverage_lines()
    total = len(TOOL_API_SOURCES)
    published = sum(
        1
        for pairs in TOOL_API_SOURCES.values()
        if not any(is_private(p.split("/", 1)[1]) for p in pairs)
        and any(p.endswith("/official") for p in pairs)
    )
    private = sum(
        1
        for pairs in TOOL_API_SOURCES.values()
        if any(is_private(p.split("/", 1)[1]) for p in pairs)
    )
    assert lines[0].startswith(f"spec coverage ({total} tools")
    assert lines[1].lstrip().startswith(f"{published} reach only published routes")
    assert lines[2].lstrip().startswith(f"{private} reach at least one private route")
    neither = total - published - private
    assert lines[4].lstrip().startswith(f"{neither} call no published or private route")
    assert published > 0 and private > 0 and published + private + neither == total


def test_a_private_route_makes_the_tool_unchecked_and_is_named(script):
    lines = script.spec_coverage_lines(
        {
            "a": ("site_manager/official", "network/official"),
            "b": ("site_manager/official", "protect/private"),
            "c": ("site_manager/official", "network/private.classic", "network/private.v2"),
            "d": ("relay/generic",),
        }
    )
    text = "\n".join(lines)
    assert "(4 tools" in lines[0]
    assert lines[1].lstrip().startswith("1 reach only published routes")
    assert lines[2].lstrip().startswith("2 reach at least one private route")
    assert lines[4].lstrip().startswith("1 call no published or private route")
    assert "network/private.classic=1" in text and "protect/private=1" in text
    assert "NOT compared here" in text and "route baselines" in text


def test_the_baseline_report_carries_the_coverage_lines(script, capsys):
    baseline = script.load_snapshot_file(script.DEFAULT_BASELINE)
    assert script._emit(baseline) == 0
    out = capsys.readouterr().out
    assert "spec coverage (" in out and "NOT compared here" in out
