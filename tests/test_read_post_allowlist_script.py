"""scripts/read_post_allowlist.py emits the read-POST allowlist as EREs from the source."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from unifi_fabric import read_post_routes as rpr

GREP = shutil.which("grep") or "grep"
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/read_post_allowlist.py"


def _lines() -> list[tuple[str, str, str]]:
    out = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT)], check=True, capture_output=True, text=True
    ).stdout
    rows = [tuple(line.split("\t")) for line in out.splitlines()]
    assert all(len(r) == 3 for r in rows)
    return rows  # type: ignore[return-value]


def _ere(ere: str, path: str) -> bool:
    # grep -E is the dialect a shell or awk scanner uses.
    result = subprocess.run(  # noqa: S603
        [GREP, "-Eq", "--", ere], input=path + "\n", text=True, check=False
    )
    return result.returncode == 0


def _is_read_by_ere(rows, path: str) -> str | None:
    bare = path.split("?", 1)[0]
    if any(_ere(e, bare) for k, _, e in rows if k == "reject"):
        return None
    for kind, _name, ere in rows:
        if kind in {"route", "command"} and _ere(ere, bare):
            return kind
    return None


def test_one_line_per_listed_route_and_command_route():
    rows = _lines()
    assert [n for k, n, _ in rows if k == "route"] == [r.name for r in rpr.READ_POST_ROUTES]
    assert sorted(n for k, n, _ in rows if k == "command") == sorted(
        {c.route for c in rpr.READ_COMMANDS}
    )
    assert {k for k, _, _ in rows} == {"route", "command", "reject"}


def test_every_listed_sample_matches_and_every_near_miss_does_not():
    rows = _lines()
    for sample in rpr.refusal_samples():
        if sample["expect"] == "read":
            assert _is_read_by_ere(rows, sample["path"]) == "route", sample
    for path in rpr.NOT_LISTED_SAMPLES:
        assert _is_read_by_ere(rows, path) is None, path


def test_command_routes_match_the_command_template_and_stay_exact():
    rows = _lines()
    for command in rpr.READ_COMMANDS:
        assert _is_read_by_ere(rows, command.sample) == "command"
        assert _is_read_by_ere(rows, command.sample + "/extra") is None
        assert _is_read_by_ere(rows, command.sample.upper()) is None


@pytest.mark.parametrize(
    "path",
    [
        "/v1/connector/consoles/c1/proxy/network/api/s/default/stat/session",
        "/v1/connector/consoles/c1/proxy/network/v2/api/site/default/traffic-flows?pageSize=5",
        "/v1/isp-metrics/1h/query",
    ],
)
def test_the_source_classifier_and_the_ere_agree_on_real_routes(path):
    rows = _lines()
    assert (rpr.read_post_route("POST", path) is not None) == (
        _is_read_by_ere(rows, path) == "route"
    )
