"""Test-harness ``UNIFI_TEST_*`` variables must not refuse server startup as retired names."""

from __future__ import annotations

import re
from pathlib import Path

from unifi_fabric.config import known_setting_names

ROOT = Path(__file__).resolve().parents[1]
_READ = re.compile(
    r"""(?:environ\.get|getenv|environ\[|setdefault)\(?\s*["'](UNIFI_TEST_[A-Z0-9_]+)["']"""
)


def _harness_reads() -> set[str]:
    names: set[str] = set()
    for base in ("tests", "scripts"):
        for path in (ROOT / base).rglob("*.py"):
            names.update(_READ.findall(path.read_text(encoding="utf-8")))
    return names


def test_every_harness_variable_the_tests_read_is_a_known_setting() -> None:
    reads = _harness_reads()
    assert "UNIFI_TEST_SELECTION_CACHE" in reads
    assert not reads - known_setting_names(), sorted(reads - known_setting_names())
