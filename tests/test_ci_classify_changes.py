"""Tests for the conservative private CI change classifier."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "ci_classify_changes", ROOT / "scripts" / "ci_classify_changes.py"
)
assert _spec and _spec.loader
classifier = importlib.util.module_from_spec(_spec)
sys.modules.setdefault(_spec.name, classifier)
_spec.loader.exec_module(classifier)


def test_documentation_only_change_stays_fast(tmp_path):
    decision = classifier.classify({"docs/CONFIGURATION.md", "README.md"}, root=tmp_path)
    assert decision.tier == "fast"


def test_one_tool_module_uses_its_test_and_shared_invariants(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_clients.py").touch()

    decision = classifier.classify(
        {
            "src/unifi_fabric/tools/clients.py",
            "tests/test_clients.py",
            "changelog.d/clients.fixed.md",
        },
        root=tmp_path,
    )

    assert decision.tier == "targeted"
    assert decision.test_file == "tests/test_clients.py"


def test_missing_matching_test_escalates_to_full(tmp_path):
    decision = classifier.classify({"src/unifi_fabric/tools/clients.py"}, root=tmp_path)
    assert decision.tier == "full"
    assert "absent" in decision.reason


def test_shared_or_unknown_path_escalates_to_full(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_clients.py").touch()

    decision = classifier.classify(
        {"src/unifi_fabric/tools/clients.py", "src/unifi_fabric/client.py"}, root=tmp_path
    )

    assert decision.tier == "full"


def test_force_full_does_not_need_a_git_diff(tmp_path):
    decision = classifier.classify([], root=tmp_path, force_full=True)
    assert decision.tier == "full"
