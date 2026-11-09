"""No test is switched off by a static marker.

A ``pytest.mark.skip`` or ``pytest.mark.xfail`` marker, a ``skipif`` on a constant and a
``pytest.importorskip`` of a locked dependency all keep a test collected while it checks
nothing, and they outlive the reason they were added for; so does a bare ``pytest.skip()``
or ``pytest.xfail()`` that names no reason. Conditional skips that name a live
environment reason (an opt-in env var, a platform, a missing binary) stay allowed.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def static_skips(source: str) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and _dotted(node) in {
            "pytest.mark.skip",
            "pytest.mark.xfail",
        }:
            found.append(f"{node.lineno}: {_dotted(node)}")
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name == "pytest.importorskip":
                found.append(f"{node.lineno}: pytest.importorskip")
            if name in {"pytest.skip", "pytest.xfail"} and not node.args and not node.keywords:
                found.append(f"{node.lineno}: bare {name}()")
            if (
                name in {"pytest.mark.skipif", "unittest.skipIf", "unittest.skipUnless"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                found.append(f"{node.lineno}: {name}({node.args[0].value!r})")
    return found


def test_no_static_skip_markers_in_tests() -> None:
    offenders = [
        f"{path.relative_to(TESTS.parent)}:{hit}"
        for path in sorted(TESTS.rglob("*.py"))
        for hit in static_skips(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"statically skipped or xfailed tests: {offenders}"


def test_detector_catches_each_static_form() -> None:
    source = """
import pytest
pytest.importorskip("x")
@pytest.mark.skip(reason="later")
def test_a(): ...
@pytest.mark.xfail(strict=True, reason="flips later")
def test_b(): ...
@pytest.mark.skipif(True, reason="off")
def test_c(): ...
P = pytest.param("t", marks=pytest.mark.skip(reason="later"))
@pytest.mark.skipif(not ENV, reason="live only")
def test_live(): ...
def test_d():
    pytest.skip()
def test_e():
    pytest.xfail()
def test_env():
    if not ENV:
        pytest.skip("UNIFI_TEST_HOST must be set")
"""
    hits = static_skips(source)
    assert len(hits) == 7, hits
    assert not any("must be set" in hit for hit in hits)
    assert not any("ENV" in hit for hit in hits)
