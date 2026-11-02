"""The untraced measurement child is unobserved, measures real peaks and fails loudly."""

from __future__ import annotations

import subprocess
import sys
import tracemalloc

import pytest

from tests import _untraced as untraced

BLOCK = 8 * 1024 * 1024


def observed_state():
    """Run in the child: what observes it, and a known allocation's traced peak."""
    state = {
        "trace": sys.gettrace() is not None,
        "profile": sys.getprofile() is not None,
        "monitoring": [t for t in range(6) if sys.monitoring.get_tool(t) is not None],
        "coverage": "coverage" in sys.modules,
        "tracing_before": tracemalloc.is_tracing(),
    }
    tracemalloc.start()
    try:
        block = bytearray(BLOCK)
        del block
        state["peak"] = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return state


def explode():
    raise RuntimeError("child-side failure marker")


def test_child_is_unobserved_and_measures_the_peak():
    state = untraced.run("tests.test_untraced:observed_state")
    assert state.pop("peak") >= BLOCK
    assert state == {
        "trace": False,
        "profile": False,
        "monitoring": [],
        "coverage": False,
        "tracing_before": False,
    }


def test_child_environment_drops_tracer_and_product_settings(monkeypatch):
    monkeypatch.setenv("COVERAGE_PROCESS_START", "pyproject.toml")
    monkeypatch.setenv("COV_CORE_SOURCE", "src")
    monkeypatch.setenv("PYTHONTRACEMALLOC", "1")
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    env = untraced.child_env()
    for name in ("COVERAGE_PROCESS_START", "COV_CORE_SOURCE", "PYTHONTRACEMALLOC"):
        assert name not in env
    assert "UNIFI_REDACT_SECRETS" not in env
    # Even with those set in the parent, the child runs unobserved.
    state = untraced.run("tests.test_untraced:observed_state")
    assert not state["coverage"] and not state["tracing_before"]


@pytest.mark.parametrize(
    "observer",
    [
        "sys.settrace(lambda *a: None)",
        "sys.setprofile(lambda *a: None)",
        "sys.monitoring.use_tool_id(sys.monitoring.COVERAGE_ID, 'probe')",
        "import tracemalloc; tracemalloc.start()",
    ],
)
def test_child_refuses_to_measure_when_observed(observer, tmp_path):
    prelude = f"import sys\n{observer}\n"
    out = tmp_path / "result.json"
    args = [str(untraced.ROOT), "tests.test_untraced:observed_state", "[]", str(out)]
    proc = subprocess.run(  # noqa: S603 -- fixed interpreter and in-repo script
        [sys.executable, "-I", "-c", prelude + untraced._CHILD, *args],
        cwd=untraced.ROOT,
        env=untraced.child_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "measurement child is observed" in proc.stderr
    assert not out.exists()


def test_child_failure_fails_the_caller_with_its_output():
    with pytest.raises(AssertionError, match="child-side failure marker"):
        untraced.run("tests.test_untraced:explode")
