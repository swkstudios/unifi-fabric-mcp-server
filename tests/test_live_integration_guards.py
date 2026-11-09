"""Offline checks for the live integration test safety gates.

The live-mutation gate (``tests/_live_gates.py``) runs from ``tests/conftest.py``'s
``pytest_runtest_setup`` for every item. The pytester runs below load that real hook into
an inner session whose mutating class creates "live" state in a class-scoped fixture (the
shape of ``TestVLANCRUDIntegration.created_vlan``) and check the state is never created
by an unauthorized run.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import _live_gates
from tests import test_protect_integration as live

pytest_plugins = ["pytester"]

TESTS = Path(__file__).resolve().parent

INNER_INI = """
[pytest]
addopts = -m 'not mutating'
asyncio_default_fixture_loop_scope = function
markers =
    integration: live-console test
    mutating: live write
"""

INNER_CONFTEST = "from tests.conftest import pytest_runtest_setup  # noqa: F401\n"

INNER_MODULE = """
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
CREATED = Path(__file__).with_name("created")


def test_live_read():
    pass


@pytest.mark.mutating
class TestLiveWrite:
    @pytest.fixture(scope="class")
    def created(self):
        CREATED.write_text("live state")
        yield

    def test_write(self, created):
        pass
"""

REFUSED_SELECTION = "*select it explicitly with -m mutating*"
REFUSED_ENV = "*Set UNIFI_TEST_ALLOW_MUTATIONS=1*"
REFUSED_POLICY = "*set UNIFI_WRITE_POLICY=allow*"


def test_live_host_precondition_fails(monkeypatch):
    monkeypatch.setattr(live, "_TEST_HOST", "")
    with pytest.raises(pytest.fail.Exception, match="UNIFI_TEST_HOST"):
        live._require_host()


def _inner(pytester, monkeypatch, *, allow: str | None, policy: str | None):
    pytester.makeini(INNER_INI)
    pytester.makeconftest(INNER_CONFTEST)
    pytester.makepyfile(test_inner=INNER_MODULE)
    for name, value in (("UNIFI_TEST_ALLOW_MUTATIONS", allow), ("UNIFI_WRITE_POLICY", policy)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    return pytester.path / "created"


@pytest.mark.parametrize(
    ("markexpr", "allow", "policy", "refusal", "reads"),
    [
        # -m replaces addopts' "not mutating": every live write would be collected.
        ("integration", "1", "allow", REFUSED_SELECTION, 1),
        ("", "1", "allow", REFUSED_SELECTION, 1),
        ("integration or mutating", "1", "allow", REFUSED_SELECTION, 1),
        ("not mutating or integration", "1", "allow", REFUSED_SELECTION, 1),
        ("mutating", None, "allow", REFUSED_ENV, 0),
        ("mutating", "0", "allow", REFUSED_ENV, 0),
        ("integration and mutating", "1", "dry-run", REFUSED_POLICY, 0),
        ("mutating", "1", "deny", REFUSED_POLICY, 0),
    ],
    ids=[
        "m-integration",
        "m-empty",
        "m-integration-or-mutating",
        "m-not-mutating-or-integration",
        "allow-unset",
        "allow-0",
        "policy-dry-run",
        "policy-deny",
    ],
)
def test_unauthorized_mutation_fails_before_its_class_fixture(
    pytester, monkeypatch, markexpr, allow, policy, refusal, reads
):
    created = _inner(pytester, monkeypatch, allow=allow, policy=policy)
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-m", markexpr)
    result.assert_outcomes(passed=reads, errors=1)
    result.stdout.fnmatch_lines([refusal])
    assert not created.exists(), "the class-scoped fixture created live state before the gate"


@pytest.mark.parametrize("markexpr", ["mutating", "integration and mutating"])
def test_authorized_mutation_runs(pytester, monkeypatch, markexpr):
    created = _inner(pytester, monkeypatch, allow="1", policy="allow")
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-m", markexpr)
    result.assert_outcomes(passed=1)
    assert created.read_text() == "live state"


def test_mutating_test_must_also_be_integration(pytester, monkeypatch):
    created = _inner(pytester, monkeypatch, allow="1", policy="allow")
    pytester.makepyfile(test_inner=INNER_MODULE.replace("pytestmark = pytest.mark.integration", ""))
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-m", "mutating")
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*a mutating test must also be marked integration*"])
    assert not created.exists()


def _item(*names: str, markexpr: str):
    marks = [getattr(pytest.mark, name).mark for name in names]
    return SimpleNamespace(
        iter_markers=lambda: iter(marks),
        get_closest_marker=lambda name: next((m for m in marks if m.name == name), None),
        config=SimpleNamespace(option=SimpleNamespace(markexpr=markexpr)),
        nodeid="tests/test_x.py::TestX::test_x",
    )


@pytest.mark.parametrize(
    ("markexpr", "expected"),
    [
        ("mutating", True),
        ("integration and mutating", True),
        ("mutating and not slow", True),
        ("integration", False),
        ("", False),
        ("not mutating", False),
        ("integration or mutating", False),
    ],
)
def test_selected_as_mutating(markexpr, expected):
    item = _item("integration", "mutating", markexpr=markexpr)
    assert _live_gates.selected_as_mutating(markexpr, item) is expected


def test_non_mutating_items_pass_the_gate_untouched():
    _live_gates.authorize_live_mutation(_item("integration", markexpr="integration"))


def _uses_mutating_mark(tree: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Attribute)
        and n.attr == _live_gates.MUTATING
        and isinstance(n.value, ast.Attribute)
        and n.value.attr == "mark"
        for n in ast.walk(tree)
    )


def test_mutating_marks_live_only_in_integration_modules():
    """Every module using ``pytest.mark.mutating`` is an integration module (inventory floor)."""
    mutating_modules = set()
    for path in sorted(TESTS.glob("test_*.py")):
        source = path.read_text()
        if _uses_mutating_mark(ast.parse(source, filename=str(path))):
            mutating_modules.add(path.name)
            assert "pytest.mark.integration" in source, f"{path.name}: mutating, not integration"
    assert {"test_networks_integration.py", "test_protect_integration.py"} <= mutating_modules
