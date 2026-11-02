"""The chokepoint-class partition of the catalog (tests/_tool_classes.py)."""

from __future__ import annotations

import pytest

from tests import _tool_catalog, _tool_classes


def _names() -> list[str]:
    return sorted(t.name for t in _tool_catalog.tools())


def test_tool_classes_cover_every_tool():
    """Every registered tool is in exactly one batch and one class with a representative."""
    names = _names()
    _tool_classes.assert_covers_every_tool(names)
    for subset in (
        [n for n in names if _tool_classes.rw(n) == "read"],
        [n for n in names if _tool_classes.rw(n) == "write"],
    ):
        _tool_classes.assert_covers_every_tool(subset)


def test_tool_classes_are_statically_classified():
    """No tool falls outside the family or envelope classification."""
    names = _names()
    assert [n for n in names if _tool_classes.area(n) == "unclassified"] == []
    assert [n for n in names if _tool_classes.envelope_kind(n) == "unclassified"] == []


def test_runtime_classification_matches_the_static_source_indexes():
    """The fast classification used at collection equals the source-parsed indexes."""
    from unifi_fabric import families

    names = _names()
    static = _tool_classes.module_index()
    assert {n: _tool_classes.envelope_kind(n) for n in names} == {n: static.get(n) for n in names}
    fam = families.build_family_index()
    assert {n: _tool_classes.area(n) for n in names} == {n: fam.get(n) for n in names}


def test_tool_batches_never_exceed_the_batch_bound():
    names = _names()
    assert "list_hosts" in names
    batches = _tool_classes.batches(names)
    assert batches
    for batch in batches:
        assert 0 < len(batch.names) <= _tool_classes.MAX_BATCH, batch


def test_single_tool_batches_retain_full_catalog_coverage():
    names = _names()
    chunks = _tool_classes.batches(names, bound=1)
    assert all(len(batch.names) == 1 for batch in chunks)
    assert sorted(name for batch in chunks for name in batch.names) == names


_PROBE_TOOLS = ["list_hosts", "list_sites"]


def _isolation_probe(monkeypatch, name, seen):
    import os

    assert "PROBE_BATCH_ISOLATION" not in os.environ
    monkeypatch.setenv("PROBE_BATCH_ISOLATION", name)
    seen.append(name)


@_tool_classes.tool_batches("name", lambda: _PROBE_TOOLS)
def test_tool_batches_run_every_tool_with_a_fresh_monkeypatch(monkeypatch, name):
    _isolation_probe(monkeypatch, name, [])


def test_tool_batches_ran_every_tool():
    """The batching runs every tool of every batch, each with a fresh monkeypatch.

    Self-contained: it builds the batches and drives the same runner the collected items
    use, so it never depends on another test's side effects, worker or order."""
    import os

    seen: list[str] = []

    def probe(monkeypatch, name):
        _isolation_probe(monkeypatch, name, seen)

    run = _tool_classes._run_each(probe, "name")
    for batch in _tool_classes.batches(_PROBE_TOOLS):
        run(name=batch, monkeypatch=None)
    assert sorted(seen) == _PROBE_TOOLS
    assert "PROBE_BATCH_ISOLATION" not in os.environ


def test_tool_batches_report_every_failing_tool():
    calls: list[str] = []

    def body(monkeypatch, name):
        calls.append(name)
        assert name != "b", "b fails"
        if name == "c":
            raise RuntimeError("c fails")

    run = _tool_classes._run_each(body, "name")
    batch = _tool_classes.ToolBatch("probe", ("a", "b", "c", "d"))
    with pytest.raises(pytest.fail.Exception) as info:
        run(monkeypatch=None, name=batch)
    assert calls == ["a", "b", "c", "d"]
    text = str(info.value)
    assert "FAILED-TOOL b:" in text and "FAILED-TOOL c:" in text
    assert "FAILED-TOOL a" not in text and "FAILED-TOOL d" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
async def test_tool_batches_preserve_fixture_installed_server_state(monkeypatch, asynchronous):
    from unifi_fabric import server

    baseline = {name: object() for name in ("_settings", "_client", "_registry")}
    for name, value in baseline.items():
        monkeypatch.setattr(server, name, value)
    seen = []

    def body(monkeypatch, name):
        assert all(getattr(server, attr) is value for attr, value in baseline.items())
        seen.append(name)
        for attr in baseline:
            monkeypatch.setattr(server, attr, object())

    async def async_body(monkeypatch, name):
        body(monkeypatch, name)

    run = _tool_classes._run_each(async_body if asynchronous else body, "name")
    batch = _tool_classes.ToolBatch("fixture-baseline", ("a", "b"))
    if asynchronous:
        await run(monkeypatch=None, name=batch)
    else:
        run(monkeypatch=None, name=batch)
    assert seen == ["a", "b"]
    assert all(getattr(server, attr) is value for attr, value in baseline.items())


@pytest.mark.parametrize("derived", [False, True])
def test_class_axis_single_case_bound_preserves_every_combination(monkeypatch, derived):
    monkeypatch.setattr(_tool_classes, "rw", lambda name: "read")
    names = ["a", "b", "c"]
    member = (lambda name: True) if derived else None

    @_tool_classes.class_axis(
        "name",
        lambda: names,
        member=member,
        max_batch=1,
        mode=lambda: ("success", "failure"),
    )
    def probe(name, mode):
        pass

    mark = next(mark for mark in probe.pytestmark if mark.name == "lazy_parametrize")
    rows = mark.args[1]()
    assert all(len(batch.names) == 1 for _mode, batch in rows)
    assert sorted((mode, name) for mode, batch in rows for name in batch.names) == [
        (mode, name) for mode in ("failure", "success") for name in names
    ]
    assert len(rows) == 6


def test_class_axis_default_still_uses_axis_batch(monkeypatch):
    monkeypatch.setattr(_tool_classes, "rw", lambda name: "read")
    monkeypatch.setattr(_tool_classes, "AXIS_BATCH", 2)

    @_tool_classes.class_axis("name", lambda: ["a", "b", "c"], mode=lambda: ("only",))
    def probe(name, mode):
        pass

    mark = next(mark for mark in probe.pytestmark if mark.name == "lazy_parametrize")
    rows = mark.args[1]()
    assert [len(batch.names) for _mode, batch in rows] == [2, 1]
    assert sorted(name for _mode, batch in rows for name in batch.names) == ["a", "b", "c"]


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
async def test_selected_member_cannot_hide_a_runtime_skip(asynchronous, capsys):
    def body(name):
        if name == "not-exercised":
            pytest.skip("unexpected applicability change")

    async def async_body(name):
        body(name)

    run = _tool_classes._run_each(async_body if asynchronous else body, "name")
    batch = _tool_classes.ToolBatch("mixed", ("exercised", "not-exercised"))
    with pytest.raises(pytest.fail.Exception, match="FAILED-TOOL not-exercised"):
        if asynchronous:
            await run(name=batch)
        else:
            run(name=batch)
    report = capsys.readouterr().out
    assert "PASSED-TOOL exercised" in report
    assert "FAILED-TOOL not-exercised" in report


def test_applicability_filters_before_batching_and_reports_every_member(monkeypatch, capsys):
    from types import SimpleNamespace

    monkeypatch.setattr(_tool_classes, "batch_key", lambda name: ("probe", "read"))
    checked, executed = [], []

    def eligible(name):
        checked.append(name)
        return name != "inapplicable"

    @_tool_classes.tool_batches("name", lambda: ["a", "inapplicable", "b"], eligible=eligible)
    def body(name):
        executed.append(name)

    mark = next(mark for mark in body.pytestmark if mark.name == "lazy_parametrize")
    batches = mark.args[1]()
    assert checked == ["a", "inapplicable", "b"]
    assert [name for batch in batches for name in batch.names] == ["a", "b"]
    request = SimpleNamespace(node=SimpleNamespace(user_properties=[]))
    for batch in batches:
        body(name=batch, request=request)
    assert executed == ["a", "b"]
    assert request.node.user_properties == [
        ("tool_outcome", "a: passed"),
        ("tool_outcome", "b: passed"),
    ]
    report = capsys.readouterr().out
    assert "PASSED-TOOL a" in report and "PASSED-TOOL b" in report


def test_unexpected_applicability_baseline_error_fails_collection():
    def eligible(name):
        raise RuntimeError("bad baseline")

    with pytest.raises(
        AssertionError, match="a: applicability baseline failed: RuntimeError: bad baseline"
    ):
        _tool_classes._select_entries(["a"], eligible=eligible)
