"""Smoke mode is opt-in, deterministic and leaves ordinary tests alone."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tests import _pr_smoke as smoke
from tests._tool_classes import ToolBatch


def test_sample_is_deterministic_and_in_input():
    batch = ToolBatch("synthetic", ("z", "a", "b"))
    with patch("tests._tool_classes.class_of", side_effect=lambda n: (n, "read", "test")):
        first = smoke.sample_batch(batch, "family")
        second = smoke.sample_batch(batch, "family")
    assert first.names == second.names
    assert set(first.names) == set(batch.names)
    assert not getattr(first, "stop_after_outcome", False)
    assert batch.names == ("z", "a", "b")


def test_hook_does_not_sample_full_tier_or_ordinary_tests():
    for enabled, path in [(False, "tests/test_invariants_x.py"), (True, "tests/test_discovery.py")]:
        calls = [SimpleNamespace(params={"value": i}) for i in range(4)]
        metafunc = SimpleNamespace(
            config=SimpleNamespace(getoption=lambda _, enabled=enabled: enabled),
            definition=SimpleNamespace(path=path),
            _calls=calls,
        )
        hook = smoke.pytest_generate_tests(metafunc)
        next(hook)
        try:
            next(hook)
        except StopIteration:
            pass
        assert metafunc._calls == calls and len(calls) == 4


def test_smoke_batch_runs_each_class_and_release_keeps_all():
    import pytest

    from tests._tool_classes import _run_each

    seen = []

    def body(name):
        seen.append(name)
        if name == "skip":
            pytest.skip("not this class")

    wrapped = _run_each(body, "name")
    with (
        patch("tests._tool_classes._reset_server_state", return_value=None),
        patch("tests._tool_classes._restore_server_state"),
    ):
        with patch("tests._tool_classes.class_of", side_effect=lambda n: (n, "read", "test")):
            batch = smoke.sample_batch(ToolBatch("smoke", ("skip", "pass", "later")), "family")
        with pytest.raises(pytest.fail.Exception, match="FAILED-TOOL skip"):
            wrapped(name=batch)
        assert set(seen) == {"skip", "pass", "later"}
        seen.clear()
        with pytest.raises(pytest.fail.Exception, match="FAILED-TOOL skip"):
            wrapped(name=ToolBatch("full", ("skip", "pass", "later")))
        assert seen == ["skip", "pass", "later"]


def test_axis_key_handles_inputs_that_reject_repr():
    class Extreme:
        def __repr__(self):
            raise ValueError("decimal digit limit")

    assert smoke.axis_key(Extreme(), 7) == "Extreme parameter 7"


def test_fixed_eligible_member_takes_precedence_within_its_class():
    with (
        patch.dict(smoke.PREFERRED_TOOLS, {"family": "b"}),
        patch("tests._tool_classes.class_of", return_value=("app", "read", "envelope")),
    ):
        sampled = smoke.sample_batch(ToolBatch("test", ("a", "b", "c")), "family")
    assert sampled.names == ("b",)


def test_every_explicit_suite_uses_the_same_sampling_policy():
    from scripts.select_pr_tests import SMOKE_TEST_FILES

    assert all(smoke.invariant_file(name) for name in SMOKE_TEST_FILES)
    assert not smoke.invariant_file("tests/test_unrelated_catalog_helper.py")


@pytest.mark.parametrize("as_objects", [False, True])
def test_unbatched_tool_rows_keep_every_class_in_one_harness_scenario(as_objects):
    from dataclasses import dataclass

    @dataclass
    class Call:
        params: dict
        indices: dict

    calls = [
        Call(
            {"name": SimpleNamespace(name=name) if as_objects else name, "status": status},
            {"name": i, "status": j},
        )
        for j, status in enumerate([200, 400, 500])
        for i, name in enumerate(["b", "a", "c"])
    ]
    metafunc = SimpleNamespace(
        config=SimpleNamespace(getoption=lambda _: True),
        definition=SimpleNamespace(path="tests/test_secret_leak_invariant.py"),
        function=SimpleNamespace(__name__="family"),
        _calls=calls,
    )
    with (
        patch("tests._tool_classes.runtime_module_index", return_value={"a": 1, "b": 1, "c": 1}),
        patch(
            "tests._tool_classes.class_of",
            side_effect=lambda n: ("shared" if n in {"a", "b"} else "other", "read", "test"),
        ),
    ):
        hook = smoke.pytest_generate_tests(metafunc)
        next(hook)
        try:
            next(hook)
        except StopIteration:
            pass
    assert {
        (r.params["name"].name if as_objects else r.params["name"], r.params["status"])
        for r in calls
    } == {("a", 200), ("c", 200)}


def test_preferred_tool_selects_one_harness_row_and_all_classes():
    from dataclasses import dataclass

    @dataclass
    class Call:
        params: dict
        indices: dict

    calls = [
        Call({"name": name, "status": status}, {"name": i, "status": j})
        for j, (status, names) in enumerate(
            [(200, ["a", "c"]), (400, ["b", "c"]), (500, ["a", "c"])]
        )
        for i, name in enumerate(names)
    ]
    metafunc = SimpleNamespace(
        config=SimpleNamespace(getoption=lambda _: True),
        definition=SimpleNamespace(path="tests/test_secret_leak_invariant.py"),
        function=SimpleNamespace(__name__="family"),
        _calls=calls,
    )
    with (
        patch.dict(smoke.PREFERRED_TOOLS, {"family": "b"}),
        patch("tests._tool_classes.runtime_module_index", return_value={"a": 1, "b": 1, "c": 1}),
        patch(
            "tests._tool_classes.class_of",
            side_effect=lambda n: ("shared" if n in {"a", "b"} else "other", "read", "test"),
        ),
    ):
        hook = smoke.pytest_generate_tests(metafunc)
        next(hook)
        try:
            next(hook)
        except StopIteration:
            pass
    assert {(row.params["name"], row.params["status"]) for row in calls} == {
        ("b", 400),
        ("c", 400),
    }


def test_axis_rows_are_retained_when_they_contain_a_missing_tool_class():
    from dataclasses import dataclass

    @dataclass
    class Call:
        params: dict
        indices: dict

    calls = [
        Call({"name": "a", "status": 200}, {"name": 0, "status": 0}),
        Call({"name": "b", "status": 400}, {"name": 1, "status": 1}),
        Call({"name": "a", "status": 500}, {"name": 2, "status": 2}),
    ]
    metafunc = SimpleNamespace(
        config=SimpleNamespace(getoption=lambda _: True),
        definition=SimpleNamespace(path="tests/test_secret_leak_invariant.py"),
        function=SimpleNamespace(__name__="family"),
        _calls=calls,
    )
    with (
        patch.dict(smoke.PREFERRED_TOOLS, {}, clear=False),
        patch("tests._tool_classes.runtime_module_index", return_value={"a": 1, "b": 1}),
        patch(
            "tests._tool_classes.class_of",
            side_effect=lambda n: (n, "read", "test"),
        ),
    ):
        hook = smoke.pytest_generate_tests(metafunc)
        next(hook)
        try:
            next(hook)
        except StopIteration:
            pass
    assert {(row.params["name"], row.params["status"]) for row in calls} == {
        ("a", 200),
        ("b", 400),
    }


def test_batched_axis_rows_cover_classes_missing_from_the_first_row():
    from dataclasses import dataclass

    @dataclass
    class Call:
        params: dict
        indices: dict

    rows = [
        Call(
            params={"name": ToolBatch("first", ("a",)), "status": 200},
            indices={"name": 0, "status": 0},
        ),
        Call(
            params={"name": ToolBatch("second", ("b",)), "status": 400},
            indices={"name": 1, "status": 1},
        ),
        Call(
            params={"name": ToolBatch("last", ("a",)), "status": 500},
            indices={"name": 2, "status": 2},
        ),
    ]
    metafunc = SimpleNamespace(
        config=SimpleNamespace(getoption=lambda _: True),
        definition=SimpleNamespace(path="tests/test_cross_tool_invariants.py"),
        function=SimpleNamespace(__name__="family"),
        _calls=rows,
    )
    with (
        patch("tests._tool_classes.runtime_module_index", return_value={"a": 1, "b": 1}),
        patch("tests._tool_classes.class_of", side_effect=lambda name: (name, "read", "test")),
    ):
        hook = smoke.pytest_generate_tests(metafunc)
        next(hook)
        with pytest.raises(StopIteration):
            next(hook)
    assert {(row.params["name"].names, row.params["status"]) for row in rows} == {
        (("a",), 200),
        (("b",), 400),
    }


@pytest.mark.parametrize("batched", [False, True])
def test_non_manifest_catalog_consumers_keep_every_class(batched):
    from _pytest.python import CallSpec2

    calls = []
    for index, tool in enumerate(("alpha", "beta", "gamma")):
        calls.append(
            CallSpec2(
                params={"tool": ToolBatch(tool, (tool,)) if batched else tool},
                indices={"tool": index},
            )
        )
    metafunc = SimpleNamespace(
        config=SimpleNamespace(getoption=lambda _: True),
        definition=SimpleNamespace(path="tests/test_catalog_consumer.py"),
        function=SimpleNamespace(__name__="test_family"),
        _calls=calls,
    )
    classes = {
        "alpha": ("a", "read", "x"),
        "beta": ("a", "read", "x"),
        "gamma": ("b", "write", "y"),
    }
    with (
        patch("tests._tool_classes.runtime_module_index", return_value=dict.fromkeys(classes)),
        patch("tests._tool_classes.class_of", side_effect=classes.__getitem__),
    ):
        hook = smoke.pytest_generate_tests(metafunc)
        next(hook)
        with pytest.raises(StopIteration):
            next(hook)
    selected = {
        tool
        for row in calls
        for tool in (row.params["tool"].names if batched else (row.params["tool"],))
    }
    assert selected == {"alpha", "gamma"}


def _hook(metafunc):
    hook = smoke.pytest_generate_tests(metafunc)
    next(hook)
    try:
        next(hook)
    except StopIteration:
        pass


def _focus_config(tmp_path, modules, enabled=True):
    focus = tmp_path / "focus.txt"
    focus.write_text("".join(f"{module}\n" for module in modules))
    options = {"--pr-smoke": enabled, "--pr-smoke-focus": str(focus)}
    return SimpleNamespace(getoption=options.__getitem__)


@pytest.mark.parametrize(
    "path", ["tests/test_module_owned.py", "tests/test_secret_leak_invariant.py"]
)
def test_focus_keeps_every_harness_row_of_a_changed_modules_tools(tmp_path, path):
    from dataclasses import dataclass

    @dataclass
    class Call:
        params: dict
        indices: dict

    calls = [
        Call({"name": name, "body": body}, {"name": i, "body": j})
        for j, body in enumerate(["dict", "list", "none"])
        for i, name in enumerate(["create_a", "delete_a", "list_b"])
    ]
    metafunc = SimpleNamespace(
        config=_focus_config(tmp_path, ["mod_a"]),
        definition=SimpleNamespace(path=path),
        function=SimpleNamespace(__name__="family"),
        _calls=calls,
    )
    modules = {"create_a": "mod_a", "delete_a": "mod_a", "list_b": "mod_b"}
    with (
        patch("tests._tool_classes.runtime_module_index", return_value=modules),
        patch("tests._tool_classes.class_of", side_effect=lambda n: ("area", "rw", "env")),
    ):
        _hook(metafunc)
    kept = {(r.params["name"], r.params["body"]) for r in calls}
    # Every mod_a row in every body; mod_b only through the class sample.
    assert {(n, b) for n in ("create_a", "delete_a") for b in ("dict", "list", "none")} <= kept
    assert not any(name == "list_b" for name, _ in kept)


def test_focus_keeps_a_changed_modules_batch_entries(tmp_path):
    batch = ToolBatch("synthetic", ("a1", "a2", "b1", "b2"))
    modules = {"a1": "mod_a", "a2": "mod_a", "b1": "mod_b", "b2": "mod_b"}
    with (
        patch("tests._tool_classes.runtime_module_index", return_value=modules),
        patch("tests._tool_classes.class_of", return_value=("area", "rw", "env")),
    ):
        sampled = smoke.sample_batch(batch, "family", frozenset({"mod_b"}))
        unfocused = smoke.sample_batch(batch, "family")
    assert unfocused.names == ("a1",)
    assert sampled.names == ("a1", "b1", "b2")


def test_focus_keeps_a_batch_harness_row_holding_a_changed_module(tmp_path):
    from dataclasses import dataclass

    @dataclass
    class Call:
        params: dict
        indices: dict

    calls = [
        Call({"names": ToolBatch(f"b{j}", names), "status": status}, {"names": 0, "status": j})
        for j, (status, names) in enumerate([(200, ("a1",)), (400, ("a1", "b1"))])
    ]
    metafunc = SimpleNamespace(
        config=_focus_config(tmp_path, ["mod_b"]),
        definition=SimpleNamespace(path="tests/test_secret_leak_invariant.py"),
        function=SimpleNamespace(__name__="family"),
        _calls=calls,
    )
    with (
        patch("tests._tool_classes.runtime_module_index", return_value={"a1": "a", "b1": "b"}),
        patch("tests._tool_classes.class_of", return_value=("area", "rw", "env")),
    ):
        _hook(metafunc)
    # No changed module: one harness row covers the only class.
    assert [(c.params["status"], c.params["names"].names) for c in calls] == [(200, ("a1",))]
    calls[:] = [
        Call({"names": ToolBatch(f"b{j}", names), "status": status}, {"names": 0, "status": j})
        for j, (status, names) in enumerate([(200, ("a1",)), (400, ("a1", "b1"))])
    ]
    with (
        patch(
            "tests._tool_classes.runtime_module_index",
            return_value={"a1": "mod_a", "b1": "mod_b"},
        ),
        patch("tests._tool_classes.class_of", return_value=("area", "rw", "env")),
    ):
        _hook(metafunc)
    # The row holding the changed module's tool runs too, with that tool in its batch.
    assert [(c.params["status"], c.params["names"].names) for c in calls] == [
        (200, ("a1",)),
        (400, ("a1", "b1")),
    ]


def test_focus_file_is_required_to_exist_when_named(tmp_path):
    config = SimpleNamespace(
        getoption={"--pr-smoke-focus": str(tmp_path / "missing.txt")}.__getitem__
    )
    with pytest.raises(pytest.UsageError, match="--pr-smoke-focus"):
        smoke.focus_modules(config)
    assert smoke.focus_modules(SimpleNamespace(getoption=lambda _: None)) == frozenset()


def test_a_changed_test_node_keeps_every_case(tmp_path):
    focus = tmp_path / "focus.txt"
    focus.write_text("tests/test_x.py::test_changed\ntests/test_x.py::TestGroup\n")
    options = {"--pr-smoke": True, "--pr-smoke-focus": str(focus)}
    config = SimpleNamespace(getoption=options.__getitem__)
    assert smoke.focus_node(config, "tests/test_x.py::test_changed")
    assert smoke.focus_node(config, "tests/test_x.py::TestGroup::test_member")
    assert not smoke.focus_node(config, "tests/test_x.py::test_changed_too")
    assert not smoke.focus_node(config, "tests/test_x.py::test_other")
    assert smoke.focus_modules(config) == frozenset()
    calls = [SimpleNamespace(params={"name": name}) for name in ("a", "b")]
    metafunc = SimpleNamespace(
        config=config,
        definition=SimpleNamespace(
            path="tests/test_secret_leak_invariant.py", nodeid="tests/test_x.py::test_changed"
        ),
        _calls=calls,
    )
    _hook(metafunc)
    assert [c.params["name"] for c in calls] == ["a", "b"]
