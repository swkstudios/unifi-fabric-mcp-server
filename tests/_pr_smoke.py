"""Opt-in development smoke: every suite/function, deterministic tool-class samples.

Keep the fewest deterministic harness scenarios needed to cover one tool per (area,
rw, envelope) class. Functions with a preferred tool start from its first scenario;
other functions start from the first scenario, then add a row only if it contains a
class not covered yet. This reduces repeated harness variations while keeping every
function family and tool class represented. The same policy applies to selected catalog
consumers outside the invariant manifest; ordinary unit parameter cases stay intact.
Every sampled class runs, including classes following a passing or failing tool.
Full/release runs never enable this plugin mode.

Changed code is never sampled: --pr-smoke-focus names the file that
scripts/select_pr_tests.py --focus-output writes. A line without "::" is a changed tool
module: every collected case whose tool belongs to it runs, in every harness row, beside
the class sample, so a module's own tests keep their whole parameter surface. A
"path::name" line is a changed test function or class: all of its cases run.
"""

from __future__ import annotations

import dataclasses
import functools
import os
from pathlib import Path

import pytest

from scripts.select_pr_tests import SMOKE_TEST_FILES

# Verified eligible class members at 04d56963. Runtime-derived predicates can
# exclude the lexical member of an otherwise applicable tool class.
PREFERRED_TOOLS = {
    "test_ca_two_key_merge_keeps_each_keys_envelope": "get_isp_metrics",
    "test_br_a_value_of_another_type_is_never_already_applied": "suspend_carrier_subscriber",
    "test_h_capped_lookup_miss_says_list_incomplete": "get_radius_profile",
    "test_i_by_key_kept_for_envelope_less_keys": "get_isp_metrics",
    "test_bd_spec_query_parameters_reachable": "delete_rtsps_stream",
}


def pytest_addoption(parser):
    parser.addoption(
        "--pr-smoke", action="store_true", help="sample invariant families for development"
    )
    parser.addoption(
        "--pr-smoke-focus",
        default=None,
        help="file listing the changed tool modules and test nodes smoke mode never samples",
    )


@functools.cache
def _read_focus(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise pytest.UsageError(f"--pr-smoke-focus: cannot read {path}: {exc}") from exc
    return frozenset(line.strip() for line in text.splitlines() if line.strip())


def _focus_entries(config):
    path = config.getoption("--pr-smoke-focus")
    if not isinstance(path, str | os.PathLike) or not str(path):
        return frozenset()
    return _read_focus(os.fspath(path))


def focus_modules(config):
    """The changed tool modules named by --pr-smoke-focus (empty when not given)."""
    return frozenset(entry for entry in _focus_entries(config) if "::" not in entry)


def focus_node(config, nodeid):
    """True when --pr-smoke-focus names this test node or its enclosing class."""
    return bool(nodeid) and any(
        nodeid == entry or nodeid.startswith(entry + "::")
        for entry in _focus_entries(config)
        if "::" in entry
    )


def invariant_file(path):
    return f"tests/{Path(path).name}" in SMOKE_TEST_FILES


def sample_batch(batch, family, focus=frozenset()):
    from tests._tool_classes import ToolBatch, class_of, runtime_module_index, tool_of

    classes = {}
    for entry in batch.names:
        name = tool_of(entry)
        classes.setdefault(class_of(name), []).append(entry)
    keys = sorted(classes)
    preferred = PREFERRED_TOOLS.get(family)
    if preferred in (tool_of(e) for e in batch.names):
        preferred_class = class_of(preferred)
        keys = [preferred_class, *(k for k in keys if k != preferred_class)]
    chosen = tuple(
        min(classes[key], key=lambda e: (tool_of(e) != preferred, repr(e))) for key in keys
    )
    if focus:
        # Every entry of a changed module runs beside the class sample.
        modules = runtime_module_index()
        chosen += tuple(
            e for e in batch.names if e not in chosen and modules.get(tool_of(e)) in focus
        )
    return ToolBatch(batch.id + "-smoke", chosen)


def axis_key(value, index):
    try:
        return repr(value)
    except ValueError:
        # Deliberately huge integer test inputs exceed Python's decimal repr limit.
        return f"{type(value).__name__} parameter {index}"


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_generate_tests(metafunc):
    yield
    if not metafunc.config.getoption("--pr-smoke"):
        return
    if focus_node(metafunc.config, getattr(metafunc.definition, "nodeid", "")):
        return  # A changed test runs every case.
    from tests._tool_classes import ToolBatch, class_of, runtime_module_index, tool_of

    calls = metafunc._calls
    focus = focus_modules(metafunc.config)
    # Group by harness axes, pooling tool batches before selecting one scenario.
    # Keep the family present in smoke while avoiding repeating the full class sweep
    # for every harness variation. A declared preferred tool chooses its scenario.
    known_tools = runtime_module_index() if calls else {}

    def tool_name(value):
        if isinstance(value, str) and value in known_tools:
            return value
        registered_name = getattr(value, "name", None)
        if isinstance(registered_name, str) and registered_name in known_tools:
            return registered_name
        if isinstance(value, tuple) and value and isinstance(value[0], str):
            return value[0] if value[0] in known_tools else None
        return None

    tool_axes = {
        name
        for call in calls
        for name, value in call.params.items()
        if tool_name(value) is not None
    }

    def focus_row(row):
        """True when the row runs a tool of a changed module (tool axis or batch)."""
        for name, value in row.params.items():
            if name in tool_axes and known_tools.get(tool_name(value)) in focus:
                return True
            if isinstance(value, ToolBatch) and any(
                known_tools.get(tool_of(entry)) in focus for entry in value.names
            ):
                return True
        return False

    # Selected consumers outside the smoke manifest can also have catalog axes.
    # Sample those by the identical class policy, leaving ordinary unit cases intact.
    if (
        not invariant_file(metafunc.definition.path)
        and not tool_axes
        and not any(
            isinstance(value, ToolBatch) for call in calls for value in call.params.values()
        )
    ):
        return
    groups = {}
    for call in calls:
        key = tuple(
            (n, axis_key(v, call.indices[n]))
            for n, v in call.params.items()
            if not isinstance(v, ToolBatch) and n not in tool_axes
        )
        groups.setdefault(key, []).append(call)
    keys = list(groups)
    indices = {0} if keys else set()
    preferred = PREFERRED_TOOLS.get(metafunc.function.__name__)
    if preferred:
        preferred_indices = {
            i
            for i, key in enumerate(keys)
            if any(
                isinstance(v, str) and v == preferred
                for row in groups[key]
                for v in row.params.values()
            )
        }
        if preferred_indices:
            indices = {min(preferred_indices)}
    if keys:
        # Some scenario groups may contain tool classes absent from the default
        # (or preferred) row. Retain a stable set of rows that covers every class
        # present anywhere in this function's collected input.
        def group_classes(group):
            found = set()
            for row in group:
                if tool_axes:
                    found.add(
                        tuple(
                            (name, class_of(tool_name(value)) if tool_name(value) else None)
                            for name, value in row.params.items()
                            if name in tool_axes
                        )
                    )
                else:
                    for name, value in row.params.items():
                        if isinstance(value, ToolBatch):
                            found.update((name, class_of(tool_of(entry))) for entry in value.names)
            return found

        coverage = {i: group_classes(groups[keys[i]]) for i in range(len(keys))}
        covered = set().union(*(coverage[i] for i in indices))
        for i in range(len(keys)):
            if coverage[i] - covered:
                indices.add(i)
                covered.update(coverage[i])
        if focus and not tool_axes:
            # A harness row whose batches hold a changed module's tool always runs.
            indices.update(i for i in range(len(keys)) if any(map(focus_row, groups[keys[i]])))
    indices = sorted(indices)
    selected = []
    for i in indices:
        group = groups[keys[i]]
        if tool_axes:
            representatives = {}
            for row in group:
                classes = tuple(
                    (name, class_of(tool_name(value)) if tool_name(value) else None)
                    for name, value in row.params.items()
                    if name in tool_axes
                )
                # Original collection order is stable; prefer the lexical tool
                # within a class, with its original compound-case order as tie-break.
                order = tuple(tool_name(row.params[name]) or "" for name in sorted(tool_axes))
                if classes not in representatives or order < representatives[classes][0]:
                    representatives[classes] = (order, row)
            selected.extend(row for _, row in representatives.values())
            continue
        call = group[0]
        params = dict(call.params)
        for name, value in params.items():
            if isinstance(value, ToolBatch):
                candidates = {
                    repr(entry): entry for row in group for entry in row.params[name].names
                }
                batch = ToolBatch(value.id, tuple(candidates[k] for k in sorted(candidates)))
                if batch.names:
                    params[name] = sample_batch(batch, metafunc.function.__name__, focus)
        selected.append(dataclasses.replace(call, params=params))
    if focus and tool_axes:
        # Every row of a changed module's tool runs, in every harness row.
        kept = {id(row) for row in selected}
        selected.extend(row for row in calls if id(row) not in kept and focus_row(row))
    metafunc._calls[:] = selected
