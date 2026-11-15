"""Static checks of deferred tool loading (public #41): no server start, no subprocess.

Selected for every PR that touches a family module (``scripts/ci_classify_changes.py``
``COMMON_SELECTED_TESTS``), so a family move cannot add a step that touches its app beyond
``mcp.tool`` (S1) or a new reader of a tool's ``fn`` (S5) and stay green.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from unifi_fabric.catalog import deferred, loaders

ROOT = Path(__file__).resolve().parents[1]


def _register_function(entry: loaders.Loader) -> ast.FunctionDef:
    path = ROOT / "src" / Path(*entry.module_path.split(".")).with_suffix(".py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == entry.function:
            return node
    raise AssertionError(f"{entry.ref}: register function not found")


def test_steps_touch_mcp_only_through_tool() -> None:
    """S1 (design review C6), as an AST rule: inside a step's register (at any depth), the app is
    used only as ``mcp.tool``; passing it on is allowed only to ``live_app``."""
    problems: list[str] = []
    for entry in loaders.LOADERS:
        function = _register_function(entry)
        app = function.args.args[0].arg
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == app
                and node.attr != "tool"
            ):
                problems.append(f"{entry.ref}: {app}.{node.attr} (line {node.lineno})")
            if isinstance(node, ast.Call):
                callee = node.func.id if isinstance(node.func, ast.Name) else None
                for arg in [*node.args, *(k.value for k in node.keywords)]:
                    if isinstance(arg, ast.Name) and arg.id == app and callee != "live_app":
                        problems.append(f"{entry.ref}: {app} passed on (line {node.lineno})")
    assert problems == []


def test_aggregation_counts_the_live_catalog() -> None:
    """C6: the diagnostic bundle's tool count reads the live server, not the staging app."""
    source = inspect.getsource(
        __import__("unifi_fabric.families.site_manager.registrar", fromlist=["x"])
    )
    assert "live_app(mcp).list_tools" in source
    staging = deferred.StagingMCP("live-sentinel", None)
    assert deferred.live_app(staging) == "live-sentinel"
    assert deferred.live_app("plain") == "plain"


def test_no_unreviewed_fn_reader() -> None:
    """S5 (design review C7): every read of a registered tool's ``fn`` in the package (``.fn`` or
    ``getattr(x, "fn")``) is a reviewed site: one that runs on loaded tools only, on
    staging, or passes a stub through."""
    reviewed = {
        "_adapter_runtime.py",  # loads through the deferred path first (C7)
        "_call_graph.py",  # build-time, its own scratch registration of every step
        "_read_only_audit.py",  # the audit: staging, the generator, write_names on loaded
        "_request_shape_audit.py",  # build-time, every step loaded
        "argument_errors.py",  # on the resolved (loaded) tool
        "catalog/deferred.py",  # verification on staged tools
        "catalog/membership.py",  # a stub (no fn) is checked by its deferred_step
        "catalog/inventory.py",  # build-time, runtime_view loads every step
        "catalog_build.py",  # build-time, every step loaded
        "catalog_descriptions.py",  # an install pass: staging
        "discovery.py",  # describe envelope of a loaded tool
        "list_results.py",  # a stub (no fn) passes through
        "redaction.py",  # an install pass: staging
        "resolution_state.py",  # an install pass: staging
        "tool_annotations.py",  # an install pass: staging
    }
    found: set[str] = set()
    package = ROOT / "src" / "unifi_fabric"
    for path in package.rglob("*.py"):
        rel = path.relative_to(package).as_posix()
        if rel.startswith(("families/", "_generated/")):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            reads_fn = isinstance(node, ast.Attribute) and node.attr == "fn"
            reads_fn = reads_fn or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("getattr", "hasattr")
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "fn"
            )
            if reads_fn:
                found.add(rel)
    assert found - reviewed == set()
