"""The block registry (scripts/doc_blocks.py) is the one list of generated documentation regions.

Every ``<!-- BEGIN GENERATED: name -->`` block in the repository is registered, each registered
block is present exactly once and in order, and each has exactly one owning generator that
renders it. The marker code fails closed: a missing, duplicated, unregistered, reordered or
unpaired block is a problem in every mode. Hermetic: synthetic text and the real files only.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return sys.modules[spec.name]


registry = _load("doc_blocks")
reference = _load("gen_reference_blocks")
figures = _load("gen_catalog_figures")

_LINE_MARKER = re.compile(r"^[ ]*<!-- BEGIN GENERATED: ([a-z0-9-]+) -->$", re.M)
_SKIP_DIRS = {"node_modules", "build", "dist", "site-packages"}


def _documents() -> list[Path]:
    """Every Markdown file and llms.txt in the tree (dot directories and builds excluded)."""
    found = [ROOT / "llms.txt"] if (ROOT / "llms.txt").is_file() else []
    for path in ROOT.rglob("*.md"):
        parts = path.relative_to(ROOT).parts
        if any(p.startswith(".") or p in _SKIP_DIRS for p in parts):
            continue
        found.append(path)
    return sorted(found)


def test_every_generated_block_in_the_tree_is_registered_and_present_once() -> None:
    seen: list[tuple[str, str]] = []
    for path in _documents():
        rel = path.relative_to(ROOT).as_posix()
        seen += [(rel, name) for name in _LINE_MARKER.findall(path.read_text())]
    registered = [(b.file, b.name) for b in registry.BLOCKS]
    assert sorted(seen) == sorted(registered), (
        "generated blocks in the tree differ from BLOCKS in scripts/doc_blocks.py: "
        f"unregistered {sorted(set(seen) - set(registered))}, "
        f"absent {sorted(set(registered) - set(seen))}"
    )
    assert len(set(registered)) == len(registered), "a block is registered twice"


def test_every_registered_file_is_structurally_intact() -> None:
    for file in registry.files():
        assert registry.problems(file, (ROOT / file).read_text()) == [], file


def test_each_block_has_exactly_one_owner_and_that_owner_renders_it() -> None:
    owners = {registry.CATALOG: figures, registry.REFERENCE: reference}
    assert {b.owner for b in registry.BLOCKS} <= set(owners)
    assert {reference.OWNER, figures.OWNER} == set(owners)
    reference_names = {b.name for b in registry.BLOCKS if b.owner == registry.REFERENCE}
    assert reference_names == set(reference.RENDERERS)
    catalog = [b for b in registry.BLOCKS if b.owner == registry.CATALOG]
    assert {b.file for b in catalog} == {"README.md"}
    rendered = figures.readme_blocks(figures.Figures(1, 0, {}, {}, 0, 0, 0, {}, {}, {}, 0, 0))
    assert {b.name for b in catalog} == set(rendered)


def test_registry_order_is_file_order_for_every_file() -> None:
    for file in registry.files():
        text = (ROOT / file).read_text()
        assert tuple(m["name"] for m in registry.BLOCK_RE.finditer(text)) == registry.names(file)


def test_no_marker_line_splits_a_markdown_list() -> None:
    """A marker at column 0 between two list items would end the list and start a new one;
    inside a list the marker line is indented, so the rendered list stays one list."""
    for file in registry.files():
        lines = (ROOT / file).read_text().splitlines()
        for i, line in enumerate(lines):
            if not line.startswith("<!-- ") or "GENERATED" not in line:
                continue
            before = next((ln for ln in reversed(lines[:i]) if ln.strip()), "")
            after = next((ln for ln in lines[i + 1 :] if ln.strip()), "")
            in_list = before.startswith(("- ", "  ")) and after.startswith(("- ", "  "))
            assert not in_list, f"{file}:{i + 1}: marker at column 0 inside a list"


# --- the marker code ----------------------------------------------------------------------

FILE = "README.md"
NAMES = registry.names(FILE)


def _text(*, drop: str = "", indent_end: str = "") -> str:
    lines = ["# Title", ""]
    for name in NAMES:
        if name != drop:
            lines += [f"<!-- BEGIN GENERATED: {name} -->", "old", f"{indent_end}{registry.END}"]
            lines.append("free prose")
    return "\n".join(lines) + "\n"


def _renderers(owner: str) -> dict[str, object]:
    return {name: (lambda name=name: f"new {name}") for name in registry.names(FILE, owner)}


def test_fill_rewrites_only_the_owners_bodies_and_is_idempotent() -> None:
    new, found = registry.fill(FILE, _text(), registry.CATALOG, _renderers(registry.CATALOG))
    assert found == []
    for name in NAMES:
        body = registry.body(new, name)
        assert body == (f"new {name}\n" if name in _renderers(registry.CATALOG) else "old\n")
    assert new.count("free prose") == len(NAMES)
    again, _ = registry.fill(FILE, new, registry.CATALOG, _renderers(registry.CATALOG))
    assert again == new


def test_fill_keeps_an_indented_end_marker_as_it_is() -> None:
    text = _text(indent_end="  ")
    new, found = registry.fill(FILE, text, registry.CATALOG, _renderers(registry.CATALOG))
    assert found == []
    assert new.count(f"\n  {registry.END}\n") == len(NAMES)


@pytest.mark.parametrize("name", NAMES)
def test_a_missing_block_is_a_problem_naming_its_marker_lines(name: str) -> None:
    found = registry.problems(FILE, _text(drop=name))
    assert any(
        block == name and f"<!-- BEGIN GENERATED: {name} -->" in msg and registry.END in msg
        for block, msg in found
    ), found


def test_duplicated_unregistered_and_unpaired_blocks_are_problems() -> None:
    first = NAMES[0]
    dup = _text() + f"<!-- BEGIN GENERATED: {first} -->\nx\n{registry.END}\n"
    assert (first, "block appears more than once") in registry.problems(FILE, dup)
    unknown = _text() + f"<!-- BEGIN GENERATED: not-registered -->\nx\n{registry.END}\n"
    assert any("unknown block name" in m for _b, m in registry.problems(FILE, unknown))
    unpaired = _text() + "<!-- BEGIN GENERATED: not-registered -->\nx\n"
    assert any(b == "(markers)" for b, _m in registry.problems(FILE, unpaired))


def test_out_of_order_blocks_are_a_problem() -> None:
    a, b = NAMES[0], NAMES[1]
    swapped = (
        _text()
        .replace(f"GENERATED: {a} ", "GENERATED: @@ ")
        .replace(f"GENERATED: {b} ", f"GENERATED: {a} ")
        .replace("GENERATED: @@ ", f"GENERATED: {b} ")
    )
    assert any(block == "(order)" for block, _m in registry.problems(FILE, swapped))


def test_fill_or_raise_fails_closed_and_a_renderer_mismatch_is_an_error() -> None:
    with pytest.raises(registry.MarkerError, match="README.md"):
        registry.fill_or_raise(
            FILE, _text(drop=NAMES[-1]), registry.CATALOG, _renderers(registry.CATALOG)
        )
    with pytest.raises(registry.MarkerError, match="assigns it"):
        registry.fill(FILE, _text(), registry.CATALOG, {"tool-families": lambda: ""})


def test_body_is_none_unless_the_block_appears_exactly_once() -> None:
    assert registry.body("no blocks", NAMES[0]) is None
    one = f"<!-- BEGIN GENERATED: {NAMES[0]} -->\nx\n{registry.END}\n"
    assert registry.body(one, NAMES[0]) == "x\n"
    assert registry.body(one + one, NAMES[0]) is None
