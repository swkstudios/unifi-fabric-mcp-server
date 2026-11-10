"""Generators fail closed when a block they depend on is missing, duplicated or crossed.

``gen_catalog_figures.py`` and ``gen_reference_blocks.py`` both depend on the
generated-block markers of the one block registry (``BLOCKS`` in scripts/doc_blocks.py). A
generator that rewrites only what sits between its markers cannot tell "nothing to update"
from "the block I guard was deleted", so each one must exit non-zero, naming the file and
the marker, in both write and ``--check`` modes. Everything here is hermetic: synthetic text
and ``tmp_path`` trees, no console, no network.
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


figures = _load("gen_catalog_figures")
blocks = _load("gen_reference_blocks")
registry = _load("doc_blocks")

START, END = "<!-- BEGIN GENERATED: verification-status -->", "<!-- END GENERATED -->"
#: The README blocks in registry (file) order, and the ones gen_catalog_figures owns.
README_BLOCKS = registry.names("README.md")
OWNED = registry.names("README.md", figures.OWNER)


def _readme(*, drop: str = "", bodies: dict[str, str] | None = None) -> str:
    """A synthetic README carrying every registered README block (minus ``drop``) in order."""
    parts = ["# Title", "prose before"]
    for name in README_BLOCKS:
        if name != drop:
            body = (bodies or {}).get(name, "old")
            parts += [f"<!-- BEGIN GENERATED: {name} -->", body, END, f"prose after {name}"]
    return "\n".join(parts) + "\n"


def _fill(text: str) -> str:
    return figures.fill_blocks(
        figures.README, text, {name: (lambda name=name: f"new {name}") for name in OWNED}
    )


# --- gen_catalog_figures: generated README blocks ------------------------------------------


def test_owned_blocks_are_rewritten_in_place_and_nothing_else() -> None:
    new = _fill(_readme())
    assert new == _readme(bodies={name: f"new {name}" for name in OWNED})
    for name in set(README_BLOCKS) - set(OWNED):  # another generator's block is left alone
        assert f"<!-- BEGIN GENERATED: {name} -->\nold\n{END}" in new


def test_a_missing_block_names_the_file_and_the_marker() -> None:
    with pytest.raises(figures.MarkerError) as err:
        _fill(_readme(drop="verification-status"))
    message = str(err.value)
    assert "README.md" in message and START in message and END in message


@pytest.mark.parametrize("name", README_BLOCKS)
def test_every_registered_block_is_required(name: str) -> None:
    """No block is optional: deleting any registered README block fails the generator."""
    with pytest.raises(figures.MarkerError, match="block is missing") as err:
        _fill(_readme(drop=name))
    assert "README.md" in str(err.value) and name in str(err.value)


def _broken(case: str) -> str:
    text = _readme()
    if case == "begin-only":
        return text.replace(f"{START}\nold\n{END}\n", f"{START}\nold\n")
    if case == "end-only":
        return text.replace(f"{START}\n", "")
    if case == "duplicated":
        return text + f"{START}\nold\n{END}\n"
    if case == "crossed":
        return text.replace(f"{START}\nold\n{END}", f"{END}\nold\n{START}")
    first, second = README_BLOCKS[0], README_BLOCKS[1]  # out-of-order: swap two blocks
    return (
        text.replace(f"GENERATED: {first} ", "GENERATED: @@ ")
        .replace(f"GENERATED: {second} ", f"GENERATED: {first} ")
        .replace("GENERATED: @@ ", f"GENERATED: {second} ")
    )


@pytest.mark.parametrize(
    ("case", "fragment"),
    [
        ("begin-only", "unpaired BEGIN or END"),
        ("end-only", "unpaired BEGIN or END"),
        ("duplicated", "appears more than once"),
        ("crossed", "(markers)"),
        ("out-of-order", "out of order"),
    ],
)
def test_an_incomplete_duplicated_crossed_or_reordered_block_fails(
    case: str, fragment: str
) -> None:
    with pytest.raises(figures.MarkerError, match=re.escape(fragment)) as err:
        _fill(_broken(case))
    assert "README.md" in str(err.value)


def test_an_unregistered_block_fails() -> None:
    text = _readme() + "<!-- BEGIN GENERATED: not-registered -->\nx\n<!-- END GENERATED -->\n"
    with pytest.raises(figures.MarkerError, match="unknown block name"):
        _fill(text)


@pytest.mark.parametrize("check", [True, False])
def test_main_exits_nonzero_and_writes_nothing_on_a_marker_error(
    check: bool, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken() -> object:
        _fill(_readme(drop="verification-status"))
        raise AssertionError("unreachable")

    monkeypatch.setattr(figures, "render_outputs", broken)
    monkeypatch.setattr(sys, "argv", ["gen_catalog_figures.py", *(["--check"] if check else [])])
    assert figures.main() == 1
    err = capsys.readouterr().err
    assert "README.md" in err and START in err


def test_the_real_readme_has_every_registered_block_intact() -> None:
    """Asserted against the real file, not a fixture: every block present once and in order."""
    text = figures.README.read_text()
    assert registry.problems("README.md", text) == []
    for name in README_BLOCKS:
        assert text.count(f"<!-- BEGIN GENERATED: {name} -->") == 1, name
    assert set(OWNED) == {"catalog-headline", "how-it-works-catalog", "verification-status"}


# --- gen_reference_blocks ----------------------------------------------------------------


def _findings(text: str, path: Path | None = None) -> list[str]:
    path = path or blocks.CONFIGURATION
    return [str(f) for f in blocks.render_file(path, text)[1]]


def _real(path: Path) -> str:
    return path.read_text()


def _drop_block(text: str, name: str) -> str:
    start = text.index(f"<!-- BEGIN GENERATED: {name} -->")
    end = text.index("<!-- END GENERATED -->", start) + len("<!-- END GENERATED -->\n")
    return text[:start] + text[end:]


def test_the_real_files_have_no_structural_findings() -> None:
    for path in blocks.BLOCKS:
        assert _findings(_real(path), path) == [], path


def test_a_missing_block_names_the_file_and_the_marker_line() -> None:
    findings = _findings(_drop_block(_real(blocks.CONFIGURATION), "write-switches"))
    assert any(
        "docs/CONFIGURATION.md" in f
        and "write-switches" in f
        and "<!-- BEGIN GENERATED: write-switches -->" in f
        for f in findings
    ), findings


def test_a_duplicated_block_is_reported() -> None:
    text = _real(blocks.CONFIGURATION)
    start = text.index("<!-- BEGIN GENERATED: audit-schema -->")
    end = text.index("<!-- END GENERATED -->", start) + len("<!-- END GENERATED -->\n")
    findings = _findings(text[:end] + text[start:])
    assert any("audit-schema" in f and "more than once" in f for f in findings), findings


def test_blocks_out_of_order_are_reported() -> None:
    text = _real(blocks.TOOL_USAGE)

    def span(name: str) -> tuple[int, int]:
        start = text.index(f"<!-- BEGIN GENERATED: {name} -->")
        return start, text.index("<!-- END GENERATED -->", start) + len("<!-- END GENERATED -->")

    (a0, a1), (b0, b1) = span("family-names"), span("search-tools-limit")
    swapped = text[:a0] + text[b0:b1] + text[a1:b0] + text[a0:a1] + text[b1:]
    findings = _findings(swapped, blocks.TOOL_USAGE)
    assert any("(order)" in f and "out of order" in f for f in findings), findings


def test_crossed_markers_with_matching_counts_are_reported() -> None:
    text = _real(blocks.CONFIGURATION)
    begin = "<!-- BEGIN GENERATED: settings-reference -->"
    end_marker = "<!-- END GENERATED -->"
    first = text.index(begin)
    last_end = text.index(end_marker, first)
    crossed = text[:first] + end_marker + "\n" + text[first:last_end] + text[last_end + 22 :]
    findings = _findings(crossed)
    assert any("(markers)" in f for f in findings), findings


@pytest.mark.parametrize("check", [True, False])
def test_main_fails_on_a_missing_block_in_both_modes(
    check: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    doc = tmp_path / "docs" / "CONFIGURATION.md"
    doc.parent.mkdir()
    text = _drop_block(_real(blocks.CONFIGURATION), "write-switches")
    doc.write_text(text)
    monkeypatch.setattr(blocks, "ROOT", tmp_path)
    monkeypatch.setattr(blocks, "BLOCKS", {doc: blocks.BLOCKS[blocks.CONFIGURATION]})
    monkeypatch.setattr(blocks, "DEFAULT_TABLES", {})
    monkeypatch.setattr(sys, "argv", ["gen_reference_blocks.py", *(["--check"] if check else [])])
    assert blocks.main() == 1
    assert "docs/CONFIGURATION.md" in capsys.readouterr().err
    assert doc.read_text() == text  # a file whose markers are broken is never rewritten
