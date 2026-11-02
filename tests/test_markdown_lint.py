"""Rendered-Markdown lint: table column counts, escaped pipes and internal links.

scripts/check_markdown.py checks every tracked Markdown file the way GitHub renders it.
These tests run it over the repository and pin its rules on small planted documents.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
_SPEC = importlib.util.spec_from_file_location(
    "check_markdown", ROOT / "scripts" / "check_markdown.py"
)
assert _SPEC is not None and _SPEC.loader is not None
lint = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lint)


def _check(tmp_path: Path, text: str, name: str = "doc.md") -> list[str]:
    path = tmp_path / name
    path.write_text(text)
    return lint.check([path])


def test_every_tracked_markdown_file_renders_cleanly():
    files = lint.tracked_markdown()
    assert ROOT / "README.md" in files and ROOT / "docs" / "TOOLS.md" in files
    assert lint.check(files) == []


def test_every_tools_reference_table_row_has_the_header_column_count():
    """docs/TOOLS.md specifically: a ``string | null`` type once split 224 rows."""
    lines = list(lint.prose_lines((ROOT / "docs" / "TOOLS.md").read_text()))
    rows = 0
    for index, (_number, line) in enumerate(lines):
        if line.startswith("| Name | Type | Required | Default | Description |"):
            width = len(lint.split_cells(line))
            for _n, row in lines[index + 2 :]:
                if not row.startswith("|"):
                    break
                rows += 1
                assert len(lint.split_cells(row)) == width, row
    assert rows > 500


@pytest.mark.parametrize(
    "row",
    [
        "| `a` | `string | null` | no |",
        "| `a` | string | no | extra |",
        "| `a` | no |",
    ],
)
def test_a_row_with_the_wrong_cell_count_is_reported(tmp_path, row):
    text = f"| Name | Type | Required |\n| --- | --- | --- |\n{row}\n"
    (finding,) = _check(tmp_path, text)
    assert "doc.md:3: table row has" in finding


@pytest.mark.parametrize(
    "row",
    [
        "| `a` | `string \\| null` | no |",
        "| `a` | a \\| b | no |",
        "a | b | c",
        "| `a` | trailing backslash \\\\ | no |",
    ],
)
def test_escaped_pipes_and_bare_rows_pass(tmp_path, row):
    assert _check(tmp_path, f"| Name | Type | Required |\n| --- | :---: | ---: |\n{row}\n") == []


def test_a_delimiter_row_that_does_not_match_the_header_is_reported(tmp_path):
    (finding,) = _check(tmp_path, "| a | b |\n| --- |\n| 1 | 2 |\n")
    assert "renders this block as plain text" in finding


def test_tables_in_code_fences_and_comments_are_ignored(tmp_path):
    text = (
        "```\n| a | b |\n| --- | --- |\n| 1 | 2 | 3 |\n```\n\n"
        "<!--\n| a | b |\n| --- | --- |\n| 1 |\n-->\n"
    )
    assert _check(tmp_path, text) == []


def test_internal_anchor_links_resolve_to_github_heading_slugs(tmp_path):
    text = (
        "# Use with Claude Desktop\n\n## Listing & Discovery\n\n## Setup\n\n## Setup\n\n"
        '### `UNIFI_API_KEY` and *more*\n\n<a id="custom"></a>\n\n'
        "[a](#use-with-claude-desktop) [b](#listing--discovery) [c](#setup-1) "
        "[d](#unifi_api_key-and-more) [e](#custom)\n"
    )
    assert _check(tmp_path, text) == []


def test_a_broken_anchor_and_a_missing_file_are_reported(tmp_path):
    (tmp_path / "other.md").write_text("# Other\n")
    text = "[a](#claude-desktop)\n[b](other.md#missing)\n[c](missing.md)\n[d](other.md#other)\n"
    findings = _check(tmp_path, text)
    assert len(findings) == 3, findings
    assert "doc.md:1: link fragment" in findings[0]
    assert "doc.md:2: link fragment" in findings[1]
    assert "doc.md:3: link target does not exist" in findings[2]


def test_links_in_code_spans_and_external_links_are_not_checked(tmp_path):
    text = "`[a](#nowhere)` [b](https://example.com/#x) [c](mailto:a@example.com)\n"
    assert _check(tmp_path, text) == []


def test_the_tools_doc_generator_escapes_pipes_in_type_labels():
    spec = importlib.util.spec_from_file_location(
        "gen_tools_doc", ROOT / "scripts" / "gen_tools_doc.py"
    )
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    class Tool:
        name = "t"
        description = ""
        parameters = {
            "properties": {"a": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None}}
        }

    table = gen._parameter_table(Tool())
    assert "`string \\| null`" in table[-1]
    assert len(lint.split_cells(table[-1])) == len(lint.split_cells(table[0]))


def test_lint_reads_lines_through_the_one_shared_scanner():
    import markdown_blocks

    assert lint.prose_lines is markdown_blocks.prose_lines


@pytest.mark.parametrize(
    "prose",
    [
        "Write `<!--` to open a comment.\n",
        "Prose with an unmatched <!-- marker.\n",
    ],
)
def test_inline_comment_opener_does_not_hide_later_lines_from_lint(tmp_path, prose):
    text = prose + "\n[broken](missing.md)\n\n| a | b |\n| --- | --- |\n| 1 | 2 | 3 |\n"
    findings = _check(tmp_path, text)
    assert any("link target does not exist: missing.md" in f for f in findings), findings
    assert any("table row has 3 cells" in f for f in findings), findings


def test_complete_inline_and_block_comments_stay_hidden_from_lint(tmp_path):
    text = "Prose <!-- [a](gone.md) --> ok.\n<!--\n[b](gone.md)\n-->\n"
    assert _check(tmp_path, text) == []


def test_tracked_files_have_no_merge_conflict_markers():
    import subprocess

    result = subprocess.run(
        ["git", "grep", "-nE", "^(<<<<<<<|>>>>>>>) "],  # noqa: S607
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
