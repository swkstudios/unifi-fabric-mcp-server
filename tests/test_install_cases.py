"""CommonMark fence regressions for executable install examples."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import extract_install_cases as extraction  # noqa: E402


@pytest.fixture
def docroot(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# Installation\n")
    return tmp_path


@pytest.mark.parametrize("opener,closer", [("```", "````"), ("~~~", "~~~~~"), ("~~~~", "~~~~")])
def test_longer_and_tilde_fences_extract_cases(docroot, opener, closer):
    (docroot / "README.md").write_text(
        f"<!-- install-case: wheel mode=pip -->\n{opener}bash\npip install package.whl\n{closer}\n"
    )
    assert extraction.extract_cases(docroot) == [
        {
            "id": "wheel",
            "mode": "pip",
            "reason": None,
            "path": "README.md",
            "language": "bash",
            "body": "pip install package.whl\n",
        }
    ]


@pytest.mark.parametrize("opener,closer", [("```", "````"), ("~~~", "~~~~~")])
def test_unmarked_install_mutation_with_longer_closer_fails(docroot, opener, closer):
    (docroot / "README.md").write_text(
        "<!-- install-case: wheel mode=pip -->\n"
        "```bash\npip install package.whl\n```\n"
        f"{opener}bash\npip install unmarked.whl\n{closer}\n"
    )
    with pytest.raises(ValueError, match="unmarked install example"):
        extraction.extract_cases(docroot)


@pytest.mark.parametrize("false_closer", ["```", "~~~~", "````bash", "    ````"])
def test_short_mixed_or_nonclosing_fences_are_content(false_closer):
    blocks = list(
        extraction.fenced_blocks(
            f"````bash\npip install package.whl\n{false_closer}\nmore\n`````\n"
        )
    )
    assert blocks == [(0, "bash", f"pip install package.whl\n{false_closer}\nmore\n")]


def test_closer_indent_and_trailing_whitespace_can_differ():
    assert list(extraction.fenced_blocks("  ~~~bash\n  pip install package.whl\n ~~~~ \t\n")) == [
        (0, "bash", "pip install package.whl\n")
    ]


def test_unclosed_fence_consumes_document_to_eof():
    assert list(extraction.fenced_blocks("```bash\npip install package.whl\n")) == [
        (0, "bash", "pip install package.whl\n")
    ]


def test_backtick_in_info_string_is_not_an_opening_fence():
    assert list(extraction.fenced_blocks("```bash`invalid\nordinary text\n")) == []


def test_four_space_indented_fence_is_not_fenced_code():
    assert list(extraction.fenced_blocks("    ~~~bash\npip install package.whl\n")) == []


def test_adjacent_blocks_preserve_offsets_and_do_not_swallow_cases():
    text = "```bash\npip install first.whl\n`````\n~~~bash\npip install second.whl\n~~~~\n"
    blocks = list(extraction.fenced_blocks(text))
    assert blocks == [
        (0, "bash", "pip install first.whl\n"),
        (text.index("~~~"), "bash", "pip install second.whl\n"),
    ]
