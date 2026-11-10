"""One shared Markdown scanner: extraction and provenance must agree with CommonMark."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_doc_provenance as provenance  # noqa: E402
import extract_install_cases as extraction  # noqa: E402

# Every README install region's start and end heading; extraction fails closed when
# one is missing, so planted READMEs end with the full set.
REGION_HEADINGS = (
    "## Quick Start\n## Example Prompts\n## Set up your client\n"
    "## About this server\n## Docker Deployment\n## Contributing\n"
)
MARKED = "<!-- install-case: wheel mode=pip -->\n```bash\npip install package.whl\n```\n"


def test_both_gates_use_the_shared_scanner():
    import markdown_blocks

    assert extraction.fenced_blocks is markdown_blocks.fenced_blocks
    assert provenance.scan is markdown_blocks.scan


@pytest.mark.parametrize(
    "line,text",
    [
        ("## C#", "C#"),
        ("## F#", "F#"),
        ("## C# ##", "C#"),
        ("## Foo#bar", "Foo#bar"),
        ("## Foo ##   ", "Foo"),
        ("## Foo \\#", "Foo \\#"),
        ("## ###", ""),
        ("##", ""),
    ],
)
def test_atx_closing_sequence_needs_a_preceding_space(line, text):
    assert provenance.markdown_h2_headings(line + "\n") == [text]


@pytest.mark.parametrize("line", ["##C#", "    ## Indented code", "#5 bolt"])
def test_non_headings_are_not_headings(line):
    assert provenance.markdown_h2_headings(line + "\n") == []


@pytest.mark.parametrize(
    "prose",
    [
        "Write `<!--` to open a comment.\n",
        "Prose with an unmatched <!-- marker.\n",
        "Paragraph `<!--`\ncontinues here\n",
    ],
)
def test_unmatched_inline_comment_opener_does_not_hide_later_headings(prose):
    text = "## Quick Start\n" + prose + "## Example Prompts\n```bash\nx\n```\n"
    assert provenance.markdown_h2_headings(text) == ["Quick Start", "Example Prompts"]
    assert len(list(extraction.fenced_blocks(text))) == 1


def test_line_start_comment_block_runs_to_its_closer_or_eof():
    assert provenance.markdown_h2_headings("<!--\n## Hidden\n-->\n## Shown\n") == ["Shown"]
    assert provenance.markdown_h2_headings("## Shown\n<!-- unclosed\n## Hidden\n") == ["Shown"]


def test_fence_after_comment_closer_on_same_line_is_html_for_both_gates():
    # CommonMark: the whole line is an HTML block; the ``` is not an opening fence, so
    # the following heading is a real heading and there is no fenced example.
    text = "## Quick Start\n<!-- c --> ```bash\n## Example Prompts\n"
    assert list(extraction.fenced_blocks(text)) == []
    assert provenance.markdown_h2_headings(text) == ["Quick Start", "Example Prompts"]


def test_fence_inside_comment_block_is_not_an_example(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(
        MARKED + "<!--\n```bash\npip install hidden.whl\n```\n-->\n"
    )
    assert [case["id"] for case in extraction.extract_cases(tmp_path)] == ["wheel"]
    assert len(list(provenance.examples(tmp_path / "README.md", tmp_path))) == 1


@pytest.mark.parametrize(
    "fake_heading",
    [
        "```bash\n## Example Prompts\n```\n",
        "~~~\n## Example Prompts\n~~~\n",
        "<!-- ## Example Prompts -->\n",
        "<!--\n## Example Prompts\n-->\n",
        "### Example Prompts\n",
    ],
)
def test_fake_end_heading_does_not_end_readme_install_region(tmp_path, fake_heading):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(
        "## Quick Start\n"
        + MARKED
        + fake_heading
        + "```json\n{}\n```\n## Example Prompts\n"
        + REGION_HEADINGS
    )
    with pytest.raises(ValueError, match="unmarked install example"):
        extraction.extract_cases(tmp_path)


def test_real_end_heading_ends_readme_install_region(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(
        "## Quick Start\n" + MARKED + "## Example Prompts\n```json\n{}\n```\n" + REGION_HEADINGS
    )
    assert [case["id"] for case in extraction.extract_cases(tmp_path)] == ["wheel"]


def test_gates_agree_on_examples_and_sections(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(
        "## Quick Start\n<!-- c --> ```bash\n## Set up your client\n"
        "<!-- x -->\n```json\n{}\n```\n## C#\n```text\nlate\n```\n" + REGION_HEADINGS
    )
    text = readme.read_text()
    lines = [text[:offset].count("\n") + 1 for offset, _, _ in extraction.fenced_blocks(text)]
    assert lines == [5, 9]
    assert [line for line, _ in provenance.examples(readme, tmp_path)] == [5]
    assert provenance.example_identity(readme, 5, tmp_path)[1] == "Set up your client"
    assert provenance.example_identity(readme, 9, tmp_path)[1] == "C#"


README_REGIONS = (
    "## Quick Start\n{quick}## Example Prompts\n{prompts}## Set up your client\n"
    "## About this server\n## Docker Deployment\n## Contributing\n"
)


def test_region_headings_compare_case_insensitively(tmp_path):
    (tmp_path / "docs").mkdir()
    inside = README_REGIONS.format(quick="```json\n{}\n```\n", prompts="")
    (tmp_path / "README.md").write_text(inside.replace("## Quick Start", "## Quick start"))
    with pytest.raises(ValueError, match="unmarked install example"):
        extraction.extract_cases(tmp_path)
    after_end = README_REGIONS.format(quick=MARKED, prompts="```json\n{}\n```\n")
    renamed = after_end.replace("## Example Prompts", "## Example prompts")
    (tmp_path / "README.md").write_text(renamed)
    assert [case["id"] for case in extraction.extract_cases(tmp_path)] == ["wheel"]


@pytest.mark.parametrize(
    "heading",
    ["## Quick Start", "## Example Prompts", "## About this server", "## Contributing"],
)
def test_missing_region_heading_fails_closed(tmp_path, heading):
    (tmp_path / "docs").mkdir()
    readme = README_REGIONS.format(quick=MARKED, prompts="```text\nprompt\n```\n")
    (tmp_path / "README.md").write_text(readme.replace(heading + "\n", "## Renamed\n"))
    with pytest.raises(ValueError, match="install region heading"):
        extraction.extract_cases(tmp_path)


def test_region_end_heading_must_follow_its_start(tmp_path):
    (tmp_path / "docs").mkdir()
    body = README_REGIONS.format(quick=MARKED, prompts="").replace("## Example Prompts\n", "")
    (tmp_path / "README.md").write_text("## Example Prompts\n" + body + "```text\nx\n```\n")
    with pytest.raises(ValueError, match="install region heading"):
        extraction.extract_cases(tmp_path)


@pytest.mark.parametrize(
    "comment",
    [
        "<!-- note: a > b -->",
        "<!-- doc-provenance: source=https://example.com/1.2.3/a>b -->",
        "<!--\nmulti > line\n-->",
    ],
)
def test_adjacent_comment_containing_gt_is_kept(comment):
    import markdown_blocks

    text = comment + "\n" + MARKED
    found = markdown_blocks.adjacent_comments(text, text.index("```"))
    assert comment in found and "install-case: wheel" in found


def test_adjacent_comments_do_not_cross_prose():
    import markdown_blocks

    text = "<!-- far -->\nprose --> here\n<!-- near -->\n```bash\nx\n```\n"
    found = markdown_blocks.adjacent_comments(text, text.index("```"))
    assert found.strip() == "<!-- near -->"


def test_install_reason_containing_gt_is_still_a_marked_case(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "X.md").write_text(
        "<!-- install-case: arrow mode=non-executable reason=a > b -->\n"
        "```bash\npip install x\n```\n"
    )
    (tmp_path / "README.md").write_text("# t\n")
    assert [case["id"] for case in extraction.extract_cases(tmp_path)] == ["arrow"]


# A fence nested in a list item (indented four or more spaces) or in a block quote is
# prose to the scanner, so it escapes extraction and provenance. These cases pin the
# detector, and the repository check below keeps public docs free of such fences.
@pytest.mark.parametrize(
    "text,lines",
    [
        ("1. item\n\n     ```yaml\n     a: 1\n     ```\n", [3, 5]),
        ("- item\n\n    ~~~\n    x\n    ~~~\n", [3, 5]),
        ("> ```bash\n> x\n> ```\n", [1, 3]),
        ("> > ~~~~\n", [1]),
        ("```bash\nx\n```\n", []),
        ("   ```\n    ```\n   ```\n", []),
        ("<!--\n    ```\n-->\n", []),
        ("prose with ``` inline\n", []),
        # A fence opening on a list-marker line is list content, not a top-level fence.
        ("- ```bash\n  x\n  ```\n", [1]),
        ("1. ```yaml\n   a: 1\n   ```\n", [1]),
        ("* ```\n", [1]),
        ("+ ~~~\n", [1]),
        ("1) ```sh\n", [1]),
        ("> - ```bash\n", [1]),
        ("- > ~~~\n", [1]),
        ("-```\n", []),
        # Lines that only look like fences: a backtick fence's info string may not
        # contain a backtick (CommonMark), so these are inline code, never a fence.
        ("```inline``` text\n", []),
        ("```a`b\n", []),
        ("- ```a`b\n", []),
        ("> ```x`y\n", []),
        ("    ```a`b\n", []),
    ],
)
def test_unseen_fences_flags_nested_fences_only(text, lines):
    import markdown_blocks

    assert [number for number, _ in markdown_blocks.unseen_fences(text)] == lines


def _strip_containers(line: str) -> str:
    """Drop leading whitespace, block quote markers and list markers, one at a time."""
    rest = line
    while True:
        rest = rest.lstrip(" \t")
        if rest.startswith(">"):
            rest = rest[1:]
            continue
        digits = len(rest) - len(rest.lstrip("0123456789"))
        if rest[:1] in ("-", "*", "+"):
            marker = 1
        elif 1 <= digits <= 9 and rest[digits : digits + 1] in (".", ")"):
            marker = digits + 1
        else:
            marker = 0
        if marker and rest[marker : marker + 1] in (" ", "\t"):
            rest = rest[marker:]
            continue
        return rest


def test_unseen_fences_agrees_with_the_scanner_on_random_documents():
    """A prose line is reported exactly when the scanner would open a fence on it once
    its container prefix (indentation, block quote and list markers) is removed."""
    import random

    import markdown_blocks

    tokens = [
        "```",
        "````",
        "~~~",
        "`",
        "~",
        "> ",
        ">",
        "- ",
        "* ",
        "+ ",
        "1. ",
        "2) ",
        "-",
        " ",
        "    ",
        "\t",
        "a",
        "b`",
        "<!--",
        "-->",
        "#",
        "\n",
        "\n",
        "\n",
        "\r\n",
        "\r",
        # Python splitlines() breaks on all of these; CommonMark breaks on none of them.
        "\x0b",
        "\x0c",
        "\x1c",
        "\x1d",
        "\x1e",
        "\x85",
        "\u2028",
        "\u2029",
    ]
    rng = random.Random(372)  # noqa: S311 - reproducible fuzz, not cryptography
    for _ in range(4000):
        text = "".join(rng.choice(tokens) for _ in range(rng.randint(1, 18)))
        lines = markdown_blocks.split_lines(text)
        prose_items = list(markdown_blocks.prose_lines(text))
        prose = {number for number, _ in prose_items}
        # Every line number the scanner reports is a CommonMark line, and no prose line
        # spans a CommonMark line ending.
        assert all(1 <= number <= len(lines) for number in prose), text
        assert not any(set(line) & {"\r", "\n"} for _, line in prose_items), text
        reported = {number for number, _ in markdown_blocks.unseen_fences(text)}
        assert reported <= prose, text
        for number in prose:
            raw = lines[number - 1]
            # Keep the CommonMark terminator so the line count never changes.
            body = raw.rstrip("\r\n")
            stripped = _strip_containers(body)
            changed = "".join(lines[: number - 1]) + stripped + raw[len(body) :]
            changed += "".join(lines[number:])
            if not stripped:
                # An empty line is never a fence (and "\r" + "\n" would merge two lines).
                assert number not in reported, (text, number)
                continue
            assert len(markdown_blocks.split_lines(changed)) == len(lines), (text, number)
            opens = any(f.line == number for f in markdown_blocks.scan(changed)[0])
            assert (number in reported) == (opens and stripped != body), (text, number)


def _tracked_public_markdown() -> list[Path]:
    import subprocess

    root = SCRIPTS.parent
    listed = subprocess.run(  # noqa: S603
        ["git", "ls-files", "-z", "--", "*.md"],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert listed.returncode == 0, "Tracked Markdown enumeration failed: " + listed.stderr
    paths = [root / name for name in listed.stdout.split("\0") if name]
    return [
        p
        for p in paths
        if (
            p.relative_to(root).parts[:1] != ("docs",)
            or p.relative_to(root).parts[1:2] != ("internal",)
        )
        and p.is_file()
    ]


def test_tracked_public_markdown_has_no_fence_the_scanner_cannot_see():
    import markdown_blocks

    documents = _tracked_public_markdown()
    assert any(p.name == "README.md" for p in documents)
    unseen = [
        f"{path.relative_to(SCRIPTS.parent)}:{number}: {line.strip()}"
        for path in documents
        for number, line in markdown_blocks.unseen_fences(path.read_text(encoding="utf-8"))
    ]
    assert not unseen, "fences the shared scanner reads as prose:\n" + "\n".join(unseen)


def _regex_adjacent_comments(text: str, offset: int) -> str:
    """The previous regex implementation, kept as the semantic oracle."""
    import re

    comment = r"<!--(?:(?!-->).)*?-->"
    # A CommonMark line ending is "\n", "\r\n" or "\r".
    pattern = re.compile(r"(?:" + comment + r"[ \t]*(?:\r\n|\r|\n)\s*)+$", re.S)
    match = pattern.search(text[:offset])
    return match.group() if match else ""


@pytest.mark.parametrize("eol", ["\n", "\r\n", "\r"], ids=["LF", "CRLF", "CR"])
def test_adjacent_comments_accept_every_commonmark_line_ending(tmp_path, eol):
    import markdown_blocks

    marker = "<!-- install-case: wheel mode=pip -->"
    text = eol.join(
        ["intro", "", "<!-- first -->  ", marker, "```bash", "pip install package.whl", "```", ""]
    )
    offset = text.index("```")
    found = markdown_blocks.adjacent_comments(text, offset)
    assert found.startswith("<!-- first -->")
    assert marker in found
    # Both gates see the marked example in a document saved with these line endings.
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_bytes(text.encode())
    assert [case["id"] for case in extraction.extract_cases(tmp_path)] == ["wheel"]
    examples = list(provenance.examples(tmp_path / "README.md", tmp_path))
    assert len(examples) == 1
    assert marker in examples[0][1]


def test_adjacent_comments_match_the_regex_semantics_on_random_input():
    import random

    import markdown_blocks

    pieces = [
        "<!--",
        "-->",
        "<!-->",
        "<!--->",
        " ",
        "\t",
        "\n",
        "\n\n",
        "\r\n",
        "\r",
        "a",
        ">",
        "-",
    ]
    rng = random.Random(372)  # noqa: S311 - reproducible fuzz, not cryptography
    for _ in range(4000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))
        for offset in {len(text), rng.randint(0, len(text))}:
            assert markdown_blocks.adjacent_comments(text, offset) == _regex_adjacent_comments(
                text, offset
            ), repr(text[:offset])


@pytest.mark.parametrize("tail", ["", "prose\n"])
@pytest.mark.parametrize(
    "line",
    ["<!-- c -->\n", "<!-- c > d -->\n\n", "<!-- c\n", "<!--->\n"],
)
def test_adjacent_comments_is_linear_on_pathological_input(line, tail):
    import markdown_blocks

    from tests.cpu_scaling import SCALE, python_line_events

    def run(count: int):
        text = line * count + tail + "```bash\nx\n```\n"
        offset = text.index("```")
        return lambda: markdown_blocks.adjacent_comments(text, offset)

    # Keep the full historical reproducer and count its parser work. Intervening
    # prose or openers with no later closer cannot form adjacent comments. The
    # <!---> case pairs successive lines: both tested counts are even.
    counts = []
    for count in (20_000 // SCALE, 20_000):
        call = run(count)
        result = call()
        expected = line * count if not tail and line != "<!-- c\n" else ""
        assert result == expected
        counts.append(python_line_events(markdown_blocks, call))
    assert counts[0] > 0
    assert counts[1] <= SCALE * counts[0], counts


# Python's str.splitlines() also breaks on these; CommonMark line endings are only "\n",
# "\r\n" and "\r", so to GitHub each of them is ordinary content inside one line.
NON_COMMONMARK_SEPARATORS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "]
SEPARATOR_IDS = [f"U+{ord(sep):04X}" for sep in NON_COMMONMARK_SEPARATORS]


def test_split_lines_breaks_only_on_commonmark_line_endings():
    import markdown_blocks

    assert markdown_blocks.split_lines("") == []
    assert markdown_blocks.split_lines("a") == ["a"]
    assert markdown_blocks.split_lines("a\n") == ["a\n"]
    assert markdown_blocks.split_lines("\n\r\n\r") == ["\n", "\r\n", "\r"]
    assert markdown_blocks.split_lines("a\nb\r\nc\rd") == ["a\n", "b\r\n", "c\r", "d"]
    assert markdown_blocks.split_lines("a\nb\r\nc\rd", keepends=False) == ["a", "b", "c", "d"]
    odd = "a" + "".join(NON_COMMONMARK_SEPARATORS) + "b\n"
    assert markdown_blocks.split_lines(odd) == [odd]


@pytest.mark.parametrize("sep", NON_COMMONMARK_SEPARATORS, ids=SEPARATOR_IDS)
def test_non_commonmark_separator_does_not_open_a_fence(sep):
    import markdown_blocks

    text = f"prose{sep}```bash\npip install x\n"
    assert markdown_blocks.scan(text)[0] == []
    assert list(markdown_blocks.prose_lines(text)) == [
        (1, f"prose{sep}```bash"),
        (2, "pip install x"),
    ]


@pytest.mark.parametrize("sep", NON_COMMONMARK_SEPARATORS, ids=SEPARATOR_IDS)
def test_non_commonmark_separator_does_not_close_a_fence(sep):
    import markdown_blocks

    text = f"```bash\necho one{sep}```\necho two\n```\nafter\n"
    fences = markdown_blocks.scan(text)[0]
    assert [(f.line, f.body) for f in fences] == [(1, f"echo one{sep}```\necho two\n")]
    assert list(markdown_blocks.prose_lines(text)) == [(5, "after")]


@pytest.mark.parametrize("sep", NON_COMMONMARK_SEPARATORS, ids=SEPARATOR_IDS)
def test_non_commonmark_separator_does_not_start_a_heading_or_comment(sep):
    import markdown_blocks

    text = f"prose{sep}## Quick Start\nprose{sep}<!-- hidden\n## Visible\n"
    assert [(h.line, h.text) for h in markdown_blocks.scan(text)[1]] == [(3, "Visible")]


@pytest.mark.parametrize("sep", NON_COMMONMARK_SEPARATORS, ids=SEPARATOR_IDS)
def test_non_commonmark_separator_does_not_make_an_unseen_fence(sep):
    import markdown_blocks

    assert markdown_blocks.unseen_fences(f"text{sep}> ```bash\n") == []


@pytest.mark.parametrize("sep", NON_COMMONMARK_SEPARATORS, ids=SEPARATOR_IDS)
def test_non_commonmark_separator_does_not_create_an_install_example(tmp_path, sep):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(MARKED + f"text{sep}```bash\npip install hidden.whl\n")
    assert [case["id"] for case in extraction.extract_cases(tmp_path)] == ["wheel"]
    assert len(list(provenance.examples(tmp_path / "README.md", tmp_path))) == 1


@pytest.mark.parametrize("sep", NON_COMMONMARK_SEPARATORS, ids=SEPARATOR_IDS)
def test_executed_case_table_counts_commonmark_lines(tmp_path, sep):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/INSTALL-AGENT.md").write_text(
        f"intro{sep}more\n| Path | Executed case |\n|---|---|\n| pip | `missing-case` |\n"
    )
    assert provenance.check_executed_cases(tmp_path, {"cases": []}) == [
        "docs/INSTALL-AGENT.md:4: executed case missing-case has no successful execution evidence"
    ]


def test_provenance_and_extraction_share_one_public_document_set(tmp_path):
    import check_doc_images as images
    import check_doc_links as links

    for relative in (
        "README.md",
        "docs/TOP.md",
        "docs/guides/NESTED.md",
        "docs/TOOLS.md",
        "plugins/codex/README.md",
        "plugins/internal/README.md",
        "docs/notes.txt",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# doc\n")
    expected = [
        tmp_path / relative
        for relative in (
            "README.md",
            "docs/TOOLS.md",
            "docs/TOP.md",
            "docs/guides/NESTED.md",
            "plugins/codex/README.md",
            "plugins/internal/README.md",
        )
    ]
    assert extraction.public_documents(tmp_path) == sorted(expected)
    # Provenance covers the complete set; only link/image checks exclude generated tools.
    assert provenance.public_docs(tmp_path) == sorted(expected)
    generated = tmp_path / "docs/TOOLS.md"
    assert provenance.public_reference_docs(tmp_path) == [
        p for p in sorted(expected) if p != generated
    ]
    assert links.public_reference_docs is provenance.public_reference_docs
    assert images.public_reference_docs is provenance.public_reference_docs
