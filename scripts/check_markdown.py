#!/usr/bin/env python3
"""Lint Markdown the way GitHub renders it: tables, pipes and internal links.

Checks every tracked Markdown file outside test fixtures (or the paths given):

* **Tables.** Every row of a GitHub-flavoured table has exactly as many cells as its
  header. A ``|`` inside a cell must be escaped as ``\\|``, also inside a code span
  (GitHub splits cells before it parses code spans), so an unescaped pipe shows up
  here as a row with too many cells. A delimiter row whose cell count differs from the
  header makes GitHub render the block as plain text, which is reported too.
* **Internal links.** A relative link or image (``[t](other.md)``, ``![i](img.png)``,
  reference definitions ``[r]: path``) must name an existing file or directory, and a
  ``#fragment`` (``[t](#section)`` or ``[t](other.md#section)``) must name a heading
  anchor that GitHub generates for the target file, or an explicit ``id`` / ``name``.

Fenced code blocks, inline code spans and HTML comments are skipped; lines are read
through ``markdown_blocks.prose_lines``, the one scanner every documentation gate
shares, so a fence or comment means the same thing here as in install-case extraction
and provenance checking. External ``http(s)://`` links are the link checker's job (lychee in CI).

Usage: ``python scripts/check_markdown.py [FILE ...]``. Prints ``file:line: problem``
for each finding and exits 1 when there is any.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unicodedata
from collections.abc import Iterable, Iterator
from pathlib import Path
from urllib.parse import unquote

from markdown_blocks import prose_lines

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PREFIXES = ("tests/fixtures/",)

_DELIM_CELL_RE = re.compile(r"^\s*:?-+:?\s*\Z")
_HEADING_RE = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*\Z")
_SETEXT_RE = re.compile(r"^ {0,3}(=+|-+)[ \t]*\Z")
_EXPLICIT_ID_RE = re.compile(r"""<[a-zA-Z][^>]*?\s(?:id|name)\s*=\s*["']([^"']+)["']""")
_INLINE_LINK_RE = re.compile(
    r"(!?)\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\(\s*<?([^)\s>]*)>?(?:\s+[\"'(][^)]*)?\)"
)
_REF_DEF_RE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?\Z")
_HTML_LINK_RE = re.compile(r"""<(?:a|img)\s[^>]*?(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
_CODE_SPAN_RE = re.compile(r"(`+)(.+?)(?<!`)\1(?!`)")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def tracked_markdown() -> list[Path]:
    """Every tracked ``*.md`` file outside the excluded fixture trees."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "-C", str(ROOT), "ls-files", "-z", "*.md"],  # noqa: S607
            capture_output=True,
            check=True,
        ).stdout.decode()
        names = [n for n in out.split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [
            p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.md") if ".git" not in p.parts
        ]
    return sorted(
        ROOT / n for n in names if not n.startswith(EXCLUDED_PREFIXES) and (ROOT / n).is_file()
    )


def split_cells(row: str) -> list[str]:
    """Split a table row into cells the way GitHub does: on pipes not escaped by ``\\``."""
    body = row.strip()
    cells: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            current.append(body[index : index + 2])
            index += 2
            continue
        if char == "|":
            cells.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    cells.append("".join(current))
    if body.startswith("|"):
        cells = cells[1:]
    if len(cells) > 1 and body.endswith("|") and not body.endswith("\\|"):
        cells = cells[:-1]
    return cells


def _is_delimiter_row(line: str) -> bool:
    if "-" not in line:
        return False
    cells = split_cells(line)
    return (
        bool(cells)
        and all(_DELIM_CELL_RE.match(c) for c in cells)
        and ("|" in line or len(cells) > 1)
    )


_BLOCK_START_RE = re.compile(r"^ {0,3}(?:#{1,6}\s|>|[-*+]\s|\d+[.)]\s|```|~~~)")


def table_problems(lines: list[tuple[int, str]]) -> Iterator[tuple[int, str]]:
    """Rows whose cell count differs from their table's header."""
    index = 0
    while index + 1 < len(lines):
        (head_no, head), (delim_no, delim) = lines[index], lines[index + 1]
        if "|" not in head or delim_no != head_no + 1 or not _is_delimiter_row(delim):
            index += 1
            continue
        width = len(split_cells(head))
        delim_width = len(split_cells(delim))
        if delim_width != width:
            yield (
                delim_no,
                (
                    f"table delimiter row has {delim_width} cells but the header has {width}; "
                    "GitHub renders this block as plain text"
                ),
            )
        index += 2
        previous = delim_no
        while index < len(lines):
            number, row = lines[index]
            if number != previous + 1 or not row.strip() or _BLOCK_START_RE.match(row):
                break
            cells = len(split_cells(row))
            if cells != width:
                yield (
                    number,
                    (
                        f"table row has {cells} cells but the header has {width} "
                        "(escape a literal | as \\|, also inside `code`)"
                    ),
                )
            previous = number
            index += 1


def _strip_inline(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", text)
    return text.replace("`", "")


def github_slug(heading: str) -> str:
    """The anchor GitHub generates for a heading (before de-duplication)."""
    text = _strip_inline(heading).strip().lower()
    kept = []
    for char in text:
        category = unicodedata.category(char)
        if char in " -_" or category[0] in "LN" or category == "Mn":
            kept.append(char)
    return "".join(kept).replace(" ", "-")


def anchors(text: str) -> set[str]:
    """Every fragment GitHub resolves in a rendered Markdown file."""
    found: set[str] = set()
    counts: dict[str, int] = {}
    previous = ""
    for _number, line in prose_lines(text):
        heading = None
        match = _HEADING_RE.match(line)
        if match:
            heading = match.group(2)
        elif _SETEXT_RE.match(line) and previous.strip() and "|" not in previous:
            heading = previous.strip()
        if heading is not None:
            slug = github_slug(heading)
            seen = counts.get(slug, 0)
            counts[slug] = seen + 1
            found.add(slug if seen == 0 else f"{slug}-{seen}")
        found.update(m.group(1) for m in _EXPLICIT_ID_RE.finditer(line))
        previous = line
    return found


def _without_code_spans(line: str) -> str:
    return _CODE_SPAN_RE.sub(lambda m: " " * len(m.group(0)), line)


def link_targets(line: str) -> Iterable[str]:
    line = _without_code_spans(line)
    for match in _INLINE_LINK_RE.finditer(line):
        yield match.group(3)
    match = _REF_DEF_RE.match(line)
    if match:
        yield match.group(1)
    for match in _HTML_LINK_RE.finditer(line):
        yield match.group(1)


def link_problems(path: Path, lines: list[tuple[int, str]], cache: dict[Path, set[str]]):
    """Relative links whose file or ``#fragment`` does not exist."""
    for number, line in lines:
        for target in link_targets(line):
            if not target or _SCHEME_RE.match(target) or target.startswith("//"):
                continue
            target_path, _, fragment = target.partition("#")
            target_path = unquote(target_path.split("?", 1)[0])
            if target_path:
                base = ROOT if target_path.startswith("/") else path.parent
                resolved = (base / target_path.lstrip("/")).resolve()
                if not resolved.exists():
                    yield number, f"link target does not exist: {target}"
                    continue
            else:
                resolved = path
            if not fragment or resolved.suffix.lower() != ".md" or resolved.is_dir():
                continue
            if resolved not in cache:
                cache[resolved] = anchors(resolved.read_text(encoding="utf-8"))
            if unquote(fragment).lower() not in {a.lower() for a in cache[resolved]}:
                yield number, f"link fragment does not match any heading or id: {target}"


_RELEASED_HEADING_RE = re.compile(r"^## \[[^\]]+\] - \d{4}-\d{2}-\d{2}")


def without_released_sections(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Drop released (dated) CHANGELOG sections: they are frozen to their tag text, so
    their relative links name the README as it was released and are not rewritten."""
    kept: list[tuple[int, str]] = []
    released = False
    for number, line in lines:
        if line.startswith("## "):
            released = bool(_RELEASED_HEADING_RE.match(line))
        if not released:
            kept.append((number, line))
    return kept


def check(paths: Iterable[Path]) -> list[str]:
    findings: list[str] = []
    cache: dict[Path, set[str]] = {}
    for path in paths:
        path = path.resolve()
        lines = list(prose_lines(path.read_text(encoding="utf-8")))
        try:
            rel = path.relative_to(ROOT).as_posix()
        except ValueError:
            rel = str(path)
        link_lines = without_released_sections(lines) if path.name == "CHANGELOG.md" else lines
        problems = sorted({*table_problems(lines), *link_problems(path, link_lines, cache)})
        findings.extend(f"{rel}:{number}: {problem}" for number, problem in problems)
    return findings


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    paths = [Path(a) for a in args] if args else tracked_markdown()
    findings = check(paths)
    for finding in findings:
        print(finding)
    print(f"checked {len(paths)} Markdown file(s): {len(findings)} problem(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
