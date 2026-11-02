#!/usr/bin/env python3
"""The one Markdown block scanner shared by the documentation gates.

Install-case extraction, provenance checking and the rendered-Markdown lint must agree
on which lines are fenced code, which are ATX headings and which are hidden inside HTML
comments; separate parsers disagreed in the past. Every gate reads lines through
``_walk`` below. It follows the CommonMark block rules the gates rely on:

* a line ends only at ``\n``, ``\r\n`` or ``\r`` (``split_lines``). Python's
  ``str.splitlines`` also breaks on form feed, vertical tab, ``\x1c``-``\x1e``, NEL and
  the Unicode line/paragraph separators, which would let a gate see a fence or heading
  GitHub renders as ordinary text, so no gate splits Markdown with it;
* fenced code opens with three or more backticks/tildes indented at most three spaces
  (a backtick fence's info string may not contain a backtick) and closes with at least
  as many of the same character and nothing but whitespace after them;
* an HTML comment block (CommonMark HTML block type 2) starts only when ``<!--`` begins
  a line indented at most three spaces, and ends on the first line containing ``-->``;
  everything on those lines, including a fence or heading after ``-->``, is HTML.
  ``<!--`` inside prose or inline code is inline content and hides nothing;
* an ATX heading is one to six ``#`` followed by a space, tab or end of line; an optional
  closing sequence of ``#`` is stripped only when preceded by a space or tab, so
  ``## C#`` keeps the text ``C#``.

Known limitation: container blocks are not modelled. A fence or comment nested inside a
block quote (``> ```bash``), opened on a list-marker line (``- ```bash``) or indented
under a list item beyond three spaces is read as prose, not as a fence or HTML block, so
such an example would be neither extracted nor provenance-checked. ``unseen_fences``
reports every such fence line, and tests/test_markdown_blocks.py fails when any tracked
public Markdown file has one, so public examples stay at the top level where every gate
sees them.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from collections.abc import Iterator
from dataclasses import dataclass

# CommonMark line: everything up to and including "\r\n", "\r" or "\n", or a final
# unterminated run of content.
LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+\Z")
FENCE = re.compile(r"^( {0,3})(`{3,}|~{3,})(.*)$")
COMMENT_START = re.compile(r"^ {0,3}<!--")
ATX = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*))?$")
CLOSING_SEQUENCE = re.compile(r"(?:^|[ \t]+)#+[ \t]*$")
# One comment: "<!--", then any text that does not itself close the comment, then "-->".
# The tempered token keeps a comment containing ">" whole and never lets one comment
# swallow a closer, the prose after it and the next comment.
COMMENT = r"<!--(?:(?!-->).)*?-->"
INLINE_COMMENT = re.compile(COMMENT, re.S)
# The container prefix a fence can hide behind: any run of indentation, block quote
# markers and list markers ("-", "*", "+", "1." or "1)" followed by a space or tab).
# What follows the prefix is a fence exactly when ``opening_fence`` accepts it, so the
# detector applies the same rules (including the backtick-free info string) as the scanner.
CONTAINER_PREFIX = re.compile(r"(?:[ \t]*(?:>|(?:[-*+]|[0-9]{1,9}[.)])[ \t]))*[ \t]*")


@dataclass(frozen=True)
class Fence:
    offset: int
    line: int
    info: str
    body: str


@dataclass(frozen=True)
class Heading:
    offset: int
    line: int
    level: int
    text: str


def split_lines(text: str, *, keepends: bool = True) -> list[str]:
    """Split ``text`` at CommonMark line endings only (``\n``, ``\r\n``, ``\r``).

    Like ``str.splitlines`` there is no trailing empty element, but form feed, vertical
    tab, ``\x1c``-``\x1e``, NEL, U+2028 and U+2029 stay inside the line.
    """
    lines = LINE.findall(text)
    return lines if keepends else [line.rstrip("\r\n") for line in lines]


def opening_fence(line: str) -> re.Match[str] | None:
    """Return the fence match for a CommonMark opening fence line, else None."""
    match = FENCE.fullmatch(line)
    if match is None or (match[2][0] == "`" and "`" in match[3]):
        return None
    return match


def heading_text(content: str) -> str:
    """Strip an ATX closing sequence only when a space or tab precedes it."""
    return CLOSING_SEQUENCE.sub("", content.strip(" \t")).strip(" \t")


def _walk(text: str) -> Iterator[tuple[int, int, str] | Fence]:
    """Yield ``(offset, line number, line)`` for prose lines and a Fence per fenced block.

    Lines inside HTML comment blocks are consumed silently; the lines of a fenced block
    (opening, body and closing) are represented only by its Fence.
    """
    lines = split_lines(text)
    index = 0
    offset = 0
    while index < len(lines):
        raw = lines[index]
        line = raw.rstrip("\r\n")
        start, number = offset, index + 1
        offset += len(raw)
        index += 1
        if COMMENT_START.match(line):
            # HTML block type 2 runs to the first line containing "-->" (or EOF).
            while "-->" not in line and index < len(lines):
                raw = lines[index]
                line = raw.rstrip("\r\n")
                offset += len(raw)
                index += 1
            continue
        opening = opening_fence(line)
        if opening is not None:
            indent, delimiter, info = opening.groups()
            closing = re.compile(
                r"^ {0,3}" + re.escape(delimiter[0]) + "{" + str(len(delimiter)) + r",}[ \t]*$"
            )
            body = []
            while index < len(lines):
                raw = lines[index]
                offset += len(raw)
                index += 1
                if closing.fullmatch(raw.rstrip("\r\n")):
                    break
                # CommonMark strips at most the opening indentation from content.
                removable = min(len(indent), len(raw) - len(raw.lstrip(" ")))
                body.append(raw[removable:])
            yield Fence(start, number, info.strip(), "".join(body))
            continue
        yield start, number, line


def scan(text: str) -> tuple[list[Fence], list[Heading]]:
    """Return fenced code blocks and ATX headings outside fences and HTML comments."""
    fences: list[Fence] = []
    headings: list[Heading] = []
    for item in _walk(text):
        if isinstance(item, Fence):
            fences.append(item)
            continue
        start, number, line = item
        heading = ATX.fullmatch(line)
        if heading is not None:
            headings.append(Heading(start, number, len(heading[1]), heading_text(heading[2] or "")))
    return fences, headings


def prose_lines(text: str) -> Iterator[tuple[int, str]]:
    """``(line number, line)`` for lines outside fenced code blocks and HTML comment blocks.

    A comment opened and closed on the same prose line is removed from that line; an
    unmatched inline ``<!--`` is left in place and hides nothing after it. Indented code
    blocks are left in: a four-space-indented line inside a list is list content on
    GitHub, so dropping indented lines would hide real tables and links.
    """
    for item in _walk(text):
        if not isinstance(item, Fence):
            _start, number, line = item
            yield number, INLINE_COMMENT.sub("", line)


def fenced_blocks(text: str):
    """Yield offset, info string and body of each CommonMark fenced code block."""
    for fence in scan(text)[0]:
        yield fence.offset, fence.info, fence.body


def h2_headings(text: str) -> list[Heading]:
    return [heading for heading in scan(text)[1] if heading.level == 2]


def section_at(headings: list[Heading], offset: int) -> str:
    """Return the text of the last H2 heading that starts before ``offset``."""
    current = ""
    for heading in headings:
        if heading.offset >= offset:
            break
        if heading.level == 2:
            current = heading.text
    return current


def unseen_fences(text: str) -> list[tuple[int, str]]:
    """``(line number, line)`` for fence markers the scanner reads as prose.

    A prose line is reported when removing its container prefix (indentation, block quote
    markers and list markers) leaves a line ``opening_fence`` accepts, so a fence indented
    four or more spaces, behind ``>`` or opened on a list-marker line is reported, while
    inline code that only looks like a fence (a backtick run followed by text containing
    another backtick) is not. Lines inside fenced code and HTML comment blocks are not
    reported.
    """
    found = []
    for item in _walk(text):
        if not isinstance(item, Fence):
            _start, number, line = item
            prefix = CONTAINER_PREFIX.match(line)
            if prefix.end() and opening_fence(line[prefix.end() :]) is not None:
                found.append((number, line))
    return found


def _after_comment(text: str, close: int) -> int | None:
    """Where the whitespace after the comment closer at ``close`` ends, else None.

    The closer must be followed by optional spaces or tabs, a CommonMark line ending
    (``\n``, ``\r\n`` or ``\r``) and then any whitespace.
    """
    index = close + 3
    while index < len(text) and text[index] in " \t":
        index += 1
    if index == len(text) or text[index] not in "\r\n":
        return None
    index += 1
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _positions(text: str, needle: str) -> list[int]:
    """Every (possibly overlapping) start index of ``needle`` in ``text``, ascending."""
    found = []
    position = text.find(needle)
    while position >= 0:
        found.append(position)
        position = text.find(needle, position + 1)
    return found


def adjacent_comments(text: str, offset: int) -> str:
    """Return the HTML comment lines immediately preceding the block at ``offset``.

    The result is the longest run of comments, each followed by a line break and blank
    space, that reaches ``offset``; prose between comments (even prose containing
    ``-->``) ends the run. A comment ends at the first ``-->`` after its ``<!--``, so it
    may contain ``>``. Openers and closers are each located once and every opener is
    resolved once, so the scan is linear in the text (no backtracking regex).
    """
    head = text[:offset]
    starts = _positions(head, "<!--")
    closers = _positions(head, "-->")
    # A comment run is valid when the chain of comments from its opener reaches the end.
    # Each link points strictly forward, so resolve validity from the last opener back.
    valid: dict[int, bool] = {}
    # Openers nested before one closer share it; resolve each closer's whitespace once.
    ends: dict[int, int | None] = {}
    first = None
    for start in reversed(starts):
        index = bisect_left(closers, start + 4)
        if index < len(closers) and index not in ends:
            ends[index] = _after_comment(head, closers[index])
        after = ends.get(index)
        if after is None:
            valid[start] = False
        elif after == len(head):
            valid[start] = True
        else:
            valid[start] = valid.get(after, False)
        if valid[start]:
            first = start
    return head[first:] if first is not None else ""
