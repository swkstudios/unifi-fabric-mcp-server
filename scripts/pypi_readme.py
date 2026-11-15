#!/usr/bin/env python3
"""Make README.md's relative links absolute for the PyPI long description.

PyPI renders the long description outside the repository, so a relative link
(``docs/TOOLS.md``) or image (the banner) does not resolve there. This rewrites every
relative Markdown link and image target, and the ``src`` and ``srcset`` of every HTML
``<img>`` and ``<source>`` tag, to an absolute URL on the repository's main branch (pages
under ``/blob/main/``, images from ``raw.githubusercontent.com``), taking the repository
from ``[project.urls] Repository`` in pyproject.toml. Absolute URLs, in-page anchors and
``mailto:`` links are left alone.

What it leaves alone on purpose: the ``src`` of a ``<script>`` or ``<iframe>``, ``data-src``
and any other attribute that merely contains "src", anything inside a fenced code block, an
inline code span or a ``<pre>``/``<code>`` element, and prose. Tag and attribute names may
be in any case, and a value may be double-quoted, single-quoted or unquoted.

``--check`` fails while any relative target remains in the file: a Markdown link or image, an
``<img>``/``<source>`` ``src`` or ``srcset`` URL, or an ``<img>``/``<source>`` tag this script
cannot read (an attribute it cannot parse, a tag with no closing ``>``). It therefore also
fails on a relative image the rewrite would have missed.

publish-pypi.yml (and the public-artifact dry run) run it on the build workspace right
before ``python -m build``; the repository's README itself keeps its relative links.

Usage:
  python scripts/pypi_readme.py [README.md]          rewrite the file in place
  python scripts/pypi_readme.py --check [README.md]  exit 1 if a relative target remains
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# ``[label](target)`` and ``![alt](target)``; the label may hold one nested image (a
# linked badge), and the target ends at whitespace (an optional "title") or ")".
LINK = re.compile(r"(!?)\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\(([^)\s]+)((?:\s+\"[^\"]*\")?)\)")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
# An HTML ``<img>`` or ``<source>`` start tag, up to the ``>`` that is not inside a quoted value.
_TAG = re.compile(r"<(img|source)(?![\w:-])(?:\"[^\"]*\"|'[^']*'|[^>\"'])*>", re.IGNORECASE)
_TAG_START = re.compile(r"<(?:img|source)(?![\w:-])", re.IGNORECASE)
# One attribute: a name, and optionally ``=`` and a double-quoted, single-quoted or bare value.
_ATTR = re.compile(r"([^\s\"'<>/=]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'<>`]+)))?")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_INLINE_CODE = re.compile(r"(?<!`)(`+)(?!`)((?:(?!\n[ \t]*\n).)+?)(?<!`)\1(?!`)", re.DOTALL)
_HTML_CODE = re.compile(r"<(pre|code)(?![\w:-])[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)


def repository_url(pyproject: Path = ROOT / "pyproject.toml") -> str:
    urls = tomllib.loads(pyproject.read_text())["project"]["urls"]
    url = urls["Repository"].rstrip("/")
    if not re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+", url):
        raise SystemExit(f"[project.urls] Repository is not a GitHub repository URL: {url!r}")
    return url


def is_relative(target: str) -> bool:
    # An empty value (``src=""``) names nothing: it is left as it is, and it is not a target.
    if not target.strip():
        return False
    return not (_SCHEME.match(target) or target.startswith(("#", "//")))


def _fence_spans(text: str) -> list[tuple[int, int]]:
    """Character spans of fenced code blocks (an unclosed fence runs to the end)."""
    spans: list[tuple[int, int]] = []
    offset = 0
    open_at: int | None = None
    marker = ""
    for line in text.splitlines(keepends=True):
        m = _FENCE.match(line)
        if open_at is None:
            if m:
                open_at, marker = offset, m.group(1)
        elif m and m.group(1)[0] == marker[0] and len(m.group(1)) >= len(marker):
            if not line.strip(" \t\r\n" + marker[0]):
                spans.append((open_at, offset + len(line)))
                open_at = None
        offset += len(line)
    if open_at is not None:
        spans.append((open_at, len(text)))
    return spans


def _code_spans(text: str) -> list[tuple[int, int]]:
    """Fenced blocks, inline code spans and ``<pre>``/``<code>`` elements."""
    spans = _fence_spans(text)
    spans += [m.span() for m in _INLINE_CODE.finditer(text)]
    spans += [m.span() for m in _HTML_CODE.finditer(text)]
    return spans


def _inside(spans: list[tuple[int, int]], position: int) -> bool:
    return any(start <= position < end for start, end in spans)


def _attributes(tag: str):
    """The attributes of a start tag as (name, value, value_start, value_end), and whether all
    of the tag was read. A value-less attribute has value None."""
    name_end = _TAG_START.match(tag).end()  # type: ignore[union-attr]
    body_end = len(tag) - 1  # before the closing ">"
    found = []
    pos = name_end
    while pos < body_end:
        while pos < body_end and (tag[pos].isspace() or tag[pos] == "/"):
            pos += 1
        if pos >= body_end:
            break
        m = _ATTR.match(tag, pos, body_end)
        if not m:
            return found, False
        for group in (2, 3, 4):
            if m.group(group) is not None:
                found.append((m.group(1), m.group(group), m.start(group), m.end(group)))
                break
        else:
            found.append((m.group(1), None, -1, -1))
        pos = m.end()
    return found, True


def _srcset_urls(value: str):
    """(start, end) of each candidate URL in a ``srcset`` value, read the way HTML reads it: a
    URL runs to whitespace, trailing commas end a candidate, and a descriptor runs to the
    next comma. A ``data:`` URI keeps its inner comma because it holds no whitespace."""
    pos = 0
    n = len(value)
    while pos < n:
        while pos < n and (value[pos].isspace() or value[pos] == ","):
            pos += 1
        if pos >= n:
            break
        start = pos
        while pos < n and not value[pos].isspace():
            pos += 1
        end = pos
        while end > start and value[end - 1] == ",":
            end -= 1
        yield start, end
        if value[pos - 1 : pos] == ",":
            continue  # the URL ended with a comma: no descriptor
        depth = 0
        while pos < n:  # skip the descriptor
            if value[pos] == "(":
                depth += 1
            elif value[pos] == ")":
                depth = max(0, depth - 1)
            elif value[pos] == "," and depth == 0:
                break
            pos += 1


def absolutize(text: str, repo: str) -> str:
    owner_repo = repo.removeprefix("https://github.com/")
    blob = f"{repo}/blob/main/"
    raw = f"https://raw.githubusercontent.com/{owner_repo}/main/"

    def fix(target: str, image: bool) -> str:
        if not is_relative(target):
            return target
        return (raw if image else blob) + target.removeprefix("./").lstrip("/")

    def sub(m: re.Match[str]) -> str:
        bang, label, target, title = m.groups()
        label = LINK.sub(sub, label)  # a linked badge: the image inside the label
        return f"{bang}[{label}]({fix(target, bool(bang))}{title})"

    def tag(original: str) -> str:
        attrs, _ = _attributes(original)
        out = original
        for name, value, start, end in sorted(attrs, key=lambda a: -a[2]):
            lowered = name.lower()
            if value is None or lowered not in ("src", "srcset"):
                continue
            if lowered == "src":
                replacement = fix(value, True)
            else:
                replacement = value
                for u_start, u_end in reversed(list(_srcset_urls(value))):
                    replacement = (
                        replacement[:u_start]
                        + fix(replacement[u_start:u_end], True)
                        + replacement[u_end:]
                    )
            out = out[:start] + replacement + out[end:]
        return out

    # Markdown links first (offsets are those of the original text), then the HTML tags on
    # the result, with their code spans found again because the first pass moved the text.
    fences = _fence_spans(text)
    text = LINK.sub(lambda m: m.group(0) if _inside(fences, m.start()) else sub(m), text)
    code = _code_spans(text)
    return _TAG.sub(lambda m: m.group(0) if _inside(code, m.start()) else tag(m.group(0)), text)


def relative_targets(text: str) -> list[str]:
    found: list[str] = []
    code = _code_spans(text)
    fences = _fence_spans(text)

    def walk(s: str) -> None:
        for m in LINK.finditer(s):
            walk(m.group(2))  # a linked badge: the image inside the label
            if is_relative(m.group(3)):
                found.append(m.group(3))

    # A Markdown link inside a fenced block is a sample, not a link: it is skipped, as the
    # rewrite skips it. (Nested labels are never inside a fence on their own.)
    cursor = 0
    for start, end in sorted(fences):
        walk(text[cursor:start])
        cursor = end
    walk(text[cursor:])
    for m in _TAG_START.finditer(text):
        if _inside(code, m.start()):
            continue
        whole = _TAG.match(text, m.start())
        if whole is None:
            found.append(f"unterminated {text[m.start() : m.start() + 40]!r}")
            continue
        attrs, complete = _attributes(whole.group(0))
        for name, value, _start, _end in attrs:
            lowered = name.lower()
            if value is None or lowered not in ("src", "srcset"):
                continue
            if lowered == "src":
                urls = [value]
            else:
                urls = [value[a:b] for a, b in _srcset_urls(value)]
            found.extend(u for u in urls if u and is_relative(u))
        if not complete and re.search(r"src", whole.group(0), re.IGNORECASE):
            found.append(f"unreadable {whole.group(0)[:40]!r}")
    return found


def main(argv: list[str]) -> int:
    check = "--check" in argv
    args = [a for a in argv if a != "--check"]
    path = Path(args[0]) if args else ROOT / "README.md"
    text = path.read_text(encoding="utf-8")
    if check:
        left = relative_targets(text)
        for target in left:
            print(f"relative link target left in {path}: {target}")
        return 1 if left else 0
    path.write_text(absolutize(text, repository_url()), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
