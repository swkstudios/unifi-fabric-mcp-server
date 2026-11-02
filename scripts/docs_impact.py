#!/usr/bin/env python3
"""Per-change docs impact map: which Markdown lines mention what this change touched.

Step one (always): read ``git diff BASE...HEAD`` over the product source, extract what
changed, and list every Markdown line in the repository that mentions any of it,
grouped by document and symbol, as text or as JSON (``--json``).

Extracted symbols (Python files under ``--source-prefix``, default ``src/``):

* ``function`` and ``class``: the innermost def or class that encloses a changed line, in
  the old or the new revision (so a tool whose body changed counts, and so does a tool
  that was removed or renamed). Private names, dunders, names under 5 characters and a
  short list of generic names are skipped because they match unrelated prose.
* ``env``: every ``UNIFI_*`` or ``MCP_*`` variable named on a changed line, plus the
  variable behind every settings field in ``src/unifi_fabric/config*.py`` whose default
  changed.
* ``default``: a changed settings default. A doc line matches when it names the variable
  and the old or the new value.
* ``message``: a string literal of at least three words on a changed line (the old text
  and the new text), matched by its longest static fragment.
* ``annotation``: a changed tool annotation hint (``readOnlyHint`` and its siblings),
  matched by the hint name and by the tool the change sits in.

Step two (``--adjudicate``, optional): ask a small Claude model whether each doc line
still matches the changed code. The model must quote one code line from the diff as
evidence; a quote that is not in the diff is reported as unverified. The key comes from
the ``ANTHROPIC_API_KEY`` environment variable only and is never printed. The output is
advisory text and never changes the exit code.

Exit status: 0 whenever a map is produced (the map is advisory), 2 on a usage or git
error.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = "claude-haiku-5-5"
SOURCE_PREFIX = "src/"
CONFIG_GLOB = re.compile(r"^src/unifi_fabric/config[^/]*\.py$")
#: Markdown that records history rather than current behaviour.
EXCLUDED_DOC_PREFIXES = ("CHANGELOG.md", "changelog.d/", "tests/fixtures/")
ENV_RE = re.compile(r"\b(?:UNIFI|MCP)_[A-Z][A-Z0-9_]*[A-Z0-9]\b")
HINT_RE = re.compile(
    r"\b(readOnlyHint|destructiveHint|idempotentHint|openWorldHint"
    r"|read_only_hint|destructive_hint|idempotent_hint|open_world_hint)\b"
)
HINT_CONSTANT_RE = re.compile(r"\bannotations\s*=\s*([A-Z_]+)\b")
STRING_RE = re.compile(r"""(?<![\w"'])(?:[rbfu]|rb|br|fr|rf)?(["'])((?:\\.|(?!\1).)*)\1""", re.I)
PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}|%[-#0 +]*\d*(?:\.\d+)?[sdrif]|\\[nrt]")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
MIN_NAME_LENGTH = 5
MIN_FRAGMENT_LENGTH = 15
GENERIC_NAMES = frozenset(
    {"setup", "build", "serve", "start", "close", "write", "parse", "model", "value", "items"}
)


@dataclass(frozen=True)
class Symbol:
    kind: str
    name: str
    #: Extra literal strings a doc line must also carry (the default-value case).
    needs_any: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass
class Extraction:
    symbols: dict[Symbol, list[str]] = field(default_factory=dict)

    def add(self, symbol: Symbol, evidence: str) -> None:
        lines = self.symbols.setdefault(symbol, [])
        if evidence not in lines:
            lines.append(evidence)


@dataclass(frozen=True)
class Hit:
    doc: str
    line: int
    text: str
    symbol: Symbol


@dataclass(frozen=True)
class DiffLine:
    path: str
    side: str  # "old" or "new"
    number: int
    text: str


def parse_diff(diff: str) -> list[DiffLine]:
    """The changed lines of a unified diff, with their line number on their own side."""
    out: list[DiffLine] = []
    path = ""
    old_path = ""
    old = new = 0
    in_hunk = False
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            in_hunk = False
            path = old_path = ""
            continue
        if not in_hunk and raw.startswith("+++ "):
            target = raw[4:].strip()
            path = (
                target[2:] if target.startswith("b/") else old_path if target == "/dev/null" else ""
            )
            continue
        if not in_hunk and raw.startswith("--- "):
            source = raw[4:].strip()
            old_path = source[2:] if source.startswith("a/") else ""
            continue
        match = HUNK_RE.match(raw)
        if match:
            old, new = int(match.group(1)), int(match.group(3))
            in_hunk = True
            continue
        if not in_hunk or not path:
            continue
        if raw.startswith("+"):
            out.append(DiffLine(path, "new", new, raw[1:]))
            new += 1
        elif raw.startswith("-"):
            out.append(DiffLine(path, "old", old, raw[1:]))
            old += 1
        elif raw.startswith(" "):
            old += 1
            new += 1
    return out


def _spans(source: str) -> list[tuple[str, str, int, int]]:
    """``(kind, name, first_line, last_line)`` for every def and class in ``source``."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            first = min([node.lineno, *(d.lineno for d in node.decorator_list)])
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            spans.append((kind, node.name, first, node.end_lineno or node.lineno))
    return spans


def _innermost(spans: list[tuple[str, str, int, int]], number: int):
    inside = [s for s in spans if s[2] <= number <= s[3]]
    return min(inside, key=lambda s: s[3] - s[2]) if inside else None


def _usable_name(name: str) -> bool:
    return (
        not name.startswith("_")
        and len(name) >= MIN_NAME_LENGTH
        and name not in GENERIC_NAMES
        and not (name.startswith("test_"))
    )


def _static_fragment(literal: str) -> str:
    parts = [p.strip() for p in PLACEHOLDER_RE.split(literal)]
    return max(parts, key=len, default="")


def _is_message(literal: str) -> bool:
    fragment = _static_fragment(literal)
    return len(fragment) >= MIN_FRAGMENT_LENGTH and len(fragment.split()) >= 3


def _config_defaults(source: str) -> dict[str, str]:
    """Settings field name -> source text of its default, for every annotated field."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    defaults: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)):
            continue
        if node.value is None or node.target.id.startswith("_"):
            continue
        value = node.value
        if isinstance(value, ast.Call):
            default = next((k.value for k in value.keywords if k.arg == "default"), None)
            if default is None:
                if not value.keywords and not value.args:
                    continue
                default = next(
                    (k.value for k in value.keywords if k.arg == "default_factory"), None
                )
            if default is None:
                continue
            value = default
        defaults[node.target.id] = ast.unparse(value)
    return defaults


def _default_values(text: str) -> tuple[str, ...]:
    """The forms a doc may use for a default: the source text and the bare value."""
    forms = [text]
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return tuple(forms)
    if isinstance(value, bool):
        forms += [str(value).lower(), str(value)]
    elif isinstance(value, str):
        forms.append(value)
    else:
        forms.append(str(value))
    return tuple(dict.fromkeys(f for f in forms if f))


def extract(diff: str, read_file: Callable[[str, str], str | None]) -> Extraction:
    """What the diff changed. ``read_file(side, path)`` returns the file at the old or new
    revision (``None`` when it does not exist there)."""
    result = Extraction()
    lines = [
        d for d in parse_diff(diff) if d.path.startswith(SOURCE_PREFIX) and d.path.endswith(".py")
    ]
    spans: dict[tuple[str, str], list[tuple[str, str, int, int]]] = {}
    for d in lines:
        key = (d.side, d.path)
        if key not in spans:
            spans[key] = _spans(read_file(*key) or "")
        enclosing = _innermost(spans[key], d.number)
        stripped = d.text.strip()
        if enclosing and _usable_name(enclosing[1]):
            result.add(Symbol(enclosing[0], enclosing[1]), f"{d.side} {d.path}:{d.number}")
        if stripped.startswith("#"):
            continue
        for var in ENV_RE.findall(d.text):
            result.add(Symbol("env", var), f"{d.side} {d.path}:{d.number}: {stripped}")
        for hint in HINT_RE.findall(d.text):
            result.add(Symbol("annotation", hint), f"{d.side} {d.path}:{d.number}: {stripped}")
            if enclosing and _usable_name(enclosing[1]):
                result.add(
                    Symbol("annotation", f"{hint} on {enclosing[1]}"),
                    f"{d.side} {d.path}:{d.number}: {stripped}",
                )
        const = HINT_CONSTANT_RE.search(d.text)
        if const and const.group(1) in {"READ_ONLY", "WRITE"} and enclosing:
            # A decorator belongs to the span of the def under it.
            if _usable_name(enclosing[1]):
                result.add(
                    Symbol("annotation", f"{const.group(1)} on {enclosing[1]}"),
                    f"{d.side} {d.path}:{d.number}: {stripped}",
                )
        if stripped.startswith(('"""', "'''")) or '"""' in stripped:
            continue
        for match in STRING_RE.finditer(d.text):
            literal = match.group(2)
            if _is_message(literal):
                result.add(
                    Symbol("message", _static_fragment(literal)),
                    f"{d.side} {d.path}:{d.number}: {stripped}",
                )
    _extract_defaults(diff, read_file, result)
    return result


def _extract_defaults(
    diff: str, read_file: Callable[[str, str], str | None], result: Extraction
) -> None:
    paths = sorted({d.path for d in parse_diff(diff) if CONFIG_GLOB.match(d.path)})
    for path in paths:
        old = _config_defaults(read_file("old", path) or "")
        new = _config_defaults(read_file("new", path) or "")
        for name in sorted(old.keys() | new.keys()):
            if old.get(name) == new.get(name):
                continue
            var = f"UNIFI_{name.upper()}"
            forms = tuple(
                dict.fromkeys(
                    f
                    for text in (old.get(name), new.get(name))
                    if text
                    for f in _default_values(text)
                )
            )
            evidence = (
                f"{path}: {name} default {old.get(name, '(none)')} -> {new.get(name, '(removed)')}"
            )
            result.add(Symbol("default", var, forms), evidence)
            result.add(Symbol("env", var), evidence)


def _word(name: str) -> re.Pattern[str]:
    return re.compile(rf"(?<!\w){re.escape(name)}(?!\w)")


ANNOTATION_WORDS = re.compile(
    r"read[- ]?only|destructive|idempotent|open[- ]?world|annotation|hint", re.I
)
CODE_SPAN = r"`[^`\n]*(?<!\w){name}(?!\w)[^`\n]*`|(?<!\w){name}\("


def _is_plain_word(name: str) -> bool:
    """A name that reads as ordinary prose: no underscore and at most one capital."""
    return "_" not in name and sum(c.isupper() for c in name) <= 1


def _matcher(symbol: Symbol) -> Callable[[str], bool]:
    name = symbol.name
    if symbol.kind == "message":
        return lambda line: name in line
    if symbol.kind == "annotation" and " on " in name:
        tool = name.split(" on ", 1)[1]
        word = _word(tool)
        return lambda line: (
            tool in line and bool(word.search(line)) and bool(ANNOTATION_WORDS.search(line))
        )
    if symbol.kind in {"function", "class"} and _is_plain_word(name):
        # A plain English word is a mention only inside a code span or as a call.
        code = re.compile(CODE_SPAN.format(name=re.escape(name)))
        return lambda line: name in line and bool(code.search(line))
    word = _word(name)
    if symbol.needs_any:
        needs = symbol.needs_any
        return lambda line: (
            name in line and bool(word.search(line)) and any(n in line for n in needs)
        )
    return lambda line: name in line and bool(word.search(line))


def markdown_files(root: Path, tracked: Iterable[str]) -> list[str]:
    return sorted(
        p for p in tracked if p.lower().endswith(".md") and not p.startswith(EXCLUDED_DOC_PREFIXES)
    )


def _index_key(symbol: Symbol) -> str | None:
    """The identifier a doc line must contain for the symbol to match; None: scan every line."""
    if symbol.kind == "message":
        return None
    return symbol.name.split(" on ", 1)[-1] if symbol.kind == "annotation" else symbol.name


def find_hits(extraction: Extraction, docs: dict[str, list[str]]) -> list[Hit]:
    by_word: dict[str, list[tuple[Symbol, Callable[[str], bool]]]] = defaultdict(list)
    scanned: list[tuple[Symbol, Callable[[str], bool]]] = []
    for symbol in extraction.symbols:
        key = _index_key(symbol)
        (scanned if key is None else by_word[key]).append((symbol, _matcher(symbol)))
    hits = []
    for doc in sorted(docs):
        for number, text in enumerate(docs[doc], 1):
            candidates = list(scanned)
            for word in set(re.findall(r"\w+", text)):
                candidates.extend(by_word.get(word, ()))
            for symbol, matches in candidates:
                if matches(text):
                    hits.append(Hit(doc, number, text.rstrip(), symbol))
    return hits


def group(hits: list[Hit]) -> dict[str, dict[str, list[Hit]]]:
    grouped: dict[str, dict[str, list[Hit]]] = defaultdict(lambda: defaultdict(list))
    for hit in hits:
        grouped[hit.doc][hit.symbol.label].append(hit)
    return grouped


def to_json(base: str, head: str, extraction: Extraction, hits: list[Hit]) -> dict:
    grouped = group(hits)
    return {
        "base": base,
        "head": head,
        "symbols": [
            {"kind": s.kind, "name": s.name, "evidence": ev}
            for s, ev in sorted(extraction.symbols.items(), key=lambda i: i[0].label)
        ],
        "counts": {doc: sum(len(v) for v in by.values()) for doc, by in sorted(grouped.items())},
        "total": len(hits),
        "docs": {
            doc: {
                label: [{"line": h.line, "text": h.text} for h in items]
                for label, items in sorted(by.items())
            }
            for doc, by in sorted(grouped.items())
        },
    }


def to_text(base: str, head: str, extraction: Extraction, hits: list[Hit]) -> str:
    out = [
        f"Docs impact map {base}...{head}: {len(extraction.symbols)} changed symbols, "
        f"{len(hits)} doc lines in {len({h.doc for h in hits})} files (advisory)"
    ]
    for doc, by in sorted(group(hits).items()):
        out.append("")
        out.append(f"{doc} ({sum(len(v) for v in by.values())})")
        for label, items in sorted(by.items()):
            out.append(f"  {label}")
            out.extend(f"    {h.line}: {h.text.strip()[:200]}" for h in items)
    if not hits:
        out.append("No Markdown line mentions a changed symbol.")
    return "\n".join(out)


# --- git plumbing -----------------------------------------------------------------


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=check, encoding="utf-8"
    )


def read_revision(base: str, head: str) -> Callable[[str, str], str | None]:
    merge_base = git("merge-base", base, head).stdout.strip()

    def read(side: str, path: str) -> str | None:
        rev = merge_base if side == "old" else head
        proc = git("show", f"{rev}:{path}", check=False)
        return proc.stdout if proc.returncode == 0 else None

    return read


def load_docs(tracked: Iterable[str]) -> dict[str, list[str]]:
    docs = {}
    for path in markdown_files(ROOT, tracked):
        file = ROOT / path
        if file.is_file():
            docs[path] = file.read_text(encoding="utf-8", errors="replace").splitlines()
    return docs


# --- step two: adjudication -------------------------------------------------------

PROMPT = """\
You check whether a documentation line still matches code that just changed.

Changed symbol: {symbol}
Doc file: {doc}, line {line}
Doc line and its neighbours:
{context}

Changed code lines from the diff (old lines start with "-", new lines with "+"):
{evidence}

Answer with one JSON object and nothing else:
{{"verdict": "matches" | "stale" | "unclear",
  "evidence": "<one code line copied exactly from the changed code lines above>",
  "reason": "<one sentence>"}}
Use "stale" only when the doc line states something the new code contradicts. Use
"matches" only when the new code supports the doc line. The evidence must be a verbatim
code line from above, without its leading "+" or "-"; without one, answer "unclear".
"""


def adjudicate(
    hits: list[Hit],
    docs: dict[str, list[str]],
    extraction: Extraction,
    diff_lines: list[DiffLine],
    client,
    model: str = MODEL,
) -> list[str]:
    """One advisory line per hit. Never raises; a failed call is reported and skipped."""
    changed = {d.text.strip() for d in diff_lines if d.text.strip()}
    report = []
    for hit in hits:
        lines = docs[hit.doc]
        lo = max(0, hit.line - 3)
        context = "\n".join(
            f"{n + 1}: {lines[n]}" for n in range(lo, min(len(lines), hit.line + 2))
        )
        evidence = "\n".join(extraction.symbols.get(hit.symbol, [])) or "(see symbol)"
        evidence = _code_evidence(hit.symbol, diff_lines, evidence)
        prompt = PROMPT.format(
            symbol=hit.symbol.label,
            doc=hit.doc,
            line=hit.line,
            context=context,
            evidence=evidence,
        )
        where = f"{hit.doc}:{hit.line} [{hit.symbol.label}]"
        try:
            reply = client.messages.create(
                model=model, max_tokens=400, messages=[{"role": "user", "content": prompt}]
            )
            text = "".join(getattr(b, "text", "") for b in reply.content)
            verdict = _parse_verdict(text, changed)
        except Exception as exc:  # advisory step: report the class only, never the message
            report.append(f"{where}: adjudication unavailable ({type(exc).__name__})")
            continue
        report.append(f"{where}: {verdict}")
    return report


def _code_evidence(symbol: Symbol, diff_lines: list[DiffLine], fallback: str) -> str:
    """The changed lines the model may quote: those that mention the symbol, else all."""
    needle = symbol.name.split(" on ")[-1] if symbol.kind != "message" else symbol.name
    picked = [d for d in diff_lines if needle in d.text and d.path.startswith(SOURCE_PREFIX)]
    if not picked:
        picked = [d for d in diff_lines if d.path.startswith(SOURCE_PREFIX)][:60]
    body = "\n".join(f"{'-' if d.side == 'old' else '+'} {d.text}" for d in picked[:60])
    return body or fallback


def _parse_verdict(text: str, changed: set[str]) -> str:
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return "unclear (no structured answer)"
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return "unclear (unreadable answer)"
    verdict = str(data.get("verdict", "unclear"))
    quote = str(data.get("evidence", "")).strip()
    reason = str(data.get("reason", "")).strip()
    if verdict not in {"matches", "stale", "unclear"}:
        verdict = "unclear"
    if verdict != "unclear" and quote not in changed:
        return f"unverified {verdict} (quoted line not in the diff): {reason}"
    return f'{verdict}: {reason} evidence: "{quote}"' if quote else f"{verdict}: {reason}"


def make_client():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None, "ANTHROPIC_API_KEY is not set"
    try:
        import anthropic
    except ImportError:
        return None, "the anthropic package is not installed (pip install anthropic)"
    return anthropic.Anthropic(api_key=key), ""


# --- command line -----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="origin/dev", help="base revision (default origin/dev)")
    parser.add_argument("--head", default="HEAD", help="head revision (default HEAD)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument(
        "--adjudicate",
        action="store_true",
        help=f"ask {MODEL} whether each doc line still matches (advisory, needs ANTHROPIC_API_KEY)",
    )
    args = parser.parse_args(argv)
    try:
        diff = git("diff", "--no-color", "-U0", f"{args.base}...{args.head}").stdout
        read = read_revision(args.base, args.head)
        tracked = git("ls-files").stdout.splitlines()
    except subprocess.CalledProcessError as exc:
        print(f"docs_impact: git failed: {exc.stderr.strip()}", file=sys.stderr)
        return 2
    extraction = extract(diff, read)
    docs = load_docs(tracked)
    hits = find_hits(extraction, docs)
    if args.json:
        print(json.dumps(to_json(args.base, args.head, extraction, hits), indent=2))
    else:
        print(to_text(args.base, args.head, extraction, hits))
    if args.adjudicate:
        client, why = make_client()
        if client is None:
            print(f"\nAdjudication skipped: {why}.")
        else:
            print("\nAdjudication (advisory; the model can be wrong):")
            for line in adjudicate(hits, docs, extraction, parse_diff(diff), client):
                print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
