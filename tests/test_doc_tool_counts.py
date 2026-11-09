"""Read-only and write tool counts stated in the public docs are the registered catalog's.

A tool is read-only when its ``readOnlyHint`` annotation is true (the annotation is derived
from the code, never hand-listed); every other tool is a write. Each count a public
document states — "N read-only tools", "the N write tools", the number of write tools
that take the ignored ``confirm`` argument — must
equal the number computed from the catalog the server registers, so a count can never
drift from the code again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._tool_catalog import is_read, tools
from tests.changelog_section import current_release

ROOT = Path(__file__).resolve().parents[1]

#: Every public document that can state a catalog count.
PUBLIC_DOCS = (
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "PRIVACY.md",
    ROOT / ".github" / "SECURITY.md",
    ROOT / "docs" / "AUTH-OAUTH.md",
    ROOT / "docs" / "AUTH-TLS.md",
    ROOT / "docs" / "CHATGPT.md",
    ROOT / "docs" / "CONFIGURATION.md",
    ROOT / "docs" / "COVERAGE.md",
    ROOT / "docs" / "INSTALL-AGENT.md",
    ROOT / "docs" / "MIGRATING-0.7.md",
    ROOT / "docs" / "PAGINATION.md",
    ROOT / "docs" / "RETRY.md",
    ROOT / "docs" / "TLS.md",
    ROOT / "docs" / "TOOL-USAGE.md",
    ROOT / "plugins" / "antigravity" / "README.md",
    ROOT / "plugins" / "claude" / "README.md",
    ROOT / "plugins" / "claude-desktop" / "README.md",
    ROOT / "plugins" / "codex" / "README.md",
)

_READ_ONLY = re.compile(r"\b(\d[\d,]*) read-only tools\b")
_WRITE = re.compile(r"\bthe (\d[\d,]*) write tools\b")
_CONFIRM = re.compile(r"\b(\d[\d,]*) write and action tools\b")


def _text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.name == "CHANGELOG.md":
        text = current_release()[1]
    return " ".join(text.split())


def _counts() -> dict[str, int]:
    catalog = tools()
    writes = [t for t in catalog if not is_read(t)]
    return {
        "read_only": sum(1 for t in catalog if is_read(t)),
        "write": len(writes),
        "confirm": sum(
            1 for t in writes if "confirm" in ((t.parameters or {}).get("properties") or {})
        ),
    }


def _stated(pattern: re.Pattern[str]) -> list[tuple[str, int]]:
    found = []
    for path in PUBLIC_DOCS:
        for match in pattern.finditer(_text(path)):
            found.append((str(path.relative_to(ROOT)), int(match.group(1).replace(",", ""))))
    return found


def test_every_public_doc_exists():
    missing = [str(p.relative_to(ROOT)) for p in PUBLIC_DOCS if not p.is_file()]
    assert not missing, missing


@pytest.mark.parametrize(
    ("pattern", "key"),
    [
        (_READ_ONLY, "read_only"),
        (_WRITE, "write"),
        (_CONFIRM, "confirm"),
    ],
    ids=["read-only", "write", "confirm"],
)
def test_stated_counts_are_the_catalog_counts(pattern: re.Pattern[str], key: str):
    expected = _counts()[key]
    stated = _stated(pattern)
    wrong = [(doc, n) for doc, n in stated if n != expected]
    assert not wrong, f"{key}: the registered catalog has {expected}; the docs state {wrong}"


def test_the_read_only_and_write_counts_are_stated():
    """The migration guide states both counts, so the check above is never vacuous."""
    assert _stated(_READ_ONLY), "no public document states the read-only tool count"
    assert _stated(_WRITE), "no public document states the write tool count"


def test_read_only_and_write_counts_cover_the_catalog():
    counts = _counts()
    assert counts["read_only"] + counts["write"] == len(tools())
