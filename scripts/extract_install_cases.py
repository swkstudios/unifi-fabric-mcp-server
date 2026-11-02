#!/usr/bin/env python3
"""Extract reviewed install examples; never execute arbitrary documentation as shell code."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from markdown_blocks import adjacent_comments, fenced_blocks, h2_headings

ROOT = Path(__file__).resolve().parents[1]
MODES = {
    "uvx",
    "pipx",
    "pip",
    "desktop",
    "codex",
    "plugin",
    "docker",
    "source",
    "antigravity",
    "non-executable",
}
MARKER = re.compile(
    r"<!-- install-case: ([a-z0-9][a-z0-9-]*) mode=([a-z-]+)"
    r"(?: reason=([^\n]*?))? -->"
)
INSTALL = re.compile(
    r"\b(?:uvx|pipx|pip install|docker (?:run|pull)|mcpServers|mcp_servers|"
    r"plugin install|plugin add|marketplace add|extensions install|"
    r"claude --plugin-dir|(?:claude|codex|agy) mcp add)\b"
)


# Execution modes that can run on one platform only. Elsewhere the install smoke records
# such a case as NOT-TESTED with this reason, and the executed-case claim check excuses
# exactly these cases on exactly those other platforms (never on the required one).
PLATFORM_ONLY = {"docker": "Linux"}
PLATFORM_ONLY_REASON = {"docker": "Docker runs on the Linux job only"}
DOCKER_DEFERRED_REASON = "Docker cases run only on a protected-ref manual dispatch or release path"


def public_documents(root: Path) -> list[Path]:
    """The one public documentation set every documentation gate reads.

    README.md plus every Markdown file under docs/ and plugins/ (recursively).
    """
    return sorted(
        p
        for p in {
            root / "README.md",
            *(root / "docs").rglob("*.md"),
            *(root / "plugins").rglob("*.md"),
        }
        if p.is_file()
    )


README_INSTALL_REGIONS = (
    ("Quick Start", "Example Prompts"),
    ("Set up your client", "About this server"),
    ("Docker Deployment", "Contributing"),
)


def in_readme_install_region(text: str, offset: int) -> bool:
    """Whether ``offset`` lies in a README install region bounded by real H2 headings.

    Headings compare case-insensitively. A region whose start heading, or an end heading
    after that start, is missing (renamed or deleted) raises instead of silently
    exempting the examples it used to cover.
    """
    headings = h2_headings(text)
    inside = False
    for first, last in README_INSTALL_REGIONS:
        start = next((h.offset for h in headings if h.text.casefold() == first.casefold()), None)
        if start is None:
            raise ValueError(f"README.md: install region heading '## {first}' not found")
        end = next(
            (
                h.offset
                for h in headings
                if h.text.casefold() == last.casefold() and h.offset > start
            ),
            None,
        )
        if end is None:
            raise ValueError(
                f"README.md: install region heading '## {last}' not found after '## {first}'"
            )
        inside = inside or start <= offset < end
    return inside


def requires_case(path: Path, text: str, offset: int, body: str, root: Path) -> bool:
    if INSTALL.search(body):
        return True
    relative = path.relative_to(root).as_posix()
    if relative == "docs/INSTALL-AGENT.md":
        return True
    return relative == "README.md" and in_readme_install_region(text, offset)


def extract_cases(root: Path = ROOT) -> list[dict]:
    cases = []
    ids = set()
    for path in public_documents(root):
        text = path.read_text()
        for offset, language, body in fenced_blocks(text):
            # Both provenance and case comments may immediately precede the fence.
            marker = MARKER.search(adjacent_comments(text, offset))
            if not marker:
                if requires_case(path, text, offset, body, root):
                    line = text[:offset].count("\n") + 1
                    raise ValueError(f"{path.relative_to(root)}:{line}: unmarked install example")
                continue
            case_id, mode, reason = marker.groups()
            if mode not in MODES:
                raise ValueError(f"{case_id}: unknown execution mode {mode}")
            if case_id in ids:
                raise ValueError(f"duplicate install case {case_id}")
            if mode == "non-executable" and not reason:
                raise ValueError(f"{case_id}: non-executable requires a reason")
            if "sudo pip" in body:
                raise ValueError(f"{case_id}: sudo pip is forbidden")
            ids.add(case_id)
            cases.append(
                {
                    "id": case_id,
                    "mode": mode,
                    "reason": reason,
                    "path": str(path.relative_to(root)),
                    "language": language,
                    "body": body,
                }
            )
    if not cases:
        raise ValueError("no install cases found")
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    payload = json.dumps(extract_cases(args.root), indent=2) + "\n"
    if args.out:
        args.out.write_text(payload)
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
