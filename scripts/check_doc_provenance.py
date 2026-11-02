#!/usr/bin/env python3
"""Check example provenance without installing the server or contacting upstream APIs.

Each fenced example in public docs/plugins and each README installation example has
an adjacent comment naming a source file and its SHA-256, support version and case; any
other README example that carries a doc-provenance marker is checked the same way.
Relative file:<path>@sha256:<digest> pins resolve from the repository root and survive
public mirroring without private Git history. A citation may replace an install case,
except for an executed install example: one whose install-case marker names an
executable mode must name that same case with case=, so its provenance is tied to the
launcher the install smoke runs. A case= that names a different adjacent case fails.
Fences, headings and comments are read by the shared markdown_blocks scanner, the same
one install-case extraction uses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

from extract_install_cases import (
    DOCKER_DEFERRED_REASON,
    PLATFORM_ONLY,
    public_documents,
    requires_case,
)
from extract_install_cases import MARKER as INSTALL_MARKER
from markdown_blocks import Fence, adjacent_comments, scan, section_at, split_lines

ROOT = Path(__file__).resolve().parents[1]
MARKER = re.compile(r"<!--\s*doc-provenance:\s*(.*?)\s*-->")
FILE_PIN = re.compile(r"file:([^@\s]+)@sha256:([0-9a-f]{64})$")
PIN = re.compile(
    r"(?:file:[^@\s]+@sha256:[0-9a-f]{64}|git:[0-9a-f]{40}|https://[^\s]+/"
    r"(?:[0-9a-f]{40}|v?\d+\.\d+\.\d+)/[^\s]+)$"
)
VERSION = re.compile(r"\d+\.\d+\.\d+(?:[a-zA-Z0-9.+-]*)$")
SUPPORTED_PLATFORMS = frozenset({"Linux", "Darwin", "Windows"})
INSTALL_HEADING = re.compile(
    r"install|quick.?start|use with|running locally|docker|from source|"
    r"set up your client|troubleshooting",
    re.I,
)


def public_docs(root: Path) -> list[Path]:
    """Every public document needs example provenance, including generated tools."""
    return public_documents(root)


def public_reference_docs(root: Path) -> list[Path]:
    """Link and image checks alone exclude the generated tool reference."""
    generated = root / "docs" / "TOOLS.md"
    return [p for p in public_docs(root) if p != generated]


def fields(raw: str) -> dict[str, str]:
    return dict(item.split("=", 1) for item in shlex.split(raw) if "=" in item)


def markdown_h2_headings(text: str) -> list[str]:
    """Return H2 headings outside fenced code and HTML comments."""
    return [heading.text for heading in scan(text)[1] if heading.level == 2]


def _examples(path: Path, root: Path):
    """Yield (fence, adjacent comments, marked case, case required?) per checked example."""
    text = path.read_text(encoding="utf-8")
    fences, headings = scan(text)
    for fence in fences:
        comments = adjacent_comments(text, fence.offset)
        install_marker = INSTALL_MARKER.search(comments)
        scoped = path != root / "README.md"
        if not scoped:
            scoped = bool(INSTALL_HEADING.search(section_at(headings, fence.offset)))
        # A provenance marker is verified wherever it appears, so a pin outside the
        # install sections cannot go stale unnoticed.
        if scoped or install_marker or MARKER.search(comments):
            if install_marker is None:
                # Extraction rejects an unmarked install example; never let it pass here.
                if requires_case(path, text, fence.offset, fence.body, root):
                    yield fence, comments, None, True
                else:
                    yield fence, comments, None, False
            else:
                executed = install_marker[2] != "non-executable"
                yield fence, comments, install_marker[1], executed


def examples(path: Path, root: Path = ROOT):
    """Yield CommonMark fenced examples and their adjacent comment block."""
    for fence, comments, _, _ in _examples(path, root):
        yield fence.line, comments


def _identity(path: Path, fence: Fence, headings_text: str, root: Path) -> tuple[str, str, str]:
    digest = hashlib.sha256(fence.body.encode("utf-8")).hexdigest()
    return path.relative_to(root).as_posix(), headings_text, digest


def example_identity(path: Path, number: int, root: Path) -> tuple[str, str, str]:
    """Identify an example by file, H2 section and CommonMark fenced body."""
    text = path.read_text(encoding="utf-8")
    fences, headings = scan(text)
    for fence in fences:
        if fence.line == number:
            return _identity(path, fence, section_at(headings, fence.offset), root)
    raise ValueError("example line must start a fenced block")


def file_pin_exists(root: Path, pin: str) -> bool:
    """Verify source bytes without requiring the private repository history."""
    match = FILE_PIN.fullmatch(pin)
    if match is None:
        return False
    relative, expected = match.groups()
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        return False
    target = (root / path).resolve()
    if not target.is_relative_to(root.resolve()) or not target.is_file():
        return False
    return hashlib.sha256(target.read_bytes()).hexdigest() == expected


def sidecar_entries(root: Path) -> list[dict[str, str]]:
    path = root / "scripts/doc_provenance.json"
    if not path.exists():
        return []
    entries = json.loads(path.read_text())["examples"]
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("invalid documentation provenance sidecar")
    return entries


def git_object_exists(root: Path, revision: str, *, file: str | None = None) -> bool:
    """Resolve commits and cited file bytes in Git, rather than the current checkout."""
    if file is not None:
        kind = subprocess.run(  # noqa: S603
            ["git", "cat-file", "-t", f"{revision}:{file}"],  # noqa: S607
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if kind.returncode or kind.stdout.strip() != "blob":
            return False
    command = (
        ["git", "show", f"{revision}:{file}"]
        if file is not None
        else ["git", "cat-file", "-e", f"{revision}^{{commit}}"]
    )
    result = subprocess.run(  # noqa: S603
        command, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    )
    return result.returncode == 0


def check_executed_cases(
    root: Path, report: dict, not_tested: list[dict] | None = None
) -> list[str]:
    """Check the agent guide claims against successful launcher execution evidence.

    A claimed case needs a TESTED-LIVE row with every probe passing. The only exception
    is a case whose documented mode runs on one platform only (``PLATFORM_ONLY``, for
    example Docker on Linux) in a report from a different platform, or a Docker case
    deliberately deferred to the protected-ref/release Docker lane, whose row is
    NOT-TESTED: it is excused and appended to ``not_tested`` with its reason. A report
    from the required platform, without the explicit deferral, or one without a
    supported platform, excuses nothing.
    Case ids must be unique: duplicate rows cannot supply successful or excused evidence.
    """
    path = root / "docs/INSTALL-AGENT.md"
    if not path.is_file():
        return []
    rows = report.get("cases", [])
    seen = set()
    failures = []
    for row in rows:
        case_id = row["id"]
        if case_id in seen:
            failures.append(f"install results: duplicate execution case {case_id}")
        seen.add(case_id)
    if failures:
        return failures
    successful = {
        row["id"]
        for row in rows
        if row.get("status") == "TESTED-LIVE"
        and all(
            row.get(key) is True
            for key in ("starts", "tools_ok", "read", "missing_key", "wrong_key", "version_ok")
        )
    }
    untested = {row["id"]: row for row in rows if row.get("status") == "NOT-TESTED"}
    system = report.get("platform")
    supported_platform = isinstance(system, str) and system in SUPPORTED_PLATFORMS
    modes: dict[str, str] | None = None
    executed_column = None
    for number, line in enumerate(split_lines(path.read_text(encoding="utf-8"), keepends=False), 1):
        if not line.startswith("|"):
            executed_column = None
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if "Executed case" in cells:
            executed_column = cells.index("Executed case")
            continue
        if executed_column is None or all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        if executed_column >= len(cells):
            failures.append(f"docs/INSTALL-AGENT.md:{number}: missing Executed case cell")
            continue
        ids = re.findall(r"`([^`]+)`", cells[executed_column])
        if not ids:
            failures.append(f"docs/INSTALL-AGENT.md:{number}: Executed case requires a case id")
        for case_id in ids:
            if case_id in successful:
                continue
            if case_id in untested and supported_platform:
                if modes is None:
                    from extract_install_cases import extract_cases

                    try:
                        modes = {case["id"]: case["mode"] for case in extract_cases(root)}
                    except ValueError as error:
                        failures.append(f"install case extraction: {error}")
                        modes = {}
                required = PLATFORM_ONLY.get(modes.get(case_id, ""))
                deferred_docker = (
                    modes.get(case_id) == "docker"
                    and untested[case_id].get("reason") == DOCKER_DEFERRED_REASON
                )
                if required is not None and (system != required or deferred_docker):
                    if not_tested is not None:
                        not_tested.append(
                            {
                                "id": case_id,
                                "line": number,
                                "platform": system,
                                "required_platform": required,
                                "reason": untested[case_id].get("reason", ""),
                            }
                        )
                    continue
            failures.append(
                f"docs/INSTALL-AGENT.md:{number}: executed case {case_id} "
                "has no successful execution evidence"
            )
    return failures


def check(root: Path = ROOT, cases: set[str] | None = None) -> list[str]:
    if cases is None:
        from extract_install_cases import extract_cases

        cases = {c["id"] for c in extract_cases(root)}
    failures = []
    sidecars = sidecar_entries(root)
    used = set()
    resolved_commits: dict[str, bool] = {}
    for path in public_docs(root):
        for fence, comments, marked_case, case_required in _examples(path, root):
            number = fence.line
            prefix = f"{path.relative_to(root)}:{number}"
            marker = MARKER.search(comments)
            if marker:
                try:
                    value = fields(marker.group(1))
                except ValueError:
                    failures.append(f"{prefix}: malformed provenance fields")
                    continue
            else:
                identity = example_identity(path, number, root)
                matching = [
                    (index, entry)
                    for index, entry in enumerate(sidecars)
                    if index not in used
                    and identity
                    == (entry.get("file"), entry.get("section"), entry.get("body_sha256"))
                ]
                if not matching:
                    failures.append(f"{prefix}: missing doc-provenance marker or exact sidecar")
                    continue
                index, value = matching[0]
                used.add(index)
            if not PIN.fullmatch(value.get("source", "")):
                failures.append(
                    f"{prefix}: source must have an immutable content hash, commit or URL pin"
                )
            elif value["source"].startswith("file:"):
                if not file_pin_exists(root, value["source"]):
                    failures.append(f"{prefix}: source file content hash does not resolve")
            elif value["source"].startswith("git:"):
                commit = value["source"][4:]
                if commit not in resolved_commits:
                    resolved_commits[commit] = git_object_exists(root, commit)
                if not resolved_commits[commit]:
                    failures.append(f"{prefix}: source commit does not resolve in Git: {commit}")
            if not VERSION.fullmatch(value.get("support", "")):
                failures.append(f"{prefix}: support must name a semantic version")
            case = value.get("case")
            citation = value.get("citation", "")
            if case_required and case is None:
                failures.append(
                    f"{prefix}: executed install example requires case=, not a citation"
                )
            elif case is not None and marked_case is not None and case != marked_case:
                failures.append(
                    f"{prefix}: provenance case {case} does not match install-case {marked_case}"
                )
            if case is not None:
                if case not in cases:
                    failures.append(f"{prefix}: unknown install case {case}")
            elif citation.startswith("file:"):
                if not file_pin_exists(root, citation):
                    failures.append(f"{prefix}: cited source file content hash does not resolve")
            elif citation.startswith("git:"):
                target, sep, pin = citation[4:].rpartition("@")
                if (
                    not sep
                    or not re.fullmatch(r"[0-9a-f]{40}", pin)
                    or not target
                    or not git_object_exists(root, pin)
                    or not git_object_exists(root, pin, file=target)
                ):
                    failures.append(f"{prefix}: citation must name an existing source at a commit")
            elif not citation.startswith("https://"):
                failures.append(f"{prefix}: provenance requires case or cited source")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--install-results", type=Path)
    args = parser.parse_args()
    try:
        failures = check(args.root.resolve())
        if args.install_results:
            report = json.loads(args.install_results.read_text())
            not_tested: list[dict] = []
            failures.extend(check_executed_cases(args.root.resolve(), report, not_tested))
            for entry in not_tested:
                print(
                    f"docs/INSTALL-AGENT.md:{entry['line']}: executed case {entry['id']} "
                    f"NOT-TESTED on {entry['platform']} ({entry['reason']}); "
                    f"required on {entry['required_platform']}"
                )
    except ValueError as error:
        print(f"install case extraction: {error}")
        return 1
    print("\n".join(failures) if failures else "example provenance: PASS")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
