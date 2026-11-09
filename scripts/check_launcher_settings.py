#!/usr/bin/env python3
"""Fail when a launcher pins a release that does not accept a setting it passes.

A launcher is a documented install command or configuration block (a fenced code block, or
a prose line outside one, in the public documentation set and ``llms.txt``, the
``MIGRATING-*`` guides included) or a client manifest (``scripts/prepare_release.py``
``PIN_MANIFESTS``, the files whose install pins it flips). It
pins a release with ``unifi-fabric-mcp-server==X.Y.Z``, an image tag
``unifi-fabric-mcp-server:X.Y.Z`` or a bare ``:X.Y.Z`` tag, and passes the ``UNIFI_*``
names it mentions.

A server older than a setting ignores it silently: a launcher pinned to 0.7.0 that passes
``UNIFI_WRITE_POLICY=deny`` starts with every write tool live. So, for every launcher
pinned to a release other than VERSION (the release being cut, ``pyproject.toml``
``[project] version`` by default), every ``UNIFI_*`` name it passes must be one that
release accepts:

- a pin at the published release (``scripts/published-settings.txt`` ``release``) may pass
  the current settings recorded there, which that release also accepts, and the retired
  names of the migration table (``scripts/check_retired_settings.py``), which it accepted;
- a pin at any other earlier release has no record and may pass no ``UNIFI_*`` name.

A pin at VERSION needs no record: VERSION refuses to start on a name it does not know.
After ``prepare_release.py VERSION --published --write`` flips the install pins, run
``check_launcher_settings.py --record`` so the record names the new published release
(``tests/test_launcher_settings.py`` fails until it does).

Exit status: 0 when every launcher is compatible, 1 when one is not, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_retired_settings  # noqa: E402
import markdown_blocks  # noqa: E402
import prepare_release  # noqa: E402
from extract_install_cases import public_documents  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RECORD = "scripts/published-settings.txt"

#: The pin forms the release package's docs-pin guard reads (scripts/release_package.py).
PIN_RE = re.compile(
    r"`:(\d+\.\d+\.\d+)`|unifi-fabric-mcp-server(?::|==)v?(\d+\.\d+\.\d+)(?![\w.-])"
)
NAME_RE = re.compile(r"(?<![A-Za-z0-9_])UNIFI_[A-Z0-9_]+(?![A-Za-z0-9_])")

#: The client manifests whose install pins the published flip renders, read whole: one list
#: for the flip, this check and the release package's docs-pin guard.
MANIFESTS = prepare_release.PIN_MANIFESTS
#: Top-level documents read like the documentation set (the agent index).
TOP_LEVEL_DOCS = ("README.md", "llms.txt")


class RecordError(ValueError):
    """The published-settings record is missing a release line or is malformed."""


@dataclass(frozen=True)
class Launcher:
    path: str
    line: int
    versions: frozenset[str]
    names: frozenset[str]


@dataclass(frozen=True)
class Record:
    release: str
    names: frozenset[str]


def documents(root: Path) -> list[Path]:
    """The public documentation set every documentation gate reads
    (``extract_install_cases.public_documents``) and the top-level documents."""
    found = {*public_documents(root), *(root / rel for rel in TOP_LEVEL_DOCS)}
    return sorted(p for p in found if p.is_file())


def _launcher(path: str, line: int, text: str) -> Launcher | None:
    versions = frozenset(m[1] or m[2] for m in PIN_RE.finditer(text))
    if not versions:
        return None
    return Launcher(path, line, versions, frozenset(NAME_RE.findall(text)))


def launchers(root: Path) -> list[Launcher]:
    """Every pinned launcher in the documentation set and the client manifests."""
    found: list[Launcher] = []
    for doc in documents(root):
        rel = doc.relative_to(root).as_posix()
        text = doc.read_text(encoding="utf-8")
        fences, _headings = markdown_blocks.scan(text)
        for fence in fences:
            if item := _launcher(rel, fence.line, fence.body):
                found.append(item)
        for number, line in markdown_blocks.prose_lines(text):
            if item := _launcher(rel, number, line):
                found.append(item)
    for rel in MANIFESTS:
        path = root / rel
        if path.is_file() and (item := _launcher(rel, 1, path.read_text(encoding="utf-8"))):
            found.append(item)
    return found


def parse_record(text: str) -> Record:
    release: str | None = None
    names: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("release "):
            if release is not None:
                raise RecordError("more than one release line")
            release = line.removeprefix("release ").strip()
            if not re.fullmatch(r"\d+\.\d+\.\d+", release):
                raise RecordError(f"release {release!r} is not X.Y.Z")
        elif NAME_RE.fullmatch(line):
            names.add(line)
        else:
            raise RecordError(f"unexpected line {line!r}")
    if release is None:
        raise RecordError("no release line")
    return Record(release, frozenset(names))


def load_record(root: Path) -> Record | None:
    path = root / RECORD
    return parse_record(path.read_text(encoding="utf-8")) if path.is_file() else None


def project_version(root: Path) -> str:
    return tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]


def problems(
    tree: Path,
    version: str,
    record: Record | None,
    retired: Iterable[str],
) -> list[str]:
    """``path:line`` problems for every launcher pinned below ``version`` that passes a
    name its pinned release does not accept."""
    retired = frozenset(retired)
    out: list[str] = []
    for item in launchers(tree):
        for pinned in sorted(item.versions - {version}):
            if record is not None and pinned == record.release:
                unknown = item.names - record.names - retired
                why = f"{pinned} does not accept"
            else:
                unknown = item.names
                why = f"{pinned} has no settings record ({RECORD}), so it may pass no"
            if unknown:
                out.append(f"{item.path}:{item.line} pins {why} {', '.join(sorted(unknown))}")
    return out


def record_text(release: str, names: Iterable[str]) -> str:
    return (
        "# The current UNIFI_* settings the published release accepts, read by\n"
        "# scripts/check_launcher_settings.py; written by its --record after the published\n"
        "# flip (scripts/prepare_release.py VERSION --published --write).\n"
        f"release {release}\n" + "".join(f"{name}\n" for name in sorted(names))
    )


def current_names(root: Path) -> frozenset[str]:
    sys.path.insert(0, str(root / "src"))
    from unifi_fabric.config import known_setting_names

    return known_setting_names()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", help="the release being cut (default: pyproject.toml)")
    parser.add_argument(
        "--record",
        action="store_true",
        help="write the record from the current settings; the published release "
        "(scripts/published-version.txt) must be the current version",
    )
    args = parser.parse_args(argv)
    version = args.version or project_version(ROOT)
    if args.record:
        published = (ROOT / "scripts" / "published-version.txt").read_text().strip()
        if published != version:
            print(
                f"--record writes the settings of {version}, but the published release is "
                f"{published}: flip the pins first (prepare_release.py {version} --published "
                "--write)",
                file=sys.stderr,
            )
            return 2
        (ROOT / RECORD).write_text(record_text(version, current_names(ROOT)), encoding="utf-8")
        print(f"wrote {RECORD} for {version}")
        return 0
    try:
        record = load_record(ROOT)
    except RecordError as exc:
        print(f"{RECORD}: {exc}", file=sys.stderr)
        return 2
    found = problems(ROOT, version, record, check_retired_settings.retired_names(ROOT))
    for line in found:
        print(line)
    print(f"{len(found)} launcher(s) pin a release older than a setting they pass")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
