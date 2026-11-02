"""Public dependency versions match the lock files and pyproject.toml.

``docs/MIGRATING-0.7.md`` describes 0.7.0 against the public v0.6.2 release, so each major
upgrade in change-079 reads the v0.6.2 lock first and ``requirements.lock`` second, every
other list names the ``requirements.lock`` version, and the lists name every pin that
changed. The v0.6.2 lock is frozen in
``tests/fixtures/v0_6_2_lock_pins.json`` (package -> version, taken from the tag).
change-075, change-080, the matching CHANGELOG lines and every other public page that puts
a locked package next to a version name what ``requirements.lock`` and ``pyproject.toml`` pin.
"""

from __future__ import annotations

import importlib.metadata
import json
import re
import tomllib
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock"
RUNTIME_LOCK = ROOT / "requirements-runtime.lock"
OLD_LOCK = ROOT / "tests" / "fixtures" / "v0_6_2_lock_pins.json"
MIGRATING = ROOT / "docs" / "MIGRATING-0.7.md"
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
VERSION = PYPROJECT["project"]["version"]
PUBLIC_DOCS = [
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "PRIVACY.md",
    *sorted(p for p in (ROOT / "docs").glob("*.md") if p != MIGRATING),
    *sorted((ROOT / "plugins").glob("*/README.md")),
]

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s\;]+)", re.MULTILINE)
_VER = r"\d+(?:\.\d+)+"
_PAIR = re.compile(rf"([a-z0-9][a-z0-9._-]*) ({_VER}) to ({_VER})")
_ONE = re.compile(rf"([a-z0-9][a-z0-9._-]*) ({_VER})")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


HEAD = {_norm(n): v for n, v in _PIN.findall(LOCK.read_text())}
RUNTIME = {_norm(n): v for n, v in _PIN.findall(RUNTIME_LOCK.read_text())}
OLD = json.loads(OLD_LOCK.read_text())["pins"]
CHANGED = {n: (OLD[n], HEAD[n]) for n in OLD.keys() & HEAD.keys() if OLD[n] != HEAD[n]}


def _major(old: str, new: str) -> bool:
    return old.split(".")[0] != new.split(".")[0]


def _declared(name: str) -> str:
    """The version specifier pyproject.toml declares for ``name`` (e.g. ``>=4.0,<5.0``)."""
    for dep in PYPROJECT["project"]["dependencies"]:
        m = re.fullmatch(rf"{re.escape(name)}\s*([<>=!~].*)", dep)
        if m:
            return m.group(1)
    raise AssertionError(f"{name} is not a declared dependency")


def _entry(change: str) -> str:
    text = MIGRATING.read_text()
    m = re.search(rf"^### {change}\n(.*?)(?=^### |\Z)", text, re.MULTILINE | re.DOTALL)
    assert m, f"{change} missing from {MIGRATING.name}"
    return " ".join(m.group(1).split())


def _items(entry: str, label: str) -> list[str]:
    """The comma-separated list after ``<label>:``, up to the sentence's closing period."""
    m = re.search(rf"(?:^|[.] |- ){re.escape(label)}: (.*?)\.(?= [A-Z]|$)", entry)
    assert m, f"no {label!r} list in: {entry[:120]}"
    return [item.strip() for item in m.group(1).split(", ")]


def _changelog_line(change: str) -> str:
    text = CHANGELOG.read_text()
    section = text[text.index(f"## [{VERSION}]") :]
    section = section[: section.find("\n## [", 1)]
    lines = [line for line in section.splitlines() if line.endswith(f"#{change}).")]
    assert len(lines) == 1, (change, lines)
    return lines[0]


def _pairs(items: list[str]) -> dict[str, tuple[str, str]]:
    out = {}
    for item in items:
        m = _PAIR.fullmatch(item)
        assert m, f"not a '<package> <0.6.2 version> to <0.7.0 version>' pair: {item!r}"
        out[_norm(m[1])] = (m[2], m[3])
    return out


def _singles(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items:
        m = _ONE.fullmatch(item)
        assert m, f"not a '<package> <version>' item: {item!r}"
        out[_norm(m[1])] = m[2]
    return out


def test_change_079_pairs_read_the_v0_6_2_lock_then_requirements_lock():
    entry = _entry("change-079")
    major = _pairs(_items(entry, "Major upgrades (0.6.2 version to 0.7.0 version)"))
    minor = _singles(_items(entry, "Also upgraded"))
    assert major == {n: p for n, p in CHANGED.items() if _major(*p)}
    assert minor == {n: new for n, (old, new) in CHANGED.items() if not _major(old, new)}


def test_change_079_lists_every_added_and_dropped_pin():
    entry = _entry("change-079")
    runtime = _singles(_items(entry, "New"))
    assert runtime == {n: RUNTIME[n] for n in RUNTIME.keys() - OLD.keys()}
    dev_specs = PYPROJECT["project"]["optional-dependencies"]["dev"]
    dev_extra = {_norm(re.split(r"[<>=!~\[ ]", spec)[0]) for spec in dev_specs}
    assert not dev_extra & RUNTIME.keys(), "the runtime lock carries a dev-extra tool"
    assert not dev_extra & runtime.keys(), "change-079 lists a dev-extra tool as shipped"
    assert sorted(_items(entry, "Dropped")) == sorted(OLD.keys() - RUNTIME.keys())


def test_change_075_names_the_locked_fastmcp_and_mcp():
    expected = (
        f"FastMCP {HEAD['fastmcp']} (MCP SDK {HEAD['mcp']}; "
        f"`fastmcp` range `{_declared('fastmcp')}`"
    )
    assert _entry("change-075").startswith(f"- {expected}")
    assert _changelog_line("change-075").startswith(f"- {expected}")


def test_changelog_dependency_line_names_the_locked_versions():
    line = _changelog_line("change-079")
    found = []
    for names, ver in re.findall(rf"([a-z][a-z0-9-]*(?:/[a-z][a-z0-9-]*)*) ({_VER})", line):
        for name in names.split("/"):
            if _norm(name) in HEAD:
                found.append(name)
                assert HEAD[_norm(name)] == ver, (name, ver, HEAD[_norm(name)])
    assert len(found) >= 5, found


def test_change_080_names_the_declared_httpx2_floor_and_fastmcp_floor():
    declared = f"`httpx2{_declared('httpx2')}`"
    assert _entry("change-080").startswith(f"- {declared} is a declared dependency")
    assert _changelog_line("change-080").startswith(f"- {declared} is a declared dependency")
    m = re.search(rf"fastmcp alone admits httpx2 ({_VER})", _entry("change-080"))
    assert m, "change-080 no longer states fastmcp's own httpx2 floor"
    floors = {
        Version(r.split(";")[0].strip().removeprefix("httpx2>="))
        for r in importlib.metadata.requires("fastmcp-slim") or []
        if r.startswith("httpx2>=")
    }
    assert floors == {Version(m[1])}, floors


def test_other_public_docs_name_only_locked_versions():
    stale = []
    for path in PUBLIC_DOCS:
        for i, line in enumerate(path.read_text().splitlines(), 1):
            for m in re.finditer(rf"(?<![\w./-])([A-Za-z][A-Za-z0-9._-]*)(?: |==)({_VER})\b", line):
                name = _norm(m[1])
                if name in HEAD and HEAD[name] != m[2]:
                    stale.append(f"{path.relative_to(ROOT)}:{i}: {m[0]} (lock: {HEAD[name]})")
    assert not stale, stale
