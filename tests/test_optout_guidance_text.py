"""Write opt-out guidance names a setting that exists in 0.7.1.

0.7.1 replaced the per-area boolean switches (``UNIFI_ENABLE_<AREA>_WRITE`` and friends)
with ``UNIFI_WRITE_EXCEPTIONS`` entries such as ``family:carrier=deny``. An entry is
``<target>=deny`` or ``<target>=dry-run``; there is no boolean to "set 0", and an entry
like ``family:carrier=0`` fails startup. Text carried over from the boolean switches
("enabled by default; set 0 for read-only", "set it to 0/false", "set to a falsey value")
therefore tells a user to do something that stops the server. This guards every
registered tool description (published in ``docs/TOOLS.md`` and the catalog) and the
tracked source and user docs against that class of leftover.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests import _tool_catalog

ROOT = Path(__file__).resolve().parents[1]

#: Boolean-switch phrasing that has no meaning for a ``UNIFI_WRITE_EXCEPTIONS`` entry:
#: "set 0" / "set it to 0/false" / "set the opt-out to 0" / "set to a falsey value" /
#: "0/false for read-only", a deny entry described as "enabled by default" as if it were
#: the write switch itself, and a deny entry called a boolean "flag".
STALE_GUIDANCE = re.compile(
    r"\bset (?:it |the [\w-]+ )?(?:to )?0(?:/false)?\b"
    r"|\bset (?:it )?to a falsey value\b"
    r"|\bflag is explicitly set to a falsey\b"
    r"|\b0/false (?:for|to) (?:a )?read-only\b"
    r"|family:[a-z_]+=deny`{0,2}\)?\s*[(,]\s*enabled by default"
    r"|family:[a-z_]+=deny`{0,2} (?:env |capability )?flag\b"
    r"|family:[a-z_]+=deny`{0,2}\)? (?:is|are) (?:on|enabled) by default"
    r"|\bopt-outs? (?:is|are) (?:on|enabled) by default",
    re.IGNORECASE,
)

#: Text the scan covers: shipped source, plugin and skill text, scripts that generate docs,
#: the user docs and the top-level docs and manifests. The changelog is out of scope
#: (released sections are never edited and correctly describe the settings of their
#: release), as are dated evidence captures.
SCANNED_DIRS = ("src", "docs", "plugins", "skills", "scripts", "config")
SCANNED_FILES = (
    "README.md",
    "PRIVACY.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "llms.txt",
    "server.json",
    "gemini-extension.json",
    "glama.json",
)
TEXT_SUFFIXES = {".py", ".md", ".json", ".txt", ".toml", ".yml", ".yaml", ".sh"}
#: Dated evidence captures live only in an "evidence" directory (the publication verifier
#: fails any other evidence path), so the directory name excludes them without naming
#: the private docs tree, which the public artifact does not ship.
EXCLUDED_DIR_NAMES = frozenset({"evidence"})


def _scanned_files() -> list[Path]:
    files = [ROOT / name for name in SCANNED_FILES if (ROOT / name).is_file()]
    for top in SCANNED_DIRS:
        for path in sorted((ROOT / top).rglob("*")):
            if (
                path.is_file()
                and path.suffix in TEXT_SUFFIXES
                and "__pycache__" not in path.parts
                and EXCLUDED_DIR_NAMES.isdisjoint(path.relative_to(ROOT).parts)
            ):
                files.append(path)
    return files


def test_no_tool_description_gives_boolean_optout_guidance():
    hits = [
        f"{tool.name}: {m.group(0)!r}"
        for tool in _tool_catalog.tools()
        for m in STALE_GUIDANCE.finditer(tool.description or "")
    ]
    assert hits == [], "stale boolean opt-out guidance in tool descriptions: " + "; ".join(hits)


def test_no_tracked_source_or_doc_gives_boolean_optout_guidance():
    hits: list[str] = []
    for path in _scanned_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            if STALE_GUIDANCE.search(line):
                hits.append(f"{rel}:{lineno}")
    assert hits == [], "stale boolean opt-out guidance: " + ", ".join(hits)


def test_create_carrier_subscriber_names_the_real_optouts():
    desc = _tool_catalog.tools_by_name()["create_carrier_subscriber"].description
    flat = " ".join(desc.split())
    assert "UNIFI_WRITE_POLICY=deny" in flat
    assert "UNIFI_WRITE_EXCEPTIONS entry family:carrier=deny" in flat


@pytest.mark.parametrize(
    "text",
    [
        "Gated by family:carrier=deny (enabled by default; set 0 for read-only).",
        "flag, enabled by default; set it to 0/false for a read-only deployment.",
        "writes enabled by default; set 0/false for a read-only deployment",
        "``confirm`` argument, which is ignored. Set the opt-out to 0 for a read-only deployment.",
        "set the switch to 0/false to disable writes",
        "the flag is explicitly set to a falsey value (0/false/no/off/f/n)",
        "one flow: the area opt-out (``family:carrier=deny``, enabled by default)",
        "``write_enabled`` (the ``family:connector=deny`` env flag) is False",
        "`family:network=deny` is on by default. An opt-out binds typed Network-area writes",
        "The per-area write opt-outs are on by default:",
        "The write gate (``family:carrier=deny``) is ON by default",
    ],
)
def test_pattern_catches_the_known_leftovers(text):
    assert STALE_GUIDANCE.search(text)


@pytest.mark.parametrize(
    "text",
    [
        "each first page (offset 0) is the same",
        "Refused when UNIFI_WRITE_POLICY=deny or the UNIFI_WRITE_EXCEPTIONS entry "
        "family:carrier=deny is set (writes are enabled by default).",
        # A retired 0.7.0 name, split so the tracked tree never spells it whole.
        "| Writes on except one area | `UNIFI_ENABLE_" + "NETWORK_WRITE=0` |",
        "Writes are enabled by default; set `UNIFI_WRITE_POLICY=deny` to refuse every write.",
        "Mutation — writes **enabled by default**; opt out with "
        "`UNIFI_WRITE_EXCEPTIONS=family:connector=deny`.",
        "the area opt-out (writes are enabled by default; the ``UNIFI_WRITE_EXCEPTIONS``",
        "For a read-only deployment add ``family:carrier=deny`` to ``UNIFI_WRITE_EXCEPTIONS`` or "
        "set ``UNIFI_WRITE_POLICY=deny``.",
        "set the offset to 0x10 for the second page",
        "Network writes are enabled by default; the `UNIFI_WRITE_EXCEPTIONS` entry "
        "`family:network=deny`",
        "Writes are enabled by default; each area has its own write opt-out:",
        "Writes are on by default; `UNIFI_WRITE_POLICY=deny` hides every write and action tool",
    ],
)
def test_pattern_spares_legitimate_text(text):
    assert not STALE_GUIDANCE.search(text)
