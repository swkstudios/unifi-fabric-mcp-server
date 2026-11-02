"""The CHANGELOG's input-schema comparison with 0.6.2 is recomputed, never hand-counted.

``tests/fixtures/tool_input_schemas_v0_6_2.json`` holds every tool's ``tools/list``
input schema as the v0.6.2 release served it (FastMCP 3.2.4), with the ``description``
keywords removed. The in-flight section's "input schemas compared with 0.6.2" entry must
state the catalog sizes, the number of tools in both catalogs whose schema changed and
the exact list of those tools, as computed here from the registered tools, and how many
gain `confirm` and how many the other new parameters; and every parameter a tool gained
must be named, with that tool, in an Added bullet (`confirm`, `ignore_device_limit` and
`fields`: in the Changed bullet that describes them).

A branch that adds, removes or changes a parameter fails this test until the entry says
so, which is how the number stays true when several branches are integrated.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tests.changelog_section import current_release
from tests.test_tool_schema_contract import _strip_descriptions, _tools

ROOT = Path(__file__).resolve().parents[1]
V062 = Path(__file__).parent / "fixtures" / "tool_input_schemas_v0_6_2.json"
ENTRY_TITLE = "**Breaking (tool inputs): input schemas compared with 0.6.2.**"


def _section() -> str:
    return current_release()[1]


def _bullets(section: str) -> list[str]:
    """Top-level bullets of the section, each joined into one line.

    A bullet takes every following indented line (blank lines included) until the next
    top-level line: another bullet or a heading.
    """
    bullets: list[str] = []
    in_bullet = False
    for line in section.splitlines():
        if line.startswith("- "):
            bullets.append(line[2:])
            in_bullet = True
        elif line.startswith("  ") and in_bullet:
            bullets[-1] += " " + line.strip()
        elif line.strip():
            in_bullet = False
    return bullets


def _entry() -> str:
    guide = (ROOT / "docs" / "MIGRATING-0.7.md").read_text()
    (entry,) = [b for b in _bullets(guide) if b.startswith(ENTRY_TITLE)]
    return entry


def _diff() -> tuple[dict[str, Any], dict[str, Any], list[str], list[str]]:
    old = json.loads(V062.read_text())
    schemas_old = old["schemas"]
    assert len(schemas_old) == old["tool_count"]
    schemas_new = {tool.name: _strip_descriptions(tool.parameters) for tool in _tools()}
    common = sorted(set(schemas_old) & set(schemas_new))
    changed = [name for name in common if schemas_old[name] != schemas_new[name]]
    return schemas_old, schemas_new, common, changed


def test_entry_states_the_recomputed_catalog_sizes_and_added_removed_tools() -> None:
    schemas_old, schemas_new, _common, _changed = _diff()
    entry = _entry()
    grows = re.search(r"The catalog grows from (\d+) to (\d+) tools \((.*?)\)\.", entry)
    assert grows, entry
    assert (int(grows.group(1)), int(grows.group(2))) == (len(schemas_old), len(schemas_new))
    additions = set(schemas_new) - set(schemas_old)
    added_count = re.search(r"(\d+) additions listed under Added; (.*)", grows.group(3))
    assert added_count, grows.group(3)
    assert int(added_count.group(1)) == len(additions)
    # Each addition is named in Added or counted by exactly one family bullet:
    # test_every_new_tool_is_named_or_counted_by_exactly_one_family_bullet.
    named, families = _added_partition(_section(), additions)
    assert len(named) + sum(count for _anchor, count in families) == len(additions)
    assert sorted(re.findall(r"`(\w+)`", added_count.group(2))) == sorted(
        set(schemas_old) - set(schemas_new)
    )


def test_entry_states_the_recomputed_count_and_tool_list() -> None:
    _old, _new, common, changed = _diff()
    entry = _entry()
    match = re.search(
        r"(\d+) of the (\d+) tools in both catalogs change their input schema "
        r"\(descriptions aside\): (.*?)\.",
        entry,
    )
    assert match, entry
    listed = re.findall(r"`(\w+)`", match.group(3))
    assert (int(match.group(1)), int(match.group(2))) == (len(changed), len(common)), (
        f"recomputed: {len(changed)} of {len(common)}"
    )
    assert listed == changed, (
        f"missing: {sorted(set(changed) - set(listed))}; "
        f"not changed: {sorted(set(listed) - set(changed))}"
    )


# The parameters the entry itself describes (in the Changed entries that explain them);
# every other gained parameter is "listed under Added", as the entry says.
DESCRIBED_IN_CHANGED = {"confirm", "ignore_device_limit", "fields"}


def _added_bullets(section: str) -> list[str]:
    added = section.split("\n### Added\n", 1)[1].split("\n### ", 1)[0]
    return _bullets(added)


TOOLS_DOC_URL = "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md"
# A family bullet counts the added tools Added does not name that sit under one
# docs/TOOLS.md category heading, and links that heading.
FAMILY_RE = re.compile(
    r"\((\d+) tools?\): see \[tool list\]\(" + re.escape(TOOLS_DOC_URL) + r"#([a-z0-9-]+)\)\.$"
)
# A count stated before a bullet's first colon, e.g. "Thread and Matter (5 tools):".
LEAD_COUNT_RE = re.compile(r"^[^:]*?\((\d+) tools?\b")


def _tools_doc_categories() -> tuple[dict[str, str], dict[str, str]]:
    """``({category anchor: heading}, {tool: category heading})`` from docs/TOOLS.md."""
    doc = (ROOT / "docs" / "TOOLS.md").read_text()
    index = doc.split("\n## Tool Categories\n", 1)[1].split("\n## ", 1)[0]
    anchors = {
        anchor: name
        for name, anchor in re.findall(r"^- \[(.+?)\]\(#([a-z0-9-]+)\) \(\d+\)$", index, re.M)
    }
    category: dict[str, str] = {}
    current = None
    for line in doc.splitlines():
        if line.startswith("## "):
            current = line[3:]
        elif match := re.match(r"^### `(\w+)`", line):
            assert match.group(1) not in category, match.group(1)
            assert current in anchors.values(), (match.group(1), current)
            category[match.group(1)] = current
    return anchors, category


def _added_partition(section: str, additions: set[str]) -> tuple[set[str], list[tuple[str, int]]]:
    """``(added tools named in Added, [(family anchor, count), ...])``.

    Family bullets name no tool themselves; every other bullet that states a tool count
    before its first colon names exactly that many added tools, so no count in Added
    goes unchecked.
    """
    named: set[str] = set()
    families: list[tuple[str, int]] = []
    for bullet in _added_bullets(section):
        tools = set(re.findall(r"`(\w+)`", bullet))
        if match := FAMILY_RE.search(bullet):
            assert not tools, f"a family bullet names tools: {bullet}"
            families.append((match.group(2), int(match.group(1))))
            continue
        named |= tools & additions
        if (lead := LEAD_COUNT_RE.match(bullet)) and "/docs/TOOLS.md#" in bullet:
            raise AssertionError(f"a counted TOOLS.md link that is not a family bullet: {bullet}")
        if lead:
            assert len(tools & additions) == int(lead.group(1)), bullet
    return named, families


def test_every_new_tool_is_named_or_counted_by_exactly_one_family_bullet() -> None:
    """Every added tool is named in Added or counted by exactly one family bullet.

    Each family bullet links one docs/TOOLS.md category heading and its count is exactly
    the number of added tools Added does not name under that heading; every unnamed
    added tool sits under a heading a family bullet links.
    """
    schemas_old, schemas_new, _common, _changed = _diff()
    additions = set(schemas_new) - set(schemas_old)
    anchors, category = _tools_doc_categories()
    assert set(category) == set(schemas_new), "docs/TOOLS.md is stale"
    named, families = _added_partition(_section(), additions)
    linked = [anchor for anchor, _count in families]
    assert len(linked) == len(set(linked)), f"two family bullets link one heading: {linked}"
    assert set(linked) <= set(anchors), sorted(set(linked) - set(anchors))
    unnamed: dict[str, set[str]] = {}
    for name in additions - named:
        unnamed.setdefault(category[name], set()).add(name)
    outside = {
        heading: sorted(tools)
        for heading, tools in unnamed.items()
        if heading not in {anchors[a] for a in linked}
    }
    assert not outside, f"unnamed added tools under no linked heading: {outside}"
    wrong = {
        anchor: (count, len(unnamed.get(anchors[anchor], ())))
        for anchor, count in families
        if count != len(unnamed.get(anchors[anchor], ()))
    }
    assert not wrong, f"family counts (stated, recomputed): {wrong}"
    assert len(named) + sum(count for _anchor, count in families) == len(additions)


def test_every_gained_parameter_is_named_with_its_tool() -> None:
    schemas_old, schemas_new, common, _changed = _diff()
    section = _section()
    guide = (ROOT / "docs" / "MIGRATING-0.7.md").read_text()
    others = [b for b in _bullets(guide) if not b.startswith(ENTRY_TITLE)]
    added = _added_bullets(section)
    missing = []
    for name in common:
        gained = set(schemas_new[name].get("properties") or {}) - set(
            schemas_old[name].get("properties") or {}
        )
        for param in sorted(gained):
            pool = others if param in DESCRIBED_IN_CHANGED else added
            if not any(f"`{name}`" in b and f"`{param}`" in b for b in pool):
                missing.append(f"{name}.{param}")
    assert missing == [], f"gained parameters no CHANGELOG bullet names: {missing}"


def test_entry_counts_the_confirm_and_added_tools() -> None:
    schemas_old, schemas_new, common, _changed = _diff()
    gained = {
        name: set(schemas_new[name].get("properties") or {})
        - set(schemas_old[name].get("properties") or {})
        for name in common
    }
    confirm = sum("confirm" in g for g in gained.values())
    others = sum(bool(g - DESCRIBED_IN_CHANGED) for g in gained.values())
    entry = _entry()
    assert f"{confirm} tools gain the ignored `confirm`" in entry, confirm
    assert (
        f"{others} tools gain the other new optional parameters, each listed under Added" in entry
    ), others


# Keep a Changelog section order; a release uses the ones it needs.
KEEP_A_CHANGELOG = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
REMOVED_TITLE = re.compile(r"^\*\*Breaking \(tool removed\): `(\w+)`\.\*\*")


def _subsections(section: str) -> dict[str, str]:
    """``### <name>`` subsection bodies of a release section, keyed by name."""
    parts = re.split(r"^### (.+)$", section, flags=re.M)
    names = parts[1::2]
    assert len(names) == len(set(names)), names
    return dict(zip(names, parts[2::2], strict=True))


def test_subsections_follow_keep_a_changelog_order() -> None:
    names = list(_subsections(_section()))
    assert set(names) <= set(KEEP_A_CHANGELOG), names
    assert names == [name for name in KEEP_A_CHANGELOG if name in names], names


def test_every_removed_tool_is_listed_under_removed_with_its_replacement() -> None:
    """A tool 0.6.2 shipped that this release no longer registers is a Removed entry.

    Each removed tool gets exactly one ``**Breaking (tool removed): `name`.**`` bullet
    under ``### Removed`` naming a registered tool that replaces it; no other subsection
    carries a tool-removed entry, and Changed, Deprecated, Fixed and Security do not
    mention a removed tool at all. The highlights line states the recomputed counts.
    """
    schemas_old, schemas_new, _common, _changed = _diff()
    removed = set(schemas_old) - set(schemas_new)
    added = set(schemas_new) - set(schemas_old)
    section = _section()
    subsections = _subsections(section)

    highlights = re.search(r"(\d+) tools \((\d+) added, (\d+) removed\)", section)
    assert highlights, "highlights line must state the tool count with added and removed"
    assert tuple(map(int, highlights.groups())) == (len(schemas_new), len(added), len(removed)), (
        f"{highlights.group(0)}; recomputed: {len(schemas_new)} tools "
        f"({len(added)} added, {len(removed)} removed)"
    )

    if not removed:
        assert "Removed" not in subsections or not any(
            REMOVED_TITLE.match(b) for b in _bullets(subsections["Removed"])
        )
        return
    assert "Removed" in subsections, f"removed since 0.6.2 but no Removed section: {removed}"
    entries: dict[str, list[str]] = {}
    for bullet in _bullets(subsections["Removed"]):
        if match := REMOVED_TITLE.match(bullet):
            entries.setdefault(match.group(1), []).append(bullet)
    assert set(entries) == removed, {
        "missing": sorted(removed - set(entries)),
        "not removed": sorted(set(entries) - removed),
    }
    for name, bullets in entries.items():
        assert len(bullets) == 1, name
        replacements = set(re.findall(r"`(\w+)`", bullets[0])) & set(schemas_new)
        assert replacements, f"{name}: the Removed entry names no registered replacement"

    for heading, body in subsections.items():
        if heading == "Removed":
            continue
        bullets = _bullets(body)
        assert not [b for b in bullets if "(tool removed)" in b], heading
        if heading == "Added":
            continue  # an addition may say which removed tool it replaces
        named = {name for b in bullets for name in re.findall(r"`(\w+)`", b)}
        assert not (named & removed), (heading, sorted(named & removed))
