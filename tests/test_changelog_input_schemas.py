"""Each CHANGELOG release section's catalog comparison is recomputed, never hand-counted.

``tests/fixtures/tool_input_schemas_v<version>.json`` holds every tool's ``tools/list``
input schema as that release served it, with the ``description`` keywords removed
(v0.6.2: FastMCP 3.2.4; v0.7.0: FastMCP 4.1.4, dumped with ``_tools()`` and
``_strip_descriptions`` from the tree of the v0.7.0 tag in that release's locked
environment). Each release is compared with the release before it:

* the released 0.7.0 section with the 0.6.2 snapshot, from the two snapshots, so a later
  catalog change never reopens published text. Its "input schemas compared with 0.6.2"
  entry (docs/MIGRATING-0.7.md) must state the catalog sizes, the number of tools in both
  catalogs whose schema changed and the exact list of those tools, and how many gain
  `confirm` and how many the other new parameters; every parameter a tool gained is named,
  with that tool, in an Added bullet (`confirm`, `ignore_device_limit` and `fields`: in the
  Changed bullet that describes them);
* the in-flight section (with every pending fragment folded) with the snapshot of the
  release before it, from the registered tools: its Highlights state the recomputed
  counts, every added tool is named or counted, every removed tool has a Removed entry
  and every gained parameter is named with its tool.

A branch that adds, removes or changes a tool or parameter fails this test until the
in-flight section says so, which is how the numbers stay true when several branches are
integrated. Opening the next release section requires the snapshot of the release it
follows (test_every_compared_release_has_a_schema_snapshot).
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from tests.changelog_section import current_release, previous_release, section
from tests.test_tool_schema_contract import _strip_descriptions, _tools

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
V062 = FIXTURES / "tool_input_schemas_v0_6_2.json"
ENTRY_TITLE = "**Breaking (tool inputs): input schemas compared with 0.6.2.**"
#: The released section whose migration guide carries the 0.6.2 comparison entry.
RELEASED = "0.7.0"
IN_FLIGHT = "in-flight"


def _snapshot_path(version: str) -> Path:
    return FIXTURES / f"tool_input_schemas_v{version.replace('.', '_')}.json"


@cache
def _snapshot(version: str) -> dict[str, Any]:
    data = json.loads(_snapshot_path(version).read_text())
    assert len(data["schemas"]) == data["tool_count"], version
    return data["schemas"]


@cache
def _live() -> dict[str, Any]:
    return {tool.name: _strip_descriptions(tool.parameters) for tool in _tools()}


@cache
def _compared(release: str) -> tuple[str, dict[str, Any], dict[str, Any], str]:
    """``(version, old schemas, new schemas, section body)`` of one compared release."""
    if release == IN_FLIGHT:
        version, body = current_release()
        return version, _snapshot(previous_release()), _live(), body
    assert release == RELEASED
    return release, _snapshot("0.6.2"), _snapshot(release), section(release)


def _section(release: str = RELEASED) -> str:
    return _compared(release)[3]


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


def _diff(
    release: str = RELEASED,
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str]]:
    _version, schemas_old, schemas_new, _body = _compared(release)
    common = sorted(set(schemas_old) & set(schemas_new))
    changed = [name for name in common if schemas_old[name] != schemas_new[name]]
    return schemas_old, schemas_new, common, changed


def test_every_compared_release_has_a_schema_snapshot() -> None:
    """The in-flight section is compared with the release before it, never an older one."""
    baseline = previous_release()
    assert _snapshot_path(baseline).is_file(), (
        f"the in-flight section follows {baseline}: add {_snapshot_path(baseline).name}, "
        "the tools/list input schemas of that release"
    )
    assert _snapshot(RELEASED) and _snapshot("0.6.2")


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
    if "\n### Added\n" not in section:
        return []
    added = section.split("\n### Added\n", 1)[1].split("\n### ", 1)[0]
    return _bullets(added)


def _tools_doc_url(version: str) -> str:
    return f"https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v{version}/docs/TOOLS.md"


# A family bullet counts the added tools Added does not name that sit under one
# docs/TOOLS.md category heading, and links that heading at the release's tag.
def _family_re(version: str) -> re.Pattern[str]:
    return re.compile(
        r"\((\d+) tools?\): see \[tool list\]\("
        + re.escape(_tools_doc_url(version))
        + r"#([a-z0-9-]+)\)\.$"
    )


TOOLS_DOC_URL = _tools_doc_url(RELEASED)
FAMILY_RE = _family_re(RELEASED)
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


#: Tools of the released 0.7.0 catalog that the catalog has dropped since, with the docs/TOOLS.md
#: heading each was counted under when 0.7.0 shipped. The released section's family counts still
#: include them; the in-flight Removed rule lists each with its replacement.
DROPPED_SINCE_RELEASE: dict[str, str] = {
    "calibrate_door_lock": "Other",
    "create_traffic_rule": "Create",
    "delete_traffic_rule": "Delete",
    "get_camera_adoption_qr": "Reading & Inspection",
    "get_protect_case_asset_snapshot": "Reading & Inspection",
    "reboot_nvr": "Other",
    "set_door_lock_auto_close": "Configuration",
    "update_protect_user_notifications": "Update",
    "update_traffic_rule": "Update",
}


def _added_partition(
    section: str, additions: set[str], version: str = RELEASED
) -> tuple[set[str], list[tuple[str, int]]]:
    """``(added tools named in Added, [(family anchor, count), ...])``.

    Family bullets name no tool themselves; every other bullet that states a tool count
    before its first colon names exactly that many added tools, so no count in Added
    goes unchecked.
    """
    named: set[str] = set()
    families: list[tuple[str, int]] = []
    family_re = _family_re(version)
    for bullet in _added_bullets(section):
        tools = set(re.findall(r"`(\w+)`", bullet))
        if match := family_re.search(bullet):
            assert not tools, f"a family bullet names tools: {bullet}"
            families.append((match.group(2), int(match.group(1))))
            continue
        named |= tools & additions
        if (lead := LEAD_COUNT_RE.match(bullet)) and "/docs/TOOLS.md#" in bullet:
            raise AssertionError(f"a counted TOOLS.md link that is not a family bullet: {bullet}")
        if lead:
            assert len(tools & additions) == int(lead.group(1)), bullet
    return named, families


@pytest.mark.parametrize("release", [RELEASED, IN_FLIGHT])
def test_every_new_tool_is_named_or_counted_by_exactly_one_family_bullet(release: str) -> None:
    """Every added tool is named in Added or counted by exactly one family bullet.

    Each family bullet links one docs/TOOLS.md category heading and its count is exactly
    the number of added tools Added does not name under that heading; every unnamed
    added tool sits under a heading a family bullet links.
    """
    schemas_old, schemas_new, _common, _changed = _diff(release)
    version = _compared(release)[0]
    additions = set(schemas_new) - set(schemas_old)
    anchors, category = _tools_doc_categories()
    if release == IN_FLIGHT:
        assert set(category) == set(_live()), "docs/TOOLS.md is stale"
    else:
        category = {**category, **DROPPED_SINCE_RELEASE}
    named, families = _added_partition(_section(release), additions, version)
    linked = [anchor for anchor, _count in families]
    assert len(linked) == len(set(linked)), f"two family bullets link one heading: {linked}"
    assert set(linked) <= set(anchors), sorted(set(linked) - set(anchors))
    unnamed: dict[str, set[str]] = {}
    for name in additions - named:
        # A released addition the catalog has since dropped has no heading left to count it.
        unnamed.setdefault(category.get(name, f"(no docs/TOOLS.md heading: {name})"), set()).add(
            name
        )
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


@pytest.mark.parametrize("release", [RELEASED, IN_FLIGHT])
def test_every_gained_parameter_is_named_with_its_tool(release: str) -> None:
    schemas_old, schemas_new, common, _changed = _diff(release)
    section = _section(release)
    if release == RELEASED:
        guide = (ROOT / "docs" / "MIGRATING-0.7.md").read_text()
        others = [b for b in _bullets(guide) if not b.startswith(ENTRY_TITLE)]
        added = _added_bullets(section)
    else:
        # The in-flight section names a gained parameter with its tool in any bullet.
        others = added = _bullets(section)
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


@pytest.mark.parametrize("release", [RELEASED, IN_FLIGHT])
def test_subsections_follow_keep_a_changelog_order(release: str) -> None:
    names = list(_subsections(_section(release)))
    assert set(names) <= set(KEEP_A_CHANGELOG), names
    assert names == [name for name in KEEP_A_CHANGELOG if name in names], names


NO_REPLACEMENT = re.compile(r"\bNo (?:direct )?replacement\b")


def _replacement_problem(bullet: str, registered: set[str]) -> str | None:
    """Why a Removed entry neither names a replacement nor says there is none, else None.

    The entry shape is ``**Breaking (tool removed): `x`.** <reason>. Use `y`; affected: `x`.``
    Either ``Use`` names a registered tool, or the entry says ``No replacement`` (or ``No
    direct replacement``) after a reason of at least three words. Only the text before the
    ``affected:`` clause counts: the removed tool and a tool that merely stays are not
    replacements.
    """
    body = REMOVED_TITLE.sub("", bullet).split("affected:")[0]
    if NO_REPLACEMENT.search(body):
        reason = NO_REPLACEMENT.split(body)[0].strip(" .;")
        if len(reason.split()) < 3:
            return "'No replacement' needs a reason of at least three words before it"
        return None
    if set(re.findall(r"`(\w+)`", body)) & registered:
        return None
    return "the Removed entry names no registered replacement and does not say 'No replacement'"


_HEAD = "**Breaking (tool removed): `a`.** "


@pytest.mark.parametrize(
    ("bullet", "problem"),
    [
        (_HEAD + "Gone upstream. Use `b`; affected: `a`.", None),
        (_HEAD + "The console answers 501. No replacement; affected: `a`.", None),
        (_HEAD + "Protect has no route. No direct replacement; `b` mutes; affected: `a`.", None),
        (_HEAD + "Gone. No replacement; affected: `a`.", "reason"),
        (_HEAD + "Gone upstream, nothing to use; affected: `a`.", "names no registered"),
        (_HEAD + "Gone upstream; `list_a` still reads; affected: `a`.", "names no registered"),
    ],
)
def test_removed_entry_needs_a_replacement_or_an_explicit_none(bullet, problem):
    found = _replacement_problem(bullet, {"b", "list_x"})
    assert (found is None) if problem is None else (found is not None and problem in found)


@pytest.mark.parametrize("release", [RELEASED, IN_FLIGHT])
def test_every_removed_tool_is_listed_under_removed_with_its_replacement(release: str) -> None:
    """A tool the previous release shipped that this one no longer registers is Removed.

    Each removed tool gets exactly one ``**Breaking (tool removed): `name`.**`` bullet
    under ``### Removed`` naming a registered tool that replaces it, or saying ``No
    replacement`` after a reason (a tool the console no longer serves at all); no other subsection
    carries a tool-removed entry, and Changed, Deprecated, Fixed and Security do not
    mention a removed tool at all. The highlights lead states the recomputed counts.
    """
    schemas_old, schemas_new, _common, _changed = _diff(release)
    removed = set(schemas_old) - set(schemas_new)
    added = set(schemas_new) - set(schemas_old)
    section = _section(release)
    subsections = _subsections(section)

    highlights = re.match(r"\s*Highlights: (\d+) tools \((\d+) added, (\d+) removed\)", section)
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
    assert "Removed" in subsections, f"removed tools but no Removed section: {removed}"
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
        problem = _replacement_problem(bullets[0], set(schemas_new))
        assert problem is None, f"{name}: {problem}"

    for heading, body in subsections.items():
        if heading == "Removed":
            continue
        bullets = _bullets(body)
        assert not [b for b in bullets if "(tool removed)" in b], heading
        if heading == "Added":
            continue  # an addition may say which removed tool it replaces
        named = {name for b in bullets for name in re.findall(r"`(\w+)`", b)}
        assert not (named & removed), (heading, sorted(named & removed))
