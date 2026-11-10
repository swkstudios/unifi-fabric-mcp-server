"""Contract tests for the portable and Claude-plugin UniFi agent skills.

Each skill is one workflow whose tool table is checked against the registered catalog:
every catalogued tool named in the text has a row, the row's mode and readOnlyHint match
the tool's annotation, its required and optional argument names match the tool's input
schema, and the cited source file defines the tool. The Claude plugin ships a
byte-identical copy of ``skills/`` (``plugins/claude/skills/``), kept by hand like the
plugin's LICENSE and checked here.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from tests._tool_catalog import tools_by_name

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
CLAUDE_SKILLS = ROOT / "plugins" / "claude" / "skills"
SOURCE = ROOT / "src" / "unifi_fabric"
SKILL_NAMES = {
    "device-client-troubleshooting",
    "firewall-zone-policy-audit",
    "network-vlan-read-modify-write",
    "protect-camera-event-review",
    "site-health-report",
    "wifi-radio-change",
}
TOOL_ROW = re.compile(
    r"^\|\s*`(?P<name>[a-z][a-z0-9_]*)`\s*\|\s*(?P<mode>read|write)\s*\|"
    r"(?P<args>[^|]*)\|(?P<shape>.*?`readOnlyHint: (?P<hint>true|false)`)",
    re.MULTILINE,
)
# Sources are cited by function name (`families/network/network.py::get_network`), never by line
# number: line numbers go stale with every edit above the definition.
CITATION = re.compile(
    r"`(?P<path>(?:(?:families/[a-z_]+|shared_shapes)/)?[a-z_]+\.py)::(?P<func>[a-z_][a-z0-9_]*)`"
)
LINE_CITATION = re.compile(r"`(?:(?:families/[a-z_]+|shared_shapes)/)?[a-z_]+\.py:\d+`")
# Server settings belong to the operator, not the agent following a skill.
SERVER_SETTING = re.compile(r"\bUNIFI_[A-Z_]+\b")


def _skill_files(root: Path) -> list[Path]:
    return sorted(root.glob("*/SKILL.md"))


def _frontmatter(path: Path) -> dict[str, object]:
    match = re.match(r"^---\n(?P<yaml>.*?)\n---\n", path.read_text(), re.DOTALL)
    assert match, f"{path} has no YAML frontmatter"
    value = yaml.safe_load(match.group("yaml"))
    assert isinstance(value, dict), f"{path} frontmatter is not a mapping"
    return value


def _rows(path: Path) -> dict[str, re.Match[str]]:
    return {match.group("name"): match for match in TOOL_ROW.finditer(path.read_text())}


def _annotated_read_only(tool: object) -> bool:
    annotations = getattr(tool, "annotations", None)
    hint = getattr(annotations, "read_only_hint", None)
    if hint is None:
        hint = getattr(annotations, "readOnlyHint", False)
    return bool(hint)


def test_the_pack_is_the_six_workflow_skills() -> None:
    """Six single-workflow skills; no whole-server overview skill."""
    assert {path.parent.name for path in _skill_files(SKILLS)} == SKILL_NAMES
    assert sorted(p.relative_to(SKILLS).as_posix() for p in SKILLS.rglob("*") if p.is_file()) == [
        f"{name}/SKILL.md" for name in sorted(SKILL_NAMES)
    ]


def test_every_skill_has_installable_frontmatter() -> None:
    paths = _skill_files(SKILLS)
    assert {path.parent.name for path in paths} == SKILL_NAMES
    for path in paths:
        frontmatter = _frontmatter(path)
        assert set(frontmatter) == {"name", "description"}, path
        assert frontmatter["name"] == path.parent.name
        description = frontmatter["description"]
        assert isinstance(description, str) and description.startswith("Load when "), path
        # claude.ai custom skills accept at most 64 / 200 characters.
        assert len(path.parent.name) <= 64 and len(description) <= 200, path


def test_skills_route_other_tasks_to_discovery_and_leave_settings_to_the_operator() -> None:
    paths = _skill_files(SKILLS)
    assert {path.parent.name for path in paths} == SKILL_NAMES
    for path in paths:
        text = path.read_text()
        for meta_tool in ("search_tools", "describe_tool", "call_read_tool"):
            assert f"`{meta_tool}`" in text, f"{path}: does not mention {meta_tool}"
        assert not SERVER_SETTING.findall(text), f"{path}: names a server setting"


def test_skill_tool_mentions_are_catalogued_and_annotation_checked() -> None:
    catalog = tools_by_name()
    paths = _skill_files(SKILLS)
    assert {path.parent.name for path in paths} == SKILL_NAMES
    for path in paths:
        text = path.read_text()
        claims = _rows(path)
        mentioned = {
            name
            for name in catalog
            if re.search(rf"(?<![a-z0-9_]){re.escape(name)}(?![a-z0-9_])", text)
        }
        assert mentioned == set(claims), f"{path}: uncited or stale tools {mentioned ^ set(claims)}"
        for name, match in claims.items():
            claimed_read = match.group("mode") == "read"
            claimed_hint = match.group("hint") == "true"
            assert claimed_read == claimed_hint, f"{path}: {name} mode and hint disagree"
            assert _annotated_read_only(catalog[name]) == claimed_hint, f"{path}: {name} hint"
            if not claimed_read:
                assert "call_write_tool" in text, f"{path}: write tool without call_write_tool"


def test_skill_argument_columns_match_the_input_schema() -> None:
    catalog = tools_by_name()
    paths = _skill_files(SKILLS)
    assert {path.parent.name for path in paths} == SKILL_NAMES
    for path in paths:
        rows = _rows(path)
        assert rows, path
        for name, match in rows.items():
            schema = catalog[name].parameters
            required_text, _, optional_text = match.group("args").partition("(")
            required = set(re.findall(r"`([a-z_]+)`", required_text))
            optional = set(re.findall(r"`([a-z_]+)`", optional_text))
            assert required == set(schema.get("required", [])), f"{path}: {name} required"
            assert optional <= set(schema["properties"]) - required, f"{path}: {name} optional"


def _defines(rel: str, func: str) -> bool:
    return bool(
        re.search(
            rf"^\s*(?:async )?def {re.escape(func)}\(",
            (SOURCE / rel).read_text(),
            re.MULTILINE,
        )
    )


def test_skill_source_citations_define_the_tool() -> None:
    """Each row cites, by function name, functions its source files define."""
    paths = _skill_files(SKILLS)
    assert {path.parent.name for path in paths} == SKILL_NAMES
    for path in paths:
        stale = LINE_CITATION.findall(path.read_text())
        assert not stale, f"{path}: cite functions, not line numbers: {stale}"
        rows = _rows(path)
        assert rows, path
        for name, match in rows.items():
            citations = CITATION.findall(match.group("shape"))
            assert citations, f"{path}: {name} cites no source"
            for rel, func in citations:
                assert _defines(rel, func), f"{path}: {name} cites {rel}::{func}, not defined"
            defining = [rel for rel, func in citations if func == name]
            assert defining, f"{path}: {name} is not defined in {citations}"


def test_claude_plugin_ships_a_byte_identical_copy() -> None:
    def tree(root: Path) -> dict[str, bytes]:
        return {
            p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }

    assert tree(CLAUDE_SKILLS) == tree(SKILLS), (
        "plugins/claude/skills must equal skills/: rm -rf plugins/claude/skills && "
        "cp -R skills plugins/claude/skills"
    )
