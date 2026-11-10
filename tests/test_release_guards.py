"""Release guards: removed settings are announced, constrained values stay enforced, and
upstream error text never bypasses the shared formatter.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _release_notes() -> str:
    """Published release notes and pending fragments covering retired settings."""
    section = (ROOT / "CHANGELOG.md").read_text()
    fragments = [
        path.read_text()
        for path in sorted((ROOT / "changelog.d").glob("*.md"))
        if path.name != "README.md"
    ]
    return "\n".join([section, *fragments])


def _retired_settings() -> set[str]:
    """Environment variables whose ``_retired_*`` validator refuses any value."""
    source = (ROOT / "src/unifi_fabric/config.py").read_text()
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("_retired_"):
            text = ast.get_source_segment(source, node) or ""
            names.update(re.findall(r"(UNIFI_[A-Z0-9_]+) setting removed", text))
    return names


def test_every_removed_setting_has_a_breaking_release_note():
    retired = _retired_settings()
    assert retired, "no _retired_* validator found; update this guard"
    notes = [line for line in _release_notes().splitlines() if line.startswith("- **Breaking")]
    missing = sorted(name for name in retired if not any(name in line for line in notes))
    assert not missing, f"removed settings without a Breaking release note: {missing}"


_ENUM_PHRASE = re.compile(r'"([A-Za-z0-9_-]+)"\s+or\s+"([A-Za-z0-9_-]+)"')
# Parameters whose description enumerates values without a schema enum, as of 0.7.0.
# A new entry is refused; adding an enum to a listed one needs a caller-compatibility
# review (the listed values may not be exhaustive), so the list only shrinks.
_KNOWN_UNCONSTRAINED = frozenset(
    {
        "reboot_protect_device.device_type",
        "adopt_protect_device.device_type",
        "unadopt_protect_device.device_type",
        "restart_device.reboot_type",
        "create_recognition_group.type",
        "update_recognition_group.type",
        "delete_recognition_group.type",
        "assign_detections_to_recognition_group.type",
        "search_recognition_group_candidates.type",
        "set_recognition_group_image.type",
        "get_protect_device_metrics.aggregate_func",
        "list_network_events.view",
        "get_scoped_system_log.scope",
    }
)


def _has_enum(schema: object) -> bool:
    if not isinstance(schema, dict):
        return False
    if "enum" in schema or "const" in schema:
        return True
    if _has_enum(schema.get("items")):
        return True  # an array whose items are an enum constrains every value
    return any(_has_enum(s) for key in ("anyOf", "oneOf", "allOf") for s in schema.get(key, []))


def test_no_new_parameter_enumerates_values_without_an_enum():
    from tests.test_tool_schema_contract import _tools

    offenders = {
        f"{tool.name}.{name}"
        for tool in _tools()
        for name, schema in tool.parameters.get("properties", {}).items()
        if _ENUM_PHRASE.search(schema.get("description", "")) and not _has_enum(schema)
    }
    assert offenders <= _KNOWN_UNCONSTRAINED, sorted(offenders - _KNOWN_UNCONSTRAINED)


def _json_dumps_in_raise(source: str) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Raise) and node.exc is not None:
            for inner in ast.walk(node.exc):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "dumps"
                    and isinstance(inner.func.value, ast.Name)
                    and inner.func.value.id == "json"
                ):
                    lines.append(node.lineno)
    return lines


def test_raised_errors_never_format_upstream_data_with_json_dumps():
    offenders = [
        f"{path.relative_to(ROOT)}:{line}"
        for path in sorted((ROOT / "src/unifi_fabric").rglob("*.py"))
        for line in _json_dumps_in_raise(path.read_text())
    ]
    assert not offenders, f"use upstream_error_text(...) instead of json.dumps: {offenders}"


def test_json_dumps_in_raise_guard_detects_the_pattern():
    sample = 'import json\nraise ValueError(f"HTTP 500: {json.dumps(body)}")\n'
    assert _json_dumps_in_raise(sample) == [2]
    assert _json_dumps_in_raise('raise ValueError(f"HTTP 500: {text}")\n') == []
