"""Agent-facing tool text says what the code and the pinned specs do.

Each test guards a class of description defect rather than one sentence:

* an ``Args:`` continuation line indented like an argument entry is dropped by the
  docstring parser, so the served parameter text stops mid-sentence;
* a generated spec note cut at an abbreviation ("e.g.") loses its example;
* a spec field marked ``deprecated`` (no effect) is advertised as if it worked;
* a field that narrows the bounds of the component it references inherits the
  component's wider range text;
* a Network request-body block omits a key every variant of the body accepts, so the
  description says a key the schema lists is not sendable;
* a numeric time argument in a tool whose start / end are epoch SECONDS omits its own
  unit, so a caller assumes seconds for a value the console reads as milliseconds.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import re
from pathlib import Path
from typing import Any

from tests import tool_shapes_gen as gen
from unifi_fabric import server
from unifi_fabric._tool_shapes_table import TOOL_SHAPES

NETWORK_SPEC = json.loads(
    (Path(__file__).parent / "fixtures" / "openapi" / "network-11.0.97.json").read_text()
)
_NETWORK_BLOCK = re.compile(r"Request body \(Network 11\.0\.\d+, (\w+) (\S+)")


@functools.cache
def _tools() -> dict[str, Any]:
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def _dropped_args_lines(fn: Any) -> list[str]:
    """Lines of ``fn``'s ``Args:`` section the parser cannot attach to an argument."""
    lines = (inspect.getdoc(fn) or "").splitlines()
    if "Args:" not in lines:
        return []
    params = set(inspect.signature(fn).parameters)
    indent: int | None = None
    dropped = []
    for line in lines[lines.index("Args:") + 1 :]:
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip())
        if depth == 0:
            break
        indent = depth if indent is None else indent
        entry = re.match(r"\s*\**(\w+)( \([^)]*\))?:", line)
        if depth < indent or (depth == indent and (not entry or entry.group(1) not in params)):
            dropped.append(line.strip())
    return dropped


def test_no_args_continuation_line_is_dropped_from_a_parameter_description():
    dropped = {
        name: lines
        for name, tool in _tools().items()
        if (lines := _dropped_args_lines(inspect.unwrap(tool.fn)))
    }
    assert dropped == {}


def test_the_dropped_line_detector_sees_an_under_indented_continuation():
    def sample(confirm: bool = False) -> None:
        """Do it.

        Args:
            confirm: Accepted and ignored; the
            call executes immediately.
        """

    assert _dropped_args_lines(sample) == ["call executes immediately."]


def _descriptions(node: Any) -> list[str]:
    if isinstance(node, dict):
        own = [node["description"]] if isinstance(node.get("description"), str) else []
        return own + [d for value in node.values() for d in _descriptions(value)]
    if isinstance(node, list):
        return [d for value in node for d in _descriptions(value)]
    return []


def test_no_generated_shape_note_is_cut_at_an_abbreviation():
    cut = [d for d in _descriptions(TOOL_SHAPES) if d.lower().endswith(gen.ABBREVIATIONS)]
    assert cut == []
    assert gen.note("Uppercase ISO 4217 currency code, e.g. USD") == (
        "Uppercase ISO 4217 currency code, e.g. USD"
    )
    assert gen.note("First sentence. Second sentence.") == "First sentence."


def test_a_deprecated_spec_field_says_it_has_no_effect():
    for tool in ("create_acl_rule", "update_acl_rule"):
        index = TOOL_SHAPES[tool]["rule"]["properties"]["index"]["description"]
        assert "deprecated" in index and "no effect" in index, tool
        line = next(
            ln for ln in (_tools()[tool].description or "").splitlines() if "- index:" in ln
        )
        assert "deprecated" in line and "set_acl_rule_ordering" in line, tool
    assert gen.deprecated_note({"deprecated": True, "description": "Old."}) == (
        "Deprecated per spec. Old."
    )
    assert gen.deprecated_note({"description": "Live."}) == ""


def test_a_field_narrowing_its_component_bounds_states_them():
    mic = TOOL_SHAPES["update_camera"]["settings"]["properties"]["micVolume"]["description"]
    assert "minimum 1" in mic
    assert gen.narrowed_note({"minimum": 0}, {"minimum": 0}) == ""


def _deref(node: Any) -> Any:
    while isinstance(node, dict) and "$ref" in node:
        target: Any = NETWORK_SPEC
        for part in node["$ref"][2:].split("/"):
            target = target[part]
        node = {**target, **{k: v for k, v in node.items() if k != "$ref"}}
    return node


def _common_properties(node: Any) -> dict[str, Any]:
    """Properties every variant of a body accepts (own and allOf; not discriminator variants)."""
    node = _deref(node)
    props = dict(node.get("properties") or {})
    for branch in node.get("allOf") or []:
        props.update(_common_properties(branch))
    return props


def test_network_body_blocks_list_every_common_body_key():
    problems = []
    for name, tool in sorted(_tools().items()):
        text = tool.description or ""
        match = _NETWORK_BLOCK.search(text)
        if not match:
            continue
        op = NETWORK_SPEC["paths"].get(match.group(2), {}).get(match.group(1).lower())
        if not op or "requestBody" not in op:
            continue
        props = _common_properties(op["requestBody"]["content"]["application/json"]["schema"])
        listed = set(re.findall(r"^- (\w+):", text[match.start() :], re.M))
        problems += [f"{name}.{key}" for key in sorted(set(props) - listed)]
    assert problems == []


def test_classic_dynamic_dns_examples_use_native_field_names():
    for name in ("create_dynamic_dns", "update_dynamic_dns"):
        text = _tools()[name].description or ""
        assert '"host_name"' in text, name
        assert '"hostname"' not in text, name


# Name tokens that make a numeric argument a time quantity (or, for resolution, look like
# one); a unit token in the name itself ("_ms", "_seconds") states the unit.
_TIME_TOKENS = {"step", "period", "interval", "duration", "delay", "bucket", "window"}
_TIME_TOKENS |= {"resolution", "timeout", "ttl", "until", "granularity", "lookback"}
_UNIT_TOKENS = {"ms", "sec", "seconds", "minutes", "hours"}
_UNIT_TEXT = re.compile(
    r"\b(milliseconds?|ms|seconds?|minutes?|hours?|days?)\b|not a time span", re.I
)


def _unitless_time_arguments(schema: dict[str, Any]) -> list[str]:
    """Numeric time-like arguments beside an epoch-SECONDS start / end that name no unit."""
    props = schema.get("properties") or {}
    window = " ".join(str((props.get(k) or {}).get("description", "")) for k in ("start", "end"))
    if "epoch seconds" not in window.lower():
        return []
    missing = []
    for name, prop in props.items():
        tokens = set(name.lower().split("_"))
        if name in ("start", "end") or not tokens & _TIME_TOKENS or tokens & _UNIT_TOKENS:
            continue
        if not re.search(r"\b(integer|number)\b", json.dumps(prop)):
            continue
        if not _UNIT_TEXT.search(str(prop.get("description") or "")):
            missing.append(name)
    return missing


def test_a_time_argument_beside_an_epoch_seconds_window_states_its_unit():
    missing = {
        name: found
        for name, tool in sorted(_tools().items())
        if (found := _unitless_time_arguments(tool.parameters or {}))
    }
    assert missing == {}


def test_the_unit_detector_flags_a_bare_bucket_beside_epoch_seconds():
    schema = {
        "properties": {
            "start": {"type": "integer", "description": "Window start, epoch SECONDS."},
            "end": {"type": "integer", "description": "Window end, epoch SECONDS."},
            "step": {"type": "integer", "description": "Bucket size, sent as step."},
            "frame_duration_ms": {"type": "integer", "description": "Frame duration."},
        }
    }
    assert _unitless_time_arguments(schema) == ["step"]
    schema["properties"]["step"]["description"] = "Bucket width in milliseconds."
    assert _unitless_time_arguments(schema) == []


def test_playback_history_resolution_is_the_quality_channel_not_a_time_span():
    # The Protect web app passes its stream-quality enum (HQ 0, AUTO 1, LQ 2) as resolution.
    props = _tools()["get_camera_playback_history"].parameters["properties"]
    description = props["resolution"]["description"]
    assert "HQ" in description and "LQ" in description and "not a time span" in description
    assert "3600000" not in description
    step = _tools()["get_camera_analytics"].parameters["properties"]["step"]["description"]
    assert "MILLISECONDS" in step and "3600000 (1 hour)" in step
