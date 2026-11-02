#!/usr/bin/env python3
"""Generate the reference facts in README.md, docs/CONFIGURATION.md and docs/TOOL-USAGE.md.

Hand-written prose stays hand-written. The facts that the code already owns are written
between marker lines and never edited by hand:

    <!-- BEGIN GENERATED: name -->
    ...
    <!-- END GENERATED -->

Blocks (the file lists below are the only places a block may appear; a missing, unknown or
duplicated block fails the run):

* ``settings-reference`` (docs/CONFIGURATION.md): every ``UNIFI_*`` setting of
  ``unifi_fabric.config.Settings``: variable, default, accepted values and the first sentence
  of the field description;
* ``write-switch-names`` (README.md): the names of the write opt-out switches, one sentence;
* ``write-switches`` (docs/CONFIGURATION.md, docs/TOOL-USAGE.md): the per-area write
  opt-outs from ``unifi_fabric.switches.AREA_WRITE_SWITCHES`` and ``Settings``, with the
  families each one governs;
* ``tool-mode-defaults`` (docs/TOOL-USAGE.md): the tool-mode, family and read-only
  defaults and the discovery meta-tool count;
* ``family-names`` (docs/TOOL-USAGE.md): the family count and names from ``families.ALL_FAMILIES``.

The hand-written environment tables (README and docs/CONFIGURATION.md) also keep a Default
column. ``default_findings`` compares each row of those tables with the code default and the
check fails on a row that disagrees.

Usage:
    python3 scripts/gen_reference_blocks.py          # rewrite the blocks
    python3 scripts/gen_reference_blocks.py --check  # exit 1 on any stale block or default (CI)
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, get_args, get_origin

from pydantic_core import PydanticUndefined

from unifi_fabric import discovery, families, switches
from unifi_fabric.config import Settings

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CONFIGURATION = ROOT / "docs" / "CONFIGURATION.md"
TOOL_USAGE = ROOT / "docs" / "TOOL-USAGE.md"
FIX_COMMAND = "python3 scripts/gen_reference_blocks.py"

#: Which blocks each file carries, in file order.
BLOCKS: dict[Path, tuple[str, ...]] = {
    README: ("write-switch-names",),
    CONFIGURATION: ("settings-reference", "write-switches"),
    TOOL_USAGE: ("write-switches", "tool-mode-defaults", "family-names"),
}

_BLOCK_RE = re.compile(
    r"^<!-- BEGIN GENERATED: ([a-z-]+) -->\n(.*?)^<!-- END GENERATED -->$", re.M | re.S
)
#: Hand-written environment tables whose Default column is checked against the code.
DEFAULT_TABLES: dict[Path, tuple[str, int]] = {
    README: ("| Variable | Default | What it does |", 1),
    CONFIGURATION: ("| Variable | Required | Default | Description |", 2),
}
_ROW_RE = re.compile(r"^\| `([A-Z_]+)` \|(.*)\|$", re.M)


def _env(field: str) -> str:
    return f"UNIFI_{field.upper()}"


def _first_sentence(text: str) -> str:
    text = " ".join(text.split())
    end = re.search(r"\.(?:\s|$)", text)
    return (text[: end.start() + 1] if end else text).replace("|", "\\|")


def _default(field: Any) -> Any:
    if field.default is not PydanticUndefined:
        return field.default
    return field.default_factory() if field.default_factory else None


def _is_unset(value: Any) -> bool:
    return value is None or value == "" or value == []


def _show_default(value: Any) -> str:
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    return "unset" if _is_unset(value) else f"`{value}`"


def _accepted(field: Any) -> str:
    if get_origin(field.annotation) is Literal:
        return " or ".join(f"`{v}`" for v in get_args(field.annotation))
    if field.annotation is bool:
        return "boolean"
    minimums = [m.ge for m in field.metadata if hasattr(m, "ge")]
    if minimums:
        return f"integer, {minimums[0]} or more"
    if field.annotation is type(None):
        return "removed"
    return "text"


def settings_reference() -> str:
    rows = ["| Variable | Default | Accepted | Meaning |", "|---|---|---|---|"]
    for name, field in Settings.model_fields.items():
        rows.append(
            f"| `{_env(name)}` | {_show_default(_default(field))} | {_accepted(field)} | "
            f"{_first_sentence(field.description or '')} |"
        )
    return "\n".join(rows)


def _family_text(names: list[str]) -> str:
    return ", ".join(f"`{n}`" for n in names)


def write_switches() -> str:
    fields = Settings.model_fields
    lines = []
    for sw in switches.AREA_WRITE_SWITCHES:
        default = "on" if _default(fields[sw.env.removeprefix("UNIFI_").lower()]) else "off"
        governed = [sw.family, *sw.related_families]
        lines.append(
            f"- `{sw.env}` (default {default}): the write tools of {_family_text(governed)}"
        )
    connector = _default(fields["enable_connector_write"])
    lines.append(
        f"- `UNIFI_ENABLE_CONNECTOR_WRITE` (default {'on' if connector else 'off'}): "
        "the connector relay's write tools and the typed tools it also governs"
    )
    return "\n".join(lines)


def write_switch_names() -> str:
    names = [sw.env for sw in switches.AREA_WRITE_SWITCHES] + ["UNIFI_ENABLE_CONNECTOR_WRITE"]
    return f"The switches are {_family_text(names)}."


def tool_mode_defaults() -> str:
    fields = Settings.model_fields
    modes = get_args(fields["tool_mode"].annotation)
    meta = sorted(discovery.META_TOOLS)
    read_meta = len(discovery.META_TOOLS - {"call_write_tool"})
    read_only = "on" if _default(fields["read_only"]) else "off"
    return (
        f"Defaults: `UNIFI_TOOL_MODE={fields['tool_mode'].default}` "
        f"(modes {_family_text(list(modes))}), `UNIFI_TOOL_FAMILIES` "
        f"{_show_default(_default(fields['tool_families']))} (every family), "
        "`UNIFI_DISABLED_TOOL_FAMILIES` "
        f"{_show_default(_default(fields['disabled_tool_families']))}, "
        f"`UNIFI_READ_ONLY` {read_only}. Discovery mode advertises {len(meta)} meta-tools "
        f"({_family_text(meta)}), or {read_meta} with `UNIFI_READ_ONLY=1`."
    )


def family_names() -> str:
    names = list(families.ALL_FAMILIES)
    return f"The {len(names)} families are {_family_text(names)}."


RENDERERS = {
    "settings-reference": settings_reference,
    "write-switches": write_switches,
    "write-switch-names": write_switch_names,
    "tool-mode-defaults": tool_mode_defaults,
    "family-names": family_names,
}


@dataclass(frozen=True)
class Finding:
    path: Path
    block: str
    message: str

    def __str__(self) -> str:
        return f"{self.path.relative_to(ROOT).as_posix()}: {self.block}: {self.message}"


def render_file(path: Path, text: str) -> tuple[str, list[Finding]]:
    """The file text with every block regenerated, and the structural findings."""
    found: list[Finding] = []
    seen: list[str] = [m.group(1) for m in _BLOCK_RE.finditer(text)]
    expected = list(BLOCKS[path])
    for name in sorted(set(expected) - set(seen)):
        found.append(Finding(path, name, "block is missing; add its BEGIN and END marker lines"))
    for name in sorted({n for n in seen if n not in expected}):
        found.append(Finding(path, name, "unknown block name"))
    for name in sorted({n for n in seen if seen.count(n) > 1}):
        found.append(Finding(path, name, "block appears more than once"))
    if text.count("<!-- BEGIN GENERATED") != len(seen) or text.count("<!-- END GENERATED") != len(
        seen
    ):
        found.append(Finding(path, "(markers)", "unpaired BEGIN or END GENERATED marker"))

    def fill(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in RENDERERS:
            return match.group(0)
        return f"<!-- BEGIN GENERATED: {name} -->\n{RENDERERS[name]()}\n<!-- END GENERATED -->"

    return _BLOCK_RE.sub(fill, text), found


def stale_blocks(path: Path, text: str) -> list[str]:
    """Names of the blocks whose current content differs from the generated content."""
    return [
        m.group(1)
        for m in _BLOCK_RE.finditer(text)
        if m.group(1) in RENDERERS and m.group(2) != RENDERERS[m.group(1)]() + "\n"
    ]


def _default_agrees(field: Any, cell: str) -> bool:
    cell = cell.strip().strip("`").lower().replace(",", "")
    value = _default(field)
    if isinstance(value, bool):
        return cell.startswith(("true", "on")) if value else cell.startswith(("false", "off"))
    if _is_unset(value):
        return cell.startswith(
            ("unset", "none", "all", "off", "unlimited", "required", "\u2014", "no ")
        )
    return bool(re.search(r"(?<![\w.])" + re.escape(str(value).lower()) + r"(?![\w.])", cell))


def default_findings(path: Path, text: str) -> list[Finding]:
    """Rows of the hand-written environment table whose Default cell disagrees with the code."""
    header, column = DEFAULT_TABLES[path]
    start = text.find(header)
    if start < 0:
        return [Finding(path, "(env table)", f"table with header {header!r} not found")]
    end = text.find("\n\n", start)
    fields = {_env(n): f for n, f in Settings.model_fields.items()}
    out = []
    for m in _ROW_RE.finditer(text[start:end]):
        field = fields.get(m.group(1))
        cells = [c.strip() for c in m.group(2).split("|")]
        if field is not None and not _default_agrees(field, cells[column - 1]):
            out.append(
                Finding(
                    path,
                    m.group(1),
                    f"Default cell {cells[column - 1]!r} disagrees with the code default "
                    f"{_show_default(_default(field))}; edit the cell in the hand-written table",
                )
            )
    return out


def check_all() -> list[Finding]:
    """Every finding: stale blocks, structural problems and disagreeing default cells."""
    out: list[Finding] = []
    for path in BLOCKS:
        text = path.read_text()
        out += render_file(path, text)[1]
        out += [
            Finding(path, name, f"block is stale; run {FIX_COMMAND}")
            for name in stale_blocks(path, text)
        ]
        if path in DEFAULT_TABLES:
            out += default_findings(path, text)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="fail on any stale block or default")
    args = parser.parse_args()
    if args.check:
        findings = check_all()
        for finding in findings:
            print(finding, file=sys.stderr)
        if findings:
            print(f"{len(findings)} finding(s); fix with {FIX_COMMAND}", file=sys.stderr)
            return 1
        print("Reference blocks are current", file=sys.stderr)
        return 0
    changed = 0
    for path in BLOCKS:
        text = path.read_text()
        new, found = render_file(path, text)
        for finding in found:
            print(finding, file=sys.stderr)
        if new != text:
            path.write_text(new)
            changed += 1
    print(f"Wrote reference blocks to {changed} file(s)", file=sys.stderr)
    return 1 if any(render_file(p, p.read_text())[1] for p in BLOCKS) else 0


if __name__ == "__main__":
    raise SystemExit(main())
