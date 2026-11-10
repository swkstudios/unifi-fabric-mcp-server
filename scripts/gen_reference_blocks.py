#!/usr/bin/env python3
"""Generate the reference facts in README.md, docs/CONFIGURATION.md and docs/TOOL-USAGE.md.

Hand-written prose stays hand-written. The facts that the code already owns are written
between marker lines and never edited by hand:

    <!-- BEGIN GENERATED: name -->
    ...
    <!-- END GENERATED -->

The block registry, ``BLOCKS`` in scripts/doc_blocks.py, lists every generated region of
every file and the one generator that owns it; this script writes the blocks it owns there.
A registered block that is missing, duplicated or out of order, an unregistered block, or
unpaired or crossed markers fail the run, in write and ``--check`` modes, and no file with a
finding is rewritten. The blocks:

* ``settings-reference`` (docs/CONFIGURATION.md): every ``UNIFI_*`` setting of
  ``unifi_fabric.config.Settings``: variable, default, accepted values and the first sentence
  of the field description;
* ``write-switch-names`` (README.md): the per-area ``UNIFI_WRITE_EXCEPTIONS`` entries, one
  sentence;
* ``write-switches`` (docs/CONFIGURATION.md, docs/TOOL-USAGE.md): the per-area write
  exceptions from ``unifi_fabric.switches.AREA_WRITE_SWITCHES``, with the families each one
  governs;
* ``tool-mode-defaults`` (docs/TOOL-USAGE.md): the tool-mode, family, exclusion and write
  policy defaults and the discovery meta-tool count;
* ``family-names`` (docs/TOOL-USAGE.md): the family count and names from ``families.ALL_FAMILIES``;
* ``tool-families`` (README.md): the registered-tool count and the per-family tool table from
  ``families.build_family_index()``;
* ``search-tools-limit`` (docs/TOOL-USAGE.md): the ``limit`` default of the registered
  ``search_tools`` meta-tool;
* ``tool-mode-choices`` (README.md): the accepted ``UNIFI_TOOL_MODE`` values, from the
  ``Settings.tool_mode`` annotation;
* ``code-mode`` (README.md, AGENTS.md, llms.txt): what ``UNIFI_TOOL_MODE=codemode`` advertises
  (``code_mode.CODE_MODE_TOOLS``), its read-only posture and the experimental notice
  (``code_mode.EXPERIMENTAL_NOTICE``), verbatim;
* ``audit-schema`` (README.md): the audit record schema of ``unifi_fabric.audit``: schema
  version, events and their fields, outcomes, formats, sinks, levels and file modes.

The hand-written environment tables (README and docs/CONFIGURATION.md) also keep a Default
column. ``default_findings`` compares each row of those tables with the code default and the
check fails on a row that disagrees.

Usage:
    python3 scripts/gen_reference_blocks.py          # rewrite the blocks
    python3 scripts/gen_reference_blocks.py --check  # exit 1 on any stale block or default (CI)

``python3 scripts/regen_docs.py`` runs this generator together with the other documentation
generators.
"""

from __future__ import annotations

import argparse
import difflib
import functools
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, get_args, get_origin

from pydantic_core import PydanticUndefined

from unifi_fabric import audit, code_mode, config, discovery, families, switches
from unifi_fabric.config import Settings

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
AGENTS = ROOT / "AGENTS.md"
LLMS = ROOT / "llms.txt"
CONFIGURATION = ROOT / "docs" / "CONFIGURATION.md"
TOOL_USAGE = ROOT / "docs" / "TOOL-USAGE.md"
FIX_COMMAND = "python3 scripts/gen_reference_blocks.py"
#: This generator's name in the block registry (``BLOCKS`` in scripts/doc_blocks.py).
OWNER = "gen_reference_blocks"


def _load_doc_blocks():
    """scripts/doc_blocks.py, loaded by path: this module runs as a script and is loaded by
    path in tests, so ``scripts`` is not always importable."""
    path = Path(__file__).with_name("doc_blocks.py")
    module = sys.modules.get("doc_blocks")
    if module is not None and Path(module.__file__ or "").resolve() == path.resolve():
        return module
    spec = importlib.util.spec_from_file_location("doc_blocks", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("scripts/doc_blocks.py is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules["doc_blocks"] = module  # dataclasses resolve their module
    spec.loader.exec_module(module)
    return module


doc_blocks = _load_doc_blocks()

#: Which of this generator's blocks each file carries, in file order (from the registry).
BLOCKS: dict[Path, tuple[str, ...]] = doc_blocks.owned(OWNER, ROOT)
#: Hand-written environment tables whose Default column is checked against the code.
DEFAULT_TABLES: dict[Path, tuple[str, int]] = {
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


#: ``str`` settings whose validator accepts a fixed set (the tuples config.py validates with);
#: the annotation alone would render them as free text.
_CHOICES: dict[str, tuple[str, ...]] = {
    "log_level": config.LOG_LEVELS,
    "audit_log_format": config.AUDIT_LOG_FORMATS,
    "audit_sink": config.AUDIT_SINKS,
    "audit_level": config.AUDIT_LEVELS,
    "audit_log_mode": config.AUDIT_LOG_MODES,
}
#: ``str`` settings validated by ``config.api_base_url_problem``.
_URLS = frozenset({"api_base_url"})


def _accepted(field: Any, name: str = "") -> str:
    if name in _CHOICES:
        return " or ".join(f"`{v}`" for v in _CHOICES[name])
    if name in _URLS:
        return "absolute `http://` or `https://` URL"
    if get_origin(field.annotation) is Literal:
        return " or ".join(f"`{v}`" for v in get_args(field.annotation))
    if field.annotation is bool:
        return "boolean"
    minimums = [m.ge for m in field.metadata if hasattr(m, "ge")]
    if minimums:
        return f"integer, {minimums[0]} or more"
    if name in config._MIN_ONE_INTS:  # validated at construction, no Field(ge=...)
        return "integer, 1 or more"
    if name in config._AUDIT_POSITIVE_FLOATS:
        return "number above 0"
    if field.annotation is type(None):
        return "removed"
    return "text"


def settings_reference() -> str:
    rows = ["| Variable | Default | Accepted | Meaning |", "|---|---|---|---|"]
    for name, field in Settings.model_fields.items():
        rows.append(
            f"| `{_env(name)}` | {_show_default(_default(field))} | {_accepted(field, name)} | "
            f"{_first_sentence(field.description or '')} |"
        )
    return "\n".join(rows)


def _family_text(names: list[str]) -> str:
    return ", ".join(f"`{n}`" for n in names)


def _area_scope(sw: Any) -> str:
    governed = [sw.family, *sw.related_families]
    return (
        f"the write tools of {_family_text(governed)} and every write request to its console routes"
    )


def write_switches() -> str:
    lines = [
        f"- `{sw.env}`: {_area_scope(sw)}, the connector relay included"
        for sw in switches.AREA_WRITE_SWITCHES
    ]
    lines.append(
        f"- `{switches.CONNECTOR_WRITE_TOKEN}`: the connector relay's write tools and the typed "
        "tools it also governs"
    )
    lines.append(
        "Each is one entry of `UNIFI_WRITE_EXCEPTIONS` (unset by default: every write allowed); "
        "`dry-run` in place of `deny` previews the same writes instead of refusing them."
    )
    return "\n".join(lines)


def write_switch_names() -> str:
    names = [sw.env for sw in switches.AREA_WRITE_SWITCHES] + [switches.CONNECTOR_WRITE_TOKEN]
    return f"The area entries of `UNIFI_WRITE_EXCEPTIONS` are {_family_text(names)}."


def tool_mode_defaults() -> str:
    fields = Settings.model_fields
    modes = get_args(fields["tool_mode"].annotation)
    meta = sorted(discovery.META_TOOLS)
    read_meta = len(discovery.META_TOOLS - {"call_write_tool"})
    return (
        f"Defaults: `UNIFI_TOOL_MODE={fields['tool_mode'].default}` "
        f"(modes {_family_text(list(modes))}), `UNIFI_FAMILY_ALLOW` "
        f"{_show_default(_default(fields['family_allow']))} (every family), "
        f"`UNIFI_EXCLUDE` {_show_default(_default(fields['exclude']))}, "
        f"`UNIFI_WRITE_POLICY` {_show_default(_default(fields['write_policy']))} (`allow`). "
        f"Discovery mode advertises {len(meta)} meta-tools "
        f"({_family_text(meta)}), or {read_meta} with `UNIFI_WRITE_POLICY=deny`."
    )


def family_names() -> str:
    names = list(families.ALL_FAMILIES)
    return f"The {len(names)} families are {_family_text(names)}."


def tool_mode_choices() -> str:
    modes = list(get_args(Settings.model_fields["tool_mode"].annotation))
    return (
        "Empty or whitespace-only `UNIFI_TOOL_MODE` uses the default; any value other than "
        f"{_family_text(modes)} fails startup with an error naming `UNIFI_TOOL_MODE` and the "
        "valid choices."
    )


def code_mode_text() -> str:
    tools = sorted(code_mode.CODE_MODE_TOOLS)
    return (
        f"`UNIFI_TOOL_MODE=codemode` (opt-in, experimental) advertises {len(tools)} tools: "
        f"{_family_text(tools)}. `{code_mode.EXECUTE_TOOL}` runs one Python script in a sandbox "
        "with no credentials, environment, network, filesystem or process access; inside it, "
        "`call_tool` reaches the enabled read tools only and every write is refused, whatever "
        f"the write policy and its exceptions say. {code_mode.EXPERIMENTAL_NOTICE} Limits and "
        "refusal codes: [docs/CONFIGURATION.md](docs/CONFIGURATION.md#code-mode-experimental)."
    )


def audit_schema() -> str:
    def names(values: tuple[str, ...] | list[str]) -> str:
        return _family_text(list(values)) if values else "none"

    lines = [
        f"Every record carries `schema_version` `{audit.SCHEMA_VERSION}`; the fields of each "
        "event (rendered from `src/unifi_fabric/audit.py`):",
        "",
        "| Event | Required fields | Optional fields |",
        "|---|---|---|",
    ]
    for event, shape in audit.EVENT_FIELDS.items():
        lines.append(f"| `{event}` | {names(shape['required'])} | {names(shape['optional'])} |")
    lines += [
        "",
        f"The policy records {names(audit.POLICY_EVENTS)} share the stream. An `audit` record's "
        f"`outcome` is one of {names(audit.OUTCOMES)}, or `http_<status>` for a non-2xx upstream "
        f"status; a `call` record's is {names(audit.CALL_OUTCOMES)}. "
        f"`UNIFI_AUDIT_LOG_FORMAT`: {names(audit.FORMATS)}; `UNIFI_AUDIT_SINK`: "
        f"{names(audit.SINKS)}; `UNIFI_AUDIT_LEVEL`: {names(audit.LEVELS)}; "
        f"`UNIFI_AUDIT_LOG_MODE`: {names(list(audit.FILE_MODES))}.",
    ]
    return "\n".join(lines)


@functools.cache
def registered_search_limit() -> Any:
    """The ``limit`` default of ``search_tools`` as discovery mode registers it."""
    import asyncio

    from fastmcp import FastMCP

    async def read() -> Any:
        app = FastMCP("reference-blocks")
        cleanup = await discovery.apply_tool_mode(app, "discovery")
        try:
            tools = {t.name: t for t in await app.list_tools()}
            return tools["search_tools"].parameters["properties"]["limit"]["default"]
        finally:
            cleanup()

    return asyncio.run(read())


def search_tools_limit() -> str:
    return (
        f"`search_tools` returns {registered_search_limit()} matches by default; `limit` takes "
        "any positive integer, or null for every match."
    )


#: Family IDs as the README's family table titles them. ``carrier`` and ``mobility`` are the
#: ISP and mobile-routing products the table leaves out; a new family must be added to one
#: of these two structures or ``tool_families`` fails the run.
FAMILY_LABELS = {
    "network": "Network",
    "protect": "Protect",
    "vpn": "VPN",
    "devices": "Devices",
    "firewall": "Firewall",
    "innerspace": "InnerSpace",
    "site_manager": "Site Manager",
    "statistics": "Statistics",
    "clients": "Clients",
    "connector": "Connector relay",
    "hotspot": "Hotspot",
}
UNLISTED_FAMILIES = ("carrier", "mobility")


def tool_families() -> str:
    """The README catalog accounting and two-column family table, from the family index."""
    index = families.build_family_index()
    counts: dict[str, int] = {}
    for family in index.values():
        counts[family] = counts.get(family, 0) + 1
    unknown = set(counts) - set(FAMILY_LABELS) - set(UNLISTED_FAMILIES)
    if unknown:
        raise SystemExit(f"tool-families: families without a table label: {sorted(unknown)}")
    total = sum(counts.values())
    rest = sum(counts.get(f, 0) for f in UNLISTED_FAMILIES)
    listed = sorted(
        ((FAMILY_LABELS[f], n) for f, n in counts.items() if f in FAMILY_LABELS),
        key=lambda item: (-item[1], item[0]),
    )
    lines = [
        f"Catalog: **{total} registered tools**; **{total - rest}** are in the product",
        f"families listed below. The remaining {rest} cover Ubiquiti's ISP and",
        "mobile-routing products (Carrier Fabric and Mobility), which this overview",
        "leaves out. Availability depends on your hardware, permissions and API routes;",
        "see [coverage and limitations](docs/COVERAGE.md).",
        "",
        "| Family | Tools | Family | Tools |",
        "|---|---:|---|---:|",
    ]
    for i in range(0, len(listed), 2):
        pair = listed[i : i + 2]
        cells = [f"{name} | {count}" for name, count in pair]
        if len(cells) < 2:
            cells.append(" | ")
        lines.append(f"| {cells[0]} | {cells[1]} |")
    return "\n".join(lines)


RENDERERS = {
    "tool-mode-choices": tool_mode_choices,
    "code-mode": code_mode_text,
    "audit-schema": audit_schema,
    "search-tools-limit": search_tools_limit,
    "settings-reference": settings_reference,
    "write-switches": write_switches,
    "write-switch-names": write_switch_names,
    "tool-mode-defaults": tool_mode_defaults,
    "family-names": family_names,
    "tool-families": tool_families,
}


@dataclass(frozen=True)
class Finding:
    path: Path
    block: str
    message: str

    def __str__(self) -> str:
        return f"{self.path.relative_to(ROOT).as_posix()}: {self.block}: {self.message}"


def render_file(path: Path, text: str) -> tuple[str, list[Finding]]:
    """The file text with every block of this generator regenerated, and the structural
    findings for every registered block of the file (``doc_blocks.problems``)."""
    rel = path.relative_to(ROOT).as_posix()
    renderers = {name: RENDERERS[name] for name in BLOCKS[path]}
    new, found = doc_blocks.fill(rel, text, OWNER, renderers)
    return new, [Finding(path, block, message) for block, message in found]


def stale_blocks(path: Path, text: str) -> list[str]:
    """Names of this generator's blocks whose current content differs from the generated."""
    return [
        m["name"]
        for m in doc_blocks.BLOCK_RE.finditer(text)
        if m["name"] in BLOCKS[path] and m["body"] != RENDERERS[m["name"]]() + "\n"
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
        for path in BLOCKS:
            text = path.read_text()
            new, found = render_file(path, text)
            if not found and new != text:
                rel = path.relative_to(ROOT).as_posix()
                diff = difflib.unified_diff(
                    text.splitlines(keepends=True),
                    new.splitlines(keepends=True),
                    f"a/{rel}",
                    f"b/{rel}",
                )
                sys.stderr.writelines(diff)
        for finding in findings:
            print(finding, file=sys.stderr)
        if findings:
            print(f"{len(findings)} finding(s); fix with {FIX_COMMAND}", file=sys.stderr)
            return 1
        print("Reference blocks are current", file=sys.stderr)
        return 0
    changed = 0
    failed = 0
    for path in BLOCKS:
        text = path.read_text()
        new, found = render_file(path, text)
        for finding in found:
            print(finding, file=sys.stderr)
        if found:
            failed += len(found)  # never rewrite a file whose markers are not intact
        elif new != text:
            path.write_text(new)
            changed += 1
    print(f"Wrote reference blocks to {changed} file(s)", file=sys.stderr)
    if failed:
        print(f"{failed} finding(s); no file with findings was rewritten", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
