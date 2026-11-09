#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Migrate unifi-fabric-mcp settings from 0.7.0 to 0.7.1 (one shot, standard library only).

DELETE THIS FILE in 0.7.2, and no later than 2026-12-03. It is not packaged, the server
never imports it, and the v0.7.1 tag keeps it so the pinned URL (SCRIPT_URL) keeps
working: ``uv run <SCRIPT_URL> <config file>``, or download it and run
``python3 migrate-0.7.1-env.py <config file>``.

0.7.1 replaced the 0.7.0 write and exposure settings with four settings and kept no
aliases; a server that finds an old name refuses to start. This script rewrites the old
names in one configuration file, or prints the replacement lines where it does not edit
that kind of file. The mapping is the table in docs/MIGRATING-0.7.1.md; a test keeps the
two equal.

Surfaces (picked from the file name, or with --format):

* json: MCP client configuration (Claude Desktop, Claude Code .mcp.json, Gemini CLI or
  Antigravity settings): every ``env`` object, and ``-e``/``--env`` pairs in every
  ``args`` list. Rewritten with --write.
* env: an env_file (``KEY=VALUE`` lines). Rewritten with --write.
* compose: a Docker Compose file (``environment:`` in list or map form). Rewritten with
  --write, but only where the script resolves every source of a service's environment:
  its own ``environment:`` and its ``env_file`` (``NAME=value`` lines). A service whose
  environment can also come from somewhere else (YAML anchors, aliases, ``<<`` merge
  keys or tags, ``extends``, ``include``, an override file, an env_file it cannot read)
  is left byte for byte as it is, with a ``# MANUAL:`` line printed for it.
* toml: Codex ``config.toml``. Printed only: the lines to delete and the lines to add.
* shell: a shell profile or script (``export`` lines, ``docker run -e``). Printed only.
* --env (no file): the current process environment, printed as ``export`` lines.

Dry run is the default: the script prints a diff of setting names and the new values and
writes nothing. ``--write`` saves ``<file>.bak`` first. The diff never prints an old value
or any other setting's value: the only values printed are the new 0.7.1 values, which are
built from fixed vocabularies (policies, family IDs, API-source selectors). Where an old
setting has no clean mapping, the script keeps the old line, so the server keeps refusing
until it is fixed, and writes a ``# MANUAL:`` comment above it (text files) or prints the
``# MANUAL:`` line (JSON, the print-only surfaces, and a Compose service left unchanged).

Exit status: 0 when nothing needs a decision, 3 when a ``# MANUAL:`` item remains, 2 on a
usage or parse error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

GUIDE = "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/docs/MIGRATING-0.7.1.md"
SCRIPT_URL = (
    "https://raw.githubusercontent.com/swkstudios/unifi-fabric-mcp-server/v0.7.1/"
    "tools/migrate-0.7.1-env.py"
)

WRITE_POLICY = "UNIFI_WRITE_POLICY"
WRITE_EXCEPTIONS = "UNIFI_WRITE_EXCEPTIONS"
FAMILY_ALLOW = "UNIFI_FAMILY_ALLOW"
EXCLUDE = "UNIFI_EXCLUDE"
NEW_SETTINGS = (WRITE_POLICY, WRITE_EXCEPTIONS, FAMILY_ALLOW, EXCLUDE)

READ_ONLY = "UNIFI_READ_ONLY"
DRY_RUN = "UNIFI_DRY_RUN"
TOOL_FAMILIES = "UNIFI_TOOL_FAMILIES"
DISABLED_TOOL_FAMILIES = "UNIFI_DISABLED_TOOL_FAMILIES"
DISABLE_API_SOURCES = "UNIFI_DISABLE_API_SOURCES"
#: 0.7.0 per-area write flags (on by default) and the 0.7.1 family each one guarded.
FAMILY_WRITE_FLAGS = {
    "UNIFI_ENABLE_CONNECTOR_WRITE": "connector",
    "UNIFI_ENABLE_NETWORK_WRITE": "network",
    "UNIFI_ENABLE_MOBILITY_WRITE": "mobility",
    "UNIFI_ENABLE_CARRIER_FABRIC_WRITE": "carrier",
    "UNIFI_ENABLE_INNERSPACE_WRITE": "innerspace",
    "UNIFI_PROTECT_MUTATIONS_ENABLED": "protect",
}
RETIRED = (
    READ_ONLY,
    DRY_RUN,
    *FAMILY_WRITE_FLAGS,
    TOOL_FAMILIES,
    DISABLED_TOOL_FAMILIES,
    DISABLE_API_SOURCES,
)

#: 0.7.0 boolean spellings (any letter case, surrounding whitespace ignored).
TRUE = frozenset({"1", "true", "yes", "on", "t", "y"})
FALSE = frozenset({"0", "false", "no", "off", "f", "n"})
#: The frozen family IDs, identical in 0.7.0 and 0.7.1.
FAMILIES = (
    "carrier", "clients", "connector", "devices", "firewall", "hotspot", "innerspace",
    "mobility", "network", "protect", "site_manager", "statistics", "vpn",
)  # fmt: skip
#: The 0.7.1 ``source:`` selectors. 0.7.0 also took app/source/access selectors such as
#: network/private/write; 0.7.1 has no equivalent, so those are decided by hand.
SELECTORS = (
    "network", "network/official", "network/private", "network/private.v2",
    "network/private.classic", "network/private.other", "network/read", "network/write",
    "protect", "protect/official", "protect/private", "protect/read", "protect/write",
    "innerspace", "innerspace/official", "innerspace/private", "innerspace/read",
    "innerspace/write", "site_manager", "site_manager/official", "site_manager/read",
    "site_manager/private", "site_manager/write", "mobility", "mobility/official",
    "mobility/read", "mobility/write",
    "carrier_fabric", "carrier_fabric/official", "carrier_fabric/read",
    "carrier_fabric/write", "console", "console/private", "console/read", "console/write",
    "relay", "relay/generic", "relay/read", "relay/write", "server", "server/local",
    "server/read", "server/write", "*/official", "*/private", "*/generic", "*/local",
    "*/read", "*/write",
)  # fmt: skip

REMOVE = "remove the setting"
MANUAL = "decide manually"
NONE = "-"

#: The old -> new table, row for row the table in docs/MIGRATING-0.7.1.md:
#: (0.7.0 setting, 0.7.0 value, 0.7.1 setting, 0.7.1 value).
MAPPING_ROWS: tuple[tuple[str, str, str, str], ...] = (
    (READ_ONLY, "true", WRITE_POLICY, "deny"),
    (READ_ONLY, "false or empty", REMOVE, NONE),
    (DRY_RUN, "true", WRITE_POLICY, "dry-run"),
    (DRY_RUN, "false or empty", REMOVE, NONE),
    *(
        row
        for flag, family in FAMILY_WRITE_FLAGS.items()
        for row in (
            (flag, "false", WRITE_EXCEPTIONS, f"family:{family}=deny"),
            (flag, "true or empty", REMOVE, NONE),
        )
    ),
    (TOOL_FAMILIES, "family names", FAMILY_ALLOW, "the names, lower case, comma-separated"),
    (TOOL_FAMILIES, "empty", REMOVE, NONE),
    (DISABLED_TOOL_FAMILIES, "family names", EXCLUDE, "family:<name> for each name"),
    (DISABLED_TOOL_FAMILIES, "empty", REMOVE, NONE),
    (DISABLE_API_SOURCES, "selectors", EXCLUDE, "source:<selector> for each selector"),
    (DISABLE_API_SOURCES, "an app/source/access selector", MANUAL, NONE),
    (DISABLE_API_SOURCES, "empty", REMOVE, NONE),
)

_RANK = {"allow": 0, "dry-run": 1, "deny": 2}
_EXCEPTION_ITEM = re.compile(r"(?:family|tool):[a-z0-9_]+=(?:deny|dry-run)")
_EXCLUDE_ITEM = re.compile(r"(?:family:[a-z0-9_]+|tool:[a-z0-9_]+|source:[a-z0-9_.*/]+|unofficial)")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# --------------------------------------------------------------------------- mapping


@dataclass
class Plan:
    """The migration of one block of settings (one env object, file or service)."""

    removed: list[str] = field(default_factory=list)  # old names to delete
    kept: list[str] = field(default_factory=list)  # old names kept (manual)
    new: dict[str, str] = field(default_factory=dict)  # 0.7.1 name -> full new value
    manual: list[str] = field(default_factory=list)  # "# MANUAL: ..." lines

    @property
    def changed(self) -> bool:
        return bool(self.removed or self.new or self.manual)


def _manual(plan: Plan, name: str, why: str) -> None:
    plan.kept.append(name)
    plan.manual.append(f"# MANUAL: {name} {why}; see {GUIDE}")


def _items(value: str, *, whitespace: bool) -> list[str]:
    text = value.replace(",", " ") if whitespace else value
    parts = text.split() if whitespace else [p.strip() for p in text.split(",")]
    return [p.lower() for p in parts if p]


def _bool(value: str) -> bool | None:
    text = value.strip().lower()
    if text in TRUE:
        return True
    if text in FALSE:
        return False
    return None


def _strictest(*policies: str) -> str:
    return max(policies, key=_RANK.__getitem__)


@dataclass
class Layer:
    """Settings a lower layer may give the same process, which an entry in the block
    replaces: a Compose service ``env_file`` under its ``environment:``, or a
    ``docker run --env-file`` under its ``-e`` flags. ``values`` maps each 0.7.1 setting
    the layer sets to its value there, ``None`` where this script cannot read it."""

    where: str  # "by the service env_file unifi.env", for the # MANUAL: line
    values: dict[str, str | None] = field(default_factory=dict)

    @classmethod
    def unreadable(cls, where: str) -> Layer:
        return cls(where, dict.fromkeys(NEW_SETTINGS))


def plan_block(settings: Mapping[str, str | None], layer: Layer | None = None) -> Plan:
    """Plan one block. ``settings`` maps names to values; ``None`` is a value this script
    cannot read (a ``${VAR}`` reference, a pass-through name, a non-string JSON value).
    A new 0.7.1 entry replaces the value ``layer`` holds for it, so that value is merged
    in, or the old setting is kept for a manual decision."""
    plan = Plan()
    policies: list[str] = []
    exceptions: list[str] = []
    allow: list[str] | None = None
    exclude: list[str] = []
    for key in settings:
        # 0.7.0 matched names in any letter case; 0.7.1 refuses a wrong-case spelling.
        if key != key.upper() and key.upper() in (*RETIRED, *NEW_SETTINGS):
            _manual(plan, key, "is spelled in lower or mixed case (0.7.1 needs upper case)")
    for name in RETIRED:
        if name not in settings:
            continue
        raw = settings[name]
        if raw is None:
            _manual(plan, name, "has a value this script cannot read (a reference or pass-through)")
            continue
        if not raw.strip():
            plan.removed.append(name)
            continue
        if name in (READ_ONLY, DRY_RUN) or name in FAMILY_WRITE_FLAGS:
            on = _bool(raw)
            if on is None:
                _manual(plan, name, "is not a 0.7.0 true/false value")
                continue
            if name == READ_ONLY and on:
                policies.append("deny")
            elif name == DRY_RUN and on:
                policies.append("dry-run")
            elif name in FAMILY_WRITE_FLAGS and not on:
                exceptions.append(f"family:{FAMILY_WRITE_FLAGS[name]}=deny")
            plan.removed.append(name)
        elif name in (TOOL_FAMILIES, DISABLED_TOOL_FAMILIES):
            names = list(dict.fromkeys(_items(raw, whitespace=True)))
            if not names:  # only separators: an empty list, a no-op in 0.7.0
                plan.removed.append(name)
                continue
            if any(n not in FAMILIES for n in names):
                _manual(plan, name, "names a family that is not a 0.7.1 family ID")
                continue
            if name == TOOL_FAMILIES:
                allow = names
            else:
                exclude.extend(f"family:{n}" for n in names)
            plan.removed.append(name)
        else:  # DISABLE_API_SOURCES
            selectors = list(dict.fromkeys(_items(raw, whitespace=False)))
            if not selectors:
                plan.removed.append(name)
                continue
            if any(s not in SELECTORS for s in selectors):
                _manual(
                    plan, name, "names a selector 0.7.1 does not accept, such as app/source/access"
                )
                continue
            exclude.extend(f"source:{s}" for s in selectors)
            plan.removed.append(name)
    _merge(plan, settings, policies, exceptions, allow, exclude, layer)
    return plan


#: The 0.7.1 setting each 0.7.0 setting (and each 0.7.1 setting) feeds.
_TARGET = {
    READ_ONLY: WRITE_POLICY,
    DRY_RUN: WRITE_POLICY,
    **dict.fromkeys(FAMILY_WRITE_FLAGS, WRITE_EXCEPTIONS),
    TOOL_FAMILIES: FAMILY_ALLOW,
    DISABLED_TOOL_FAMILIES: EXCLUDE,
    DISABLE_API_SOURCES: EXCLUDE,
    **{name: name for name in NEW_SETTINGS},
}


def _merge(  # noqa: PLR0913 - one argument per kind of collected item
    plan: Plan,
    settings: Mapping[str, str | None],
    policies: list[str],
    exceptions: list[str],
    allow: list[str] | None,
    exclude: list[str],
    layer: Layer | None,
) -> None:
    """Combine with any 0.7.1 setting the block already has (a half-done migration), or
    else with the value a lower layer holds, which the new entry would replace.

    A 0.7.1 setting that is present with a value this script cannot read (``None``: a
    ``${VAR}`` reference, a value-less pass-through, a reference in an env_file) is
    neither merged into nor replaced: its real value is unknown, so the old settings that
    feed it are kept for a decision.
    """

    def current(setting: str) -> tuple[bool, str | None, str]:
        """Whether something sets ``setting`` that the new entry replaces, its value
        (``None`` when unreadable) and where it is set (" by ...", "" in the block)."""
        if setting in settings or layer is None or setting not in layer.values:
            return setting in settings, settings.get(setting), ""
        return True, layer.values[setting], f" {layer.where}"

    def unreadable(setting: str, where: str) -> str:
        if where:
            return f"{setting} may also be set{where}, and this script cannot read that value"
        return f"{setting} has a value this script cannot read"

    if policies:
        present, value, where = current(WRITE_POLICY)
        if present and value is None:
            _undo(plan, [READ_ONLY, DRY_RUN], unreadable(WRITE_POLICY, where))
        elif value is not None and value.strip() not in _RANK:
            _undo(plan, [READ_ONLY, DRY_RUN], f"{WRITE_POLICY} is already set to a value{where}")
        else:
            if value is not None:
                policies.append(value.strip())
            plan.new[WRITE_POLICY] = _strictest(*policies)
    for setting, items, sep, item_re, sources in (
        (WRITE_EXCEPTIONS, exceptions, ";", _EXCEPTION_ITEM, list(FAMILY_WRITE_FLAGS)),
        (EXCLUDE, exclude, ",", _EXCLUDE_ITEM, [DISABLED_TOOL_FAMILIES, DISABLE_API_SOURCES]),
    ):
        if not items:
            continue
        present, value, where = current(setting)
        if present and value is None:
            _undo(plan, sources, unreadable(setting, where))
            continue
        existing: list[str] = []
        if value is not None and value.strip():
            existing = [p.strip() for p in value.split(sep)]
            if not all(item_re.fullmatch(p) for p in existing):
                _undo(plan, sources, f"{setting} is already set to a value{where}")
                continue
        if setting == WRITE_EXCEPTIONS:
            merged = _merge_exceptions([*existing, *items])
        else:
            merged = list(dict.fromkeys([*existing, *items]))
        if merged != existing or where:  # the new entry replaces the lower layer's value
            plan.new[setting] = sep.join(merged)
    if allow is not None:
        present, value, where = current(FAMILY_ALLOW)
        if present and value is None:
            _undo(plan, [TOOL_FAMILIES], unreadable(FAMILY_ALLOW, where))
        elif present:  # an allow list cannot be merged without widening or narrowing it
            _undo(plan, [TOOL_FAMILIES], f"{FAMILY_ALLOW} is already set{where}")
        else:
            plan.new[FAMILY_ALLOW] = ",".join(allow)


def _merge_exceptions(items: Iterable[str]) -> list[str]:
    """One entry per target (0.7.1 refuses a repeated target), the strictest value kept,
    in first-seen order."""
    merged: dict[str, str] = {}
    for item in items:
        target, _, value = item.rpartition("=")
        previous = merged.get(target)
        merged[target] = value if previous is None else _strictest(previous, value)
    return [f"{target}={value}" for target, value in merged.items()]


def _mentions_retired(names: Iterable[object]) -> bool:
    """True when any name is a retired setting in any letter case."""
    return any(isinstance(n, str) and n.upper() in RETIRED for n in names)


def _ours(name: str) -> bool:
    return name.upper().startswith("UNIFI_")


def _undo(plan: Plan, names: Iterable[str], why: str) -> None:
    for name in names:
        if name in plan.removed:
            plan.removed.remove(name)
            _manual(plan, name, f"cannot be merged: {why}")


def apply_plan(block: Mapping[str, object], plan: Plan) -> dict[str, object]:
    """``block`` with ``plan`` applied, order kept: the new settings take the place of the
    first setting they replace; a setting kept for a manual decision stays where it is."""
    out: dict[str, object] = {}
    placed = False
    for name, value in block.items():
        if name in plan.removed or name in plan.new:
            if not placed:
                out.update(plan.new)
                placed = True
            continue
        out[name] = value
    if not placed:
        out.update(plan.new)
    return out


# --------------------------------------------------------------------------- reporting


class Report:
    def __init__(self) -> None:
        self.manual = False
        self.changed = False

    def block(self, where: str, plan: Plan) -> None:
        if not plan.changed:
            return
        self.changed = True
        print(f"{where}:")
        for name in plan.removed:
            print(f"  - {name}")
        for name, value in plan.new.items():
            print(f"  + {name}={value}")
        for line in plan.manual:
            self.manual = True
            print(f"  {line}")


# --------------------------------------------------------------------------- json


def _json_value(value: object) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return None if "${" in value else value
    return None


_ENV_FLAGS = ("-e", "--env")


def _args_settings(args: list[object]) -> dict[str, tuple[int, int, str | None]]:
    """name -> (start index, item count, value) for every -e/--env pair in ``args``."""
    found: dict[str, tuple[int, int, str | None]] = {}
    i = 0
    while i < len(args):
        item = args[i]
        pair: tuple[str, int] | None = None
        if item in _ENV_FLAGS and i + 1 < len(args) and isinstance(args[i + 1], str):
            pair = (str(args[i + 1]), 2)
        elif isinstance(item, str) and item.startswith("--env="):
            pair = (item[len("--env=") :], 1)
        if pair is None:
            i += 1
            continue
        text, count = pair
        name, eq, value = text.partition("=")
        if _NAME.fullmatch(name):
            found[name] = (i, count, (None if "${" in value else value) if eq else None)
        i += count
    return found


def _env_file_layer(args: Iterable[object]) -> Layer | None:
    """A ``--env-file`` in a ``docker run`` command: its ``-e`` flags replace the values
    it sets. The file is read by Docker relative to a directory this script cannot know."""
    if any(a == "--env-file" or (isinstance(a, str) and a.startswith("--env-file=")) for a in args):
        return Layer.unreadable("by the --env-file file")
    return None


def _migrate_args(args: list[object], where: str, report: Report) -> list[object]:
    found = _args_settings(args)
    if not _mentions_retired(found):
        return args
    plan = plan_block({name: v for name, (_, _, v) in found.items()}, _env_file_layer(args))
    report.block(where, plan)
    drop = {found[n][0]: found[n][1] for n in plan.removed}
    drop.update({found[n][0]: found[n][1] for n in plan.new if n in found})
    anchor = min(drop) if drop else None
    out: list[object] = []
    i = 0
    while i < len(args):
        if i == anchor:
            for name, value in plan.new.items():
                out.extend(["-e", f"{name}={value}"])
        if i in drop:
            i += drop[i]
            continue
        out.append(args[i])
        i += 1
    return out


def _walk_json(node: object, path: str, report: Report) -> object:
    if isinstance(node, dict):
        out: dict[str, object] = {}
        for key, value in node.items():
            where = f"{path}.{key}" if path else str(key)
            if key == "env" and isinstance(value, dict) and _mentions_retired(value):
                plan = plan_block({k: _json_value(v) for k, v in value.items()})
                report.block(where, plan)
                out[key] = apply_plan(value, plan)
            elif key == "args" and isinstance(value, list):
                out[key] = _migrate_args(value, where, report)
            else:
                out[key] = _walk_json(value, where, report)
        return out
    if isinstance(node, list):
        return [_walk_json(item, f"{path}[{i}]", report) for i, item in enumerate(node)]
    return node


def _indent(text: str) -> int:
    match = re.search(r"\n( +)\S", text)
    return len(match.group(1)) if match else 2


def migrate_json(text: str, report: Report) -> str:
    data = json.loads(text)
    out = _walk_json(data, "", report)
    return json.dumps(out, indent=_indent(text), ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- text files

_ID = r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
_ENV_LINE = re.compile(r"^(?P<indent>\s*)(?P<export>export\s+)?" + _ID + r"=(?P<value>.*)$")
_LIST_LINE = re.compile(
    r"^(?P<indent>\s*)-\s+(?P<q>[\"']?)" + _ID + r"(?:=(?P<value>.*?))?(?P=q)\s*(?:#.*)?$"
)
_MAP_LINE = re.compile(
    r"^(?P<indent>\s*)(?P<q>[\"']?)" + _ID + r"(?P=q)\s*:\s*(?P<value>.*?)\s*(?:#.*)?$"
)


def _unquote(value: str) -> str | None:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    elif " #" in value:
        value = value.split(" #", 1)[0].strip()
    if "$" in value or "`" in value:
        return None
    return value


@dataclass
class _Line:
    index: int
    name: str
    value: str | None
    style: str  # "env", "list" or "map"
    indent: str
    prefix: str  # "export " or the list quote character


def _render(line: _Line, name: str, value: str) -> str:
    if line.style == "list":
        q = line.prefix
        return f"{line.indent}- {q}{name}={value}{q}"
    if line.style == "map":
        return f'{line.indent}{name}: "{value}"'
    if line.prefix:  # an ``export`` line is sourced by a shell: quote ``;`` and the like
        return f"{line.indent}{line.prefix}{name}={shlex.quote(value)}"
    return f"{line.indent}{name}={value}"


Lines = list[str | None]


def _rewrite(
    lines: Lines, block: list[_Line], where: str, report: Report, layer: Layer | None = None
) -> None:
    """Rewrite one block of parsed setting lines in ``lines`` (in place; None deletes)."""
    settings = {line.name: line.value for line in block}
    if not _mentions_retired(settings):
        return
    plan = plan_block(settings, layer)
    report.block(where, plan)
    by_name = {line.name: line for line in block}
    targets = [by_name[n] for n in [*plan.removed, *plan.new] if n in by_name]
    if targets:
        anchor = min(targets, key=lambda line: line.index)
        new_text = [_render(anchor, n, v) for n, v in plan.new.items()]
        for line in targets:
            lines[line.index] = None
        lines[anchor.index] = "\n".join(new_text) if new_text else None
    for name in plan.kept:
        line = by_name[name]
        note = next(m for m in plan.manual if m.startswith(f"# MANUAL: {name} "))
        lines[line.index] = f"{line.indent}{note}\n{lines[line.index]}"


def _env_lines(text: str) -> list[_Line]:
    block = []
    for i, raw in enumerate(text.splitlines()):
        match = _ENV_LINE.match(raw)
        if match and _ours(match["name"]):
            value = _unquote(match["value"])
            prefix = match["export"] or ""
            block.append(_Line(i, match["name"], value, "env", match["indent"], prefix))
    return block


def migrate_env(text: str, report: Report) -> str:
    lines: Lines = list(text.splitlines())
    _rewrite(lines, _env_lines(text), "file", report)
    return _join(lines, text)


class _Unresolved(Exception):
    """A source of a service's environment this script does not resolve (the message
    names it), so rewriting the service's ``environment:`` could drop a value."""


def migrate_compose(
    text: str, report: Report, base: Path | None = None, name: str | None = None
) -> str:
    """``base`` is the directory a service ``env_file`` path is relative to (the Compose
    file's directory; the current directory when not given); ``name`` is the Compose
    file's name, to find an override file Compose reads over it.

    A block is rewritten only when it is the ``environment:`` of a service under
    ``services:`` and every other source of that service's environment is one this
    script reads: its ``env_file`` of ``NAME=value`` lines. Anything else that can feed
    or share a service's settings (see ``_file_constructs``, ``_other_files`` and
    ``_service_layer``) leaves the block byte for byte as it is, with a ``# MANUAL:``
    line printed that names the service, the construct and the settings."""
    base = base or Path()
    lines: Lines = list(text.splitlines())
    blocks: dict[int, list[_Line]] = {}
    for i, raw in enumerate(text.splitlines()):
        line = _compose_line(i, raw)
        if line is None:
            continue
        header = _header(lines, i, len(line.indent), item=line.style == "list")
        blocks.setdefault(header, []).append(line)
    shared = [*_file_constructs(lines), *_other_files(base, name)]
    parsed: set[int] = set()
    for header, block in blocks.items():
        parsed.update(line.index for line in block)
        if not _mentions_retired(line.name for line in block):
            continue
        service = _service_of(lines, header)
        if header < 0:
            where = "file"
        elif service is None:
            where = f"line {header + 1}: {(lines[header] or '').strip().rstrip(':')}"
        else:
            where = f"line {header + 1}: environment"
        problems = list(shared)
        layer = None
        if service is None:
            problems.append("these settings are not the environment: of a service under services:")
        elif not problems:
            try:
                layer = _service_layer(lines, header, base)
            except _Unresolved as exc:
                problems.append(str(exc))
        if problems:
            report.block(where, _unresolved(service, block, problems))
            continue
        _rewrite(lines, block, where, report, layer)
    stray = _stray_settings(lines, parsed)
    if stray.manual:
        report.block("file", stray)
    return _join(lines, text)


def _unresolved(service: str | None, block: list[_Line], problems: list[str]) -> Plan:
    """The plan for a block left as it is: one ``# MANUAL:`` line naming the service,
    what it uses that this script does not resolve, and the 0.7.0 settings in it."""
    names = list(dict.fromkeys(line.name for line in block if line.name.upper() in RETIRED))
    owner = f"service {service}" if service else "this block"
    plan = Plan(kept=names)
    plan.manual.append(
        f"# MANUAL: {', '.join(names)} left unchanged in {owner}: this script cannot resolve "
        f"every source of its environment ({'; '.join(problems)}); migrate them by hand, "
        f"merging any value the other sources set; see {GUIDE}"
    )
    return plan


def _stray_settings(lines: Lines, parsed: set[int]) -> Plan:
    """A ``# MANUAL:`` line for each retired name on a line that is not a block entry this
    script reads, such as a flow ``environment: [...]`` or ``{...}``, or a block scalar."""
    plan = Plan()
    for i, raw in enumerate(lines):
        if i in parsed or _blank(raw):
            continue
        for name in RETIRED:
            if re.search(rf"(?<![A-Za-z0-9_]){name}(?![A-Za-z0-9_])", raw or "", re.IGNORECASE):
                _manual(
                    plan,
                    name,
                    f"on line {i + 1} is in a form this script does not rewrite "
                    "(a flow list or mapping, a block scalar, or a value), so it is left unchanged",
                )
    return plan


_KEY = re.compile(r"^\s*(?P<q>[\"']?)(?P<key>[A-Za-z0-9_<.-]+)(?P=q)\s*:(?:\s+|$)(?P<rest>.*)$")
_BLOCK_SCALAR = re.compile(r"[|>][-+0-9]*")
_NODE_PROPERTY = re.compile(r"^(?:[&!]\S*\s+)+")
_FLOW_NODE = re.compile(r"[\[{,]\s*(?P<c>[&*!])|<<\s*:")
#: What a node-start character means in YAML, for the ``# MANUAL:`` line.
_PROPERTY = {"&": "a YAML anchor &", "*": "a YAML alias *",
             "!": "a YAML tag such as !reset or !override"}  # fmt: skip


def _code(text: str, *, keep_quoted: bool = False) -> str:
    """``text`` without its comment and, unless ``keep_quoted``, without the contents of
    its quoted scalars (the quotes stay), so a ``&``, ``*``, ``!`` or ``#`` inside quotes
    is not read as YAML."""
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            if char == "\\" and quote == '"':
                out.append(text[i : i + 2] if keep_quoted else "")
                i += 2
                continue
            if char == quote:
                quote = ""
            if keep_quoted or not quote:
                out.append(char)
        elif char in "\"'":
            quote = char
            out.append(char)
        elif char == "#" and (not out or out[-1].isspace()):
            break
        else:
            out.append(char)
        i += 1
    return "".join(out).strip()


#: A double-quoted key with a backslash escape (``"env\\x5ffile":``), which names a key
#: this script cannot match by its text.
_ESCAPED_KEY = re.compile(r'^"(?:[^"\\]|\\.)*\\(?:[^"\\]|\\.)*"\s*:')


def _file_constructs(lines: Lines) -> list[str]:
    """The YAML and Compose constructs in the file that let one service's settings come
    from, or go to, another place: anchors, aliases, tags (``!reset``, ``!override``),
    ``<<`` merge keys, ``extends`` and a top-level ``include``. Any of them makes every
    service's environment one this script does not resolve, so each is named once, with
    the line it is first on. Block scalar contents (``|``, ``>``) are text, not YAML."""
    found: dict[str, str] = {}
    scalar: int | None = None
    content = False
    for i, raw in enumerate(lines):
        text = raw or ""
        if _blank(text):
            continue
        indent = _indent_of(text)
        if scalar is not None and indent > scalar:
            continue
        scalar = None
        if indent == 0 and (text.startswith("---") or text.rstrip() == "..."):
            # Compose merges every document of a multi-document file.
            if content:
                found.setdefault("docs", f"the file has more than one YAML document (line {i + 1})")
            continue
        content = True
        entry = text.strip()
        while entry == "-" or entry.startswith("- "):
            entry = entry[1:].lstrip()
        key = _KEY.match(entry)
        value = _code(key["rest"] if key else entry)
        kinds: list[str] = []
        if entry == "?" or entry.startswith("? "):
            kinds.append("an explicit ? key")
        elif _ESCAPED_KEY.match(entry):
            kinds.append("a quoted key with an escape sequence")
        if key is not None:
            if key["key"] == "<<":
                kinds.append("a << merge key")
            elif key["key"] == "extends":
                kinds.append("extends:")
            elif key["key"] == "include" and indent == 0:
                kinds.append("include:")
            elif key["key"] == "build" and indent > 0:
                # An ENV in a built image is the lowest layer of the service's environment.
                kinds.append("build: (an ENV in the built image is not read)")
        if value[:1] in _PROPERTY:
            kinds.append(_PROPERTY[value[0]])
        if value[:1] in ("[", "{"):
            for match in _FLOW_NODE.finditer(value):
                kinds.append(_PROPERTY[match["c"]] if match["c"] else "a << merge key")
        if _BLOCK_SCALAR.fullmatch(_NODE_PROPERTY.sub("", value)):
            scalar = indent
        for kind in kinds:
            found.setdefault(kind, f"the file uses {kind} on line {i + 1}")
    return list(found.values())


#: The override files Compose reads over a main file by default (any main file name).
_OVERRIDE_NAMES = (
    "compose.override.yml",
    "compose.override.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
)


def _other_files(base: Path, name: str | None) -> list[str]:
    """Compose files Compose reads together with this one: an override file next to it
    (``compose.override.yaml`` beside ``compose.yaml``), or this file being one."""
    if name is None:
        return []
    stem = name.rpartition(".")[0]
    if ".override" in stem.lower():
        return [f"{name} is an override file, read over another Compose file"]
    # Compose reads the first of the default override names that exists, whatever the
    # main file is called, so every one of them (and the stem-matched names) counts.
    names = dict.fromkeys((*_OVERRIDE_NAMES, f"{stem}.override.yaml", f"{stem}.override.yml"))
    found = [
        f"Compose also reads {other} over this file"
        for other in names
        if other != name and (base / other).exists()
    ]
    return found + _compose_file_setting(base)


def _compose_file_setting(base: Path) -> list[str]:
    """COMPOSE_FILE, from the environment or from the .env file beside the Compose file
    (which a plain ``docker compose up`` reads), makes Compose read other files with
    this one; COMPOSE_ENV_FILES replaces that .env with other env files that may set it.
    An unreadable .env counts too: the script cannot tell what it sets."""
    if os.environ.get("COMPOSE_FILE"):
        return [
            "Compose reads the files COMPOSE_FILE names (set in the environment) with this file"
        ]
    if os.environ.get("COMPOSE_ENV_FILES"):
        # Compose then reads these env files instead of .env, and COMPOSE_FILE from them.
        return ["Compose reads COMPOSE_FILE from the env files COMPOSE_ENV_FILES names"]
    dotenv = base / ".env"
    if not dotenv.exists():
        return []
    try:
        text = dotenv.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [".env beside this file cannot be read, so COMPOSE_FILE there is unknown"]
    if re.search(r"^\s*(?:export\s+)?COMPOSE_FILE\s*[=:]", text, re.M):
        return ["Compose reads the files COMPOSE_FILE names (set in .env) with this file"]
    return []


def _service_of(lines: Lines, header: int) -> str | None:
    """The service name when the block at ``header`` is the ``environment:`` key of a
    service directly under the top-level ``services:``; ``None`` otherwise."""

    def key(index: int, name: str | None = None) -> str | None:
        match = _KEY.match(lines[index] or "") if index >= 0 else None
        if match is None or _is_item(lines[index] or "") or (name and match["key"] != name):
            return None
        rest = _NODE_PROPERTY.sub("", _code(match["rest"]) + " ")  # an anchor or tag only
        return None if rest.strip() else match["key"]

    if key(header, "environment") is None:
        return None
    service = _header(lines, header, _indent_of(lines[header] or ""))
    top = _header(lines, service, _indent_of(lines[service] or "")) if service >= 0 else -1
    if key(top, "services") is None or _indent_of(lines[top] or ""):
        return None
    return key(service)


def _indent_of(text: str) -> int:
    return len(text) - len(text.lstrip())


def _blank(text: str | None) -> bool:
    return not (text or "").strip() or (text or "").lstrip().startswith("#")


def _service_layer(lines: Lines, header: int, base: Path) -> Layer | None:
    """The lower layer under the service that holds the ``environment:`` at ``header``:
    Compose applies its ``env_file`` first, and an ``environment:`` entry replaces a
    value the env_file sets. ``None`` when the service has no env_file; ``_Unresolved``
    when the env_file is one this script cannot read in full."""
    key_indent = _indent_of(lines[header] or "")
    service = _header(lines, header, key_indent)
    if service < 0:
        return None
    paths: list[str] = []
    for j in range(service + 1, len(lines)):
        text = lines[j] or ""
        if _blank(text):
            continue
        if _indent_of(text) <= _indent_of(lines[service] or ""):
            break
        match = _KEY.match(text)
        if _indent_of(text) != key_indent or match is None or _is_item(text):
            continue
        if match["key"] == "env_file":
            paths.extend(_env_file_paths(lines, j, match["rest"]))
    if not paths:
        return None
    where = f"by the service env_file {', '.join(paths)}"
    settings: dict[str, str | None] = {}
    for path in paths:  # a later env_file replaces a value an earlier one sets
        try:
            text = (base / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise _Unresolved(f"its env_file {path} cannot be read") from exc
        settings.update(_env_file_settings(text, path))
    return Layer(where, _effective(settings))


#: The name at the start of an env_file line, in any form Compose reads (``NAME=value``,
#: ``NAME = value``, ``NAME: value``, a bare ``NAME`` passed through from the environment).
_ENV_FILE_NAME = re.compile(r"^\s*(?:export\s+)?(?P<name>[A-Za-z0-9_.\-\[\]]+)")


def _env_file_settings(text: str, path: str) -> dict[str, str | None]:
    """The ``UNIFI_`` settings a Compose env_file sets, ``None`` for a value this script
    cannot read (a ``${VAR}`` reference). Only a plain ``NAME=value`` line is read.
    Compose also accepts ``NAME = value``, ``NAME: value`` and a bare ``NAME``, and a
    quoted value that runs over several lines; ``_Unresolved`` when a ``UNIFI_`` setting
    is written in one of those forms, a quoted value runs past its line (the lines after
    it may belong to it) or a line that mentions ``UNIFI_`` has no name this script finds."""
    settings: dict[str, str | None] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        if _blank(raw):
            continue
        unparsed = _Unresolved(f"its env_file {path} has a line this script does not parse "
                               f"(line {number}; only NAME=value lines are read)")  # fmt: skip
        named = _ENV_FILE_NAME.match(raw)
        if named is None:
            if "UNIFI_" in raw.upper():
                raise unparsed
            continue
        rest = raw[named.end() :].lstrip()
        value = rest[1:].strip() if rest[:1] in ("=", ":") else ""
        if value[:1] in ("'", '"') and not _closes(value):
            raise unparsed
        if not _ours(named["name"]):
            continue
        match = _ENV_LINE.match(raw)
        if match is None:
            raise unparsed
        settings[named["name"]] = _unquote(match["value"])
    return settings


def _closes(value: str) -> bool:
    """True when the quote that opens ``value`` closes on the same line."""
    quote, i = value[0], 1
    while i < len(value):
        if value[i] == "\\" and quote == '"':
            i += 2
            continue
        if value[i] == quote:
            return True
        i += 1
    return False


def _env_file_paths(lines: Lines, index: int, rest: str) -> list[str]:
    """The paths of the ``env_file:`` at ``index`` (a string, a flow list or a block list
    of strings or ``path:`` entries with ``required:``); ``_Unresolved`` for any other
    form, an interpolated path, or a ``format:`` (``raw`` reads values unquoted)."""
    rest = _code(rest, keep_quoted=True)
    if rest:
        if rest.startswith("[") and rest.endswith("]"):
            items: list[str | None] = [_unquote(p) for p in rest[1:-1].split(",") if p.strip()]
        elif rest[0] in "{&*|>!":
            raise _Unresolved("its env_file: is in a form this script does not read")
        else:
            items = [_unquote(rest)]
    else:
        items = []
        indent = _indent_of(lines[index] or "")
        for j in range(index + 1, len(lines)):
            text = lines[j] or ""
            if _blank(text):
                continue
            if _indent_of(text) < indent or (_indent_of(text) == indent and not _is_item(text)):
                break  # the items may sit at the key's own indent
            entry = _code(text.strip().removeprefix("-").strip(), keep_quoted=True)
            match = _KEY.match(entry)
            if match is None:
                items.append(_unquote(entry))
            elif match["key"] == "path":
                items.append(_unquote(match["rest"]))
            elif match["key"] != "required":
                raise _Unresolved(
                    f"its env_file uses {match['key']}:, which this script does not read"
                )
    if any(p is None for p in items):
        raise _Unresolved("its env_file path uses interpolation")
    if not items or not all(items):
        raise _Unresolved("its env_file: is in a form this script does not read")
    return [p for p in items if p]


def _effective(settings: Mapping[str, str | None]) -> dict[str, str | None]:
    """The 0.7.1 settings an env_file gives once it is migrated too: its 0.7.1 values,
    or the values its 0.7.0 settings become; ``None`` where that is not known (a value
    this script cannot read, or a setting left for a manual decision)."""
    plan = plan_block(settings)
    unknown = {_TARGET[name.upper()] for name in plan.kept if name.upper() in _TARGET}
    unknown |= {name for name, value in settings.items() if value is None and name in NEW_SETTINGS}
    values: dict[str, str | None] = {}
    for name in NEW_SETTINGS:
        if name in unknown:
            values[name] = None
        elif name in plan.new:
            values[name] = plan.new[name]
        elif name in settings:
            values[name] = settings[name]
    return values


def _compose_line(i: int, raw: str) -> _Line | None:
    match = _LIST_LINE.match(raw)
    if match and _ours(match["name"]):
        value = None if match["value"] is None else _unquote(match["value"])
        return _Line(i, match["name"], value, "list", match["indent"], match["q"])
    match = _MAP_LINE.match(raw)
    if match and _ours(match["name"]):
        raw_value = match["value"].strip()
        # ``NAME:`` (or ``NAME: null`` / ``~``) takes its value from the shell or .env.
        value = None if raw_value in ("", "null", "Null", "NULL", "~") else _unquote(raw_value)
        return _Line(i, match["name"], value, "map", match["indent"], "")
    return None


def _header(lines: Lines, index: int, indent: int, *, item: bool = False) -> int:
    """The line that opens the block holding line ``index`` (indented ``indent``): the
    nearest line above it indented less, or, for a ``- `` list ``item``, a mapping key at
    the item's own indent too (YAML lets a block sequence sit at its key's indent, so
    ``environment:`` above ``- NAME=value`` at the same indent is still its key); -1 when
    there is none."""
    for j in range(index - 1, -1, -1):
        text = lines[j] or ""
        if _blank(text):
            continue
        level = _indent_of(text)
        if level < indent or (item and level == indent and not _is_item(text)):
            return j
    return -1


def _is_item(text: str) -> bool:
    return text.lstrip() == "-" or text.lstrip().startswith("- ")


def _join(lines: Lines, original: str) -> str:
    out = "\n".join(line for line in lines if line is not None)
    return out + "\n" if original.endswith("\n") else out


# --------------------------------------------------------------------------- print-only


def print_toml(text: str, report: Report) -> None:
    data = tomllib.loads(text)

    def walk(node: object, path: str) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            where = f"{path}.{key}" if path else str(key)
            if key == "env" and isinstance(value, dict) and _mentions_retired(value):
                plan = plan_block({k: _json_value(v) for k, v in value.items()})
                report.block(f"[{where}]", plan)
                if plan.removed or plan.new:
                    print("  replace the lines above in that table with:")
                    for name, new in plan.new.items():
                        print(f'  {name} = "{new}"')
            elif key == "env_vars" and isinstance(value, list):
                passed = [v for v in value if isinstance(v, str) and v.upper() in RETIRED]
                if passed:
                    plan = Plan()
                    for name in passed:
                        _manual(
                            plan,
                            name,
                            "is forwarded from the environment Codex starts in: "
                            "migrate that environment (--env), then list the new names here",
                        )
                    report.block(f"{where}", plan)
            elif key == "args" and isinstance(value, list):
                _migrate_args(value, where, report)
            else:
                walk(value, where)

    walk(data, "")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """(first physical line number, text) per shell command, backslash continuations
    joined, so a ``docker run \\`` over several lines is read as one command."""
    out: list[tuple[int, str]] = []
    start = 0
    parts: list[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not parts:
            start = number
        if raw.endswith("\\"):
            parts.append(raw[:-1])
            continue
        parts.append(raw)
        out.append((start, " ".join(parts)))
        parts = []
    if parts:
        out.append((start, " ".join(parts)))
    return out


def print_shell(text: str, report: Report) -> None:
    exports = {}
    commands = _logical_lines(text)
    for _, raw in commands:
        match = _ENV_LINE.match(raw)
        if match and _ours(match["name"]):
            exports[match["name"]] = _unquote(match["value"])
    if _mentions_retired(exports):
        plan = plan_block(exports)
        report.block("export lines", plan)
        if plan.new:
            print("  replace the removed export lines with:")
            for name, value in plan.new.items():
                print(f"  export {name}={shlex.quote(value)}")
    for number, raw in commands:
        if not any(flag in raw for flag in ("-e", "--env")):
            continue
        try:
            words = shlex.split(raw, comments=True)
        except ValueError:
            continue
        found = _args_settings(list(words))
        if _mentions_retired(found):
            plan = plan_block({n: v for n, (_, _, v) in found.items()}, _env_file_layer(words))
            report.block(f"line {number}: -e flags", plan)
            if plan.new:
                flags = " ".join("-e " + shlex.quote(f"{n}={v}") for n, v in plan.new.items())
                print(f"  replace the removed -e flags with: {flags}")


def print_environ(environ: Mapping[str, str], report: Report) -> None:
    settings = {k: v for k, v in environ.items() if _ours(k)}
    plan = plan_block(settings)
    report.block("environment", plan)
    for name in plan.removed:
        print(f"unset {name}")
    for name, value in plan.new.items():
        print(f"export {name}={shlex.quote(value)}")


# --------------------------------------------------------------------------- main


def detect(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".json"):
        return "json"
    if name.endswith(".toml"):
        return "toml"
    if name.endswith((".yml", ".yaml")):
        return "compose"
    if name == ".env" or name.endswith(".env") or name.startswith(".env."):
        return "env"
    return "shell"


def _backup(path: Path) -> Path:
    backup = path.with_name(path.name + ".bak")
    n = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.bak.{n}")
        n += 1
    shutil.copy2(path, backup)
    return backup


def _replace(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (same directory, same permissions)."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        shutil.copymode(path, tmp)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Migrate unifi-fabric-mcp settings from 0.7.0 to 0.7.1 (dry run by default)."
    )
    parser.add_argument("file", nargs="?", type=Path, help="configuration file to migrate")
    parser.add_argument("--env", action="store_true", help="migrate the current environment")
    parser.add_argument("--format", choices=("json", "env", "compose", "toml", "shell"))
    parser.add_argument("--write", action="store_true", help="save changes (keeps <file>.bak)")
    args = parser.parse_args(argv)
    report = Report()
    if args.env:
        if args.file is not None:
            parser.error("give a file or --env, not both")
        print_environ(os.environ, report)
        return _finish(report, wrote=False, printable=True)
    if args.file is None:
        parser.error("give a configuration file, or --env for the current environment")
    path: Path = args.file
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read {path}: {exc.strerror}", file=sys.stderr)
        return 2
    kind = args.format or detect(path)
    print(f"== {path} ({kind})")
    try:
        if kind in ("toml", "shell"):
            (print_toml if kind == "toml" else print_shell)(text, report)
            if args.write and report.changed:
                print("This file is not edited by the script: change the lines above by hand.")
            return _finish(report, wrote=False, printable=True)
        if kind == "compose":
            new_text = migrate_compose(text, report, path.parent, path.name)
        else:
            new_text = {"json": migrate_json, "env": migrate_env}[kind](text, report)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"cannot parse {path} as {kind} (line {getattr(exc, 'lineno', '?')}); "
              f"edit it by hand using {GUIDE}", file=sys.stderr)  # fmt: skip
        return 2
    wrote = False
    if args.write and new_text != text:
        backup = _backup(path)
        _replace(path, new_text)
        print(f"Saved {path} (backup: {backup.name}).")
        wrote = True
    return _finish(report, wrote=wrote, printable=False)


def _finish(report: Report, *, wrote: bool, printable: bool) -> int:
    if not report.changed:
        print("No 0.7.0 settings found; nothing to migrate.")
    elif not wrote and not printable:
        print("Dry run: nothing written. Run again with --write to save (keeps a .bak copy).")
    if report.manual:
        print(f"Some settings need a decision (# MANUAL above); see {GUIDE}")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
