#!/usr/bin/env python3
"""Freeze, dump and compare the behaviour baseline of the tool surface (public #42 step 1).

Every L1 move, L2 description pass and L3 tool PR is judged against this baseline, so a
refactor that must not change behaviour is *proved* not to, and a change that is meant to
change one thing is proved to change only that.

The baseline is a set of fixture files under ``tests/fixtures/behavior_baseline/``:

``<family>.json`` (one per family of ``families.ALL_FAMILIES``)
    ``tools``     the family's entries of the FULL-mode ``tools/list``, in list order:
                  ``name``, ``description``, ``inputSchema``, ``outputSchema`` (null when
                  the tool has none), ``annotations``, and the client-visible ``title`` and
                  ``_meta`` when present.
    ``describe``  tool name -> the ``describe_tool`` result envelope, in discovery mode.
    ``calls``     fixture-driven calls (no live console: the shape-faithful fake upstream
                  of ``tests/upstream_harness.py``) with each call's arguments, profile
                  (environment) and result or error recorded exactly: ``read``,
                  ``write_dry_run``, ``write_confirm``, ``write_denied`` (null in a family
                  without write tools), ``validation_error`` and ``tool_not_exposed`` (the
                  read tool called under a profile that excludes the family).
``order.json``
    The full-mode ``tools/list`` name order. A caller sees the order, so it is parity.
``docs.json``
    sha256 (in eight-character groups) of every operator doc the tool descriptions cite and
    of each cited section, plus the generated tool reference pages.

Usage (run from the repository root, in the locked virtualenv)::

    python scripts/dump_tool_baseline.py                  # write the files from the runtime
    python scripts/dump_tool_baseline.py --verify         # runtime must equal the files
    python scripts/dump_tool_baseline.py --compare l1 --base-ref origin/dev
    python scripts/dump_tool_baseline.py --compare l3 --family network --base-ref origin/dev
    python scripts/dump_tool_baseline.py --compare l2 --base-dir /path/to/base/files
    python scripts/dump_tool_baseline.py --check-docs     # docs.json equals the docs on disk
    python scripts/dump_tool_baseline.py --rehash-docs    # public transform: re-pin rewritten docs

Comparison modes (the runtime and the committed files are compared with the files at the
PR's base, so a correct merge of an earlier PR never turns a later one red):

``l1``  a move: no file may differ in any way, and neither may the runtime.
``l2``  a description pass: only string ``description`` values (a tool's, and the parameter
        descriptions inside its schemas) may differ, and the docs hashes. The order, the
        annotations, every other schema field, every call result and every error string
        must stay equal.
``l3``  a tool PR on ``--family F``: only family F's file may differ; the name order of the
        other families' tools must stay equal; the docs hashes may differ.

Capture in a fresh process. An exposure policy (``UNIFI_EXCLUDE``, ``UNIFI_FAMILY_ALLOW``,
a write deny) de-registers tools for a session and puts them back at the *end* of the
registry when it ends, so any capture after such a session in the same process sees a
different registration order. This script captures the tool list before it opens one.

The public release rewrites the operator docs (repository names, links), so their hashes
differ in the public tree. ``scripts/public_release_transform.sh`` therefore runs
``--rehash-docs`` after its last rewrite. It re-pins every file and section ``docs.json``
already lists (none skipped or excluded), writes nothing and fails when a listed file or
section has gone missing, and leaves every other baseline file as it is. ``--check-docs`` is
the same comparison without the write. Both run without the server. Whether the private pins
are current is ``--verify``'s question, asked by ``tests/test_behavior_baseline.py``.

Exit status: 0 equal / allowed, 1 a difference the mode does not allow (a readable diff on
stdout), 2 a usage or environment error.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import AsyncIterator, Iterable, Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

BASELINE_DIR = ROOT / "tests" / "fixtures" / "behavior_baseline"
BASELINE_REL = "tests/fixtures/behavior_baseline"
ORDER_FILE = "order.json"
DOCS_FILE = "docs.json"
MODES = ("l1", "l2", "l3")

#: The tool-list fields a baseline entry carries, in this order. The first five are the
#: public #42 format; ``title`` and ``_meta`` are also client-visible, so they are frozen.
ENTRY_KEYS = ("name", "description", "inputSchema", "outputSchema", "annotations")
EXTRA_ENTRY_KEYS = ("title", "_meta")

#: Generated tool reference pages: operator documentation of the tools themselves.
PINNED_DOCS = ("docs/TOOLS.md", "docs/CATALOG.md", "docs/TOOL-USAGE.md", "docs/CONFIGURATION.md")

#: The representative calls per family, pinned by name (a rename shows as a loud failure,
#: not a silent change of coverage). ``write`` is None for a family with no write tool.
#: Arguments come from ``tests/tool_args.generated_args`` (each tool's own schema), so a
#: call is valid on its own terms; the recorded entry names them.
FAMILY_CALLS: dict[str, dict[str, str | None]] = {
    "carrier": {"read": "list_carrier_subscribers", "write": "create_carrier_subscriber"},
    "clients": {"read": "list_clients", "write": "block_client"},
    "connector": {"read": "fabric_connector_get", "write": "fabric_connector_post"},
    "devices": {"read": "list_site_devices", "write": "restart_device"},
    "firewall": {"read": "list_firewall_policies", "write": "create_firewall_policy"},
    "hotspot": {"read": "list_hotspot_operators", "write": "delete_hotspot_operator"},
    "innerspace": {"read": "get_innerspace_summary", "write": "create_innerspace_plan"},
    "mobility": {"read": "list_mobility_workspaces", "write": "update_mobility_device_name"},
    "network": {"read": "list_networks", "write": "create_network"},
    "protect": {"read": "list_cameras", "write": "reboot_protect_device"},
    "site_manager": {"read": "get_host", "write": None},
    "statistics": {"read": "get_site_statistics", "write": "get_system_log"},
    "vpn": {"read": "list_vpn_servers", "write": "create_vpn_server"},
}

#: An argument no tool declares: the validation-error call.
INVALID_ARGUMENT = {"baseline_unknown_argument": 1}

_DOC_REF = re.compile(r"(?<![\w/.-])((?:docs/)?[A-Za-z][A-Za-z0-9_-]*\.md)(?:#([A-Za-z0-9_-]+))?")

Baseline = dict[str, Any]

#: ``UNIFI_PRELOAD`` for every session of this capture (``--preload``), set after the
#: ambient environment is cleared; None leaves the server default (public #41).
_PRELOAD: str | None = None


# ------------------------------------------------------------------------------ runtime
@contextlib.asynccontextmanager
async def _session(mode: str, env: Mapping[str, str]) -> AsyncIterator[Any]:
    """One in-process MCP session on a fresh fake upstream, in ``mode`` under ``env``.

    The ambient ``UNIFI_*``/``MCP_*`` environment is cleared first, so the baseline never
    depends on the machine that ran it.
    """
    import pytest
    from fastmcp import Client

    from tests import upstream_harness as uh
    from unifi_fabric import server

    with pytest.MonkeyPatch.context() as mp:
        for name in [n for n in os.environ if n.startswith(("UNIFI_", "MCP_"))]:
            mp.delenv(name)
        if _PRELOAD is not None:
            mp.setenv("UNIFI_PRELOAD", _PRELOAD)
        for name, value in env.items():
            mp.setenv(name, value)
        uh.install(mp, uh.FakeUpstream(), tool_mode=mode)
        async with Client(server.mcp) as client:
            yield client


def _blocks(result: Any) -> list[Any]:
    return [block.model_dump(by_alias=True, exclude_none=True) for block in result.content]


def _envelope(result: Any) -> dict[str, Any]:
    """The client-visible ``CallToolResult``: content blocks, structured content, error flag."""
    return {
        "isError": bool(result.is_error),
        "content": _blocks(result),
        "structuredContent": result.structured_content,
    }


async def _call(client: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        return _envelope(await client.call_tool(name, arguments, raise_on_error=False))
    except Exception as exc:  # a protocol-level failure is a result too
        return {"raised": {"type": type(exc).__name__, "message": str(exc)}}


def _entry(tool: Any) -> dict[str, Any]:
    dumped = tool.model_dump(by_alias=True, exclude_none=True)
    entry = {key: dumped.get(key) for key in ENTRY_KEYS}
    entry.update({key: dumped[key] for key in EXTRA_ENTRY_KEYS if key in dumped})
    return entry


async def capture_tools(app: Any = None) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Every full-mode ``tools/list`` entry in list order, and the family of each tool.

    ``app`` lists a given FastMCP app (a test's seeded clone) instead of the server.
    """
    from fastmcp import Client

    from unifi_fabric.families import build_family_index

    if app is not None:
        async with Client(app) as client:
            entries = [_entry(tool) for tool in await client.list_tools()]
    else:
        async with _session("full", {}) as client:
            entries = [_entry(tool) for tool in await client.list_tools()]
    return entries, dict(build_family_index())


async def capture_describe(names: Iterable[str]) -> dict[str, Any]:
    """``describe_tool`` for each name, in discovery mode."""
    out: dict[str, Any] = {}
    async with _session("discovery", {}) as client:
        for name in names:
            out[name] = await _call(client, "describe_tool", {"name": name})
    return out


async def _tool_objects() -> dict[str, Any]:
    from unifi_fabric import server

    return {t.name: t for t in await server.mcp.list_tools(run_middleware=False)}


async def capture_calls(family: str) -> dict[str, Any]:
    """The representative calls of ``family``: one fresh session and fake upstream each."""
    from tests import tool_args

    plan = FAMILY_CALLS[family]
    registered = await _tool_objects()
    read = plan["read"]
    write = plan["write"]
    if read not in registered:
        raise RuntimeError(f"{family}: pinned read tool {read!r} is not registered")
    read_args = dict(tool_args.generated_args(registered[read]))

    async def record(
        tool: str, arguments: dict[str, Any], env: dict[str, str], mode: str = "full"
    ) -> dict[str, Any]:
        async with _session(mode, env) as client:
            result = await _call(client, tool, arguments)
        return {"tool": tool, "arguments": arguments, "env": env, "result": result}

    calls: dict[str, Any] = {
        "read": await record(read, read_args, {}),
        "validation_error": await record(read, dict(INVALID_ARGUMENT), {}),
        "tool_not_exposed": await record(read, read_args, {"UNIFI_EXCLUDE": f"family:{family}"}),
    }
    if write is None:
        calls.update(write_dry_run=None, write_confirm=None, write_denied=None)
    else:
        if write not in registered:
            raise RuntimeError(f"{family}: pinned write tool {write!r} is not registered")
        write_args = dict(tool_args.generated_args(registered[write]))
        calls["write_dry_run"] = await record(write, write_args, {"UNIFI_WRITE_POLICY": "dry-run"})
        calls["write_confirm"] = await record(write, {**write_args, "confirm": True}, {})
        calls["write_denied"] = await record(write, write_args, {"UNIFI_WRITE_POLICY": "deny"})
    return {
        key: calls[key]
        for key in (
            "read",
            "write_dry_run",
            "write_confirm",
            "write_denied",
            "validation_error",
            "tool_not_exposed",
        )
    }


# ---------------------------------------------------------------------------------- docs
def _slug(heading: str) -> str:
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", heading.strip().lower()))


def _section(text: str, anchor: str) -> str | None:
    """The Markdown section with heading slug ``anchor`` (to the next heading of its level)."""
    lines = text.splitlines()
    for start, line in enumerate(lines):
        match = re.match(r"(#+)\s+(.*)", line)
        if match and _slug(match.group(2)) == anchor:
            level = len(match.group(1))
            end = len(lines)
            for i in range(start + 1, len(lines)):
                nxt = re.match(r"(#+)\s", lines[i])
                if nxt and len(nxt.group(1)) <= level:
                    end = i
                    break
            return "\n".join(lines[start:end])
    return None


def _sha(data: bytes) -> str:
    """sha256 in eight-character groups: the fixture sanitiser reads a 16-digit run as an IMEISV."""
    digest = hashlib.sha256(data).hexdigest()
    return "-".join(digest[i : i + 8] for i in range(0, len(digest), 8))


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def capture_docs(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Hashes of the operator docs the tool entries cite, and of the generated tool pages."""
    cited: dict[str, dict[str, set[str]]] = {}
    for entry in entries:
        for text in _strings(entry):
            for match in _DOC_REF.finditer(text):
                name, anchor = match.group(1), match.group(2)
                path = name if name.startswith("docs/") else f"docs/{name}"
                if not (ROOT / path).is_file():
                    path = name
                    if not (ROOT / path).is_file():
                        continue
                slot = cited.setdefault(path, {})
                slot.setdefault(anchor or "", set()).add(entry["name"])
    for path in PINNED_DOCS:
        cited.setdefault(path, {})
    docs: dict[str, Any] = {}
    for path in sorted(cited):
        raw = (ROOT / path).read_bytes()
        text = raw.decode("utf-8")
        sections: dict[str, Any] = {}
        for anchor in sorted(a for a in cited[path] if a):
            body = _section(text, anchor)
            sections[anchor] = _sha(body.encode()) if body is not None else "missing"
        cited_by = sorted({name for names in cited[path].values() for name in names})
        docs[path] = {"sha256": _sha(raw), "sections": sections, "cited_by": cited_by}
    return docs


def _doc_entry(path: str, entry: Mapping[str, Any], root: Path) -> tuple[dict[str, Any], list[str]]:
    """``entry`` of ``docs.json`` recomputed from ``root`` / ``path``, with what went missing."""
    target = root / path
    if not target.is_file():
        return dict(entry), [f"{path}: listed in {DOCS_FILE} but not in the tree"]
    raw = target.read_bytes()
    text = raw.decode("utf-8")
    problems: list[str] = []
    sections: dict[str, Any] = {}
    for anchor in sorted(entry.get("sections", {})):
        body = _section(text, anchor)
        if body is not None:
            sections[anchor] = _sha(body.encode())
        else:
            sections[anchor] = "missing"
            if entry["sections"][anchor] != "missing":
                problems.append(f"{path}: section #{anchor} is pinned but not in the file")
    fresh = {"sha256": _sha(raw), "sections": sections, "cited_by": entry.get("cited_by", [])}
    return fresh, problems


def docs_drift(directory: Path = BASELINE_DIR, root: Path = ROOT) -> list[str]:
    """What differs between ``docs.json`` and the docs on disk (nothing: they agree)."""
    recorded = json.loads((directory / DOCS_FILE).read_text(encoding="utf-8"))
    problems: list[str] = []
    for path, entry in recorded.items():
        fresh, missing = _doc_entry(path, entry, root)
        problems += missing
        problems += _file_diff(DOCS_FILE, {path: entry}, {path: fresh}) if not missing else []
    return problems


def rehash_docs(directory: Path = BASELINE_DIR, root: Path = ROOT) -> list[str]:
    """Re-pin ``docs.json`` to the docs on disk: only listed files and sections, fail closed.

    Returns the problems; the file is written only when there are none.
    """
    recorded = json.loads((directory / DOCS_FILE).read_text(encoding="utf-8"))
    problems: list[str] = []
    fresh_docs: dict[str, Any] = {}
    for path, entry in recorded.items():
        fresh, missing = _doc_entry(path, entry, root)
        problems += missing
        fresh_docs[path] = fresh
    if not problems:
        (directory / DOCS_FILE).write_text(dumps(fresh_docs), encoding="utf-8")
    return problems


# ------------------------------------------------------------------------------ baseline
def split_by_family(
    entries: list[dict[str, Any]], index: Mapping[str, str]
) -> dict[str, list[dict[str, Any]]]:
    """``entries`` grouped by family, each group in list order."""
    from unifi_fabric.families import ALL_FAMILIES

    unclassified = [e["name"] for e in entries if e["name"] not in index]
    if unclassified:
        raise RuntimeError(f"tools with no family: {unclassified}")
    by_family: dict[str, list[dict[str, Any]]] = {fam: [] for fam in ALL_FAMILIES}
    for entry in entries:
        by_family[index[entry["name"]]].append(entry)
    return by_family


async def capture_family(family: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
    """One family's file: its ``tools`` entries, ``describe`` for each and the ``calls``."""
    return {
        "tools": tools,
        "describe": await capture_describe([entry["name"] for entry in tools]),
        "calls": await capture_calls(family),
    }


async def capture(families: Iterable[str] | None = None, *, progress: bool = False) -> Baseline:
    """The baseline of the running server. ``families`` limits the per-family files."""
    from unifi_fabric.families import ALL_FAMILIES

    wanted = list(families) if families is not None else list(ALL_FAMILIES)
    entries, index = await capture_tools()
    by_family = split_by_family(entries, index)
    out: Baseline = {ORDER_FILE: [e["name"] for e in entries], DOCS_FILE: capture_docs(entries)}
    for fam in wanted:
        if progress:
            print(f"capture {fam}: {len(by_family[fam])} tools", file=sys.stderr)
        out[f"{fam}.json"] = await capture_family(fam, by_family[fam])
    return out


def dumps(value: Any) -> str:
    return json.dumps(value, indent=1, ensure_ascii=False) + "\n"


def write_baseline(baseline: Baseline, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, value in baseline.items():
        path = directory / name
        path.write_text(dumps(value), encoding="utf-8")
        written.append(path)
    return written


def read_baseline_dir(directory: Path) -> Baseline:
    """The baseline files in ``directory`` (empty when it has none)."""
    out: Baseline = {}
    for path in sorted(directory.glob("*.json")):
        out[path.name] = json.loads(path.read_text(encoding="utf-8"))
    if not out:
        raise RuntimeError(f"no baseline files in {directory}")
    return out


def read_baseline_ref(ref: str, repo: Path = ROOT) -> Baseline:
    """The baseline files committed at git ``ref`` (the PR's base)."""
    listing = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "--name-only", ref, f"{BASELINE_REL}/"],
        capture_output=True,
        text=True,
        check=False,
    )
    if listing.returncode != 0:
        raise RuntimeError(f"git ls-tree {ref}: {listing.stderr.strip()}")
    out: Baseline = {}
    for line in listing.stdout.split():
        name = line.rsplit("/", 1)[-1]
        if not name.endswith(".json"):
            continue
        shown = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{line}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if shown.returncode != 0:
            raise RuntimeError(f"git show {ref}:{line}: {shown.stderr.strip()}")
        out[name] = json.loads(shown.stdout)
    if not out:
        raise RuntimeError(f"no baseline files at {ref}:{BASELINE_REL}/ (the PR's base has none)")
    return out


# ------------------------------------------------------------------------------- compare
def _short(value: Any, limit: int = 140) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else f"{text[: limit - 1]}… ({len(text)} chars)"


def _maybe_json(value: Any) -> Any:
    """A string that holds a JSON object or array, parsed, so a result diffs field by field."""
    if isinstance(value, str) and value[:1] in "{[":
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _keyed(items: list[Any]) -> dict[str, Any] | None:
    if items and all(isinstance(i, dict) and isinstance(i.get("name"), str) for i in items):
        names = [i["name"] for i in items]
        if len(set(names)) == len(names):
            return dict(zip(names, items, strict=True))
    return None


def _diff_names(base: list[str], head: list[str], where: str) -> list[str]:
    """A list of names (the tool order): what was added or removed, then what moved."""
    lines = [f"{where}: removed {name!r}" for name in base if name not in set(head)]
    lines += [f"{where}: added {name!r}" for name in head if name not in set(base)]
    kept_base = [n for n in base if n in set(head)]
    kept_head = [n for n in head if n in set(base)]
    if kept_base != kept_head:
        at = next(i for i, (b, h) in enumerate(zip(kept_base, kept_head, strict=True)) if b != h)
        moved = sum(b != h for b, h in zip(kept_base, kept_head, strict=True))
        lines.append(
            f"{where}: order changed, {moved} positions differ; first at index {at}: "
            f"base {kept_base[at]!r}, head {kept_head[at]!r} "
            f"({kept_base[at]!r} is now at index {kept_head.index(kept_base[at])})"
        )
    return lines


def diff(base: Any, head: Any, path: str = "") -> list[str]:
    """Readable differences between two JSON values, one line each: ``path: base -> head``."""
    base, head = _maybe_json(base), _maybe_json(head)
    where = path or "<root>"
    if isinstance(base, dict) and isinstance(head, dict):
        lines: list[str] = []
        for key in base.keys() | head.keys():
            sub = f"{path}.{key}" if path else str(key)
            if key not in head:
                lines.append(f"{sub}: removed (was {_short(base[key])})")
            elif key not in base:
                lines.append(f"{sub}: added ({_short(head[key])})")
            else:
                lines.extend(diff(base[key], head[key], sub))
        key_order = [k for k in base if k in head]
        if not lines and key_order != [k for k in head if k in base]:
            lines.append(f"{where}: key order changed")
        return sorted(lines) if lines else lines
    if isinstance(base, list) and isinstance(head, list):
        if all(isinstance(x, str) for x in (*base, *head)):
            return _diff_names(base, head, where)
        kb, kh = _keyed(base), _keyed(head)
        if kb is not None and kh is not None:
            lines = []
            for name in kb.keys() | kh.keys():
                sub = f"{path}[{name}]"
                if name not in kh:
                    lines.append(f"{sub}: removed")
                elif name not in kb:
                    lines.append(f"{sub}: added")
                else:
                    lines.extend(diff(kb[name], kh[name], sub))
            if not lines and list(kb) != list(kh):
                lines.append(
                    f"{where}: order changed {_short(list(kb), 90)} -> {_short(list(kh), 90)}"
                )
            return sorted(lines) if lines else lines
        if len(base) != len(head):
            return [f"{where}: length {len(base)} -> {len(head)}"]
        lines = []
        for i, (b, h) in enumerate(zip(base, head, strict=True)):
            lines.extend(diff(b, h, f"{path}[{i}]"))
        return lines
    return [] if base == head else [f"{where}: {_short(base)} -> {_short(head)}"]


def _strip_descriptions(value: Any) -> Any:
    """``value`` without its string ``description`` values (a parameter *named* description,
    whose value is a schema object, stays). JSON held in a string is looked through."""
    value = _maybe_json(value)
    if isinstance(value, dict):
        return {
            k: _strip_descriptions(v)
            for k, v in value.items()
            if not (k == "description" and isinstance(v, str))
        }
    if isinstance(value, list):
        return [_strip_descriptions(v) for v in value]
    return value


def _order_without(order: list[str], names: set[str]) -> list[str]:
    return [n for n in order if n not in names]


def _file_diff(name: str, base: Any, head: Any) -> list[str]:
    return [f"{name}: {line}" for line in diff(base, head)]


def compare(base: Baseline, head: Baseline, mode: str, family: str | None = None) -> list[str]:
    """The differences between ``head`` and ``base`` that ``mode`` does not allow.

    ``base`` and ``head`` map file name to parsed JSON. Only files present in both are
    compared per family, so a partial capture (one family) compares like for like.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
    if mode == "l3" and not family:
        raise ValueError("mode l3 needs the family the PR changes")
    problems: list[str] = []
    for name in sorted(base.keys() | head.keys()):
        if name not in head and name != ORDER_FILE and name != DOCS_FILE:
            if name in base:
                problems.append(f"{name}: missing from the head")
            continue
        if name not in base:
            # a file the base never had (only a partial capture or a new family): not a drift
            continue
        b, h = base[name], head[name]
        if mode == "l1":
            problems.extend(_file_diff(name, b, h))
        elif mode == "l2":
            if name == DOCS_FILE:
                continue
            problems.extend(_file_diff(name, _strip_descriptions(b), _strip_descriptions(h)))
        else:  # l3
            if name == DOCS_FILE or name == f"{family}.json":
                continue
            if name == ORDER_FILE:
                own = {t["name"] for t in (head.get(f"{family}.json") or {}).get("tools", [])} | {
                    t["name"] for t in (base.get(f"{family}.json") or {}).get("tools", [])
                }
                problems.extend(
                    _file_diff(
                        f"{name} (without {family} tools)",
                        _order_without(b, own),
                        _order_without(h, own),
                    )
                )
            else:
                problems.extend(_file_diff(name, b, h))
    return problems


def report(problems: list[str], *, limit: int = 60) -> str:
    shown = problems[:limit]
    more = len(problems) - len(shown)
    tail = [f"... and {more} more differences"] if more > 0 else []
    return "\n".join([*shown, *tail])


# ---------------------------------------------------------------------------------- CLI
def _load_base(args: argparse.Namespace) -> Baseline:
    if args.base_dir:
        return read_baseline_dir(Path(args.base_dir))
    return read_baseline_ref(args.base_ref)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dir", default=str(BASELINE_DIR), help="baseline directory (head files)")
    parser.add_argument("--verify", action="store_true", help="the runtime must equal the files")
    parser.add_argument("--compare", choices=MODES, help="compare the runtime with the base")
    parser.add_argument("--family", help="the family an l3 PR changes")
    parser.add_argument("--base-ref", default="origin/dev", help="git ref of the PR's base")
    parser.add_argument("--base-dir", help="a directory of base files, instead of --base-ref")
    parser.add_argument("--only", action="append", help="limit to this family (repeatable)")
    parser.add_argument(
        "--no-order-docs", action="store_true", help="leave order.json and docs.json out"
    )
    parser.add_argument(
        "--preload",
        help="UNIFI_PRELOAD for every capture session (all, none, family:<id>[,...]); set "
        "after the ambient environment is cleared",
    )
    parser.add_argument(
        "--warm",
        action="store_true",
        help="load every deferred step before the capture (warm), whatever --preload says",
    )
    parser.add_argument(
        "--check-docs", action="store_true", help="docs.json must equal the docs on disk"
    )
    parser.add_argument(
        "--rehash-docs",
        action="store_true",
        help="re-pin docs.json to the docs on disk (the public transform's step), fail closed",
    )
    args = parser.parse_args(argv)
    global _PRELOAD
    _PRELOAD = args.preload
    directory = Path(args.dir)
    if args.check_docs or args.rehash_docs:
        try:
            problems = (rehash_docs if args.rehash_docs else docs_drift)(directory)
        except (OSError, ValueError, KeyError) as exc:
            print(f"dump_tool_baseline: {exc}", file=sys.stderr)
            return 2
        if problems:
            print(report(problems))
            print(f"\n{DOCS_FILE}: {len(problems)} difference(s)")
            return 1
        print(f"{DOCS_FILE} {'re-pinned' if args.rehash_docs else 'matches the docs'}")
        return 0
    # The docs modes above never import the server (the public transform runs them without
    # the runtime installed, and they must leave no bytecode in the shipped tree).
    from unifi_fabric import server
    from unifi_fabric.catalog import deferred

    if args.warm:
        deferred.load_all(server.mcp)
    controller = deferred.controller_for(server.mcp)
    print(
        f"effective UNIFI_PRELOAD={_PRELOAD if _PRELOAD is not None else 'default'} "
        f"deferred={'yes' if controller is not None else 'no (eager)'} "
        f"warm={'yes' if args.warm else 'no'} "
        f"steps_loaded_before_capture="
        f"{sum(1 for v in (controller.state() if controller else {}).values() if v == 'loaded')}",
        flush=True,
    )
    try:
        base_files = _load_base(args) if args.compare else {}  # fail fast, before the capture
        runtime = asyncio.run(capture(args.only, progress=True))
        keep = {f"{f}.json" for f in args.only or ()}
        if not args.no_order_docs:
            keep |= {ORDER_FILE, DOCS_FILE}

        def limited(files: Baseline) -> Baseline:
            return (
                {k: v for k, v in files.items() if k in keep}
                if (args.only or args.no_order_docs)
                else files
            )

        if args.compare:
            base = limited(base_files)
            problems = compare(base, limited(runtime), args.compare, args.family)
            head_files = limited(read_baseline_dir(directory))
            problems += [
                f"[files] {p}" for p in compare(base, head_files, args.compare, args.family)
            ]
        elif args.verify:
            problems = compare(limited(read_baseline_dir(directory)), limited(runtime), "l1")
        else:
            paths = write_baseline(runtime, directory)
            print(f"wrote {len(paths)} files to {directory}")
            return 0
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"dump_tool_baseline: {exc}", file=sys.stderr)
        return 2
    if problems:
        print(report(problems))
        print(f"\n{len(problems)} difference(s) not allowed by the baseline rules")
        return 1
    print("baseline matches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
