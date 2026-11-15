#!/usr/bin/env python3
"""AST rule: a family module never imports another family; core never imports a family.

Families are the directories under ``src/unifi_fabric/families/<family>/``. Every import
(``import``, ``from ... import``, relative forms, function-level forms, and
``importlib.import_module`` / ``__import__`` calls with a string-literal argument) that
targets a module under ``unifi_fabric.families.<F>`` is an edge:

* family F -> family G (G != F): ``family-to-family``, allowlisted per edge in
  ``scripts/family_import_allowlist.txt`` until the L1-C family PR removes it;
* non-family module -> any family: ``core-to-family``, never allowlisted;
* the module-level import graph among family modules must have no cycle (strongly
  connected component of more than one module) beyond the reviewed network pair.

Modes: strict (default; exit 1 on a violation, a stale allowlist entry or a cycle),
``--report`` (every edge as JSON lines, exit 0), ``--markdown`` (the per-family list),
``--write-allowlist`` (regenerate the allowlist from the current family-to-family edges).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "unifi_fabric"
FAMILIES_PKG = f"{PACKAGE}.families"
ALLOWLIST = Path("scripts/family_import_allowlist.txt")
#: Exact repo-relative paths whose imports are not checked: the catalog loader imports a
#: family by a computed module path, and the placement snapshot is a separate console script.
EXEMPT_FILES = frozenset(
    {
        "src/unifi_fabric/catalog/loaders.py",
        "src/unifi_fabric/placement_snapshot_cli.py",
    }
)
#: Exact repo-relative paths allowed to import a module by a computed path (a dynamic
#: import whose target is not a string literal). Anywhere else such an import fails
#: closed, because the check cannot tell whether it reaches a family.
DYNAMIC_EXEMPT_FILES = frozenset(
    {
        "src/unifi_fabric/catalog/deferred.py",  # the loader map's steps, by entry
        "src/unifi_fabric/registration.py",  # registration refs, by entry
        "src/unifi_fabric/tracing.py",  # the optional OTLP exporter module
    }
)
#: The kind of a dynamic import whose target is computed (outside DYNAMIC_EXEMPT_FILES).
DYNAMIC_KIND = "dynamic-import"
DYNAMIC_TARGET = "<computed module path>"

#: The one reviewed module-level cycle.
ALLOWED_CYCLES = frozenset(
    {
        frozenset(
            {
                "unifi_fabric.families.network.network",
                "unifi_fabric.families.network.network_services_proxy",
            }
        )
    }
)

LEVEL_MODULE = "module"
LEVEL_FUNCTION = "function"
#: Under ``if TYPE_CHECKING:``: never executed, so not part of the cycle graph.
LEVEL_TYPING = "typing"

_ALLOW_RE = re.compile(r"^(?P<imp>\S+) -> (?P<mod>\S+): (?P<names>\S*)\s+# L1-C (?P<fam>\S+)$")


@dataclass(frozen=True)
class Edge:
    importer: str  # dotted module
    file: str  # repo-relative path
    lineno: int
    imported: str  # dotted module under unifi_fabric.families.<F>
    names: tuple[str, ...]  # imported names; empty for ``import x`` and submodule imports
    level: str  # module | function | typing
    via: str  # import | from | importlib
    importer_family: str | None
    imported_family: str
    kind: str  # family-to-family | core-to-family | intra-family

    def key(self) -> tuple[str, str, tuple[str, ...]]:
        return (self.importer, self.imported, self.names)


def _module_name(path: Path, src: Path) -> tuple[str, bool]:
    rel = path.relative_to(src).with_suffix("")
    parts = list(rel.parts)
    is_pkg = parts[-1] == "__init__"
    if is_pkg:
        parts = parts[:-1]
    return ".".join(parts), is_pkg


def _family_of(module: str, families: frozenset[str]) -> str | None:
    prefix = FAMILIES_PKG + "."
    if module.startswith(prefix):
        head = module[len(prefix) :].split(".", 1)[0]
        if head in families:
            return head
    return None


def _resolve_relative(module: str, is_pkg: bool, level: int, target: str | None) -> str | None:
    parts = module.split(".")
    package = parts if is_pkg else parts[:-1]
    base = package[: len(package) - (level - 1)]
    if level - 1 >= len(package) or not base:
        return None
    return ".".join([*base, *([target] if target else [])])


def _exists(src: Path, dotted: str) -> bool:
    if dotted != PACKAGE and not dotted.startswith(PACKAGE + "."):
        return False
    rel = Path(*dotted.split("."))
    base = src / rel
    return base.with_suffix(".py").is_file() or (base / "__init__.py").is_file()


def _str_arg(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


class _Visitor(ast.NodeVisitor):
    """Collect raw import references as (lineno, level, via, absolute module, names)."""

    def __init__(self, module: str, is_pkg: bool, src: Path) -> None:
        self.module, self.is_pkg, self.src = module, is_pkg, src
        self.depth = 0
        self.typing = 0
        self.refs: list[tuple[int, str, str, str, tuple[str, ...]]] = []
        # Names bound to the importlib module and to its import_module (aliases included).
        self.importlib_names: set[str] = set()
        self.import_module_names: set[str] = {"__import__"}

    def _level(self) -> str:
        if self.depth:
            return LEVEL_FUNCTION
        return LEVEL_TYPING if self.typing else LEVEL_MODULE

    def _func(self, node: ast.AST) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func
    visit_Lambda = _func

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking(node.test):
            self.typing += 1
            for child in node.body:
                self.visit(child)
            self.typing -= 1
            for child in node.orelse:
                self.visit(child)
        else:
            self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "importlib":
                self.importlib_names.add(alias.asname or "importlib")
            self.refs.append((node.lineno, self._level(), "import", alias.name, ()))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            base = _resolve_relative(self.module, self.is_pkg, node.level, node.module)
        else:
            base = node.module
        if base is None:
            return
        if base in ("importlib", "builtins"):
            for alias in node.names:
                if alias.name in ("import_module", "__import__"):
                    self.import_module_names.add(alias.asname or alias.name)
        names = tuple(sorted(alias.name for alias in node.names))
        self.refs.append((node.lineno, self._level(), "from", base, names))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # Any ``<x>.import_module(...)`` / ``<x>.__import__(...)``, and any name bound to
        # import_module or __import__ (``from importlib import import_module as im``).
        dynamic = (
            isinstance(func, ast.Attribute) and func.attr in {"import_module", "__import__"}
        ) or (
            isinstance(func, ast.Name)
            and (func.id in self.import_module_names or func.id == "import_module")
        )
        if dynamic:
            target = _str_arg(node.args[0]) if node.args else None
            if target is None:
                # A computed target: the check cannot resolve it, so it fails closed.
                self.refs.append((node.lineno, self._level(), "dynamic", DYNAMIC_TARGET, ()))
            if target is not None:
                if target.startswith("."):
                    package = _str_arg(node.args[1]) if len(node.args) > 1 else None
                    for kw in node.keywords:
                        if kw.arg == "package":
                            package = _str_arg(kw.value)
                    if package is not None:
                        stripped = target.lstrip(".")
                        up = len(target) - len(stripped)
                        parts = package.split(".")
                        base = parts[: len(parts) - (up - 1)] if up > 1 else parts
                        target = ".".join([*base, *([stripped] if stripped else [])])
                    else:
                        target = None
                if target:
                    self.refs.append((node.lineno, self._level(), "importlib", target, ()))
        self.generic_visit(node)


def _expand(
    src: Path, families: frozenset[str], via: str, base: str, names: tuple[str, ...]
) -> list[tuple[str, tuple[str, ...]]]:
    """Resolve one reference to (module, names) pairs, splitting submodule imports out."""
    if via != "from":
        return [(base, names)]
    out: list[tuple[str, tuple[str, ...]]] = []
    attrs: list[str] = []
    for name in names:
        sub = f"{base}.{name}"
        if name != "*" and _exists(src, sub):
            out.append((sub, ()))
        else:
            attrs.append(name)
    if attrs:
        out.append((base, tuple(attrs)))
    return out


def scan(root: Path) -> list[Edge]:
    """Return every import edge that targets a family module under ``root/src/unifi_fabric``."""
    src = root / "src"
    pkg_dir = src / PACKAGE
    fam_dir = pkg_dir / "families"
    families = frozenset(
        p.name for p in fam_dir.iterdir() if p.is_dir() and p.name != "__pycache__"
    )
    edges: list[Edge] = []
    for path in sorted(pkg_dir.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel in EXEMPT_FILES:
            continue
        module, is_pkg = _module_name(path, src)
        visitor = _Visitor(module, is_pkg, src)
        visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=rel))
        importer_family = _family_of(module, families)
        for lineno, level, via, base, names in visitor.refs:
            if via == "dynamic":
                if rel not in DYNAMIC_EXEMPT_FILES:
                    edges.append(
                        Edge(
                            module,
                            rel,
                            lineno,
                            DYNAMIC_TARGET,
                            (),
                            level,
                            via,
                            _family_of(module, families),
                            "?",
                            DYNAMIC_KIND,
                        )
                    )
                continue
            for imported, imp_names in _expand(src, families, via, base, names):
                target_family = _family_of(imported, families)
                if target_family is None:
                    continue  # not a family module (incl. the families package root helpers)
                if importer_family is None:
                    kind = "core-to-family"
                elif importer_family != target_family:
                    kind = "family-to-family"
                else:
                    kind = "intra-family"
                edges.append(
                    Edge(
                        module,
                        rel,
                        lineno,
                        imported,
                        imp_names,
                        level,
                        via,
                        importer_family,
                        target_family,
                        kind,
                    )
                )
    return edges


def find_cycles(edges: list[Edge]) -> list[frozenset[str]]:
    """Strongly connected components (size > 1) of the module-level family import graph."""
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if edge.level == LEVEL_MODULE and edge.importer_family is not None:
            if edge.importer != edge.imported:
                graph[edge.importer].add(edge.imported)
                graph.setdefault(edge.imported, set())
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    sccs: list[frozenset[str]] = []
    counter = 0

    def strong(v: str) -> None:
        nonlocal counter
        # iterative Tarjan to stay clear of the recursion limit
        work = [(v, iter(sorted(graph[v])))]
        index[v] = low[v] = counter
        counter += 1
        stack.append(v)
        on_stack.add(v)
        while work:
            node, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(sorted(graph[w]))))
                    advanced = True
                    break
                if w in on_stack:
                    low[node] = min(low[node], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                comp = set()
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.add(w)
                    if w == node:
                        break
                if len(comp) > 1:
                    sccs.append(frozenset(comp))

    for v in sorted(graph):
        if v not in index:
            strong(v)
    return sorted(sccs, key=sorted)


def disallowed_cycles(edges: list[Edge]) -> list[frozenset[str]]:
    return [c for c in find_cycles(edges) if c not in ALLOWED_CYCLES]


def _fmt_names(names: tuple[str, ...]) -> str:
    return ",".join(names) if names else "-"


def allowlist_line(edge: Edge) -> str:
    head = f"{edge.importer} -> {edge.imported}: {_fmt_names(edge.names)}"
    return f"{head}  # L1-C {edge.importer_family}"


def render_allowlist(edges: list[Edge]) -> str:
    cross = sorted(
        (e for e in edges if e.kind == "family-to-family"),
        key=lambda e: (e.importer_family or "", e.importer, e.imported, e.names),
    )
    header = (
        "# Allowed family-to-family imports (scripts/check_family_imports.py).\n"
        "# Line format: <importer module> -> <imported module>: <names>  # L1-C <family>\n"
        "# Each L1-C family PR deletes its family's lines; a stale line fails the check.\n"
    )
    return header + "".join(allowlist_line(e) + "\n" for e in cross)


def parse_allowlist(text: str) -> Counter[tuple[str, str, tuple[str, ...]]]:
    entries: Counter[tuple[str, str, tuple[str, ...]]] = Counter()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ALLOW_RE.match(line)
        if not match:
            raise ValueError(f"malformed allowlist line: {raw!r}")
        names = () if match["names"] == "-" else tuple(match["names"].split(","))
        entries[(match["imp"], match["mod"], names)] += 1
    return entries


@dataclass
class Result:
    violations: list[Edge]
    stale: list[tuple[str, str, tuple[str, ...]]]
    cycles: list[frozenset[str]]

    @property
    def ok(self) -> bool:
        return not (self.violations or self.stale or self.cycles)


def evaluate(edges: list[Edge], allowlist: Counter[tuple[str, str, tuple[str, ...]]]) -> Result:
    remaining = Counter(allowlist)
    violations: list[Edge] = []
    for edge in edges:
        if edge.kind == "intra-family":
            continue
        if edge.kind == "family-to-family" and edge.level == LEVEL_MODULE:
            if remaining[edge.key()] > 0:
                remaining[edge.key()] -= 1
                continue
        violations.append(edge)
    stale = sorted(k for k, n in remaining.items() for _ in range(n) if n > 0)
    return Result(violations, stale, disallowed_cycles(edges))


def _statements(edges: list[Edge]) -> int:
    return len({(e.file, e.lineno) for e in edges})


def _name_count(edges: list[Edge]) -> int:
    # A submodule import (``from .. import fam`` or ``import a.b``) counts as one name.
    return sum(len(e.names) or 1 for e in edges)


def _cross(edges: list[Edge]) -> list[Edge]:
    return [e for e in edges if e.kind == "family-to-family"]


def _head_sha(root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return out.stdout.strip()


def render_markdown(edges: list[Edge], head: str) -> str:
    cross = _cross(edges)
    core = [e for e in edges if e.kind == "core-to-family"]
    lines = [
        "# L1-E D1: cross-family imports each L1-C PR removes",
        "",
        f"Generated by `scripts/check_family_imports.py --markdown` at {head}. Each L1-C PR for "
        "family F removes every line under F by moving the shared names into a non-family "
        "common module (`unifi_fabric.shared_shapes` or the new core module) and deleting F's "
        "entries from `scripts/family_import_allowlist.txt`. The CI check fails on a stale "
        "entry, so the allowlist must shrink with each move. Firewall: C2 - L1-C moves "
        "firewall tools into their own modules/steps.",
        "",
        f"Totals: {_statements(cross)} statements, {_name_count(cross)} names, "
        f"{len({e.importer_family for e in cross})} importing families.",
        "",
    ]
    by_family: dict[str, list[Edge]] = defaultdict(list)
    for e in cross:
        by_family[e.importer_family or ""].append(e)
    for fam in sorted(by_family):
        group = sorted(by_family[fam], key=lambda e: (e.file, e.lineno, e.imported))
        lines += [
            f"## {fam}",
            "",
            f"{_statements(group)} statements, {_name_count(group)} names.",
            "",
            "| importer file:line | imports from | names | level |",
            "| --- | --- | --- | --- |",
        ]
        for e in group:
            names = ", ".join(e.names) if e.names else "(module)"
            lines.append(f"| {e.file}:{e.lineno} | {e.imported} | {names} | {e.level} |")
        lines.append("")
    owned: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for e in cross:
        for name in e.names or (e.imported.rsplit(".", 1)[-1] + " (module)",):
            owned[e.imported_family][name].add(e.importer_family or "")
    lines += ["## Imported names by owning family", ""]
    for owner in sorted(owned):
        lines += [f"### {owner}", "", "| name | imported by families |", "| --- | --- |"]
        for name in sorted(owned[owner]):
            lines.append(f"| {name} | {', '.join(sorted(owned[owner][name]))} |")
        lines.append("")
    lines += ["## Non-family code (E1 owns)", ""]
    if not core:
        lines.append("None.")
    for e in sorted(core, key=lambda e: (e.file, e.lineno)):
        names = ",".join(e.names) if e.names else "(module)"
        lines.append(f"- {e.file}:{e.lineno} -> {e.imported} ({names}), {e.level}")
    return "\n".join(lines).rstrip() + "\n"


def _describe(edge: Edge) -> str:
    return (
        f"{edge.file}:{edge.lineno}: {edge.kind} ({edge.level}, {edge.via}): "
        f"{edge.importer} -> {edge.imported}: {_fmt_names(edge.names)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--allowlist", type=Path, default=None, help="allowlist file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--strict", action="store_true", help="default mode")
    mode.add_argument("--report", action="store_true", help="print every edge as JSON lines")
    mode.add_argument("--markdown", action="store_true", help="print the per-family list")
    mode.add_argument("--write-allowlist", action="store_true", help="regenerate the allowlist")
    args = parser.parse_args(argv)
    root: Path = args.root
    allow_path: Path = args.allowlist or root / ALLOWLIST
    edges = scan(root)

    if args.report:
        for e in edges:
            print(json.dumps(asdict(e), sort_keys=True))
        return 0
    if args.markdown:
        sys.stdout.write(render_markdown(edges, _head_sha(root)))
        return 0
    if args.write_allowlist:
        allow_path.write_text(render_allowlist(edges), encoding="utf-8")
        print(f"wrote {allow_path} ({len(_cross(edges))} edges)")
        return 0

    allowlist = (
        parse_allowlist(allow_path.read_text(encoding="utf-8"))
        if allow_path.is_file()
        else Counter()
    )
    result = evaluate(edges, allowlist)
    cross = _cross(edges)
    print(
        f"family-to-family: {_statements(cross)} statements, {_name_count(cross)} names, "
        f"{len({e.importer_family for e in cross})} importing families; "
        f"core-to-family: {sum(e.kind == 'core-to-family' for e in edges)} edges"
    )
    for e in result.violations:
        print(f"VIOLATION {_describe(e)}")
    for imp, mod, names in result.stale:
        print(f"STALE allowlist entry: {imp} -> {mod}: {_fmt_names(names)}")
    for comp in result.cycles:
        print(f"CYCLE {', '.join(sorted(comp))}")
    if result.ok:
        print("OK")
        return 0
    print(
        f"FAILED: {len(result.violations)} violations, {len(result.stale)} stale entries, "
        f"{len(result.cycles)} disallowed cycles"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
